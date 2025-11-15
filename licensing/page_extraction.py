"""Web page license extraction functionality."""

import re
import requests
from typing import List
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from .models import LicenseSearchResult
from .ai_assessment import assess_license_with_ai
from .utils import get_license_patterns


def _clean_text_content(soup: BeautifulSoup) -> str:
    """Clean and extract text content from BeautifulSoup object."""
    # Remove unwanted elements
    for tag in soup(['script', 'style', 'nav', 'header']):
        tag.decompose()
    
    text = soup.get_text(separator='\n', strip=True)
    # Normalize whitespace
    text = re.sub(r'\n\s*\n', '\n\n', text)
    return text


def _extract_license_from_current_page(soup: BeautifulSoup, url: str) -> LicenseSearchResult:
    """Extract license content from the current page."""
    # Try main content first
    main_content = soup.find('main') or soup.find('article') or soup.find('div', class_=re.compile(r'content|main', re.I))
    
    if main_content:
        text = _clean_text_content(main_content)
        if text and len(text) > 100:
            return LicenseSearchResult(found=True, text=text, url=url)
    
    # Fall back to full body
    text = _clean_text_content(soup)
    if text and len(text) > 100:
        return LicenseSearchResult(found=True, text=text, url=url)
    
    return LicenseSearchResult(found=False)


def _is_valid_license_link(link_url: str, base_url: str) -> bool:
    """Check if a link is valid for following (same domain, not already visited)."""
    # Skip external links
    if urlparse(link_url).netloc != urlparse(base_url).netloc:
        return False
    
    # Skip anchors to same page
    if link_url.split('#')[0] == base_url.split('#')[0]:
        return False
    
    return True


def _fetch_and_verify_license_page(url: str, headers: dict) -> LicenseSearchResult:
    """Fetch a potential license page and verify it contains license info."""
    try:
        print(f"  Following license link: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return LicenseSearchResult(found=False)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Use AI to verify this is a license page
        assessment = assess_license_with_ai(url, soup)
        
        if not assessment.contains_license or assessment.confidence == 'low':
            return LicenseSearchResult(found=False)
        
        # Extract license text
        text = _clean_text_content(soup)
        
        if text and len(text) > 100:
            return LicenseSearchResult(found=True, text=text, url=url)
        
    except Exception as e:
        print(f"  Error following link: {e}")
    
    return LicenseSearchResult(found=False)


def _search_license_links(url: str, soup: BeautifulSoup, headers: dict) -> LicenseSearchResult:
    """Search for and follow license-related links on a page."""
    license_patterns = get_license_patterns()
    all_links = soup.find_all('a', href=True)
    
    for link in all_links:
        link_text = link.get_text().lower()
        link_href = link['href'].lower()
        
        # Check if link matches any license pattern
        is_license_link = any(
            re.search(pattern, link_text) or re.search(pattern, link_href)
            for pattern in license_patterns
        )
        
        if not is_license_link:
            continue
        
        full_url = urljoin(url, link['href'])
        
        if not _is_valid_license_link(full_url, url):
            continue
        
        result = _fetch_and_verify_license_page(full_url, headers)
        if result.found:
            return result
    
    return LicenseSearchResult(found=False)


def _search_footer_and_copyright(soup: BeautifulSoup, url: str) -> LicenseSearchResult:
    """Search for license information in footer and copyright notices."""
    license_patterns = get_license_patterns()
    
    # Check footer
    footer = soup.find('footer')
    if footer:
        footer_text = footer.get_text(separator='\n', strip=True)
        has_license_keywords = any(re.search(pattern, footer_text.lower()) for pattern in license_patterns)
        
        if has_license_keywords and len(footer_text) > 50:
            return LicenseSearchResult(found=True, text=footer_text, url=url)
    
    # Check copyright notices
    copyright_pattern = r'©.*?(?:\d{4}|copyright)'
    copyright_matches = soup.find_all(string=re.compile(copyright_pattern, re.IGNORECASE))
    
    if copyright_matches:
        copyright_text = '\n'.join([match.strip() for match in copyright_matches[:5]])
        if copyright_text:
            return LicenseSearchResult(found=True, text=copyright_text, url=url)
    
    return LicenseSearchResult(found=False)


def extract_license_from_page(url: str, soup: BeautifulSoup, headers: dict, use_ai: bool = True) -> LicenseSearchResult:
    """
    Extract license information from a single page.
    
    Args:
        url: The URL of the page being processed
        soup: BeautifulSoup object of the page
        headers: HTTP headers to use for requests
        use_ai: Whether to use AI assessment (default: True)
    
    Returns:
        LicenseSearchResult with found status and license info
    """
    # Step 1: Use AI to assess if this page contains license information
    if use_ai:
        assessment = assess_license_with_ai(url, soup)
        
        if not assessment.contains_license or assessment.confidence == 'low':
            print(f"  AI determined page does not contain license information")
            # Still check for license links to follow
            return _search_license_links(url, soup, headers)
        
        print(f"  AI confirmed license content present (type: {assessment.license_type})")
    
    # Step 2: Extract the license content from this page
    result = _extract_license_from_current_page(soup, url)
    if result.found:
        return result
    
    # Step 3: Search for license links
    result = _search_license_links(url, soup, headers)
    if result.found:
        return result
    
    # Step 4: Check footer and copyright as last resort
    return _search_footer_and_copyright(soup, url)
