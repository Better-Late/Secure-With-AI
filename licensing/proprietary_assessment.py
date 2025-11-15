"""Assessment of proprietary software terms and privacy policies."""

import os
import re
import json
import requests
from typing import List, Optional, Tuple
from bs4 import BeautifulSoup
from dotenv import load_dotenv

from .models import License, LicenseType
from .page_extraction import _clean_text_content
from .gemini_client import generate_content, summarize_legal_text, is_available
from dataclasses import dataclass

load_dotenv()


@dataclass
class ProprietaryAssessment:
    """Assessment of proprietary software terms and privacy."""
    terms_of_use: str
    privacy_assessment: str


def _get_footer_legal_patterns() -> List[str]:
    """Get regex patterns for legal/privacy links in footer."""
    return [
        r'privacy\s*(and\s*security|notice|policy)?',
        r'terms\s*(of\s*(use|service))?',
        r'legal',
        r'eula',
        r'end\s*user\s*license',
        r'data\s*protection',
        r'cookie\s*policy',
        r'acceptable\s*use',
        r'terms',
        r'privacy'
    ]


def _handle_cookie_consent(driver) -> None:
    """
    Attempt to find and click cookie consent buttons.
    Tries reject first, then accept if reject not available.
    
    Args:
        driver: Selenium WebDriver instance
    """
    return 
    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        import time
        
        # Priority 1: Reject/Decline patterns
        reject_patterns = [
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'reject')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'decline')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'deny')]",
            "//a[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'reject')]",
            "//*[@id='onetrust-reject-all-handler']",
            "//*[contains(@class, 'reject-cookies')]",
            "//*[contains(@id, 'cookie-reject')]",
        ]
        
        # Priority 2: Accept patterns (fallback)
        accept_patterns = [
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'accept')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'agree')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'allow')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'consent')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'ok')]",
            "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'confirm') and contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'choice')]",
            "//*[@id='onetrust-accept-btn-handler']",
            "//*[contains(@class, 'accept-cookies')]",
            "//*[contains(@id, 'cookie-accept')]",
        ]
        
        # Try reject patterns first
        for pattern in reject_patterns:
            try:
                button = WebDriverWait(driver, 2).until(
                    EC.element_to_be_clickable((By.XPATH, pattern))
                )
                button.click()
                print("    ✓ Rejected cookie consent")
                time.sleep(0.5)
                return
            except:
                continue
        
        # If no reject found, try accept patterns
        for pattern in accept_patterns:
            try:
                button = WebDriverWait(driver, 2).until(
                    EC.element_to_be_clickable((By.XPATH, pattern))
                )
                button.click()
                print("    ✓ Accepted cookie consent (reject not available)")
                time.sleep(0.5) 
                return
            except:
                continue
        
        print("    ℹ No cookie consent button found or already handled")
        
    except Exception as e:
        print(f"    ℹ Cookie handling skipped: {e}")


def _fetch_page_with_js(url: str) -> Optional[BeautifulSoup]:
    """
    Fetch page with JavaScript execution using Selenium.
    Falls back to requests if Selenium is not available.
    
    Args:
        url: URL to fetch
    
    Returns:
        BeautifulSoup object or None if fetch fails
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        
        # Setup headless Chrome
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        
        # Wait for page to load (wait for body to be present)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        # Additional wait for dynamic content
        import time
        time.sleep(2)
        
        # Handle cookie consent
        _handle_cookie_consent(driver)

        time.sleep(2)

        
        # Get page source after JS execution
        html = driver.page_source
        driver.quit()
        
        return BeautifulSoup(html, 'html.parser')
        
    except ImportError:
        print("  Selenium not available, falling back to requests")
        return _fetch_page_simple(url)
    except Exception as e:
        print(f"  Error with Selenium, falling back to requests: {e}")
        return _fetch_page_simple(url)


def _fetch_page_simple(url: str) -> Optional[BeautifulSoup]:
    """
    Simple page fetch without JavaScript execution.
    
    Args:
        url: URL to fetch
    
    Returns:
        BeautifulSoup object or None if fetch fails
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return None


def _normalize_domain(url: str) -> str:
    """
    Normalize domain by removing www prefix and extracting netloc.
    
    Args:
        url: URL to normalize
    
    Returns:
        Normalized domain without www prefix
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    return domain


def _find_footer_legal_links(soup: BeautifulSoup, base_url: str) -> List[str]:
    """
    Find legal/privacy related links anywhere on the page.
    
    Args:
        soup: BeautifulSoup object of the page
        base_url: Base URL for resolving relative links
    
    Returns:
        List of URLs for legal/privacy pages
    """
    from urllib.parse import urljoin
    
    patterns = _get_footer_legal_patterns()
    legal_links = []
    seen_urls = set()
    base_domain = _normalize_domain(base_url)
    
    # Search all links on the page (including deeply nested ones)
    for link in soup.find_all('a', href=True):
        link_text = link.get_text().lower().strip()
        link_href = link['href'].lower()
        
        # Check if link matches any legal pattern
        is_legal_link = any(
            re.search(pattern, link_text) or re.search(pattern, link_href)
            for pattern in patterns
        )
        
        if is_legal_link:
            full_url = urljoin(base_url, link['href'])
            link_domain = _normalize_domain(full_url)
            
            # Only include same-domain links and avoid duplicates
            if link_domain == base_domain:
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    legal_links.append(full_url)
                    print(f"  Found legal link: {link_text} -> {full_url}")
    
    return legal_links


def _fetch_page_text(url: str) -> Optional[str]:
    """
    Fetch and extract text content from a URL.
    
    Args:
        url: URL to fetch
    
    Returns:
        Extracted text content or None if fetch fails
    """
    soup = _fetch_page_with_js(url)
    
    if soup:
        text = _clean_text_content(soup)
        return text[:10000]  # Limit to 10k chars
    
    return None


def _collect_legal_texts(legal_urls: List[str]) -> str:
    """
    Fetch, summarize, and combine text from all legal pages.
    Only includes software-relevant information.
    
    Args:
        legal_urls: List of URLs to legal/privacy pages
    
    Returns:
        Combined summarized text from all pages (software-relevant only)
    """
    all_summaries = []
    
    for url in legal_urls:
        print(f"  Fetching legal page: {url}")
        text = _fetch_page_text(url)
        
        if text:
            # Summarize each page to ~1000 chars, filtering for software-relevant content
            print(f"    Analyzing page for software-relevant terms...")
            summary = summarize_legal_text(text, page_url=url, max_chars=1000)
            
            if summary and summary.strip():  # Only include non-empty summaries
                all_summaries.append(f"=== From {url} ===\n{summary}\n")
                print(f"    ✓ Found software-relevant terms")
            else:
                print(f"    ✗ No software-relevant terms found (skipping)")
    
    if not all_summaries:
        print("  Warning: No software-relevant terms found in any legal pages")
    
    return "\n\n".join(all_summaries)


def _create_proprietary_assessment_prompt(legal_text: str) -> str:
    """Create prompt for AI assessment of proprietary software terms."""
    return f"""You are a legal expert analyzing software terms of use and privacy policies.

Analyze the following legal documents and provide a clear assessment.

## Legal Documents

{legal_text[:15000]}

## Your Task

Provide a JSON response with three assessments:

```json
{{{{
  "terms_of_use": "In ONE paragraph, summarize the key conditions for using this software. Include: usage restrictions, licensing limitations, user obligations, and any notable prohibitions. FOCUS ON SOFTWARE, NOT THE WEBSITE.",
  "privacy_assessment": "In ONE paragraph, assess privacy implications. Address: what data is collected, how it's used, if it's shared with third parties, data retention, and any privacy concerns users should know about. FOCUS ON SOFTWARE.",
  "is_free": "In ONE paragraph, clearly state if the software is free to use or requires payment. Include: free tier availability, trial periods, pricing model (subscription/one-time/freemium), any usage limits on free tier, and conditions for free use. If pricing is unclear, state 'Pricing information not found in legal documents'."
}}}}
```

## Guidelines

- Keep each paragraph concise (3-5 sentences)
- Focus on USER-RELEVANT information
- Highlight any RED FLAGS or concerning terms
- If information is missing, state "Information not provided"
- Be objective and factual
"""


def _parse_proprietary_assessment(response_text: str) -> Tuple[str, str, str]:
    """
    Parse AI response into terms, privacy, and pricing assessment.
    
    Args:
        response_text: AI response text
    
    Returns:
        Tuple of (terms_of_use, privacy_assessment, is_free)
    """
    # Remove markdown code blocks
    response_text = re.sub(r'```json\s*|\s*```', '', response_text).strip()
    
    try:
        result = json.loads(response_text)
        return (
            result.get('terms_of_use', 'Assessment not available'),
            result.get('privacy_assessment', 'Assessment not available'),
            result.get('is_free', 'Pricing information not available')
        )
    except json.JSONDecodeError:
        return (
            'Failed to parse assessment',
            'Failed to parse assessment',
            'Failed to parse assessment'
        )


def assess_proprietary_software(website_url: str) -> Optional[Tuple[str, str, str]]:
    """
    Assess proprietary software terms of use, privacy, and pricing.
    
    Args:
        website_url: Website URL to assess
    
    Returns:
        Tuple of (terms_of_use, privacy_assessment, is_free) or None if assessment fails
    """
    try:
        if not is_available():
            print("Warning: GEMINI_API_KEY not set, cannot assess proprietary software")
            return None
        
        print(f"Assessing proprietary software at {website_url}...")
        
        # Step 1: Fetch main page with JavaScript support
        soup = _fetch_page_with_js(website_url)
        
        if not soup:
            print("  Failed to fetch website")
            return None
        
        # Step 2: Find legal/privacy links
        legal_urls = _find_footer_legal_links(soup, website_url)
        
        if not legal_urls:
            print("  No legal/privacy links found on page")
            return None
        
        print(f"  Found {len(legal_urls)} legal pages")
        
        # Step 3: Collect text from legal pages
        legal_text = _collect_legal_texts(legal_urls)
        
        if not legal_text or len(legal_text) < 200:
            print("  Insufficient legal text found")
            return None
        
        # Step 4: Use AI to assess terms and privacy
        print("  Analyzing terms and privacy with AI...")
        prompt = _create_proprietary_assessment_prompt(legal_text)
        response_text = generate_content(prompt)
        
        if not response_text:
            print("  Failed to get AI assessment")
            return None
        
        # Step 5: Parse response
        terms, privacy, is_free = _parse_proprietary_assessment(response_text)
        
        print("  ✓ Proprietary assessment complete")
        return terms, privacy, is_free
        
    except Exception as e:
        print(f"Error in proprietary assessment: {e}")
        return None


# Add missing import at top
from dataclasses import dataclass
