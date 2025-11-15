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
    is_free: str


def _get_footer_legal_patterns() -> List[str]:
    """Get regex patterns for legal/privacy links."""
    return [
        r'privacy\s*(and\s*security|notice|policy)?',
        r'terms\s*(of\s*(use|service))?',
        r'legal',
        r'eula',
        r'end\s*user\s*license',
        r'data\s*protection',
        r'cookie\s*policy',
        r'acceptable\s*use',
    ]


def _get_pricing_patterns() -> List[str]:
    """Get regex patterns for pricing/plans links."""
    return [
        r'pric(e|ing)',
        r'plan(s)?',
        r'subscription(s)?',
        r'buy',
        r'purchase',
        r'cost',
        r'free\s*trial',
        r'upgrade',
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


def _resolve_redirect(url: str) -> str:
    """
    Resolve URL redirects to get final destination.
    
    Args:
        url: URL that may redirect
    
    Returns:
        Final URL after following redirects
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.head(url, headers=headers, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url


def _find_links_by_patterns(soup: BeautifulSoup, base_url: str, patterns: List[str], link_type: str, max_links: int = 10) -> List[str]:
    """
    Find links matching given patterns on the page.
    
    Args:
        soup: BeautifulSoup object of the page
        base_url: Base URL for resolving relative links
        patterns: List of regex patterns to match
        link_type: Description of link type (for logging)
        max_links: Maximum number of links to collect (default: 10)
    
    Returns:
        List of URLs matching the patterns (up to max_links)
    """
    from urllib.parse import urljoin
    
    found_links = []
    seen_urls = set()
    
    for link in soup.find_all('a', href=True):
        if len(found_links) >= max_links:
            break
            
        link_text = link.get_text().lower().strip()
        link_href = link['href'].lower()
        
        is_matching_link = any(
            re.search(pattern, link_text) or re.search(pattern, link_href)
            for pattern in patterns
        )
        
        if is_matching_link:
            full_url = urljoin(base_url, link['href'])
                
            # Resolve redirects
            # resolved_url = _resolve_redirect(full_url)
            resolved_url = full_url # ignore redirects for now
            
            if resolved_url not in seen_urls:
                seen_urls.add(resolved_url)
                found_links.append(resolved_url)
                print(f"  Found {link_type} link: {link_text} -> {resolved_url}")
    
    return found_links


def _find_legal_links(soup: BeautifulSoup, base_url: str) -> List[str]:
    """Find legal/privacy related links on the page."""
    patterns = _get_footer_legal_patterns()
    return _find_links_by_patterns(soup, base_url, patterns, "legal")


def _find_pricing_links(soup: BeautifulSoup, base_url: str) -> List[str]:
    """Find pricing/plans related links on the page."""
    patterns = _get_pricing_patterns()
    return _find_links_by_patterns(soup, base_url, patterns, "pricing")


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
        return text  # Limit to 10k chars
    
    return None


def _collect_legal_texts(legal_urls: List[str]) -> str:
    """
    Fetch, summarize, and combine text from legal pages.
    Focuses on software-relevant privacy and terms information.
    
    Args:
        legal_urls: List of URLs to legal/privacy pages
    
    Returns:
        Combined summarized text from legal pages
    """
    all_summaries = []
    
    for url in legal_urls:
        print(f"  Fetching legal page: {url}")
        text = _fetch_page_text(url)
        
        if text:
            print(f"    Analyzing for software privacy/terms...")
            summary = summarize_legal_text(text, page_url=url, max_chars=1000)
            
            if summary and summary.strip():
                all_summaries.append(f"=== From {url} ===\n{summary}\n")
                print(f"    ✓ Found relevant terms")
            else:
                print(f"    ✗ No relevant terms (skipping)")
    
    if not all_summaries:
        print("  Warning: No software-relevant legal terms found")
    
    return "\n\n".join(all_summaries)


def _collect_pricing_texts(pricing_urls: List[str]) -> str:
    """
    Fetch, summarize, and combine text from pricing pages.
    
    Args:
        pricing_urls: List of URLs to pricing/plans pages
    
    Returns:
        Combined summarized text from pricing pages
    """
    all_summaries = []
    
    for url in pricing_urls:
        print(f"  Fetching pricing page: {url}")
        text = _fetch_page_text(url)
        
        if text:
            print(f"    Analyzing for pricing information...")
            # Summarize with focus on pricing
            summary = summarize_legal_text(text, page_url=url, max_chars=800)
            
            if summary and summary.strip():
                all_summaries.append(f"=== From {url} ===\n{summary}\n")
                print(f"    ✓ Found pricing info")
            else:
                print(f"    ✗ No pricing info (skipping)")
    
    if not all_summaries:
        print("  Warning: No pricing information found")
    
    return "\n\n".join(all_summaries)


def _create_proprietary_assessment_prompt(legal_text: str, pricing_text: str) -> str:
    """Create prompt for AI assessment using legal and pricing context."""
    return f"""You are a legal expert analyzing software terms, privacy policies, and pricing.

Analyze the following documents:

## Legal/Terms Documents

{legal_text[:8000] if legal_text else "No legal documents available"}

## Pricing/Plans Documents

{pricing_text[:7000] if pricing_text else "No pricing documents available"}

## Your Task

Provide a JSON response with three assessments:

```json
{{{{
  "terms_of_use": "In ONE paragraph, summarize key conditions for using this software. Use BOTH legal and pricing documents. Include: usage restrictions, licensing limitations, user obligations, prohibitions. FOCUS ON SOFTWARE, NOT THE WEBSITE.",
  "privacy_assessment": "In ONE paragraph, assess privacy implications using ONLY the Legal/Terms documents. Address: data collected, how it's used, third-party sharing, data retention, privacy concerns. FOCUS ON SOFTWARE.",
  "is_free": "In ONE paragraph, state if software is free or paid using ONLY the Pricing/Plans documents. Include: free tier, trial periods, pricing model (subscription/one-time/freemium), usage limits, conditions for free use. If unclear, state 'Pricing information not found'."
}}}}
```

## Guidelines

- Keep each paragraph concise (3-5 sentences)
- Focus on USER-RELEVANT information
- Highlight RED FLAGS or concerning terms
- If information missing, state "Information not provided"
- Be objective and factual
"""


def _parse_proprietary_assessment(response_text: str) -> ProprietaryAssessment:
    """
    Parse AI response into ProprietaryAssessment.
    
    Args:
        response_text: AI response text
    
    Returns:
        ProprietaryAssessment dataclass
    """
    response_text = re.sub(r'```json\s*|\s*```', '', response_text).strip()
    
    try:
        result = json.loads(response_text)
        return ProprietaryAssessment(
            terms_of_use=result.get('terms_of_use', 'Assessment not available'),
            privacy_assessment=result.get('privacy_assessment', 'Assessment not available'),
            is_free=result.get('is_free', 'Pricing information not available')
        )
    except json.JSONDecodeError:
        return ProprietaryAssessment(
            terms_of_use='Failed to parse assessment',
            privacy_assessment='Failed to parse assessment',
            is_free='Failed to parse assessment'
        )


def assess_proprietary_software(website_url: str) -> Optional[ProprietaryAssessment]:
    """
    Assess proprietary software terms of use, privacy, and pricing.
    
    Args:
        website_url: Website URL to assess
    
    Returns:
        ProprietaryAssessment or None if assessment fails
    """
    try:
        if not is_available():
            print("Warning: GEMINI_API_KEY not set, cannot assess proprietary software")
            return None
        
        print(f"Assessing proprietary software at {website_url}...")
        
        # Step 1: Fetch main page
        soup = _fetch_page_with_js(website_url)
        
        if not soup:
            print("  Failed to fetch website")
            return None
        
        # Step 2: Find legal and pricing links
        legal_urls = _find_legal_links(soup, website_url)
        pricing_urls = _find_pricing_links(soup, website_url)
        
        if not legal_urls and not pricing_urls:
            print("  No legal or pricing links found")
            return None
        
        print(f"  Found {len(legal_urls)} legal pages and {len(pricing_urls)} pricing pages")
        
        # Step 3: Collect texts separately
        legal_text = _collect_legal_texts(legal_urls) if legal_urls else ""
        pricing_text = _collect_pricing_texts(pricing_urls) if pricing_urls else ""
        
        if not legal_text and not pricing_text:
            print("  Insufficient content found")
            return None
        
        # Step 4: Use AI to assess with both contexts
        print("  Analyzing with AI...")
        prompt = _create_proprietary_assessment_prompt(legal_text, pricing_text)
        response_text = generate_content(prompt)
        
        if not response_text:
            print("  Failed to get AI assessment")
            return None
        
        # Step 5: Parse response
        assessment = _parse_proprietary_assessment(response_text)
        
        print("  ✓ Proprietary assessment complete")
        return assessment
        
    except Exception as e:
        print(f"Error in proprietary assessment: {e}")
        return None


# Add missing import at top
from dataclasses import dataclass
