"""Website crawler for closed-source license detection."""

import re
import requests
from typing import Optional, List
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

from .models import License, LicenseType, CrawlState
from .page_extraction import extract_license_from_page
from .search import search_licenses_via_google
from .product import extract_product_name
from .utils import detect_license_type


def _initialize_crawl_state(start_url: str) -> CrawlState:
    """Initialize crawling state."""
    base_domain = urlparse(start_url).netloc
    queue = deque([(start_url, 0)])  # (url, depth)
    
    return CrawlState(
        queue=queue,
        visited=set(),
        pages_visited=0,
        base_domain=base_domain
    )


def _should_continue_crawling(state: CrawlState, max_pages: int) -> bool:
    """Check if crawling should continue."""
    return bool(state.queue) and state.pages_visited < max_pages


def _get_next_url(state: CrawlState, max_depth: int) -> Optional[tuple[str, int]]:
    """Get next URL to crawl, respecting depth limits."""
    while state.queue:
        current_url, depth = state.queue.popleft()
        normalized_url = current_url.split('#')[0]
        
        if normalized_url not in state.visited and depth <= max_depth:
            state.visited.add(normalized_url)
            state.pages_visited += 1
            return current_url, depth
    
    return None


def _is_priority_link(link_text: str, link_href: str) -> bool:
    """Check if a link should be prioritized (license-related)."""
    priority_patterns = [r'legal', r'license', r'terms', r'eula', r'about', r'company']
    
    return any(
        re.search(pattern, link_text) or re.search(pattern, link_href)
        for pattern in priority_patterns
    )


def _should_skip_link(full_url: str, state: CrawlState) -> bool:
    """Check if a link should be skipped during crawling."""
    normalized = full_url.split('#')[0]
    
    # Skip different domains
    if urlparse(full_url).netloc != state.base_domain:
        return True
    
    # Skip already visited
    if normalized in state.visited:
        return True
    
    # Skip file downloads
    skip_extensions = ['.pdf', '.jpg', '.png', '.gif', '.zip', '.exe']
    if any(full_url.lower().endswith(ext) for ext in skip_extensions):
        return True
    
    return False


def _collect_links_to_crawl(soup: BeautifulSoup, current_url: str, depth: int, state: CrawlState) -> List[tuple[str, int]]:
    """Collect links from current page to add to crawl queue."""
    priority_links = []
    regular_links = []
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(current_url, href)
        
        if _should_skip_link(full_url, state):
            continue
        
        link_text = link.get_text().lower()
        href_lower = href.lower()
        
        if _is_priority_link(link_text, href_lower):
            priority_links.append((full_url, depth + 1))
        else:
            regular_links.append((full_url, depth + 1))
    
    # Return priority links first (limited), then some regular links
    return priority_links[:5] + regular_links[:3]


def get_license_closed_source(
    website_url: str, 
    brand_name: Optional[str] = None,
    max_pages: int = 10, 
    max_depth: int = 2
) -> Optional[License]:
    """
    Extract license/terms information from a closed-source project website.
    Uses BFS to crawl multiple pages on the same domain looking for license information.
    Also performs Google search for additional license pages.
    
    Args:
        website_url: Website URL to scrape for license information
        brand_name: Optional brand/product name. If not provided, will be extracted from the website
        max_pages: Maximum number of pages to visit (default: 10)
        max_depth: Maximum depth to crawl from the starting page (default: 2)
    
    Returns:
        License object or None if not found
    """
    try:
        # Step 1: Extract brand name if not provided
        if not brand_name:
            print("Extracting brand name from website...")
            product_info = extract_product_name(website_url)
            
            if product_info and product_info.confidence != 'low':
                brand_name = product_info.name
                print(f"Using extracted brand name: '{brand_name}'")
            else:
                print("Could not reliably extract brand name")
                brand_name = None
        
        # Step 2: Try Google search first if we have a brand name
        if brand_name:
            google_license = search_licenses_via_google(brand_name, website_url)
            if google_license:
                return google_license
        
        # Step 3: Fall back to traditional crawling
        print("Performing traditional website crawl...")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        state = _initialize_crawl_state(website_url)
        
        while _should_continue_crawling(state, max_pages):
            url_info = _get_next_url(state, max_depth)
            if not url_info:
                break
            
            current_url, depth = url_info
            print(f"Scanning page {state.pages_visited}/{max_pages}: {current_url}")
            
            try:
                response = requests.get(current_url, headers=headers, timeout=10)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract license from this page
                result = extract_license_from_page(current_url, soup, headers)
                
                if result.found and result.text and len(result.text) > 100:
                    license_type = detect_license_type(result.text)
                    
                    # For closed source, likely proprietary unless stated otherwise
                    if license_type == LicenseType.UNKNOWN:
                        license_type = LicenseType.PROPRIETARY
                    
                    return License(
                        ltype=license_type,
                        text=result.text[:5000],  # Limit text length
                        url=result.url or current_url
                    )
                
                # Add more pages to queue if we haven't reached max depth
                if depth < max_depth:
                    links_to_add = _collect_links_to_crawl(soup, current_url, depth, state)
                    state.queue.extend(links_to_add)
                
            except ZeroDivisionError as e:
                print('stop ')
            # except Exception as e:
            #     print(f"  Error processing {current_url}: {e}")
            #     continue
        
        print(f"Finished scanning {state.pages_visited} pages. No license found.")
        return None
        
    except ZeroDivisionError as e:
        print('stop ')
    # except Exception as e:
    #     print(f"Error in closed-source license scraping: {e}")
    #     return None
