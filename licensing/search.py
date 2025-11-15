"""Google search integration for license discovery."""

import os
import re
import json
import requests
from typing import List, Optional
from bs4 import BeautifulSoup
import google.genai as genai
from google.genai import types
from dotenv import load_dotenv

from .models import License, LicenseType
from .ai_assessment import assess_license_with_ai
from .page_extraction import _extract_license_from_current_page, _clean_text_content
from .utils import is_same_domain, detect_license_type

load_dotenv()


def _resolve_redirects(urls: List[str]) -> List[str]:
    """
    Resolve URL redirects to get final destinations.
    
    Args:
        urls: List of URLs that may be redirects
    
    Returns:
        List of resolved URLs
    """
    resolved = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    for url in urls:
        try:
            response = requests.head(url, headers=headers, allow_redirects=True, timeout=5)
            resolved.append(response.url)
        except:
            # If redirect resolution fails, keep original URL
            resolved.append(url)
    
    return resolved


def perform_google_search(query: str, num_results: int = 3) -> List[str]:
    """
    Perform Google search using Gemini API with Google Search grounding tool.
    
    Args:
        query: Search query
        num_results: Number of results to return
    
    Returns:
        List of URLs from search results
    """
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            print("Warning: GEMINI_API_KEY not set, cannot perform search")
            return []
        
        # Create client
        client = genai.Client(api_key=api_key)
        
        # Create prompt asking for search results with URLs
        search_prompt = f"""Search for: "{query}"

Please provide the top {num_results} most relevant URLs from the search results.

Return ONLY a JSON array of URLs, nothing else. Format:
["url1", "url2", "url3"]

Only include actual webpage URLs, skip any PDF files or non-webpage results."""
        
        # Call Gemini with Google Search grounding
        response = client.models.generate_content(
            model='gemini-2.0-flash-lite',
            contents=search_prompt,
            config=types.GenerateContentConfig(
                tools=[types.Tool(google_search=types.GoogleSearch())],
            )
        )
        
        # Parse response to extract URLs
        response_text = response.text.strip()
        
        # Remove markdown code blocks if present
        response_text = re.sub(r'```json\s*|\s*```', '', response_text).strip()
        
        # Try to parse as JSON array
        try:
            urls = json.loads(response_text)
            if isinstance(urls, list):
                # Filter out non-string items and validate URLs
                valid_urls = []
                for url in urls:
                    if isinstance(url, str) and url.startswith('http'):
                        valid_urls.append(url)
                
                # Resolve redirects
                valid_urls = _resolve_redirects(valid_urls[:num_results])
                
                print(f"Found {len(valid_urls)} URLs via Gemini search")
                return valid_urls
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract URLs using regex
            print("Falling back to regex URL extraction")
            url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
            urls = re.findall(url_pattern, response_text)
            
            # Clean and validate URLs
            valid_urls = []
            for url in urls:
                url = url.rstrip('.,;)')  # Remove trailing punctuation
                if url.startswith('http') and 'google.com' not in url:
                    valid_urls.append(url)
            
            # Resolve redirects
            valid_urls = _resolve_redirects(valid_urls[:num_results])
            return valid_urls
        
        return []
        
    except Exception as e:
        print(f"Error performing Gemini-powered Google search: {e}")
        return []


def search_licenses_via_google(brand_name: str, base_url: str) -> Optional[License]:
    """
    Search for license information using Google search.
    
    Args:
        brand_name: Name of the brand/product
        base_url: Original website URL to filter results by domain
    
    Returns:
        License object if found, None otherwise
    """
    try:
        print(f"Searching Google for '{brand_name} licensing'...")
        
        # Perform Google search
        query = f"{brand_name} licensing"
        search_results = perform_google_search(query, num_results=10)  # Get more to filter
        
        if not search_results:
            print("  No search results found")
            return None
        else:
            print(search_results)
        
        # Filter results to only include same domain
        same_domain_urls = [
            url for url in search_results 
            if is_same_domain(url, base_url)
        ][:3]  # Take first 3 from same domain
        
        if not same_domain_urls:
            print("  No results from same domain found")
            return None
        
        print(f"  Found {len(same_domain_urls)} results from same domain")
        
        # Scan each result for license information
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for url in same_domain_urls:
            print(f"  Checking Google result: {url}")
            
            try:
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Use AI to assess if this page contains license
                assessment = assess_license_with_ai(url, soup)
                
                if assessment.contains_license and assessment.confidence == 'high':
                    print(f"  ✓ License found via Google search!")
                    
                    # Extract license text
                    result = _extract_license_from_current_page(soup, url)
                    
                    if result.found and result.text:
                        license_type = detect_license_type(result.text)
                        
                        if license_type == LicenseType.UNKNOWN:
                            license_type = LicenseType.PROPRIETARY
                        
                        return License(
                            ltype=license_type,
                            text=result.text[:5000],
                            url=result.url or url
                        )
            except ZeroDivisionError as e:
                print('wtf lkmao')
            # except Exception as e:
            #     print(f"  Error processing Google result {url}: {e}")
            #     continue
        
        return None
        
    except ZeroDivisionError as e:
        print("maifmiowjifowj")
    # except Exception as e:
    #     print(f"Error in Google search: {e}")
    #     return None
