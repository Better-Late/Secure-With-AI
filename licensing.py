from dataclasses import dataclass
from enum import Enum, auto
import requests
import re
from typing import Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class LicenseType(Enum):
    MIT = auto()
    APACHE_V2 = auto()
    GPL_V3 = auto()
    GPL_V2 = auto()
    BSD_3_CLAUSE = auto()
    BSD_2_CLAUSE = auto()
    ISC = auto()
    LGPL = auto()
    MPL = auto()
    UNLICENSE = auto()
    CC0 = auto()
    PROPRIETARY = auto()
    UNKNOWN = auto()


@dataclass
class License:
    ltype: LicenseType
    text: str 
    url: str


def detect_license_type(text: str) -> LicenseType:
    """Detect license type from license text."""
    text_lower = text.lower()
    
    # Check for specific license patterns
    if "mit license" in text_lower or "mit" in text_lower and "permission is hereby granted" in text_lower:
        return LicenseType.MIT
    elif "apache license" in text_lower and "version 2.0" in text_lower:
        return LicenseType.APACHE_V2
    elif "gnu general public license" in text_lower and "version 3" in text_lower:
        return LicenseType.GPL_V3
    elif "gnu general public license" in text_lower and "version 2" in text_lower:
        return LicenseType.GPL_V2
    elif "bsd 3-clause" in text_lower or ("bsd" in text_lower and "redistribution and use" in text_lower and text_lower.count("neither") > 0):
        return LicenseType.BSD_3_CLAUSE
    elif "bsd 2-clause" in text_lower or ("bsd" in text_lower and "redistribution and use" in text_lower):
        return LicenseType.BSD_2_CLAUSE
    elif "isc license" in text_lower:
        return LicenseType.ISC
    elif "gnu lesser general public license" in text_lower or "lgpl" in text_lower:
        return LicenseType.LGPL
    elif "mozilla public license" in text_lower or "mpl" in text_lower:
        return LicenseType.MPL
    elif "unlicense" in text_lower or "public domain" in text_lower:
        return LicenseType.UNLICENSE
    elif "cc0" in text_lower or "creative commons zero" in text_lower:
        return LicenseType.CC0
    elif "proprietary" in text_lower or "all rights reserved" in text_lower:
        return LicenseType.PROPRIETARY
    else:
        return LicenseType.UNKNOWN


def get_license_opensource(github_url: str) -> Optional[License]:
    """
    Extract license from an open-source GitHub project.
    
    Args:
        github_url: GitHub repository URL (e.g., https://github.com/owner/repo)
    
    Returns:
        License object or None if not found
    """
    try:
        # Parse GitHub URL to extract owner and repo
        # Example: https://github.com/owner/repo
        pattern = r'github\.com/([^/]+)/([^/]+)'
        match = re.search(pattern, github_url)
        
        if not match:
            raise ValueError("Invalid GitHub URL format")
        
        owner, repo = match.groups()
        repo = repo.rstrip('/')  # Remove trailing slash if present
        
        # Try common license file names
        license_filenames = [
            'LICENSE',
            'LICENSE.md',
            'LICENSE.txt',
            'LICENCE',
            'LICENCE.md',
            'COPYING',
            'COPYING.md'
        ]
        
        license_text = None
        found_filename = None
        
        # Try to fetch license file from GitHub raw content
        for filename in license_filenames:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{filename}"
            
            response = requests.get(raw_url, timeout=10)
            if response.status_code == 200:
                license_text = response.text
                found_filename = filename
                break
            
            # Try 'master' branch if 'main' doesn't work
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{filename}"
            response = requests.get(raw_url, timeout=10)
            if response.status_code == 200:
                license_text = response.text
                found_filename = filename
                break
        
        # If still not found, try using GitHub API
        if not license_text:
            api_url = f"https://api.github.com/repos/{owner}/{repo}/license"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Download the license content
                download_url = data.get('download_url')
                if download_url:
                    content_response = requests.get(download_url, timeout=10)
                    if content_response.status_code == 200:
                        license_text = content_response.text
                        found_filename = data.get('name', 'LICENSE')
        
        if license_text:
            license_type = detect_license_type(license_text)
            license_url = f"{github_url.rstrip('/')}/blob/main/{found_filename}" if found_filename else github_url
            
            return License(
                ltype=license_type,
                text=license_text,
                url=license_url
            )
        
        return None
        
    except Exception as e:
        print(f"Error fetching open-source license: {e}")
        return None


def get_license_closed_source(website_url: str) -> Optional[License]:
    """
    Extract license/terms information from a closed-source project website.
    
    Args:
        website_url: Website URL to scrape for license information
    
    Returns:
        License object or None if not found
    """
    try:
        # Fetch the main page
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(website_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Common patterns for license/terms links
        license_patterns = [
            r'license',
            r'terms',
            r'legal',
            r'eula',
            r'copyright',
            r'privacy',
            r'tos',
            r'terms[_\-\s]of[_\-\s]service',
            r'terms[_\-\s]and[_\-\s]conditions'
        ]
        
        license_url = None
        license_text = None
        
        # Search for license links in the page
        all_links = soup.find_all('a', href=True)
        for link in all_links:
            link_text = link.get_text().lower()
            link_href = link['href'].lower()
            
            for pattern in license_patterns:
                if re.search(pattern, link_text) or re.search(pattern, link_href):
                    # Found a potential license link
                    full_url = urljoin(website_url, link['href'])
                    license_url = full_url
                    
                    # Fetch the license page
                    try:
                        license_response = requests.get(full_url, headers=headers, timeout=10)
                        if license_response.status_code == 200:
                            license_soup = BeautifulSoup(license_response.text, 'html.parser')
                            
                            # Remove script and style elements
                            for script in license_soup(['script', 'style', 'nav', 'footer', 'header']):
                                script.decompose()
                            
                            # Get text content
                            license_text = license_soup.get_text(separator='\n', strip=True)
                            
                            # Clean up excessive whitespace
                            license_text = re.sub(r'\n\s*\n', '\n\n', license_text)
                            
                            if license_text and len(license_text) > 100:
                                break
                    except:
                        continue
                
                if license_text:
                    break
            
            if license_text:
                break
        
        # If no dedicated license page found, extract from main page
        if not license_text:
            # Look for license in footer or specific sections
            footer = soup.find('footer')
            if footer:
                footer_text = footer.get_text(separator='\n', strip=True)
                if any(re.search(pattern, footer_text.lower()) for pattern in license_patterns):
                    license_text = footer_text
                    license_url = website_url
            
            # If still nothing, search for copyright notice
            if not license_text:
                copyright_pattern = r'©.*?(?:\d{4}|copyright)'
                copyright_matches = soup.find_all(string=re.compile(copyright_pattern, re.IGNORECASE))
                if copyright_matches:
                    license_text = '\n'.join([match.strip() for match in copyright_matches[:5]])
                    license_url = website_url
        
        if license_text:
            license_type = detect_license_type(license_text)
            
            # For closed source, likely proprietary unless stated otherwise
            if license_type == LicenseType.UNKNOWN:
                license_type = LicenseType.PROPRIETARY
            
            return License(
                ltype=license_type,
                text=license_text[:5000],  # Limit text length
                url=license_url or website_url
            )
        
        return None
        
    except Exception as e:
        print(f"Error fetching closed-source license: {e}")
        return None
    