"""GitHub license extraction functionality."""

import re
import requests
from typing import Optional
from .models import License, LicenseType


def _parse_github_url(github_url: str) -> tuple[str, str]:
    """Parse GitHub URL to extract owner and repo."""
    pattern = r'github\.com/([^/]+)/([^/]+)'
    match = re.search(pattern, github_url)
    
    if not match:
        raise ValueError("Invalid GitHub URL format")
    
    owner, repo = match.groups()
    repo = repo.rstrip('/')
    return owner, repo


def _map_github_license_to_type(github_license_key: str) -> LicenseType:
    """Map GitHub API license key to LicenseType enum."""
    license_map = {
        'mit': LicenseType.MIT,
        'apache-2.0': LicenseType.APACHE_V2,
        'gpl-3.0': LicenseType.GPL_V3,
        'gpl-2.0': LicenseType.GPL_V2,
        'bsd-3-clause': LicenseType.BSD_3_CLAUSE,
        'bsd-2-clause': LicenseType.BSD_2_CLAUSE,
        'isc': LicenseType.ISC,
        'lgpl-3.0': LicenseType.LGPL,
        'lgpl-2.1': LicenseType.LGPL,
        'mpl-2.0': LicenseType.MPL,
        'unlicense': LicenseType.UNLICENSE,
        'cc0-1.0': LicenseType.CC0,
    }
    
    return license_map.get(github_license_key.lower(), LicenseType.UNKNOWN)


def _fetch_github_license_api(owner: str, repo: str) -> tuple[Optional[str], Optional[str], Optional[LicenseType]]:
    """
    Fetch license using GitHub API and detect license type.
    
    Returns:
        Tuple of (license_text, filename, license_type)
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/license"
    headers = {'Accept': 'application/vnd.github.v3+json'}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            download_url = data.get('download_url')
            license_key = data.get('license', {}).get('key')
            
            if download_url:
                content_response = requests.get(download_url, timeout=10)
                if content_response.status_code == 200:
                    license_type = _map_github_license_to_type(license_key) if license_key else LicenseType.UNKNOWN
                    return content_response.text, data.get('name', 'LICENSE'), license_type
        
        # If no license found via API, return None
        return None, None, None
        
    except Exception as e:
        print(f"  Error using GitHub API: {e}")
        return None, None, None


def get_license_opensource(github_url: str) -> Optional[License]:
    """
    Extract license from an open-source GitHub project.
    Uses GitHub API for license detection.
    
    Args:
        github_url: GitHub repository URL (e.g., https://github.com/owner/repo)
    
    Returns:
        License object or None if not found
    """
    try:
        owner, repo = _parse_github_url(github_url)
        
        # Use GitHub API for license detection
        license_text, found_filename, license_type = _fetch_github_license_api(owner, repo)
        
        # Return license if we got text, even if type is UNKNOWN
        if license_text:
            license_url = f"{github_url.rstrip('/')}/blob/main/{found_filename}" if found_filename else github_url
            
            return License(
                ltype=license_type or LicenseType.UNKNOWN,
                text=license_text,
                url=license_url
            )
        
        # No license found
        print(f"  No license detected by GitHub API")
        return None
        
    except Exception as e:
        print(f"Error fetching open-source license: {e}")
        return None
