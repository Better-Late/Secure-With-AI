"""GitHub license extraction functionality."""

import re
import requests
from typing import Optional
from .models import License
from .utils import detect_license_type


def _parse_github_url(github_url: str) -> tuple[str, str]:
    """Parse GitHub URL to extract owner and repo."""
    pattern = r'github\.com/([^/]+)/([^/]+)'
    match = re.search(pattern, github_url)
    
    if not match:
        raise ValueError("Invalid GitHub URL format")
    
    owner, repo = match.groups()
    repo = repo.rstrip('/')
    return owner, repo


def _fetch_github_license_file(owner: str, repo: str) -> tuple[Optional[str], Optional[str]]:
    """Try to fetch license file from GitHub raw content."""
    license_filenames = [
        'LICENSE', 'LICENSE.md', 'LICENSE.txt',
        'LICENCE', 'LICENCE.md', 'COPYING', 'COPYING.md'
    ]
    
    for filename in license_filenames:
        for branch in ['main', 'master']:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
            response = requests.get(raw_url, timeout=10)
            
            if response.status_code == 200:
                return response.text, filename
    
    return None, None


def _fetch_github_license_api(owner: str, repo: str) -> tuple[Optional[str], Optional[str]]:
    """Fetch license using GitHub API."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/license"
    headers = {'Accept': 'application/vnd.github.v3+json'}
    response = requests.get(api_url, headers=headers, timeout=10)
    
    if response.status_code == 200:
        data = response.json()
        download_url = data.get('download_url')
        
        if download_url:
            content_response = requests.get(download_url, timeout=10)
            if content_response.status_code == 200:
                return content_response.text, data.get('name', 'LICENSE')
    
    return None, None


def get_license_opensource(github_url: str) -> Optional[License]:
    """
    Extract license from an open-source GitHub project.
    
    Args:
        github_url: GitHub repository URL (e.g., https://github.com/owner/repo)
    
    Returns:
        License object or None if not found
    """
    try:
        owner, repo = _parse_github_url(github_url)
        
        # Try raw content first
        license_text, found_filename = _fetch_github_license_file(owner, repo)
        
        # Fall back to API
        if not license_text:
            license_text, found_filename = _fetch_github_license_api(owner, repo)
        
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
