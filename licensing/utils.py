"""Utility functions for licensing package."""

import re
from typing import List
from urllib.parse import urlparse
from .models import LicenseType


def detect_license_type(text: str) -> LicenseType:
    """Detect license type from license text."""
    text_lower = text.lower()
    
    # Check for specific license patterns
    if "mit license" in text_lower or ("mit" in text_lower and "permission is hereby granted" in text_lower):
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


def get_license_patterns() -> List[str]:
    """Get regex patterns for license-related links."""
    return [
        r'license', r'terms', r'legal', r'eula', r'copyright',
        r'privacy', r'tos', r'terms[_\-\s]of[_\-\s]service',
        r'terms[_\-\s]and[_\-\s]conditions',
        r'end[_\-\s]user[_\-\s]license',
        r'software[_\-\s]license'
    ]


def extract_domain_root(url: str) -> str:
    """Extract root domain from URL (e.g., example.com from www.example.com)."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    # Remove www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Get last two parts of domain (e.g., example.com from subdomain.example.com)
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    
    return domain


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same root domain."""
    domain1 = extract_domain_root(url1)
    domain2 = extract_domain_root(url2)
    return domain1 == domain2
