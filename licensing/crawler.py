"""Website crawler for closed-source license detection."""

import re
import requests
from typing import Optional, List
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

from .models import License, LicenseType, CrawlState
from .proprietary_assessment import assess_proprietary_software, ProprietaryAssessment
from .utils import detect_license_type


def get_license_closed_source(
    website_url: str, 
    brand_name: Optional[str] = None,
    max_pages: int = 10, 
    max_depth: int = 2
) -> Optional[License]:
    """
    Extract license/terms information from a closed-source project website.
    Uses proprietary assessment to analyze terms, privacy, and pricing.
    
    Args:
        website_url: Website URL to scrape for license information
        brand_name: Deprecated, not used
        max_pages: Deprecated, not used
        max_depth: Deprecated, not used
    
    Returns:
        License object or None if not found
    """
    try:
        print(f"Analyzing proprietary software at {website_url}...")
        
        # Assess proprietary software terms, privacy, and pricing
        assessment = assess_proprietary_software(website_url)
        
        if assessment:
            return License(
                ltype=LicenseType.PROPRIETARY,
                text="Proprietary software - see terms of use",
                url=website_url,
                terms_of_use=assessment.terms_of_use,
                privacy_assessment=assessment.privacy_assessment,
                is_free=assessment.is_free
            )
        
        print("Failed to extract proprietary software information.")
        return None
        
    except Exception as e:
        print(f"Error in closed-source license scraping: {e}")
        return None
