"""
Licensing package for extracting license information from open-source and closed-source projects.
"""

from .models import License, LicenseType, ProductInfo
from .github import get_license_opensource
from .crawler import get_license_closed_source
from .product import extract_product_name

__all__ = [
    'License',
    'LicenseType',
    'ProductInfo',
    'get_license_opensource',
    'get_license_closed_source',
    'extract_product_name',
]
