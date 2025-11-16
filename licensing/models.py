"""Data models and enums for licensing package."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
from collections import deque
from typing import Set


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
    # Fields for proprietary software assessment
    terms_of_use: Optional[str] = None
    privacy_assessment: Optional[str] = None
    is_free: Optional[str] = None
    # Source URLs used during assessment
    legal_sources: Optional[list[str]] = None
    pricing_sources: Optional[list[str]] = None


@dataclass
class AIAssessment:
    """Result of AI license detection assessment."""
    contains_license: bool
    license_type: str
    confidence: str
    relevant_section: Optional[str] = None
    reasoning: Optional[str] = None


@dataclass
class PageContent:
    """Extracted content from a webpage."""
    url: str
    title: str
    text: str


@dataclass
class ProductInfo:
    """Information about a product extracted from website."""
    name: str
    confidence: str


@dataclass
class LicenseSearchResult:
    """Result of searching for license on a page."""
    found: bool
    text: Optional[str] = None
    url: Optional[str] = None


@dataclass
class CrawlState:
    """State for website crawling."""
    queue: deque
    visited: Set[str]
    pages_visited: int
    base_domain: str
