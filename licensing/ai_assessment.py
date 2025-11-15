"""AI-powered license assessment functionality.

DEPRECATED: This module is no longer used in the main license extraction flow.
Kept for backwards compatibility only.
"""

import os
import re
import json
from typing import Optional
from bs4 import BeautifulSoup
import google.genai as genai
from google.genai import types
from dotenv import load_dotenv

from .models import AIAssessment, PageContent

load_dotenv()


def _load_license_prompt_template() -> str:
    """Load the license detection prompt template from file."""
    prompt_file = os.path.join(os.path.dirname(__file__), '..', 'license_detection_prompt.md')
    
    try:
        with open(prompt_file, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error loading prompt template: {e}")
        return ""


def _extract_page_content(soup: BeautifulSoup, url: str, max_chars: int = 3000) -> PageContent:
    print("got here")
    """Extract relevant content from a webpage."""
    # Extract title
    title_tag = soup.find('title')
    title = title_tag.get_text(strip=True) if title_tag else "No title"
    
    # Get main content, prioritizing main/article sections
    main_content = soup.find('main') or soup.find('article') or soup.find('body')
    
    if main_content:
        # Remove unwanted elements
        for tag in main_content(['script', 'style', 'nav', 'header', 'footer']):
            tag.decompose()
        
        text = main_content.get_text(separator='\n', strip=True)
    else:
        text = soup.get_text(separator='\n', strip=True)
    
    # Limit content length
    text = text[:max_chars]
    
    return PageContent(url=url, title=title, text=text)


def _parse_ai_response(response_text: str) -> AIAssessment:
    """Parse AI response into AIAssessment object."""
    # Remove markdown code blocks if present
    response_text = re.sub(r'```json\s*|\s*```', '', response_text).strip()
    
    result = json.loads(response_text)
    
    return AIAssessment(
        contains_license=result.get('contains_license', False),
        license_type=result.get('license_type', 'Unknown').lower(),
        confidence=result.get('confidence', 'low'),
        relevant_section=result.get('relevant_section'),
        reasoning=result.get('reasoning')
    )


def assess_license_with_ai(url: str, soup: BeautifulSoup, api_key: Optional[str] = None) -> AIAssessment:
    """
    Use Gemini AI to assess if a page contains license information.
    
    Args:
        url: The URL of the page
        soup: BeautifulSoup object of the page
        api_key: Gemini API key (defaults to GEMINI_API_KEY env variable)
    
    Returns:
        AIAssessment object with detection results
    """
    # try:
    api_key = api_key or os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("Warning: GEMINI_API_KEY not set, skipping AI assessment")
        return AIAssessment(contains_license=False, license_type="unknown", confidence="low")
    
    # Create client
    client = genai.Client(api_key=api_key)
    
    # Extract page content
    page_content = _extract_page_content(soup, url)
    
    # Load and format prompt
    prompt_template = _load_license_prompt_template()
    if not prompt_template:
        return AIAssessment(contains_license=False, license_type="unknown", confidence="low")
    
    prompt = prompt_template.format(
        url=page_content.url,
        title=page_content.title,
        content=page_content.text
    )
    
    # Call Gemini API
    response = client.models.generate_content(
        model='gemini-2.0-flash-lite',
        contents=prompt
    )
    
    print("got here")
    # Parse response
    assessment = _parse_ai_response(response.text.strip())
    
    print(f"  AI Assessment: contains_license={assessment.contains_license}, "
            f"confidence={assessment.confidence}, type={assessment.license_type}")
    
    return assessment
        
    # except Exception as e:
    #     print(f"  Error in AI assessment: {e}")
    #     return AIAssessment(contains_license=False, license_type="unknown", confidence="low")
