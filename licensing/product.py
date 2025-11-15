"""Product name extraction functionality."""

import os
import re
import json
import requests
from typing import Optional
from bs4 import BeautifulSoup
import google.genai as genai
from dotenv import load_dotenv

from .models import ProductInfo, PageContent
from .ai_assessment import _extract_page_content

load_dotenv()


def _create_product_name_prompt(page_content: PageContent) -> str:
    """Create prompt for extracting product name."""
    return f"""You are an expert at analyzing websites and extracting product information.

Your task is to determine the main product or service name from a webpage.

## Input

**URL:** {page_content.url}

**Title:** {page_content.title}

**Content (first 2000 chars):**
{page_content.text[:2000]}

## Output Format

Respond with a JSON object containing:
```json
{{
  "product_name": "The main product or service name",
  "confidence": "high/medium/low",
  "reasoning": "Brief explanation of why you identified this name"
}}
```

## Guidelines

- Look for the company/product name in the title, header, and main content
- Consider domain name as a clue
- Be conservative: if unclear, return confidence "low"
- Avoid generic terms like "Home", "Welcome", etc.
- Return the most prominent product/service/company name
"""


def extract_product_name(website_url: str) -> Optional[ProductInfo]:
    """
    Extract product name from a website using AI.
    
    Args:
        website_url: Website URL to analyze
    
    Returns:
        ProductInfo object with product name and confidence, or None if extraction fails
    """
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            print("Warning: GEMINI_API_KEY not set, cannot extract product name")
            return None
        
        # Fetch the website
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(website_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse content
        soup = BeautifulSoup(response.text, 'html.parser')
        page_content = _extract_page_content(soup, website_url, max_chars=2000)
        
        # Create client and prompt
        client = genai.Client(api_key=api_key)
        prompt = _create_product_name_prompt(page_content)
        
        # Call Gemini API
        response = client.models.generate_content(
            model='gemini-2.0-flash-lite',
            contents=prompt
        )
        
        # Parse response
        response_text = response.text.strip()
        response_text = re.sub(r'```json\s*|\s*```', '', response_text).strip()
        result = json.loads(response_text)
        
        product_info = ProductInfo(
            name=result.get('product_name', 'Unknown'),
            confidence=result.get('confidence', 'low')
        )
        
        print(f"Extracted product name: '{product_info.name}' (confidence: {product_info.confidence})")
        return product_info
        
    except Exception as e:
        print(f"Error extracting product name: {e}")
        return None
