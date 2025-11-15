"""Centralized Gemini API client for the licensing package."""

import os
import asyncio
import google.genai as genai
from google.genai import types
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Initialize client once
_client: Optional[genai.Client] = None


def _get_client() -> Optional[genai.Client]:
    """Get or create the Gemini client singleton."""
    global _client

    if _client is None:
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            print("Warning: GEMINI_API_KEY not set")
            return None

        _client = genai.Client(api_key=api_key)

    return _client


async def generate_content(prompt: str, model: str = 'gemini-2.5-flash-lite') -> Optional[str]:
    """
    Generate content using Gemini API.

    Args:
        prompt: The prompt to send to Gemini
        model: Model name to use (default: gemini-2.0-flash-lite)

    Returns:
        Generated text or None if generation fails
    """
    client = _get_client()
    if not client:
        return None

    try:
        # Run synchronous Gemini call in executor to avoid blocking
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.models.generate_content(
                model=model,
                contents=prompt
            )
        )
        return response.text.strip()
    except Exception as e:
        print(f"Error generating content: {e}")
        return None


async def generate_content_with_search(prompt: str, model: str = 'gemini-2.0-flash-lite') -> Optional[str]:
    """
    Generate content using Gemini API with Google Search grounding.

    Args:
        prompt: The prompt to send to Gemini
        model: Model name to use (default: gemini-2.0-flash-lite)

    Returns:
        Generated text or None if generation fails
    """
    client = _get_client()
    if not client:
        return None

    try:
        # Run synchronous Gemini call in executor to avoid blocking
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    tools=[types.Tool(google_search=types.GoogleSearch())],
                )
            )
        )
        return response.text.strip()
    except Exception as e:
        print(f"Error generating content with search: {e}")
        return None


async def summarize_legal_text(text: str, page_url: str, max_chars: int = 1000, model: str = 'gemini-2.0-flash-lite') -> Optional[str]:
    """
    Summarize legal text focusing ONLY on software/product terms, not website terms.

    Args:
        text: Text to summarize
        page_url: URL of the page (for context)
        max_chars: Maximum characters for summary (default: 1000)
        model: Model name to use (default: gemini-2.0-flash-lite)

    Returns:
        Summarized text or empty string if no software-relevant content found
    """
    client = _get_client()
    if not client:
        return None

    prompt = f"""Analyze the following legal document from {page_url}.

Your task: Extract and summarize ONLY information related to SOFTWARE, SERVICE or PRODUCT usage, licensing, and terms.

INCLUDE:
- Software licensing terms and restrictions
- Product usage rights and limitations
- Software-specific data collection and privacy
- Information about services
- API usage terms
- Developer/integration terms
- Installation and deployment restrictions
- Pricing!!!

EXCLUDE:
- Website cookies and web analytics
- Website terms of service (unless also about software)
- General website privacy policies (unless also about software data)
- Marketing preferences
- Account creation for website access
- Newsletter subscriptions

If this document is ONLY about website usage (cookies, web browsing, etc.) and contains NO information about software/product/service licensing, pricing or terms, respond with exactly: "NO_SOFTWARE_TERMS"

Otherwise, provide a concise summary under {max_chars} characters focusing ONLY on software-relevant terms.

Document:
{text[:15000]}

Summary:"""

    try:
        # Run synchronous Gemini call in executor to avoid blocking
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.models.generate_content(
                model=model,
                contents=prompt
            )
        )
        summary = response.text.strip()

        # Check if no software terms found
        if "NO_SOFTWARE_TERMS" in summary:
            return ""

        return summary[:max_chars]  # Ensure limit
    except Exception as e:
        print(f"Error summarizing text: {e}")
        return None


def is_available() -> bool:
    """Check if Gemini API is available."""
    return _get_client() is not None
