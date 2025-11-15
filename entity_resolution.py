import os
import json
import google.genai as genai
from google.genai.types import Tool, GoogleSearch, GenerateContentConfig
from pydantic import BaseModel, Field
import re
import argparse
import sys

class SoftwareEntity(BaseModel):
    full_name: str = Field(..., description="The official full name of the software application.")
    vendor: str | None = Field(..., description="The official vendor or company name.")
    website: str | None = Field(None, description="The primary official website URL of the application.")
    github_link: str | None = Field(None, description="The official GitHub repository link, if available.")
    description: str = Field(..., description="A brief description of what the software does and its primary purpose.")


def get_gemini_api_key():
    """
    Retrieves the Gemini API key from the GEMINI_API_KEY environment variable.
    Exits the script if the key is not found.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable not set.")
        print("Please set the environment variable before running the script:")
        print("export GEMINI_API_KEY='your_api_key_here'")
        sys.exit(1)
    return api_key

def call_gemini_api(api_key, user_query):
    system_prompt = (
        "You are a software information retrieval assistant. "
        "You may call the provided Google Search tool to look up facts, but do NOT"
        " include raw HTML, full search snippets, or tool debugging info in your"
        " final answer. Instead, produce exactly one JSON object"
        " containing the fields: full_name, vendor, website, github_link, description. If a"
        " value is unknown, use null. Do not include explanatory text or markdown."
    )
    full_prompt = system_prompt + "\n\n" + user_query


    client = genai.Client(api_key=api_key)
    search_tool = Tool(google_search=GoogleSearch())
    config = GenerateContentConfig(
        tools=[search_tool],
        response_mime_type="text/plain",
    )

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash", contents=full_prompt, config=config
        )

        response_text = getattr(response, "text", None) or str(response)
        if "```json" in response_text:
            m = re.search(r"```json(.*?)```", response_text, re.S)
            if m:
                response_text = m.group(1).strip()  

        try:
            parsed = json.loads(response_text)
        except json.JSONDecodeError:
            m = re.search(r"(\{(?:[^{}]|(?R))*\})", response_text, re.S)
            if not m:
                print("Error: Response did not contain valid JSON. Raw response:")
                print(response_text)
                return None
            parsed = json.loads(m.group(1))

        return SoftwareEntity.model_validate(parsed)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if 'response_text' in locals():
            print("--- Raw API Response ---")
            print(response_text)
        return None
    
def detect_entity(text: str) -> SoftwareEntity | None:
    """
    Detect software entity information using the Gemini API.
    
    Args:
        text: Input text containing software details.
    Returns:
        SoftwareEntity object or None if not found
    """
    api_key = get_gemini_api_key()
    user_query = f"Extract software entity information from the following text: {text}"
    return call_gemini_api(api_key, user_query)

if __name__ == "__main__":
    print(detect_entity(input('Enter software name/vendor/process name: ')))