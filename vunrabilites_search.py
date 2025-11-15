from google import genai
from google.genai.types import Tool, GoogleSearch, GenerateContentConfig
from pydantic import BaseModel, Field
from typing import List, Optional
import os


# -----------------------------------------------------
# Pydantic Models (Structured Output Schema)
# -----------------------------------------------------

class Vulnerability(BaseModel):
    cve_id: Optional[str] = Field(
        default=None, description="CVE identifier if available."
    )
    title: Optional[str] = Field(
        default=None, description="Short title of the vulnerability."
    )
    description: Optional[str] = Field(
        default=None, description="Summary of the vulnerability."
    )
    source_url: Optional[str] = Field(
        default=None, description="URL of the source where this was found."
    )
    severity: Optional[str] = Field(
        default=None, description="Severity rating if available (CVSS, vendor, etc.)."
    )
    published_date: Optional[str] = Field(
        default=None, description="Published date of the advisory, if available."
    )
    status: Optional[str] = Field(
        default=None, description= "Current status (In remedy/ Solved)"
    )


class VulnerabilitySearchResult(BaseModel):
    product_name: str = Field(description="The name of the product being analyzed.")
    results: List[Vulnerability]



import base64
import re

def decode_vertex_ai_redirect(url: str) -> str:
    """
    Attempt to decode a Google grounding-api-redirect link.
    Returns the original target URL if decoding succeeds,
    otherwise returns the original URL unchanged.
    """

    pattern = r"grounding-api-redirect/([^/?#]+)"
    match = re.search(pattern, url)

    if not match:
        return url  # Not a redirect link

    encoded = match.group(1)

    # Convert to proper base64 padding
    padding = '=' * (-len(encoded) % 4)
    encoded += padding

    try:
        decoded = base64.urlsafe_b64decode(encoded.encode("utf-8"))
        decoded_str = decoded.decode("utf-8")
        return decoded_str
    except Exception:
        return url  # Failed to decode → return original



def decode_all_urls(findings: VulnerabilitySearchResult):
  for v in findings.results:
    if v.source_url:
        v.source_url = decode_vertex_ai_redirect(v.source_url)
  return findings
# -----------------------------------------------------
# Gemini Search Function
# -----------------------------------------------------

def search_vulnerabilities_structured(product_name: str):

    client = genai.Client(api_key=os.environ['GEMINI_API_KEY'])

    security_sites = [
      "https://nvd.nist.gov",
      "https://cve.mitre.org",
      "https://attack.mitre.org",
      "https://www.cvedetails.com",
      "https://security.snyk.io",
      "https://www.securityfocus.com",
      "https://www.exploit-db.com",
    ]

    prompt = f"""
    You are a cybersecurity analyst.

    TASK:
    Search the web using browsing tools for all vulnerabilities, malware, CVEs,
    or exploits related to the product:

    PRODUCT: {product_name}

    You MUST explicitly check these sites besides others
    {security_sites}


    Requirements:
    - Use web search and then browse promising pages.  
    - Extract all relevant vulnerabilities.
    - If a CVE exists, include it. If not, leave cve_id null.
    - Only return real, verified vulnerabilities. No fabrications.
    - Return ONLY JSON in the schema provided. No additional comments.


    Return only a json corrosponding this schema {VulnerabilitySearchResult.model_json_schema()} directly as '''json {"..."}'''
    """



    search_tool = Tool(google_search=GoogleSearch())
    config = GenerateContentConfig(
        tools=[search_tool],
        response_mime_type = "text/plain",
        response_json_schema= VulnerabilitySearchResult.model_json_schema(),
    )

    # Gemini call with forced structured output
    chat = client.chats.create(
        model="gemini-2.5-flash",
        config= config,
        )

    response = chat.send_message(prompt)
    retries = 0
    
    result = None
    while (retries<3):
      try:
        text = response.text.removeprefix("```json")
        text = text.removesuffix("```")
        result = VulnerabilitySearchResult.model_validate_json(text)
        break
      except Exception as e:
        retries+=1
        result = None
        response = chat.send_message(f"Error during parsing (make sure it is a valid json): str(e)")

    return decode_all_urls(result) if result else None


# -----------------------------------------------------
# Example Usage
# -----------------------------------------------------

if __name__ == "__main__":
    product = "Apache Tomcat 9"

    findings = search_vulnerabilities_structured(product)

    print(findings.model_dump_json(indent=4))

