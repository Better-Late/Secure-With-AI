from google import genai
from google.genai.types import Tool, GoogleSearch, GenerateContentConfig
from pydantic import BaseModel, Field
from typing import List, Literal, Optional, Union
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
    severity: Optional[Union[float, Literal["Low", "Medium", "High", "Critical", "Unknown"]]] = Field(
        default=None, description="Severity rating if available (CVSS, vendor, etc.)."
    )
    published_date: Optional[str] = Field(
        default=None, description="Published date of the advisory, if available."
    )
    status: Optional[Literal["Solved", "Not Solved", "Unknown Status"]] = None


class VulnerabilitySearchResult(BaseModel):
    product_name: str = Field(description="The name of the product being analyzed.")
    results: List[Vulnerability]



import aiohttp
import asyncio

async def validate_cve_on_nvd(cve_id: str, timeout: float = 10.0) -> bool:
    """
    Check if a CVE exists on the NVD database by attempting to access its detail page.
    Returns True if the CVE exists (HTTP 200), False otherwise (404 or any error).
    """
    if not cve_id:
        return False
    
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(nvd_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                return resp.status == 200
    except Exception:
        return False




async def decode_all_urls(findings: VulnerabilitySearchResult):
  # Validate CVEs against NVD first and update source URLs
  validation_tasks = []
  for v in findings.results:
      if v.cve_id:
          validation_tasks.append((v, validate_cve_on_nvd(v.cve_id)))
  
  # Filter vulnerabilities: only keep those with valid CVE IDs that exist on NVD
  valid_vulnerabilities = []
  for v in findings.results:
      # Skip vulnerabilities without CVE IDs - they don't have NVD links
      if not v.cve_id:
          continue
      
      # Find the corresponding validation task
      cve_valid = False
      for vuln, task in validation_tasks:
          if vuln is v:
              cve_valid = await task
              break
      
      # Only include if CVE is valid on NVD, and replace source with NVD URL
      if cve_valid:
          v.source_url = f"https://nvd.nist.gov/vuln/detail/{v.cve_id}"
          valid_vulnerabilities.append(v)
  
  findings.results = valid_vulnerabilities
  return findings
# -----------------------------------------------------
# Gemini Search Function
# -----------------------------------------------------

async def search_vulnerabilities_structured(product_name: str):

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
    # Run in executor since genai doesn't have native async support
    loop = asyncio.get_event_loop()
    chat = await loop.run_in_executor(
        None,
        lambda: client.chats.create(
            model="gemini-2.5-flash",
            config=config,
        )
    )

    response = await loop.run_in_executor(None, lambda: chat.send_message(prompt))
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
        response = await loop.run_in_executor(None, lambda: chat.send_message(f"Error during parsing (make sure it is a valid json): str(e)"))

    return await decode_all_urls(result) if result else None


# -----------------------------------------------------
# Example Usage
# -----------------------------------------------------

if __name__ == "__main__":
    product = "OneStart"

    findings = asyncio.run(search_vulnerabilities_structured(product))

    print(findings.model_dump_json(indent=4))

