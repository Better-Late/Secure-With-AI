import os
import json
import google.genai as genai
from google.genai.types import Tool, GoogleSearch, GenerateContentConfig
from pydantic import BaseModel, Field
import re
import argparse
import sys

class MalwareSuspicion(BaseModel):
    flagged: bool = Field(..., description="Indicates if the software is flagged as suspicious or potentially malicious.")
    reasons: list[str] = Field(..., description="List of reasons why the software is considered suspicious.")

class MalwareCheckResponse(BaseModel):
    is_malware: bool = Field(..., description="Whether the software is confirmed malware based on multiple explicit sources.")
    explanation: str = Field(..., description="Detailed explanation of why the software is or isn't considered malware.")

class SoftwareEntity(BaseModel):
    full_name: str = Field(..., description="The official full name of the software application.")
    vendor: str | None = Field(..., description="The official vendor or company name.")
    website: str | None = Field(None, description="The primary official website URL of the application.")
    github_link: str | None = Field(None, description="The official GitHub repository link, if available.")
    description: str = Field(..., description="A brief description of what the software does and its primary purpose.")
    software_type: str = Field(None, description="Type of software (e.g., File sharing, GenAI tool, SaaS CRM, Endpoint agent).")
    malware_suspicion: MalwareSuspicion | None = Field(None, description="Indicates if the software is flagged as suspicious or potentially malicious, with reasons.")


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

async def call_gemini_api(api_key, user_query) -> tuple[SoftwareEntity | None, ]:
    system_prompt = (
        "You are a software information retrieval assistant. "
        "You may call the provided Google Search tool to look up facts, but do NOT"
        " include raw HTML, full search snippets, or tool debugging info in your"
        " final answer. Instead, produce exactly one JSON object"
        " containing the fields: full_name, vendor, website, github_link, description, software_type."
        " If a value is unknown, use null. Use the process name as full name if full_name is unknown."
        " Do not include explanatory text or markdown. In the description, do NOT mention pricing and licensing."
        " In addition, if you find clear indications that the software is very suspicious or a malware,"
        " include a field 'malware_suspicion' with subfields 'flagged' (boolean) and 'reasons' (list of strings) explaining why." \
        " Use this field only if the program is a known malware, not when it is just insecure. " \
        " For software_type, classify the software (e.g., File sharing, GenAI tool, SaaS CRM, Endpoint agent), put Software if unknown." \
        " The software_type must be chosen from the following list: " + ", ".join(software_types()) + "."
    )
    full_prompt = system_prompt + "\n\n" + user_query


    client = genai.Client(api_key=api_key)
    search_tool = Tool(google_search=GoogleSearch())
    config = GenerateContentConfig(
        tools=[search_tool],
        response_mime_type="text/plain",
    )

    try:
        # Note: The genai library doesn't have native async support yet
        # We'll run this in a thread pool to avoid blocking
        import asyncio
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.models.generate_content(
                model="gemini-2.5-flash", contents=full_prompt, config=config
            )
        )

        response_text = getattr(response, "text", None) or str(response)
        if "```json" in response_text:
            m = re.search(r"```json(.*?)```", response_text, re.S)
            if m:
                response_text = m.group(1).strip()

        try:
            parsed = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON object from text by finding balanced braces
            start = response_text.find('{')
            if start == -1:
                print("Error: Response did not contain valid JSON. Raw response:")
                print(response_text)
                return None

            # Find matching closing brace
            brace_count = 0
            end = -1
            for i in range(start, len(response_text)):
                if response_text[i] == '{':
                    brace_count += 1
                elif response_text[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break

            if end == -1:
                print("Error: Response did not contain valid JSON. Raw response:")
                print(response_text)
                return None

            parsed = json.loads(response_text[start:end])

        entity = SoftwareEntity.model_validate(parsed)

        # Perform malware detection check
        malware_check_prompt = (
            f"Is '{entity.full_name}' actual malware or malicious software? "
            "IMPORTANT: Only flag software as malware if you find MULTIPLE EXPLICIT mentions "
            "confirming that this specific software is:\n"
            "- A virus, trojan, worm, ransomware, or other destructive malware\n"
            "- Distributed with malicious intent to harm users or systems\n"
            "- Confirmed as a threat by security researchers or reliable sources\n\n"
            "DO NOT flag software as malware if:\n"
            "- It's legitimate software from a known vendor (even if it has privacy concerns)\n"
            "- It collects telemetry, analytics, or user data for advertising (common in commercial software)\n"
            "- It has security vulnerabilities or is outdated\n"
            "- Critics label it 'spyware' due to data collection practices, but it's made by a reputable company\n"
            "- It's open source or from a well-known organization (Google, Microsoft, Mozilla, etc.)\n\n"
            "Examples of LEGITIMATE software that should NOT be flagged: Google Chrome, Microsoft Edge, "
            "Windows 10, Facebook, TikTok, Adobe Reader (even if they have privacy concerns).\n\n"
            "Examples that SHOULD be flagged: CryptoLocker ransomware, Zeus trojan, WannaCry, "
            "known keyloggers, confirmed backdoors.\n\n"
            "Provide a detailed explanation of your findings. "
            "Return your response as a JSON object with exactly two fields: "
            "'is_malware' (boolean) and 'explanation' (string). Do not include any other text."
        )

        try:
            malware_config = GenerateContentConfig(
                tools=[search_tool],
                response_mime_type="text/plain",
            )

            malware_response = await loop.run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=malware_check_prompt,
                    config=malware_config
                )
            )

            malware_text = getattr(malware_response, "text", None) or str(malware_response)

            # Extract JSON from response (handle markdown code blocks)
            if "```json" in malware_text:
                m = re.search(r"```json(.*?)```", malware_text, re.S)
                if m:
                    malware_text = m.group(1).strip()

            try:
                malware_result = json.loads(malware_text)
            except json.JSONDecodeError:
                # Try to extract JSON object from text by finding balanced braces
                start = malware_text.find('{')
                if start == -1:
                    raise ValueError("No valid JSON found in malware check response")

                # Find matching closing brace
                brace_count = 0
                end = -1
                for i in range(start, len(malware_text)):
                    if malware_text[i] == '{':
                        brace_count += 1
                    elif malware_text[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end = i + 1
                            break

                if end == -1:
                    raise ValueError("No valid JSON found in malware check response")

                malware_result = json.loads(malware_text[start:end])

            malware_check = MalwareCheckResponse.model_validate(malware_result)

            # Set malware_suspicion if flagged as malware
            if malware_check.is_malware:
                entity.malware_suspicion = MalwareSuspicion(
                    flagged=True,
                    reasons=[malware_check.explanation]
                )
            else:
                entity.malware_suspicion = None

        except Exception as e:
            print(f"Warning: Malware detection check failed: {e}")
            entity.malware_suspicion = None

        return entity

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if 'response_text' in locals():
            print("--- Raw API Response ---")
            print(response_text)
        return None

async def detect_entity(text: str) -> SoftwareEntity | None:
    """
    Detect software entity information using the Gemini API.

    Args:
        text: Input text containing software details.
    Returns:
        SoftwareEntity object or None if not found
    """
    api_key = get_gemini_api_key()
    user_query = f"Extract software entity information from the following text: {text}"
    return await call_gemini_api(api_key, user_query)

def software_types():
    return [
        "Operating System",
        "Database Management System (DBMS)",
        "Web Browser",
        "Email Client",
        "Office Productivity Suite",
        "Enterprise Resource Planning (ERP)",
        "Business Intelligence (BI) Tool",
        "Virtual Private Network (VPN)",
        "Firewall",
        "Antivirus Software",
        "Backup and Recovery Software",
        "Integrated Development Environment (IDE)",
        "Version Control System",
        "Content Management System (CMS)",
        "E-commerce Platform",
        "Payment Gateway",
        "Project Management Software",
        "Collaboration Tool",
        "Video Conferencing Software",
        "Streaming Service",
        "Social Media Platform",
        "Utility Software",
        "Middleware",
        "Firmware",
        "Hypervisor",
        "Containerization Platform",
        "Monitoring Software",
        "Help Desk Software",
        "Learning Management System (LMS)",
        "CAD Software",
        "Graphic Design Software",
        "Video Editing Software",
        "Cloud Storage Service",
        "Identity and Access Management (IAM)",
        "Data Loss Prevention (DLP) Software",
        "Security Information and Event Management (SIEM)",
        "Infrastructure as a Service (IaaS)",
        "Platform as a Service (PaaS)",
        "Marketing Automation Platform",
        "Customer Data Platform (CDP)",
        "Supply Chain Management (SCM) Software",
        "Geographic Information System (GIS) Software"
    ]
if __name__ == "__main__":
    import asyncio
    result = asyncio.run(detect_entity(input('Enter software name/vendor/process name: ')))
    print(result)