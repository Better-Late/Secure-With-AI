import json
import re
from google import genai
from google.genai.types import Tool, GenerateContentConfig
import pydantic
from entity_resolution import SoftwareEntity
from typing import List
import os

def search_alternatives(product: str) -> List[SoftwareEntity]:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GGEMINI_API_KEY environment variable not set.")
    
    client = genai.Client()
    model_id = "gemini-2.5-flash"

    tools = [
        {"url_context": {}},
        {"google_search": {}},
    ]
    response = client.models.generate_content(
        model=model_id,
        contents=f"List 5 popular alternatives to the software product '{product}'." 
        " Use https://european-alternatives.eu, https://alternativeto.net/, and https://www.opensourcealternative.to/."
        " For each alternative, provide the full name, vendor, website, github link (if available), and a brief description. "
        " Produce a JSON list with objects containing the fields: full_name, vendor, website, github_link, description. "
        " Use google search if needed to find the details of the software product."
        " Return only directly relevant alternatives."
        " If some value is unknown, use null. Do not include explanatory text or markdown.",
        config=GenerateContentConfig(
            tools=tools,
        )
    )

    alternatives = []
    for part in response.candidates[0].content.parts:
        part = part.text
        if "```json" in part:
            m = re.search(r"```json(.*?)```", part, re.S)
            if m:
                part = m.group(1).strip()  

        try:
            entity_data = json.loads(part)
        except json.JSONDecodeError:
            continue

        if not isinstance(entity_data, list):
            entity_data = [entity_data]
        for item in entity_data:
            try:
                entity = SoftwareEntity.model_validate(item)
                alternatives.append(entity)
            except pydantic.ValidationError as e:
                continue

    return alternatives


def main():
    product = "Microsoft VS code"
    alternatives = search_alternatives(product)
    for alt in alternatives:
        print(f"Name: {alt.full_name}, Vendor: {alt.vendor}, Website: {alt.website}, Description: {alt.description}")

if __name__ == "__main__":
    main()