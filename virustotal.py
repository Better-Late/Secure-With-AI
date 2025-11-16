import aiohttp
import os
import asyncio

async def getInfoFromHash(shash: str):
  all_url = "https://www.virustotal.com/api/v3/search?query="

  headers = {"accept": "application/json", "x-apikey" : os.environ['VIRUSTOTAL_API_KEY']}

  async with aiohttp.ClientSession() as session:
      async with session.get(all_url + shash, headers=headers) as response:
          return await response.json()


from typing import List, Optional
from pydantic import BaseModel

class DetectionSummary(BaseModel):
    malicious: int
    suspicious: int
    undetected: int
    harmless: int
    timeout: int
    vendor_labels: List[str] = []


class SignatureInfo(BaseModel):
    is_signed: bool
    signer: Optional[str]
    certificate_status: Optional[str]   # "valid", "revoked", "unknown"
    timestamp: Optional[str]


class BehavioralIndicators(BaseModel):
    processes: List[str] = []
    registry: List[str] = []
    filesystem: List[str] = []
    network: List[str] = []
    persistence: List[str] = []
    suspicious_api_calls: List[str] = []


class StaticIndicators(BaseModel):
    imphash: Optional[str]
    imports: List[str] = []
    exports: List[str] = []
    packer: Optional[str]
    entropy: Optional[float]
    sections: List[str] = []  # names or anomalies


class FuzzyHashes(BaseModel):
    ssdeep: Optional[str]
    tlsh: Optional[str]
    authentihash: Optional[str]
    vhash: Optional[str]


class ReputationInfo(BaseModel):
    first_seen: Optional[str]
    last_seen: Optional[str]
    times_submitted: Optional[int]
    threat_label: Optional[str]  # e.g. "adware.browserassistant"
    tags: List[str] = []


class FileAssessment(BaseModel):
    # 1. Identification
    sha256: str
    sha1: Optional[str]
    md5: Optional[str]
    file_name: Optional[str]
    file_type: Optional[str]
    file_size: Optional[int]

    # 2. Detection summary
    detection: DetectionSummary

    # 3. Threat / classification
    threat_category: Optional[str]     # "adware", "trojan", "ransomware"
    threat_name: Optional[str]         # dominant vendor label

    # 4. Code signing
    signature: SignatureInfo

    # 5. Static analysis
    static: StaticIndicators

    # 6. Behavioral analysis (if available)
    behavior: BehavioralIndicators

    # 7. Reputation, OSINT, timeline
    reputation: ReputationInfo

    # 8. Fuzzy hashes
    fuzzy: FuzzyHashes





from google import genai
from google.genai.types import GenerateContentConfig

async def get_parse_hashfile_assesmentAI(shash: str):

    client = genai.Client(api_key=os.environ['GEMINI_API_KEY'])

    assesment_data = await getInfoFromHash(shash)
    import json
    assesment = json.dumps(assesment_data)

    prompt = f"""
    You are a cybersecurity analyst.

    TASK:
    Parse the following file assesment and return a structered json.


    Assesment: {assesment}

    Requirements:
    - Extract all relevant information.
    - Return ONLY JSON in the schema provided corrosponding to this schema {FileAssessment.model_json_schema()}. No additional comments.

    """

    config = GenerateContentConfig(
        response_mime_type = "application/json",
        response_json_schema= FileAssessment.model_json_schema(),
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

    return FileAssessment.model_validate_json(response.text)




async def get_parse_hashfile_assesment(shash: str) -> FileAssessment:
    response_data = await getInfoFromHash(shash)
    data = response_data["data"][0]["attributes"]

    # ---- Identification ----
    sha256 = data.get("sha256")
    sha1 = data.get("sha1")
    md5 = data.get("md5")
    file_name = data.get("meaningful_name")
    file_type = data.get("type_description")
    file_size = data.get("size")

    # ---- Detection ----
    stats = data.get("last_analysis_stats", {})
    vendor_results = data.get("last_analysis_results", {})
    vendor_labels = [
        v.get("result") for v in vendor_results.values() if v.get("result")
    ]

    detection = DetectionSummary(
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        undetected=stats.get("undetected", 0),
        harmless=stats.get("harmless", 0),
        timeout=stats.get("timeout", 0),
        vendor_labels=vendor_labels
    )

    # Threat names
    threat_name = None
    threat_category = None
    if "popular_threat_classification" in data:
        ptc = data["popular_threat_classification"]
        if ptc.get("popular_threat_name"):
            threat_name = ptc["popular_threat_name"][0]["value"]
        if ptc.get("popular_threat_category"):
            threat_category = ptc["popular_threat_category"][0]["value"]

    # ---- Signature ----
    sig = data.get("signature_info", {})
    signer = None
    cert_status = None

    if "signers details" in sig or "signers details" in sig:
        # VirusTotal sometimes uses different key formats
        signer_info = sig.get("signers details", sig.get("signers_details", []))
        if isinstance(signer_info, list) and len(signer_info) > 0:
            signer = signer_info[0].get("name")
            cert_status = signer_info[0].get("status")

    signature = SignatureInfo(
        is_signed=sig.get("verified", "") == "Signed",
        signer=signer,
        certificate_status=cert_status,
        timestamp=sig.get("signing date")
    )

    # ---- Static ----
    pe_info = data.get("pe_info", {})

    imports = []
    for item in pe_info.get("import_list", []):
        lib = item.get("library_name")
        for fn in item.get("imported_functions", []):
            imports.append(f"{lib}!{fn}")

    exports = [e for e in pe_info.get("exports", [])] if pe_info.get("exports") else []

    sections = [sec.get("name") for sec in pe_info.get("sections", [])]

    static = StaticIndicators(
        imphash=pe_info.get("imphash"),
        imports=imports,
        exports=exports,
        entropy=data.get("entropy"),
        packer=None,  # Could infer from peid or packer signatures
        sections=sections
    )

    # ---- Behavior ----
    behavior = BehavioralIndicators()  # Placeholder: VT doesn't provide behavior by default

    # ---- Reputation ----
    reputation = ReputationInfo(
        first_seen=str(data.get("first_seen_itw_date")),
        last_seen=str(data.get("last_modification_date")),
        times_submitted=data.get("times_submitted"),
        threat_label=data.get("popular_threat_classification", {}).get("suggested_threat_label"),
        tags=data.get("tags", [])
    )

    # ---- Fuzzy Hashes ----
    fuzzy = FuzzyHashes(
        ssdeep=data.get("ssdeep"),
        tlsh=data.get("tlsh"),
        authentihash=data.get("authentihash"),
        vhash=data.get("vhash")
    )

    return FileAssessment(
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        file_name=file_name,
        file_type=file_type,
        file_size=file_size,
        detection=detection,
        threat_category=threat_category,
        threat_name=threat_name,
        signature=signature,
        static=static,
        behavior=behavior,
        reputation=reputation,
        fuzzy=fuzzy
    )


# -----------------------------------------------------
# Example Usage
# -----------------------------------------------------

if __name__ == "__main__":
    async def main():
        shash = "37121618e735ebf628f7ba6ce29afc251ed88503"
        info = await getInfoFromHash(shash)
        import json
        print(json.dumps(info, indent=2))

        findings = await get_parse_hashfile_assesment(shash)

        print(findings.model_dump_json(indent=4))

    asyncio.run(main())


