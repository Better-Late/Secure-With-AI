from typing import Dict, Optional
from diskcache import Cache
from entity_resolution import SoftwareEntity, detect_entity
from search_vulnerabilities import search_vulnerabilities_structured, VulnerabilitySearchResult
from alternatives import search_alternatives
from virustotal import FileAssessment, get_parse_hashfile_assesment
import os
from dotenv import load_dotenv

# load .env from project root
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# optional: fail fast in dev if missing
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError("VIRUSTOTAL_API_KEY not set. Add it to .env or env vars.")
if not GEMINI_API_KEY:
    # you can choose to raise here or just warn
    raise RuntimeError("GEMINI_API_KEY not set. Add it to .env or env vars.")

class AnalysisResult(Dict[str, any]):
    score: int


# Global cache instance using diskcache
_cache = Cache('./cache_dir')


def analysis(company_name: str, product_name: str, hash_value: Optional[str] = "bcd9fd198cab024450c1f2d09d83aeeeee6a2a4a") -> Dict[str, any]:
    """
    Placeholder function for security analysis.
    Replace this with your actual security summary generation logic.
    
    Args:
        company_name: Name of the company
        product_name: Name of the program/product
        hash_value: Optional hash value for the product
    
    Returns:
        Dict with 'score' (0-100) and 'summary' (markdown text)
    """
    # Create cache key including hash if available
    cache_key = f"{company_name}:{product_name}:{hash_value}" if hash_value else f"{company_name}:{product_name}"
    
    # Check cache first
    cached_result = _cache.get(cache_key)
    if cached_result:
        return cached_result
    
    # Perform actual analysis
    product_entity = detect_entity(f"{company_name} {product_name}")

    # Handle case when entity detection fails
    if product_entity is None:
        # Include hash in summary if available
        hash_info = f"\n**Hash:** `{hash_value}`" if hash_value else ""
        
        result = {
            'score': 0,
            'summary': f"""
### Security Analysis for: {company_name} - {product_name}{hash_info}

#### ⚠️ Insufficient Information

No sufficient information was found for this company and product combination.

**Searched for:**
- Company: {company_name}
- Product: {product_name}

**Possible reasons:**
- The company or product name may be misspelled
- The product may not be publicly documented
- The company may be using a different name
- Limited online presence or documentation

**Recommendations:**
1. Verify the company and product names
2. Try alternative spellings or official names
3. Check if the product has been renamed or acquired
4. Provide additional context or identifiers

Please try again with corrected information or contact support for manual analysis.
"""
        }
        
        # Store result in cache
        _cache.set(cache_key, result)
        return result

    hash_info = f"\n**Hash:** `{hash_value}`" if hash_value else ""

    vulnerabilities = search_vulnerabilities_structured((product_entity.vendor or '') + ' ' + (product_entity.full_name or ''))
    vulnerability_section = create_vulnerability_section(vulnerabilities)
    
    alternatives = search_alternatives(product_entity.full_name)
    alternative_section = create_alternative_section(alternatives)
    
    # --- VirusTotal: fetch assessment and render section if hash provided ---
    vt_section = ""
    if hash_value and hash_value.strip():
        try:
            vt_assessment = get_parse_hashfile_assesment(hash_value.strip())
            vt_section = create_virustotal_section(vt_assessment)
        except Exception as e:
            vt_section = f"#### VirusTotal Lookup\n\n❌ **Error fetching VirusTotal data:** {str(e)}\n"
    else:
        # No hash provided
        vt_section = create_virustotal_section(None)
    
    result = {
        'score': 75,
        'summary': f"""
### Security Analysis for: [{product_entity.full_name}]({product_entity.website}) - {product_entity.vendor or ''}{hash_info}

#### Overview
{product_entity.description or "No description available."}

{vt_section}
#### Key Findings
- **Risk Level**: Medium
- **Vulnerabilities Detected**: 2
- **Compliance Status**: Partial

#### Recommendations
1. Update dependencies to latest versions
2. Review access controls
3. Implement additional encryption

#### Details
Replace this mock function with your actual security analysis implementation.

{vulnerability_section}

{alternative_section}
"""
    }
    
    # Store entire result dictionary in cache
    _cache.set(cache_key, result)
    
    return result


def create_vulnerability_section(vulnerabilities: VulnerabilitySearchResult) -> str:
    """
    Create a markdown section summarizing vulnerabilities.
    """
    if not vulnerabilities.results:
        return "No known vulnerabilities found."

    md = "#### Vulnerabilities Detected\n\n"
    # table with vulnerability details (cve_id, title, description, source_url, severity, published_date, status)
    md += "| CVE ID | Title | Description | Severity | Published Date | Status | More Info |\n"
    md += "|--------|-------|-------------|----------|----------------|--------|-----------|\n"

    for vuln in vulnerabilities.results:
        cve_id = vuln.cve_id or "N/A"
        title = vuln.title or "N/A"
        description = vuln.description or "N/A"
        severity = vuln.severity or "N/A"
        published_date = vuln.published_date or "N/A"
        status = color_vulnerability_status(vuln.status or "N/A")
        source_url = vuln.source_url or "#"
        md += f"| {cve_id} | {title} | {description} | {severity} | {published_date} | {status} | [Link]({source_url}) |\n"

    return md


def color_vulnerability_status(status: str) -> str:
    if any([s in status.lower() for s in ['solved', 'fixed', 'patched']]):
        return ":green[Solved]"
    elif status.lower() in ("n/a", "na", "") or 'unknown' in status.lower() or 'disputed' in status.lower():
        return ":gray[N/A]"
    else:
        return f':red[{status}]'
    
def create_alternative_section(alternatives: list[SoftwareEntity]) -> str:
    """
    Create a markdown section listing alternative software products.
    """
    if not alternatives:
        return "No alternatives found."

    md = "#### Alternative Software Products\n\n"
    for alt in alternatives:
        md += f"- [{alt.full_name}]({alt.website}) by {alt.vendor}\n  - Description: {alt.description or 'N/A'}\n\n"
    return md

def create_virustotal_section(assessment: Optional[FileAssessment]) -> str:
    """
    Return a compact Markdown section with only the most important VirusTotal fields that users care about:
    - SHA256 (identification)
    - Detection counts (malicious, suspicious)
    - Top vendor labels
    - Threat name & category
    - Signature status & signer
    
    If no assessment or hash provided, notify the user.
    """
    if not assessment:
        return "#### VirusTotal Lookup\n\n⚠️ **No hash value provided.** VirusTotal analysis requires a file hash (SHA256, SHA1, or MD5). Please provide a hash to analyze the file.\n"

    # Identification
    sha256 = getattr(assessment, "sha256", None)

    # Detection
    det = getattr(assessment, "detection", None)
    malicious = getattr(det, "malicious", 0) if det else 0
    suspicious = getattr(det, "suspicious", 0) if det else 0
    undetected = getattr(det, "undetected", 0) if det else 0
    harmless = getattr(det, "harmless", 0) if det else 0
    vendor_labels = getattr(det, "vendor_labels", []) if det else []

    # Classification & signature
    threat_name = getattr(assessment, "threat_name", None)
    threat_category = getattr(assessment, "threat_category", None)
    sig = getattr(assessment, "signature", None)
    signed = getattr(sig, "is_signed", False) if sig else False
    signer = getattr(sig, "signer", None) if sig else None

    # Check if any meaningful data was found
    has_detections = malicious or suspicious or undetected or harmless
    has_threat_info = threat_name or threat_category
    has_signature_info = signed or signer
    has_vendor_labels = len(vendor_labels) > 0

    if not (has_detections or has_threat_info or has_signature_info or has_vendor_labels):
        return "#### VirusTotal Lookup\n\n⚠️ **No results found in VirusTotal.** The provided hash does not exist in VirusTotal's database. This may indicate:\n- The file is not widely distributed\n- The file is new and not yet scanned\n- The hash may be incorrect\n\nPlease verify the hash and try again.\n"

    md = "#### VirusTotal Lookup\n\n"

    # Identification
    if sha256:
        md += f"- **SHA256:** `{sha256}`\n\n"

    # Detection results
    md += f"- **Detections:** malicious={malicious}, suspicious={suspicious}, undetected={undetected}, harmless={harmless}\n"
    if vendor_labels:
        md += f"- **Top vendor labels:** {', '.join(vendor_labels[:5])}\n\n"

    # Threat classification
    md += f"- **Threat:** {threat_name or 'N/A'} ({threat_category or 'N/A'})\n"

    # Signature trust
    md += f"- **Signed:** {'Yes' if signed else 'No'}"
    if signer:
        md += f" by {signer}"
    md += "\n"

    return md
