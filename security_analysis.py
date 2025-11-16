from typing import Dict, Optional
from diskcache import Cache
from entity_resolution import SoftwareEntity, detect_entity
from search_vulnerabilities import search_vulnerabilities_structured, VulnerabilitySearchResult
from alternatives import search_alternatives
from licensing import License, LicenseType, get_license_opensource, get_license_closed_source
from popularity import getPopularity
from score import getCveScore, getReputationScore
from virustotal import get_parse_hashfile_assesment
from virustotal import FileAssessment, get_parse_hashfile_assesment
from gdpr import gdpr_search
from html import unescape
import re
import pandas as pd
import asyncio

import os
from dotenv import load_dotenv
load_dotenv()

class AnalysisResult(Dict[str, any]):
    score: int


async def calculate_security_score(
    product_name: str,
    vulnerabilities: Optional[VulnerabilitySearchResult] = None,
    hash_value: Optional[str] = None,
    isGdprFined = False,
    hasBreaches = False
    ):
    """
    Calculate overall security score based on:
    - Popularity score (0-100)
    - CVE score from vulnerabilities (0-100)
    - VirusTotal assessment (if hash provided)

    Args:
        product_name: Name of the product for popularity lookup
        vulnerabilities: Vulnerability search results
        hash_value: Optional hash for VirusTotal analysis

    Returns:
        Overall security score (0-100)
    """

    calculated_score_breakdown = {}


    gdpr_penalty = 10 if isGdprFined else 0
    calculated_score_breakdown["GDPR Penalty"] = gdpr_penalty
    
    breach_penalty = 10 if hasBreaches else 0
    calculated_score_breakdown["Breaches Penalty"] = breach_penalty
    
    # Get popularity score
    try:
        popularity_score = await getPopularity(product_name)
    except Exception as e:
        print(f"Warning: Could not get popularity score: {e}")
        popularity_score = 50.0  # Default to medium popularity

    # Get CVE score from vulnerabilities
    if vulnerabilities:
        cve_score = getCveScore(vulnerabilities)
    else:
        cve_score = 100.0  # No vulnerabilities = perfect score

    calculated_score_breakdown["CVE Score"] = cve_score

    print(f"Popularity Score: {popularity_score}, CVE Score: {cve_score}")

    # Calculate reputation score (combines popularity and CVE)
    reputation_score = getReputationScore(popularity_score, cve_score)
    calculated_score_breakdown['Reputation Score'] = reputation_score

    # If hash is provided, factor in VirusTotal results
    if hash_value:
        try:
            vt_assessment = await get_parse_hashfile_assesment(hash_value)

            # Calculate VirusTotal score based on detection ratio
            total_scans = (vt_assessment.detection.malicious +
                          vt_assessment.detection.suspicious +
                          vt_assessment.detection.undetected +
                          vt_assessment.detection.harmless)

            if total_scans > 0:
                malicious_ratio = (vt_assessment.detection.malicious +
                                  vt_assessment.detection.suspicious) / total_scans
                vt_score = (1 - malicious_ratio) * 100  # Invert so higher is better
            else:
                vt_score = 50.0  # Unknown

            calculated_score_breakdown["VT Score"] = vt_score
            # Combine scores: 50% reputation, 50% VirusTotal
            final_score = (reputation_score * 0.5) + (vt_score * 0.5)
        except Exception as e:
            print(f"Warning: Could not get VirusTotal assessment: {e}")
            final_score = reputation_score
    else:
        # No hash provided, use reputation score only
        final_score = reputation_score

    return round(max(0.0, min(100.0, final_score)), 2) - gdpr_penalty - breach_penalty, calculated_score_breakdown


# Global cache instance using diskcache
if os.environ.get('LOCAL', 'false') == 'true':
     _cache = Cache('./cache_dir')
else:
    _cache = Cache('/mnt/cache/security_analysis/') 


async def analysis(company_name: str, product_name: str, hash_value: Optional[str] = None) -> Dict[str, any]:
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

    print("detecting entity...")
    # Perform actual analysis
    product_entity = await detect_entity(f"{company_name} {product_name}")


    print("detected entiy:", product_entity)
    # Handle case when entity detection fails
    if product_entity is None:
        result = render_analysis_not_found(company_name, product_name, hash_value)
        _cache.set(cache_key, result)
        return result

    hash_info = f"\n**Hash:** `{hash_value}`" if hash_value else ""

    vt_section = ""
    license_info = None
    if product_entity.malware_suspicion and product_entity.malware_suspicion.flagged:
        malware_warning = f"\n\n**⚠️ Malware Suspicion:** This software has been flagged as potentially malicious for the following reasons:\n"
        for reason in product_entity.malware_suspicion.reasons:
            malware_warning += f"- {reason}\n"
        vulnerability_section = ""
        alternative_section = ""
        license_section = ""
        vulnerabilities = None
        # Low score for flagged malware
        calculated_score = 0.0
        calculated_score_breakdown = {}
        # Skip GDPR and breach checks for malware
        gdpr_section = ""
        breach_section = ""
        isFined = False
    else:
        malware_warning = ""

        # Prepare all async tasks
        tasks = []
        task_names = []

        # GDPR and Data Breach checks
        tasks.append(create_gdpr_fines(product_entity.vendor))
        task_names.append('gdpr')
        tasks.append(create_data_breach_section(product_entity.vendor))
        task_names.append('breach')

        # VirusTotal task (if hash provided)
        if hash_value and hash_value.strip():
            tasks.append(get_parse_hashfile_assesment(hash_value.strip()))
            task_names.append('vt')

        # Vulnerability search task
        print("searching vulnerabilities...")
        vuln_search_key = (product_entity.vendor or '') + ' ' + (product_entity.full_name or '')
        tasks.append(search_vulnerabilities_structured(vuln_search_key))
        task_names.append('vulnerabilities')

        # Alternatives search task
        tasks.append(search_alternatives(product_entity.full_name))
        task_names.append('alternatives')

        # License tasks - fetch BOTH GitHub and website licenses in parallel for open-source
        if is_open_source(product_entity):
            # For open-source, fetch both GitHub license and website pricing/terms in parallel
            tasks.append(get_license_opensource(product_entity.github_link))
            task_names.append('license_github')
            if product_entity.website:
                tasks.append(get_license_closed_source(product_entity.website, product_entity.full_name))
                task_names.append('license_website')
        else:
            # For closed-source, just fetch website license
            if product_entity.website:
                tasks.append(get_license_closed_source(product_entity.website, product_entity.full_name))
                task_names.append('license_closed')

        # Execute all tasks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        result_dict = dict(zip(task_names, results))

        # Process GDPR result
        isFined = False
        if 'gdpr' in result_dict:
            gdpr_result = result_dict['gdpr']
            if isinstance(gdpr_result, Exception):
                print(f"Warning: Error getting GDPR data: {gdpr_result}")
                gdpr_section = "#### GDPR Fines\n\nCould not retrieve GDPR data."
                isFined = False
            else:
                gdpr_section, isFined = gdpr_result

        # Process breach result
        isBreach=False
        if 'breach' in result_dict:
            breach_result = result_dict['breach']
            if isinstance(breach_result, Exception):
                print(f"Warning: Error getting breach data: {breach_result}")
                breach_section = "#### Data Breaches\n\nCould not retrieve breach data."
            else:
                breach_section, isBreach = breach_result

        # Process VirusTotal result
        if 'vt' in result_dict:
            if isinstance(result_dict['vt'], Exception):
                vt_section = f"#### VirusTotal Lookup\n\n❌ **Error fetching VirusTotal data:** {str(result_dict['vt'])}\n"
            else:
                vt_section = create_virustotal_section(result_dict['vt'])
        else:
            # No hash provided
            vt_section = create_virustotal_section(None)

        # Process vulnerabilities result
        vulnerabilities = result_dict.get('vulnerabilities')
        if isinstance(vulnerabilities, Exception):
            print(f"Warning: Error searching vulnerabilities: {vulnerabilities}")
            vulnerabilities = None
        print("found vulnerabilities:", vulnerabilities)
        vulnerability_section = create_vulnerability_section(vulnerabilities)

        # Process alternatives result
        alternatives = result_dict.get('alternatives')
        if isinstance(alternatives, Exception):
            print(f"Warning: Error searching alternatives: {alternatives}")
            alternatives = []
        alternative_section = create_alternative_section(alternatives)

        # Process license result - merge GitHub and website licenses if both were fetched
        license_info = None
        if 'license_github' in result_dict:
            github_license = result_dict.get('license_github')
            if isinstance(github_license, Exception):
                print(f"Warning: Error getting GitHub license: {github_license}")
                github_license = None

            if 'license_website' in result_dict:
                # Both GitHub and website licenses were fetched in parallel
                website_license = result_dict.get('license_website')
                if isinstance(website_license, Exception):
                    print(f"Warning: Error getting website license: {website_license}")
                    website_license = None

                if github_license is not None:
                    # Use GitHub license as base, merge pricing info from website
                    license_info = github_license
                    if website_license and website_license.is_free:
                        license_info.is_free = website_license.is_free
                elif website_license is not None:
                    # GitHub license failed, use website license
                    license_info = website_license
            else:
                # Only GitHub license was requested
                license_info = github_license

        elif 'license_closed' in result_dict:
            # Closed-source software
            license_info = result_dict.get('license_closed')
            if isinstance(license_info, Exception):
                print(f"Warning: Error getting closed source license: {license_info}")
                license_info = None

        license_section = create_license_section(license_info)

        # Calculate security score
        calculated_score, calculated_score_breakdown = await calculate_security_score(
            product_name=product_entity.full_name,
            vulnerabilities=vulnerabilities,
            hash_value=hash_value,
            isGdprFined=isFined,
            hasBreaches=isBreach,
        )
    




    # Add GitHub link if available
    github_link = f"[GitHub]({product_entity.github_link})" if product_entity.github_link else ""

    # Generate trust summary based on score and license
    trust_summary = generate_trust_summary(calculated_score, license_info)

    result = {
        'score_breakdown': calculated_score_breakdown,
        'score': calculated_score,
        'license': license_info,
        'trust_summary': trust_summary,
        'summary': f"""
### Security Analysis for: [{product_entity.full_name}]({product_entity.website}) - {product_entity.vendor or ''}  {github_link}{hash_info}

#### Overview
{product_entity.description or "No description available."}

**Type:** {product_entity.software_type or "N/A"}

{vt_section}
{malware_warning}

{license_section}

{vulnerability_section}

{gdpr_section}

{breach_section}

{alternative_section}
"""
    }
    
    _cache.set(cache_key, result)
    
    return result


def create_vulnerability_section(vulnerabilities: Optional[VulnerabilitySearchResult]) -> str:
    """
    Create a markdown section summarizing vulnerabilities.
    """
    if not vulnerabilities or not vulnerabilities.results:
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


def color_detection(label: str, count: int, color: str) -> str:
    try:
        # Uses Streamlit markdown color token convention like :red[...]
        if count > 0:
            return f":{color}[{label} = {count}]"
        else:
            return f"{label} = {count}"
    except Exception:
        return f"{label} = {count}"


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

    malicious_str = color_detection("malicious", malicious, "red")
    suspicious_str = color_detection("suspicious", suspicious, "orange")
    
    # Detection results
    md += f"- **Detections:** {malicious_str}, {suspicious_str}, undetected = {undetected}, harmless = {harmless}\n"
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

def render_analysis_not_found(company_name: str, product_name: str, hash_value: Optional[str] = None) -> Dict[str, any]:
    # Include hash in summary if available
    hash_info = f"\n**Hash:** `{hash_value}`" if hash_value else ""
    
    trust_summary = generate_trust_summary(0, None)
    
    result = {
        'score': 0,
        'license': None,
        'trust_summary': trust_summary,
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
        
    return result




async def create_gdpr_fines(company_name: str):
    """
    Create a markdown section summarizing GDPR fines against a company.
    Uses the results returned by gdpr_search().
    """


    def clean_html(text: str) -> str:
        """Remove embedded HTML tags and return readable text."""
        if not isinstance(text, str):
            return str(text)
        text = unescape(text)
        return re.sub(r'<[^>]+>', '', text).strip()

    try:
        df = await gdpr_search(company_name)
    except Exception as e:
        return f"#### GDPR Fines\n\nCould not retrieve GDPR data: {e}", False

    if df is None or df.empty:
        return "#### GDPR Fines\n\nNo GDPR enforcement actions found for this company.", False

    required_columns = [
        "ETid", "Country", "Date of Decision", "Fine [€]",
        "Controller/Processor", "Quoted Art.", "Type", "Direct URL"
    ]
    for col in required_columns:
        if col not in df.columns:
            return f"#### GDPR Fines\n\nGDPR data missing required column: `{col}`.", False

    md = "#### GDPR Enforcement Actions\n\n"
    md += f"Found **{len(df)}** GDPR enforcement case(s) matching **{company_name}**.\n\n"

    # Updated table header including Controller/Processor (company)
    md += (
        "| Date | Fine (€) | Company | Country | Type | Article | Case Link |\n"
        "|------|----------|---------|---------|------|---------|-----------|\n"
    )

    for _, row in df.iterrows():
        date = clean_html(row["Date of Decision"])
        fine = clean_html(row["Fine [€]"])
        controller = clean_html(row["Controller/Processor"])   # ← new column included
        country = clean_html(row["Country"])
        ptype = clean_html(row["Type"])
        article = clean_html(row["Quoted Art."])
        url = clean_html(row["Direct URL"])

        # extract URLs
        url_matches = re.findall(r"(https?://[^\s\"']+)", url)
        url_final = url_matches[0] if url_matches else url

        md += (
            f"| {date} | {fine} | {controller} | {country} | "
            f"{ptype} | {article} | [Link]({url_final}) |\n"
        )

    return md, True


async def create_data_breach_section(company_name: str):
    """
    Create a markdown section summarizing known data breaches for a company.
    Searches the breaches.csv file for matching entities.

    Args:
        company_name: Name of the company/brand to search for

    Returns:
        tuple: (markdown_string, has_breaches_bool)
    """
    if company_name is None or company_name.strip() == "":
        return "#### Data Breaches\n\nNo company name provided for breach search.", False
    # Run file I/O in executor to avoid blocking
    loop = asyncio.get_event_loop()

    def _read_and_filter_breaches():
        try:
            # Read the CSV file
            df = pd.read_csv('breaches.csv')
        except FileNotFoundError:
            return "#### Data Breaches\n\nCould not find breaches.csv file.", False
        except Exception as e:
            return f"#### Data Breaches\n\nError reading breach data: {e}", False

        if df.empty:
            return "#### Data Breaches\n\nNo breach data available.", False

        # Search for company name in the breach database
        # Match against the 'name' column (domain names)
        company_lower = company_name.lower()

        # Filter rows where the company name appears in the domain name
        matches = df[df['name'].str.lower().str.contains(company_lower, na=False, regex=False)]

        if matches.empty:
            return f"#### Data Breaches\n\nNo known data breaches found for **{company_name}**.", False

        # Build markdown table
        md = "#### Data Breaches\n\n"
        md += f"Found **{len(matches)}** known data breach(es) associated with **{company_name}**.\n\n"
        md += "| Entity Name | Date | Breach Link |\n"
        md += "|-------------|------|-------------|\n"

        for _, row in matches.iterrows():
            entity_name = row['name']
            year = row['year']
            month = row['month'].capitalize() if pd.notna(row['month']) else 'Unknown'
            date_str = f"{month} {year}"
            url = row['url']

            md += f"| {entity_name} | {date_str} | [Link]({url}) |\n"

        return md, True

    return await loop.run_in_executor(None, _read_and_filter_breaches)




def is_open_source(product_entity: SoftwareEntity) -> bool:
    """
    Determine if the software is open-source based on available information.
    This is a placeholder function and should be replaced with actual logic.
    """
    return bool(product_entity.github_link)


def create_license_section(license: Optional[License]) -> str:
    """
    Create a markdown section summarizing license information.
    Placeholder function - implement actual logic based on LicenseInfo structure.
    """
    if not license:
        return "No license information found."

    md = "#### License Information\n\n"
    md += f"- **License Type:** {license.ltype}\n"
    md += f"- **License URL:** {license.url}\n"
    # Escape dollar signs to prevent Streamlit from interpreting them as LaTeX
    is_free_text = (license.is_free or 'N/A').replace('$', r'\$')
    md += f"- **Is Free Software:** {is_free_text}\n"

    # Add sources section if available
    if license.legal_sources or license.pricing_sources:
        md += "\n<details>\n<summary><b>📄 View Sources</b></summary>\n\n\n"

        if license.legal_sources:
            md += "**Legal/Terms Sources:**\n"
            for source in license.legal_sources:
                md += f"- [{source}]({source})\n"
            md += "\n"

        if license.pricing_sources:
            md += "**Pricing Sources:**\n"
            for source in license.pricing_sources:
                md += f"- [{source}]({source})\n"

        md += "</details>\n"

    return md


def generate_trust_summary(score: float, license_info: Optional[License]) -> str:
    """
    Generate a trust summary based on the security score and license information.
    
    Args:
        score: Trust score (0-100)
        license_info: License information object
        
    Returns:
        A summary string indicating the trust level
    """
    if score >= 0 and score <= 30:
        return "Likely malware - don't download!"
    elif score < 70:
        return "Additional security check needed"
    elif license_info and license_info.ltype == LicenseType.PROPRIETARY:
        return "Additional compliance check needed"
    else:
        return "Likely safe."
