from typing import Dict, Optional
from diskcache import Cache
from entity_resolution import SoftwareEntity, detect_entity
from search_vulnerabilities import search_vulnerabilities_structured, VulnerabilitySearchResult
from alternatives import search_alternatives

class AnalysisResult(Dict[str, any]):
    score: int


# Global cache instance using diskcache
_cache = Cache('./cache_dir')


def analysis(company_name: str, product_name: str, hash_value: Optional[str] = None) -> Dict[str, any]:
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
        
    result = {
        'score': 75,
        'summary': f"""
### Security Analysis for: [{product_entity.full_name}]({product_entity.website}) - {product_entity.vendor or ''}{hash_info}

#### Overview
{product_entity.description or "No description available."}

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
