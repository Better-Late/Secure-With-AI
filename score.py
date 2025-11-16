from typing import Dict, List, Optional
import re
from search_vulnerabilities import VulnerabilitySearchResult, search_vulnerabilities_structured
from popularity import getPopularity
 


def extract_cvss(severity_str: Optional[str | float]) -> Optional[float]:
    if severity_str is None:
        return None

    # If severity is already numeric
    if isinstance(severity_str, (int, float)):
        if 0 <= float(severity_str) <= 10:
            return float(severity_str)
        return None

    # Otherwise try to parse string
    if not isinstance(severity_str, str):
        return None

    match = re.search(r"(\d+\.\d+|\d+)", severity_str)
    if match:
        try:
            score = float(match.group(1))
            if 0 <= score <= 10:
                return score
        except ValueError:
            pass

    sev = severity_str.lower()
    if "critical" in sev:
        return 9.0
    if "high" in sev:
        return 7.0
    if "medium" in sev:
        return 5.0
    if "low" in sev:
        return 2.0

    return 5.0


def getCveScore(cves: VulnerabilitySearchResult) -> float:
    """
    Compute a CVE safety score in the range 0–100.
    Higher = safer.

    Logic:
      - Each CVE contributes risk based on severity (CVSS preferred).
      - Unpatched CVEs add extra penalty.
      - Score decreases with more and more severe CVEs.
      - No CVEs → 100 (best score).
    """

    vulns = cves.results
    if not vulns or len(vulns) == 0:
        return 100.0  # No vulnerabilities → best score

    total_risk = 0.0

    for v in vulns:
        cvss = extract_cvss(v.severity)

        if cvss is None:
            cvss = 5.0  # default medium if completely unknown

        # Base risk weighted by severity
        risk = cvss

        # Unpatched or unknown status increases risk
        if v.status == "Not Solved":
            risk *= 1.5
        elif v.status == "Unknown Status":
            risk *= 1.2

        total_risk += risk

    # Map unbounded total_risk -> [0, 100] safety score using a saturating function
    # K controls how quickly the score drops. Tune as needed.
    K = 40.0  # "moderate" total risk level -> about 50 safety
    if total_risk <= 0:
        return 100.0

    risk_factor = total_risk / (total_risk + K)  # in (0,1)
    safety_score = (1.0 - risk_factor) * 100.0  # 0–100, higher is safer

    # Clamp & round for safety
    safety_score = max(0.0, min(100.0, safety_score))
    return safety_score



def getReputationScore(
    popularity_score: float,  # 0–100
    cve_score: float          # 0–100
) -> float:
    """
    Combine popularity (0–100) and cve_score (0–100)
    into a single reputation score (0–100).
    """

    # Weight popularity = 10 units, CVE = 5 units
    pop_component = (popularity_score / 100.0) * 10.0   # 0–10
    cve_component = (cve_score / 100.0) * 5.0           # 0–5

    # Raw score is 0–15
    combined = pop_component + cve_component

    # Convert 0–15 → 0–100
    final_score = (combined / 15.0) * 100.0
    return round(final_score, 2)






def combine_scores(reputationScore, cve_score, gdpr_fine=False): # add other scores
  score = 0.7*cve_score + 0.3*reputationScore #adjust weights 
  return score if not gdpr_fine else score - 10


if __name__ == "__main__":
    cve_s = getCveScore(search_vulnerabilities_structured("OneStart"))
    print(cve_s)
    print(getPopularity("OneStart"))
    print(getReputationScore(getPopularity("OneStart"), cve_s))
