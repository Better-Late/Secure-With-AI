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
    Compute a CVE safety score in the range 0–30.

    Logic:
      - Each CVE contributes risk based on severity (CVSS preferred).
      - Unpatched CVEs add extra penalty.
      - Score decreases with more and more severe CVEs.
      - No CVEs → full 30 points.
    """

    vulns = cves.results
    if not vulns or len(vulns) == 0:
        return 30.0  # No vulnerabilities → best score

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

    # Normalize: larger total risk → lower score
    # Assuming ~15 risk points is "moderate", scale accordingly.
    score = 30 - (total_risk * 1.5)

    # Clamp between 0 and 30
    return max(0.0, min(30.0, score)) * 100/30 # because ai,we revert back to the 100 scale



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





def combine_scores(reputationScore, cve_score):
  return 0.7*cve_score + 0.3*reputationScore #adjust weights


if __name__ == "__main__":
    cve_s = getCveScore(search_vulnerabilities_structured("OneStart"))
    print(cve_s)
    print(getPopularity("OneStart"))
    print(getReputationScore(getPopularity("OneStart"), cve_s))
