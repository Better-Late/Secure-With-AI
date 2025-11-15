# Security Score Calculation Implementation

## Overview
Added comprehensive security score calculation to the `security_analysis.py` module. The score is now dynamically calculated based on multiple security factors instead of using a hardcoded value.

## Changes Made

### 1. New Imports in `security_analysis.py`
```python
from popularity import getPopularity
from score import getCveScore, getReputationScore
from virustotal import get_parse_hashfile_assesment
```

### 2. New Function: `calculate_security_score()`

**Location:** `security_analysis.py`

**Purpose:** Calculates an overall security score (0-100) based on multiple factors.

**Parameters:**
- `product_name` (str): Name of the product for popularity lookup
- `vulnerabilities` (Optional[VulnerabilitySearchResult]): Vulnerability search results
- `hash_value` (Optional[str]): Hash for VirusTotal analysis

**Returns:** float (0-100)

**Scoring Logic:**

#### Without Hash Value:
1. **Popularity Score** (0-100): Retrieved using `getPopularity(product_name)` from Google Trends
2. **CVE Score** (0-100): Calculated using `getCveScore(vulnerabilities)` which analyzes:
   - Number of vulnerabilities
   - Severity levels (CVSS scores)
   - Patch status (solved/unsolved)
3. **Reputation Score**: Combined using `getReputationScore(popularity_score, cve_score)` with weights:
   - Popularity: 66.7% weight (10/15)
   - CVE: 33.3% weight (5/15)

#### With Hash Value:
When a hash is provided, VirusTotal analysis is included:

1. **VirusTotal Score** (0-100): Based on malware detection ratio
   - Calculated as: `(1 - malicious_ratio) * 100`
   - Higher detection = lower score
2. **Final Score**: 
   - 50% Reputation Score (popularity + CVE)
   - 50% VirusTotal Score

### 3. Integration into `analysis()` Function

The `analysis()` function now:
- Calls `calculate_security_score()` to compute the actual score
- For malware-flagged software: assigns a low score (10.0)
- For normal software: uses the calculated score based on all available data
- Returns the calculated score in the result dictionary

**Code changes:**
```python
# Calculate security score
calculated_score = calculate_security_score(
    product_name=product_entity.full_name,
    vulnerabilities=vulnerabilities,
    hash_value=hash_value
)

result = {
    'score': calculated_score,  # Changed from hardcoded 75
    'summary': f"""..."""
}
```

## Score Components Breakdown

### 1. Popularity Score (from `popularity.py`)
- Uses Google Trends data (last 12 months)
- Returns average interest over last 2 complete periods
- Range: 0-100

### 2. CVE Score (from `score.py`)
- Analyzes vulnerability list
- Factors in:
  - CVSS severity scores
  - Number of vulnerabilities
  - Patch status multipliers (1.5x for unsolved, 1.2x for unknown)
- Range: 0-100

### 3. Reputation Score (from `score.py`)
- Combines popularity and CVE scores
- Formula: `(popularity/100 * 10) + (cve_score/100 * 5)`
- Normalized to 0-100 scale
- Range: 0-100

### 4. VirusTotal Score (from `virustotal.py`)
- Detection ratio from multiple antivirus engines
- Formula: `(1 - (malicious + suspicious) / total) * 100`
- Only used when hash value is provided
- Range: 0-100

## Error Handling

The function includes robust error handling:
- Falls back to default values if popularity data unavailable (50.0)
- Handles missing vulnerability data (assumes 100.0)
- Catches VirusTotal API errors gracefully
- Returns reputation score if VirusTotal fails

## Example Usage

See `test_score_calculation.py` for examples:

```python
from security_analysis import calculate_security_score, analysis

# Simple score calculation
score = calculate_security_score(product_name="Visual Studio Code")

# With vulnerabilities
vulnerabilities = search_vulnerabilities_structured("OneStart")
score = calculate_security_score(
    product_name="OneStart",
    vulnerabilities=vulnerabilities
)

# With hash (includes VirusTotal)
score = calculate_security_score(
    product_name="MyApp",
    vulnerabilities=vulns,
    hash_value="37121618e735ebf628f7ba6ce29afc251ed88503"
)

# Full analysis (automatically calculates score)
result = analysis(
    company_name="Microsoft",
    product_name="Visual Studio Code"
)
print(f"Score: {result['score']}/100")
```

## Benefits

1. **Dynamic Scoring**: Score reflects actual security posture, not hardcoded values
2. **Multi-Factor Analysis**: Considers popularity, vulnerabilities, and malware detection
3. **Flexible**: Works with or without hash values
4. **Comprehensive**: Integrates all existing security analysis tools
5. **Cached**: Results are cached for performance

## Testing

Run the test script to verify functionality:
```bash
python test_score_calculation.py
```

This will demonstrate score calculation with different inputs and show how the analysis function integrates the scoring system.
