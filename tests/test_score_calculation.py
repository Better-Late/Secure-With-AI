"""
Test script to demonstrate the security score calculation functionality.
"""

from security_analysis import calculate_security_score
from search_vulnerabilities import search_vulnerabilities_structured

# Test 1: Calculate score with just product name (no vulnerabilities or hash)
print("=" * 60)
print("Test 1: Score calculation with product name only")
print("=" * 60)

product = "Visual Studio Code"
score = calculate_security_score(product_name=product)
print(f"Product: {product}")
print(f"Calculated Score: {score}/100")

# Test 2: Calculate score with vulnerabilities
print("\n" + "=" * 60)
print("Test 2: Score calculation with vulnerability search")
print("=" * 60)

product = "OneStart"
vulnerabilities = search_vulnerabilities_structured(product)
if vulnerabilities:
    print(f"Product: {product}")
    print(f"Vulnerabilities found: {len(vulnerabilities.results)}")
    score = calculate_security_score(
        product_name=product,
        vulnerabilities=vulnerabilities
    )
    print(f"Calculated Score: {score}/100")
else:
    print(f"No vulnerabilities found for {product}")

# Test 3: Full analysis with score
print("\n" + "=" * 60)
print("Test 3: Full security analysis with calculated score")
print("=" * 60)

from security_analysis import analysis

result = analysis(company_name="Microsoft", product_name="Visual Studio Code")
print(f"Security Score: {result['score']}/100")
print(f"\nSummary Preview (first 500 chars):")
print(result['summary'][:500] + "...")

print("\n" + "=" * 60)
print("Tests completed!")
print("=" * 60)
