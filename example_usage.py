"""
Example usage of the licensing module to scrape licenses from both
open-source GitHub projects and closed-source websites.
"""

from licensing import get_license_opensource, get_license_closed_source

# Example 1: Get license from an open-source GitHub project
print("=" * 60)
print("Example 1: Open-source GitHub Project")
print("=" * 60)

github_repos = [
    # "https://github.com/pallets/flask",
    # "https://github.com/psf/requests",
    # "https://github.com/django/django",
]

for repo_url in github_repos:
    print(f"\nFetching license for: {repo_url}")
    license_info = get_license_opensource(repo_url)
    
    if license_info:
        print(f"  License Type: {license_info.ltype.name}")
        print(f"  License URL: {license_info.url}")
        print(f"  License Text (first 200 chars): {license_info.text[:200]}...")
    else:
        print("  License not found!")


# Example 2: Get license from a closed-source project website
print("\n" + "=" * 60)
print("Example 2: Closed-source Project Websites")
print("=" * 60)
print("Note: Analyzes legal pages for software terms, privacy, and pricing!\n")

websites = [
    # "https://www.jetbrains.com",
    # "https://www.adobe.com",
    "https://www.microsoft.com/en-us/microsoft-365/word",
]

for website_url in websites:
    print(f"\n{'=' * 60}")
    print(f"Analyzing: {website_url}")
    print(f"{'=' * 60}")
    
    license_info = get_license_closed_source(website_url)
    
    if license_info:
        print(f"\n✓ Analysis Complete!")
        print(f"  License Type: {license_info.ltype.name}")
        
        if license_info.terms_of_use:
            print(f"\n  Terms of Use:\n  {license_info.terms_of_use}")
        
        if license_info.privacy_assessment:
            print(f"\n  Privacy Assessment:\n  {license_info.privacy_assessment}")
        
        if license_info.is_free:
            print(f"\n  Pricing:\n  {license_info.is_free}")
    else:
        print("\n✗ Failed to analyze proprietary software.")
