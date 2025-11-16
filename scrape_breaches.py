#!/usr/bin/env python3
"""
Script to scrape data breaches from breachsense.com
Iterates through years 2020-2025 and all months
"""

import requests
from bs4 import BeautifulSoup
from lxml import html
import json
import time
from typing import List, Dict
from datetime import datetime


def get_month_name(month_num: int) -> str:
    """Convert month number to lowercase month name."""
    months = [
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december"
    ]
    return months[month_num - 1]


def scrape_breaches_for_month(year: int, month: str) -> List[Dict[str, str]]:
    """
    Scrape breach data for a specific year and month.

    Args:
        year: Year (e.g., 2020)
        month: Month name in lowercase (e.g., "january")

    Returns:
        List of dictionaries containing breach information
    """
    url = f"https://www.breachsense.com/breaches/{year}/{month}"
    print(f"Scraping: {url}")

    breaches = []

    try:
        # Add headers to mimic a browser request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        # Parse with lxml for XPath support
        tree = html.fromstring(response.content)

        # Try the XPath pattern provided
        # /html/body/main/section/div/div/div/div/div[2]/article/div/h3/a
        breach_links = tree.xpath('//article/div/h3/a')

        if not breach_links:
            # Try alternative selectors
            breach_links = tree.xpath('//h3/a')

        for link in breach_links:
            breach_name = link.text_content().strip()
            breach_url = link.get('href', '')

            # Make URL absolute if it's relative
            if breach_url and not breach_url.startswith('http'):
                breach_url = f"https://www.breachsense.com{breach_url}"

            if breach_name:
                breaches.append({
                    'name': breach_name,
                    'url': breach_url,
                    'year': year,
                    'month': month,
                    'scraped_at': datetime.now().isoformat()
                })

        print(f"  Found {len(breaches)} breaches")

    except requests.exceptions.RequestException as e:
        print(f"  Error fetching {url}: {e}")
    except Exception as e:
        print(f"  Error parsing {url}: {e}")

    return breaches


def scrape_all_breaches(start_year: int = 2020, end_year: int = 2025) -> List[Dict[str, str]]:
    """
    Scrape all breaches from start_year to end_year.

    Args:
        start_year: Starting year (inclusive)
        end_year: Ending year (inclusive)

    Returns:
        List of all breaches found
    """
    all_breaches = []

    for year in range(start_year, end_year + 1):
        print(f"\n=== Year {year} ===")

        for month_num in range(1, 13):
            month_name = get_month_name(month_num)
            breaches = scrape_breaches_for_month(year, month_name)
            all_breaches.extend(breaches)

            # Be polite and don't hammer the server
            time.sleep(1)

    return all_breaches


def save_results(breaches: List[Dict[str, str]], output_file: str = "breaches.json"):
    """Save breaches to a JSON file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(breaches, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Saved {len(breaches)} breaches to {output_file}")


def save_results_csv(breaches: List[Dict[str, str]], output_file: str = "breaches.csv"):
    """Save breaches to a CSV file."""
    import csv

    if not breaches:
        print("No breaches to save")
        return

    keys = breaches[0].keys()

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(breaches)

    print(f"✓ Saved {len(breaches)} breaches to {output_file}")


def main():
    """Main function to run the scraper."""
    print("Starting breach scraper...")
    print("Scraping years 2020-2025, all months\n")

    # Scrape all breaches
    breaches = scrape_all_breaches(start_year=2020, end_year=2025)

    # Print summary
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Total breaches found: {len(breaches)}")

    if breaches:
        # Show first few examples
        print(f"\nFirst 5 breaches:")
        for breach in breaches[:5]:
            print(f"  - {breach['name']} ({breach['year']}/{breach['month']})")

        # Save results
        save_results(breaches, "breaches.json")
        save_results_csv(breaches, "breaches.csv")
    else:
        print("\n⚠️  No breaches found. The website structure may have changed.")
        print("    Try inspecting the page manually to verify the HTML structure.")


if __name__ == "__main__":
    main()
