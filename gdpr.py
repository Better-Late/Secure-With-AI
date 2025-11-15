import requests
import pandas as pd

# ---------------------------------------------------------------
# 1. DOWNLOAD THE FULL DATASET (same JSON loaded by the website)
# ---------------------------------------------------------------

URL = "https://www.enforcementtracker.com/data4sfk3j4hwe324kjhfdwe.json"

print("Downloading dataset...")
response = requests.get(URL)
data = response.json()["data"]

print(f"Loaded {len(data)} entries.")

# ---------------------------------------------------------------
# 2. ASSIGN COLUMN NAMES
# ---------------------------------------------------------------

columns = [
    "dtr_control",            # ignore
    "ETid",
    "Country (HTML)",
    "Authority",
    "Date of Decision",
    "Fine [€]",
    "Controller/Processor",
    "Sector",
    "Quoted Art.",
    "Type",
    "Summary",
    "Source (HTML)",
    "Direct URL (HTML)"
]

df_gdpr = pd.DataFrame(data, columns=columns)

# ---------------------------------------------------------------
# 3. CLEAN OPTIONAL (Remove HTML tags in Country + Source)
# ---------------------------------------------------------------

import re

def strip_tags(text):
    return re.sub("<.*?>", "", str(text)).strip()

df_gdpr["Country"] = df_gdpr["Country (HTML)"].apply(strip_tags)
df_gdpr["Source"] = df_gdpr["Source (HTML)"].apply(strip_tags)
df_gdpr["Direct URL"] = df_gdpr["Direct URL (HTML)"].apply(strip_tags)

# ---------------------------------------------------------------
# 4. EXACT DATATABLES COLUMN SEARCH ON Controller/Processor
# ---------------------------------------------------------------

import re

def datatables_smart_search(cell_value, search_term):
    """
    Exact DataTables smart-matching behavior.
    """
    text = str(cell_value).lower()
    s = str(search_term).lower().strip()

    if s == "":
        return True

    tokens = re.split(r"\s+", s)

    for token in tokens:
        if token and token not in text:
            return False
    return True

def gdpr_search(term):
    return df_gdpr[df_gdpr["Controller/Processor"].apply(
        lambda cell: datatables_smart_search(cell, term)
    )]



# ---------------------------------------------------------------
# 5. ASK USER FOR SEARCH TERM
# ---------------------------------------------------------------

if __name__ == "__main__":
  term = input("Search Controller/Processor for: ").strip()

  filtered = gdpr_search(term)
  print(f"\nFound {len(filtered)} matching rows.\n")

# SHOW SELECTED COLUMNS FOR READABILITY
  print(filtered[[
      "ETid",
      "Country",
      "Date of Decision",
      "Fine [€]",
      "Controller/Processor",
      "Quoted Art.",
      "Type",
      "Direct URL"
  ]].head(20).to_string(index=False))



