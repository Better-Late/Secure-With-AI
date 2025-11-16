import aiohttp
import pandas as pd
import asyncio
import re

# ---------------------------------------------------------------
# Module-level cache for GDPR data
# ---------------------------------------------------------------

_df_gdpr = None
_data_lock = asyncio.Lock()

URL = "https://www.enforcementtracker.com/data4sfk3j4hwe324kjhfdwe.json"

def strip_tags(text):
    return re.sub("<.*?>", "", str(text)).strip()

async def _load_gdpr_data():
    """Load GDPR data from remote URL and cache it."""
    global _df_gdpr

    async with _data_lock:
        if _df_gdpr is not None:
            return _df_gdpr

        print("Downloading dataset...")
        async with aiohttp.ClientSession() as session:
            async with session.get(URL) as response:
                json_data = await response.json()
                data = json_data["data"]

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

        df = pd.DataFrame(data, columns=columns)

        # ---------------------------------------------------------------
        # 3. CLEAN OPTIONAL (Remove HTML tags in Country + Source)
        # ---------------------------------------------------------------

        df["Country"] = df["Country (HTML)"].apply(strip_tags)
        df["Source"] = df["Source (HTML)"].apply(strip_tags)
        df["Direct URL"] = df["Direct URL (HTML)"].apply(strip_tags)

        _df_gdpr = df
        return _df_gdpr

# ---------------------------------------------------------------
# 4. EXACT DATATABLES COLUMN SEARCH ON Controller/Processor
# ---------------------------------------------------------------

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

async def gdpr_search(term):
    df_gdpr = await _load_gdpr_data()
    return df_gdpr[df_gdpr["Controller/Processor"].apply(
        lambda cell: datatables_smart_search(cell, term)
    )]



# ---------------------------------------------------------------
# 5. ASK USER FOR SEARCH TERM
# ---------------------------------------------------------------

if __name__ == "__main__":
  async def main():
      term = input("Search Controller/Processor for: ").strip()

      filtered = await gdpr_search(term)
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

  asyncio.run(main())



