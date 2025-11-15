
import requests
import pandas as pd

URL = "https://www.enforcementtracker.com/data4sfk3j4hwe324kjhfdwe.json"

# Load dataset
data = requests.get(URL).json()["data"]
df = pd.DataFrame(data)
# print(df)
# def datatables_column_search(df, column_name, search_value):
#     """
#     Exact DataTables-style column search:
#     - case-insensitive
#     - substring match
#     - empty search_value returns all rows
#     """
#     search_value = str(search_value).lower().strip()
#
#     if search_value == "":
#         return df  # same as DataTables: empty = no filter
#
#     return df[df[column_name].astype(str).str.lower().str.contains(search_value)]
#
#
# # Example searches
#
# filtered = datatables_column_search(df, "Controller/Processor", "digi")
# print(filtered)
#
#
