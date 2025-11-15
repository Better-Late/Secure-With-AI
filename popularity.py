from pytrends.request import TrendReq

def getPopularity(keyword: str) -> float:
    pytrends = TrendReq(hl='en-US', tz=360)
    pytrends.build_payload([keyword], timeframe='today 12-m')

    data = pytrends.interest_over_time()

    # Remove incomplete last row
    data = data[data['isPartial'] == False]

    # Use last 2 full weeks/months
    last_values = data[keyword].iloc[-2:]

    return last_values.mean()


if __name__ == "__main__":
    print(getPopularity("Tesla"))


