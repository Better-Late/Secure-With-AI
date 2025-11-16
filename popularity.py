from pytrends.request import TrendReq
import asyncio

async def getPopularity(keyword: str) -> float:
    # Run pytrends in executor since it doesn't have native async support
    loop = asyncio.get_event_loop()

    def _get_popularity():
        pytrends = TrendReq(hl='en-US', tz=360)
        pytrends.build_payload([keyword], timeframe='today 12-m')

        data = pytrends.interest_over_time()

        # Remove incomplete last row
        data = data[data['isPartial'] == False]

        # Use last 2 full weeks/months
        last_values = data[keyword] * 1.5

        return min(last_values.mean(), 100)

    return await loop.run_in_executor(None, _get_popularity)


if __name__ == "__main__":
    print(asyncio.run(getPopularity("Tesla")))
