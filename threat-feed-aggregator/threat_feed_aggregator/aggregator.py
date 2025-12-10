import os
import json
from datetime import datetime, timedelta, timezone
from .data_collector import fetch_data_from_url
from .data_processor import process_data
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "db.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")

def main(source_urls):
    """
    Main function to aggregate and process threat feeds.
    Returns a dictionary with statistics and the processed data.
    """
    start_time_total = time.time()
    
    # Read the configuration
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    lifetime_days = config.get("indicator_lifetime_days", 30)
    
    # Read the existing database
    with open(DB_FILE, "r") as f:
        db = json.load(f)
    indicators_db = db.get("indicators", {})

    # Filter out old indicators
    now = datetime.now(timezone.utc)
    for indicator, data in list(indicators_db.items()):
        last_seen = datetime.fromisoformat(data["last_seen"])
        if now - last_seen > timedelta(days=lifetime_days):
            del indicators_db[indicator]

    url_counts = {}
    for source in source_urls:
        url = source["url"]
        name = source["name"]
        data_format = source.get("format", "text")
        key_or_column = source.get("key_or_column")
        
        start_time_fetch = time.time()
        print(f"Fetching data from {url}...")
        raw_data = fetch_data_from_url(url)
        end_time_fetch = time.time()
        print(f"  Finished fetching in {end_time_fetch - start_time_fetch:.2f} seconds.")
        
        if raw_data:
            indicators_db, count = process_data(raw_data, indicators_db, data_format, key_or_column)
            url_counts[name] = {
                "count": count,
                "fetch_time": f"{end_time_fetch - start_time_fetch:.2f} seconds"
            }
        else:
            url_counts[name] = {
                "count": 0,
                "fetch_time": "N/A"
            }

    # Write the updated database
    with open(DB_FILE, "w") as f:
        json.dump({"indicators": indicators_db}, f, indent=4)

    end_time_total = time.time()
    print(f"Total aggregation process finished in {end_time_total - start_time_total:.2f} seconds.")
    return {"url_counts": url_counts, "processed_data": list(indicators_db.keys())}
