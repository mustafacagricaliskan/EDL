import os
import json
from datetime import datetime, timedelta, timezone
from .data_collector import fetch_data_from_url
from .data_processor import process_data
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "data", "db.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")
STATS_FILE = os.path.join(BASE_DIR, "stats.json")

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"source_urls": []}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, "r") as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                for key, value in stats.items():
                    if not isinstance(value, dict):
                        stats[key] = {}
                return stats
        except json.JSONDecodeError:
            pass
    return {}

def write_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)

def read_db():
    if not os.path.exists(DB_FILE):
        return {"indicators": {}}
    with open(DB_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {"indicators": {}}

def _load_db_and_filter_old_indicators(lifetime_days):
    """Loads the indicators DB and filters out old indicators."""
    db_data = read_db() # Use the read_db helper
    indicators_db = db_data.get("indicators", {})

    now = datetime.now(timezone.utc)
    initial_filtered_count = len(indicators_db)
    for indicator, data in list(indicators_db.items()):
        last_seen = datetime.fromisoformat(data["last_seen"])
        if now - last_seen > timedelta(days=lifetime_days):
            del indicators_db[indicator]
    return indicators_db

def aggregate_single_source(source_config):
    """
    Fetches and processes data for a single threat feed source.
    Updates the global indicators database and stats.
    """
    name = source_config["name"]
    url = source_config["url"]
    data_format = source_config.get("format", "text")
    key_or_column = source_config.get("key_or_column")

    config = read_config()
    lifetime_days = config.get("indicator_lifetime_days", 30)

    indicators_db = _load_db_and_filter_old_indicators(lifetime_days)
    current_db_size = len(indicators_db)

    start_time_fetch = time.time()
    raw_data = fetch_data_from_url(url)
    end_time_fetch = time.time()
    fetch_duration = f"{end_time_fetch - start_time_fetch:.2f} seconds"

    current_stats = read_stats()
    
    if raw_data:
        processed_db_before = len(indicators_db)
        indicators_db, count = process_data(raw_data, indicators_db, data_format, key_or_column)
        processed_db_after = len(indicators_db)
        current_stats[name] = {
            "count": count,
            "fetch_time": fetch_duration,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    else:
        current_stats[name] = {
            "count": 0,
            "fetch_time": fetch_duration,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

    with open(DB_FILE, "w") as f:
        json.dump({"indicators": indicators_db}, f, indent=4)

    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)

    return {
        "name": name,
        "count": current_stats[name]["count"],
        "fetch_time": current_stats[name]["fetch_time"]
    }

def main(source_urls):
    """
    Aggregates and processes threat feeds from a list of source URLs.
    This function is primarily for initial full runs or when schedules are not used.
    """
    all_processed_data = []
    all_url_counts = {}

    config = read_config()
    lifetime_days = config.get("indicator_lifetime_days", 30)

    for source in source_urls:
        single_source_result = aggregate_single_source(source)
        all_url_counts[single_source_result["name"]] = {
            "count": single_source_result["count"],
            "fetch_time": single_source_result["fetch_time"]
        }
        db_data = read_db()
        all_processed_data.extend(list(db_data.get("indicators", {}).keys()))

    return {"url_counts": all_url_counts, "processed_data": list(set(all_processed_data))}