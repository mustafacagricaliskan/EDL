import os
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from .data_collector import fetch_data_from_url
from .data_processor import process_data
from .db_manager import remove_old_indicators, get_all_indicators
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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

def aggregate_single_source(source_config):
    """
    Fetches and processes data for a single threat feed source.
    Updates the global indicators database and stats.
    """
    name = source_config["name"]
    url = source_config["url"]
    data_format = source_config.get("format", "text")
    key_or_column = source_config.get("key_or_column")

    # Note: remove_old_indicators calls are better handled centrally or periodically
    # to avoid race conditions or redundant calls in threaded execution.
    # We will remove it from here and let the main loop or scheduler handle it once.

    start_time_fetch = time.time()
    raw_data = fetch_data_from_url(url)
    end_time_fetch = time.time()
    fetch_duration = f"{end_time_fetch - start_time_fetch:.2f} seconds"

    count = 0
    if raw_data:
        count = process_data(raw_data, data_format, key_or_column)
    
    # Return stats data instead of writing to file directly to avoid race conditions
    return {
        "name": name,
        "count": count,
        "fetch_time": fetch_duration,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

def main(source_urls):
    """
    Aggregates and processes threat feeds from a list of source URLs in PARALLEL.
    """
    config = read_config()
    lifetime_days = config.get("indicator_lifetime_days", 30)
    
    # Clean up old indicators once per run
    remove_old_indicators(lifetime_days)

    all_url_counts = {}
    current_stats = read_stats()

    # Use ThreadPoolExecutor for parallel processing
    # Max workers can be adjusted based on system resources, 10 is a safe start for IO-bound tasks.
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_source = {executor.submit(aggregate_single_source, source): source for source in source_urls}
        
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                name = result["name"]
                
                # Update local stats dict
                current_stats[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"],
                    "last_updated": result["last_updated"]
                }
                
                all_url_counts[name] = {
                    "count": result["count"],
                    "fetch_time": result["fetch_time"]
                }
                print(f"Finished processing {name}")
                
            except Exception as exc:
                print(f"{source['name']} generated an exception: {exc}")

    # Update global stats file once at the end
    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)

    all_indicators = get_all_indicators()
    return {"url_counts": all_url_counts, "processed_data": list(all_indicators.keys())}