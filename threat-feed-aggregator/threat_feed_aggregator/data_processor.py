from datetime import datetime, timezone
from .parsers import parse_text, parse_json, parse_csv

def process_data(raw_data, indicators_db, data_format="text", key_or_column=None):
    """
    Processes raw data by parsing it and updating the indicators database.

    Args:
        raw_data (str): A string containing the raw data.
        indicators_db (dict): The existing database of indicators.
        data_format (str): The format of the data (text, json, csv).
        key_or_column: The key for JSON objects or the column index for CSV.

    Returns:
        tuple: A tuple containing the updated indicators database and the count of processed items.
    """
    if not raw_data:
        return indicators_db, 0

    items = []
    if data_format == "text":
        items = parse_text(raw_data)
    elif data_format == "json":
        items = parse_json(raw_data, key=key_or_column)
    elif data_format == "csv":
        items = parse_csv(raw_data, column=key_or_column)

    now = datetime.now(timezone.utc).isoformat()
    
    for item in items:
        if item not in indicators_db:
            indicators_db[item] = {}
        indicators_db[item]['last_seen'] = now
    
    return indicators_db, len(items)
