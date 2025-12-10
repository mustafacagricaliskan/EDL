import json
import csv
from io import StringIO

def parse_text(raw_data):
    """
    Parses plain text data, with one indicator per line.
    """
    return [line.strip() for line in raw_data.splitlines() if line.strip() and not line.strip().startswith('#')]

def parse_json(raw_data, key=None):
    """
    Parses JSON data. Expects a list of strings or a list of objects.
    If a key is provided, it will be used to extract the indicator from each object.
    """
    try:
        data = json.loads(raw_data)
        if isinstance(data, list):
            if key and isinstance(data[0], dict):
                return [item[key] for item in data if key in item]
            else:
                return [str(item) for item in data]
    except (json.JSONDecodeError, IndexError):
        return []
    return []

def parse_csv(raw_data, column=0):
    """
    Parses CSV data. Expects the indicator to be in a specific column.
    """
    try:
        reader = csv.reader(StringIO(raw_data))
        return [row[column] for row in reader if row]
    except (csv.Error, IndexError):
        return []
