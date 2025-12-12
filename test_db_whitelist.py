import sqlite3
from threat_feed_aggregator.db_manager import init_db, add_whitelist_item, get_whitelist

# Re-init DB to be sure
init_db()

# Add item
success, msg = add_whitelist_item("10.0.0.0/8", "Test CIDR")
print(f"Add status: {success}, Message: {msg}")

# Get items
items = get_whitelist()
print(f"Whitelist items: {items}")

if len(items) > 0 and items[0]['item'] == "10.0.0.0/8":
    print("DB Whitelist Test PASSED")
else:
    print("DB Whitelist Test FAILED")
