import sqlite3
import logging
from datetime import datetime, timezone
from ..database.connection import db_transaction, DB_WRITE_LOCK

logger = logging.getLogger(__name__)

# --- Whitelist Functions ---
def add_whitelist_item(item, description="", conn=None):
    if not item:
        return False, "Item is empty."
    
    from ..utils import validate_indicator
    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                db.execute('INSERT INTO whitelist (item, description, added_at) VALUES (?, ?, ?)', 
                             (item.strip(), description, now_iso))
                db.commit()
                return True, "Item added to whitelist."
            except sqlite3.IntegrityError:
                return False, "Item already in whitelist."
            except Exception as e:
                logger.error(f"Error adding to whitelist: {e}")
                return False, str(e)

def get_whitelist(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM whitelist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]

def remove_whitelist_item(item_id, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM whitelist WHERE id = ?', (item_id,))
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error removing from whitelist: {e}")
                return False

# --- API Blacklist Functions ---
def add_api_blacklist_item(item, item_type='ip', comment="", conn=None):
    if not item:
        return False, "Item is empty."

    from ..utils import validate_indicator
    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                db.execute('INSERT INTO api_blacklist (item, type, comment, added_at) VALUES (?, ?, ?, ?)', 
                             (item.strip(), item_type, comment, now_iso))
                db.commit()
                return True, "Item added to blacklist."
            except sqlite3.IntegrityError:
                return False, "Item already in blacklist."
            except Exception as e:
                logger.error(f"Error adding to api_blacklist: {e}")
                return False, str(e)

def get_api_blacklist_items(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM api_blacklist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]

def remove_api_blacklist_item(item, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # Can remove by ID or exact item string
                if isinstance(item, int) or (isinstance(item, str) and item.isdigit()):
                    db.execute('DELETE FROM api_blacklist WHERE id = ?', (item,))
                else:
                    db.execute('DELETE FROM api_blacklist WHERE item = ?', (item,))
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error removing from api_blacklist: {e}")
                return False

def delete_whitelisted_indicators(items_to_delete, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                if items_to_delete:
                    placeholders = ','.join(['?' for _ in items_to_delete])
                    db.execute(f'DELETE FROM indicators WHERE indicator IN ({placeholders})', items_to_delete)
                    # Also delete from sources
                    db.execute(f'DELETE FROM indicator_sources WHERE indicator IN ({placeholders})', items_to_delete)
                    db.commit()
                    return True
                return False
            except Exception as e:
                logger.error(f"Error deleting whitelisted indicators: {e}")
                return False
