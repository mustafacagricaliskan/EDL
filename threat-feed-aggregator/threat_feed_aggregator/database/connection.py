import sqlite3
import logging
import os
import threading
from contextlib import contextmanager
from ..config_manager import DATA_DIR
from ..constants import DB_TIMEOUT

logger = logging.getLogger(__name__)

DB_NAME = os.path.join(DATA_DIR, "threat_feed.db")

# Global Lock for DB Writes
DB_WRITE_LOCK = threading.Lock()

def get_db_connection(timeout=DB_TIMEOUT):
    conn = sqlite3.connect(DB_NAME, timeout=timeout)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA foreign_keys=ON;') # Enable foreign keys
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def db_transaction(conn=None):
    """
    Context manager for database transactions.
    If a connection is provided, it uses it (and does NOT close it).
    If no connection is provided, it creates a new one (and closes it).
    """
    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True
    try:
        yield conn
    finally:
        if should_close:
            conn.close()
