import logging
import os
import re
import sqlite3
import threading
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

from ..config_manager import DATA_DIR
from ..constants import DB_TIMEOUT

logger = logging.getLogger(__name__)

DB_TYPE = os.getenv('DB_TYPE', 'sqlite')
logger.info(f"Database Type Detected: {DB_TYPE}")

DB_NAME = os.path.join(DATA_DIR, "threat_feed.db")

# Global Lock for SQLite DB Writes (Postgres handles concurrency itself)
DB_WRITE_LOCK = threading.Lock()

# Postgres Connection Pool
pg_pool = None

def init_pg_pool():
    global pg_pool
    if DB_TYPE == 'postgres' and not pg_pool:
        try:
            pg_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=20,
                user=os.getenv('DB_USER', 'threat_user'),
                password=os.getenv('DB_PASS', 'secure_password'),
                host=os.getenv('DB_HOST', 'postgres'),
                port=os.getenv('DB_PORT', '5432'),
                database=os.getenv('DB_NAME', 'threat_feed')
            )
            logger.info("PostgreSQL connection pool initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize Postgres pool: {e}")
            raise

class PostgresCursorWrapper:
    """
    Wraps psycopg2 cursor to mimic sqlite3 behavior:
    1. Replaces '?' placeholders with '%s'.
    2. Allows accessing rows like dictionaries (already done by DictCursor).
    3. Handles 'INSERT OR IGNORE' -> 'ON CONFLICT DO NOTHING' conversion rudimentarily.
    """
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = None # Postgres uses RETURNING id, handled via fetchone if needed

    def execute(self, query, params=None):
        # 1. Convert Placeholder '?' -> '%s'
        query_pg = query.replace('?', '%s')
        
        # 2. Convert 'INSERT OR IGNORE' -> 'INSERT ... ON CONFLICT DO NOTHING'
        # This is a basic regex replace, might need more care for complex queries
        if 'INSERT OR IGNORE' in query_pg:
            query_pg = query_pg.replace('INSERT OR IGNORE', 'INSERT')
            query_pg += " ON CONFLICT DO NOTHING"
            
        # 3. Convert 'INSERT OR REPLACE' -> SQLite specific syntax.
        # Postgres uses 'INSERT ... ON CONFLICT (...) DO UPDATE ...'
        # This is complex to automate regex-wise. 
        # Ideally, we should update the repository code. 
        # But for now, let's try to catch it or fail loudly so we fix it in code.
        if 'INSERT OR REPLACE' in query_pg:
             # We can't auto-translate this easily without knowing the Primary Key.
             # We will handle this by refactoring the specific repository methods (upsert_bulk).
             pass 

        try:
            self.cursor.execute(query_pg, params)
            # Emulate lastrowid for single inserts if RETURNING id was used? 
            # SQLite 'lastrowid' is often used. Postgres needs 'RETURNING id'.
            if self.cursor.description and 'id' in [c.name for c in self.cursor.description]:
                 # If we returned something, maybe we can fetch it?
                 # But standard sqlite execute doesn't fetch.
                 pass
        except Exception as e:
            logger.error(f"SQL Error: {e} | Query: {query_pg}")
            raise
        return self

    def executemany(self, query, params_seq):
        query_pg = query.replace('?', '%s')
        # Same regex logic?
        self.cursor.executemany(query_pg, params_seq)
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()
    
    def __iter__(self):
        """Allows iteration over the cursor (like sqlite3 cursor)."""
        return iter(self.cursor)

    @property
    def rowcount(self):
        return self.cursor.rowcount
    
    @property
    def description(self):
        return self.cursor.description

class PostgresConnectionWrapper:
    def __init__(self, conn, pool_obj):
        self.conn = conn
        self.pool = pool_obj
        self.row_factory = None # Compat attribute

    def execute(self, query, params=None):
        cursor = self.cursor()
        cursor.execute(query, params)
        return cursor

    def executemany(self, query, params_seq):
        cursor = self.cursor()
        cursor.executemany(query, params_seq)
        return cursor

    def cursor(self):
        return PostgresCursorWrapper(self.conn.cursor(cursor_factory=DictCursor))

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        if self.pool:
            self.pool.putconn(self.conn)

def get_db_connection(timeout=DB_TIMEOUT):
    if DB_TYPE == 'postgres':
        if not pg_pool:
            init_pg_pool()
        conn = pg_pool.getconn()
        return PostgresConnectionWrapper(conn, pg_pool)
    else:
        # SQLite Fallback
        conn = sqlite3.connect(DB_NAME, timeout=timeout)
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA foreign_keys=ON;')
        conn.row_factory = sqlite3.Row
        return conn

@contextmanager
def db_transaction(conn=None):
    """
    Context manager for database transactions.
    """
    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True
    try:
        # SQLite write lock is only needed for SQLite to prevent "database locked"
        # Postgres handles it, but keeping the lock context doesn't hurt logic much 
        # (just serializes app threads, which is sub-optimal for Postgres but safe).
        # We can conditionally acquire it.
        if DB_TYPE == 'sqlite':
            with DB_WRITE_LOCK:
                yield conn
        else:
            yield conn
            
        if should_close:
            conn.commit()
    except Exception as e:
        if should_close:
            conn.rollback()
        raise e
    finally:
        if should_close:
            conn.close()