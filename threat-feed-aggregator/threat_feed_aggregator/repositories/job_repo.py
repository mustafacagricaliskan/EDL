import sqlite3
import logging
from datetime import datetime, timezone
from ..database.connection import db_transaction, DB_WRITE_LOCK

logger = logging.getLogger(__name__)

# ... (Job History functions) ...
def log_job_start(source_name, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                start_time = datetime.now(timezone.utc).isoformat()
                cursor = db.execute(
                    'INSERT INTO job_history (source_name, start_time, status) VALUES (?, ?, ?)',
                    (source_name, start_time, 'running')
                )
                db.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Error logging job start: {e}")
                return None

def log_job_end(job_id, status, items_processed=0, message=None, conn=None):
    if not job_id: return
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                end_time = datetime.now(timezone.utc).isoformat()
                db.execute('''
                    UPDATE job_history 
                    SET end_time = ?, status = ?, items_processed = ?, message = ?
                    WHERE id = ?
                ''', (end_time, status, items_processed, message, job_id))
                db.commit()
            except Exception as e:
                logger.error(f"Error logging job end: {e}")

def get_job_history(limit=50, conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM job_history ORDER BY start_time DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]

def clear_job_history(conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM job_history')
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error clearing job history: {e}")
                return False
