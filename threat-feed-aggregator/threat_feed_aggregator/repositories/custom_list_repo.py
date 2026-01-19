import json
import logging
import secrets
from datetime import datetime, UTC
from ..database.connection import db_transaction, DB_WRITE_LOCK

logger = logging.getLogger(__name__)

def create_custom_list(name, sources, types, data_format, conn=None):
    """
    Creates a new custom EDL configuration.
    sources: list of source names
    types: list of types (ip, domain, url)
    """
    token = secrets.token_urlsafe(16)
    created_at = datetime.now(UTC).isoformat()
    
    # Store lists as JSON strings
    sources_json = json.dumps(sources)
    types_json = json.dumps(types)
    
    logger.info(f"Creating custom list '{name}' with sources: {sources}")

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            cursor = db.execute('''
                INSERT INTO custom_lists (name, token, sources, types, format, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, token, sources_json, types_json, data_format, created_at))
            db.commit()
            logger.info(f"Custom list '{name}' created with ID: {cursor.lastrowid}")
            return cursor.lastrowid, token

def get_all_custom_lists(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM custom_lists ORDER BY created_at DESC')
        results = []
        for row in cursor:
            sources = json.loads(row['sources'])
            
            # Calculate total indicators for this list
            indicator_count = 0
            if sources:
                placeholders = ','.join(['?'] * len(sources))
                count_cursor = db.execute(f'''
                    SELECT COUNT(DISTINCT i.indicator)
                    FROM indicators i
                    JOIN indicator_sources s ON i.indicator = s.indicator
                    WHERE s.source_name IN ({placeholders})
                ''', sources)
                indicator_count = count_cursor.fetchone()[0]

            results.append({
                'id': row['id'],
                'name': row['name'],
                'token': row['token'],
                'sources': sources,
                'types': json.loads(row['types']),
                'format': row['format'],
                'created_at': row['created_at'],
                'indicator_count': indicator_count
            })
        logger.info(f"Retrieved {len(results)} custom lists.")
        return results

def get_custom_list_by_token(token, conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM custom_lists WHERE token = ?', (token,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row['id'],
                'name': row['name'],
                'token': row['token'],
                'sources': json.loads(row['sources']),
                'types': json.loads(row['types']),
                'format': row['format'],
                'created_at': row['created_at']
            }
        return None

def delete_custom_list(list_id, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM custom_lists WHERE id = ?', (list_id,))
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error deleting custom list {list_id}: {e}")
                return False
