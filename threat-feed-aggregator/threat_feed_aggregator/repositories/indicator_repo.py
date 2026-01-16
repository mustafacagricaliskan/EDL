import logging
from datetime import UTC, datetime, timedelta

from ..database.connection import DB_WRITE_LOCK, db_transaction

logger = logging.getLogger(__name__)

# --- SCORING & UPSERT LOGIC ---

def upsert_indicators_bulk(indicators, source_name="Unknown", conn=None):
    """
    Highly optimized bulk upsert with scoring logic.
    indicators: list of (indicator, country, type)
    """
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(UTC).isoformat()

                # Speed Optimization: Use a temporary table for bulk operations
                db.execute('CREATE TEMPORARY TABLE IF NOT EXISTS temp_bulk_indicators (indicator TEXT, country TEXT, type TEXT)')
                db.execute('DELETE FROM temp_bulk_indicators')

                db.executemany('INSERT INTO temp_bulk_indicators VALUES (?, ?, ?)', indicators)

                # Step 1: Bulk Upsert into main indicators table
                # Using INSERT OR REPLACE for compatibility with older SQLite versions
                db.execute('''
                    INSERT OR REPLACE INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                    SELECT indicator, ?, country, type, 50, 1 FROM temp_bulk_indicators
                ''', (now_iso,))

                # Step 2: Bulk Update indicator_sources
                db.execute('''
                    INSERT OR REPLACE INTO indicator_sources (indicator, source_name, last_seen)
                    SELECT indicator, ?, ? FROM temp_bulk_indicators
                ''', (source_name, now_iso))

                db.commit()
            except Exception as e:
                logger.error(f"Error bulk upserting indicators: {e}")
                raise

def clean_database_vacuum(conn=None):
    """Performs VACUUM to shrink DB size and optimize indexes."""
    with db_transaction(conn) as db:
        db.execute('VACUUM')
        logger.info("Database vacuumed and optimized.")

def get_all_indicators_iter(conn=None):
    """
    Generator that yields indicators one by one to save memory.
    Ideal for EDL generation with large datasets.
    """
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators')
        for row in cursor:
            yield row

def get_filtered_indicators_iter(source_names=None, conn=None):
    """
    Generator that yields indicators filtered by specific sources.
    source_names: List of source names (strings)
    """
    with db_transaction(conn) as db:
        if not source_names:
            # Fallback to all if no filter provided
            cursor = db.execute('SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators')
        else:
            placeholders = ','.join(['?'] * len(source_names))
            query = f'''
                SELECT DISTINCT i.indicator, i.last_seen, i.country, i.type, i.risk_score, i.source_count
                FROM indicators i
                JOIN indicator_sources s ON i.indicator = s.indicator
                WHERE s.source_name IN ({placeholders})
            '''
            cursor = db.execute(query, source_names)
            
        for row in cursor:
            yield row

def recalculate_scores(source_confidence_map=None, conn=None, target_source=None):
    """
    Optimized: Recalculates risk scores.
    If target_source is provided, only updates indicators associated with that source.
    """
    if source_confidence_map is None:
        source_confidence_map = {}

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # 1. Update source_count accurately
                # Optimization: Only update source_count for affected indicators if target_source is set
                count_where_clause = ""
                count_params = []
                if target_source:
                    count_where_clause = "WHERE indicators.indicator IN (SELECT indicator FROM indicator_sources WHERE source_name = ?)"
                    count_params = [target_source]

                db.execute(f'''
                    UPDATE indicators
                    SET source_count = (
                        SELECT COUNT(*) 
                        FROM indicator_sources 
                        WHERE indicator_sources.indicator = indicators.indicator
                    )
                    {count_where_clause}
                ''', count_params)

                # 2. Use a temporary table for confidence scores
                db.execute('CREATE TEMPORARY TABLE IF NOT EXISTS temp_source_conf (name TEXT PRIMARY KEY, score INTEGER)')
                db.execute('DELETE FROM temp_source_conf')

                data_to_insert = [(name, score) for name, score in source_confidence_map.items()]
                if data_to_insert:
                    db.executemany('INSERT INTO temp_source_conf VALUES (?, ?)', data_to_insert)

                # 3. Optimized calculation
                score_where_clause = "WHERE EXISTS (SELECT 1 FROM indicator_sources WHERE indicator = indicators.indicator)"
                score_params = []
                if target_source:
                    score_where_clause = "WHERE indicators.indicator IN (SELECT indicator FROM indicator_sources WHERE source_name = ?)"
                    score_params = [target_source]

                db.execute(f'''
                    UPDATE indicators
                    SET risk_score = (
                        SELECT MIN(100, MAX(COALESCE(sc.score, 50)) + ((indicators.source_count - 1) * 5))
                        FROM indicator_sources src
                        LEFT JOIN temp_source_conf sc ON src.source_name = sc.name
                        WHERE src.indicator = indicators.indicator
                    )
                    {score_where_clause}
                ''', score_params)

                db.commit()
                logger.info(f"Scores recalculated efficiently ({'Target: ' + target_source if target_source else 'Full'}).")
            except Exception as e:
                logger.error(f"Error recalculating scores: {e}")
                db.rollback()

def get_all_indicators(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators')
        return {row['indicator']: {
            'last_seen': row['last_seen'],
            'country': row['country'],
            'type': row['type'],
            'risk_score': row['risk_score'],
            'source_count': row['source_count']
        } for row in cursor.fetchall()}

def remove_old_indicators(source_retention_map=None, default_retention_days=30, conn=None):
    """
    Removes indicators based on per-source retention policies.
    """
    if source_retention_map is None:
        source_retention_map = {}

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now = datetime.now(UTC)
                total_deleted_sources = 0

                # 1. Clean up indicator_sources per source
                cursor = db.execute("SELECT DISTINCT source_name FROM indicator_sources")
                db_sources = [row['source_name'] for row in cursor.fetchall()]

                for source in db_sources:
                    days = source_retention_map.get(source, default_retention_days)
                    cutoff_date = now - timedelta(days=days)

                    # Delete old associations for this source
                    cur = db.execute(
                        "DELETE FROM indicator_sources WHERE source_name = ? AND last_seen < ?",
                        (source, cutoff_date.isoformat())
                    )
                    total_deleted_sources += cur.rowcount

                # 2. Clean up Orphans (Indicators with no sources left)
                cur = db.execute('''
                    DELETE FROM indicators 
                    WHERE indicator NOT IN (SELECT DISTINCT indicator FROM indicator_sources)
                ''')
                orphans_deleted = cur.rowcount

                if total_deleted_sources > 0 or orphans_deleted > 0:
                    db.commit()
                    logger.info(f"Cleanup: Removed {total_deleted_sources} expired source links and {orphans_deleted} orphaned indicators.")

                return orphans_deleted
            except Exception as e:
                logger.error(f"Error removing old indicators: {e}")
                return 0

def get_unique_indicator_count(indicator_type=None, conn=None):
    with db_transaction(conn) as db:
        if indicator_type:
            cursor = db.execute('SELECT COUNT(*) FROM indicators WHERE type = ?', (indicator_type,))
        else:
            cursor = db.execute('SELECT COUNT(*) FROM indicators')
        return cursor.fetchone()[0]

def get_indicator_counts_by_type(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT type, COUNT(*) as count FROM indicators GROUP BY type')
        return {row['type']: row['count'] for row in cursor.fetchall()}

def get_country_stats(conn=None):
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('''
                SELECT COALESCE(country, 'Unknown') as country_code, COUNT(*) as count 
                FROM indicators 
                WHERE type = 'ip'
                GROUP BY country_code 
                ORDER BY count DESC
                LIMIT 10
            ''')
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting country stats: {e}")
            return []

def save_historical_stats(conn=None):
    """Captures current stats and saves to history."""
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                cursor = db.execute("SELECT COUNT(*) FROM indicators")
                total = cursor.fetchone()[0]

                cursor = db.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type")
                counts = {row[0]: row[1] for row in cursor.fetchall()}

                ip_count = counts.get('ip', 0) + counts.get('cidr', 0)
                domain_count = counts.get('domain', 0)
                url_count = counts.get('url', 0)

                now_iso = datetime.now(UTC).isoformat()

                db.execute('''
                    INSERT INTO stats_history (timestamp, total_indicators, ip_count, domain_count, url_count)
                    VALUES (?, ?, ?, ?, ?)
                ''', (now_iso, total, ip_count, domain_count, url_count))

                db.commit()
                logger.info("Saved historical stats for trend analysis.")
            except Exception as e:
                logger.error(f"Error saving stats history: {e}")

def get_historical_stats(days=30, conn=None):
    with db_transaction(conn) as db:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()

        cursor = db.execute('''
            SELECT timestamp, total_indicators, ip_count, domain_count, url_count 
            FROM stats_history 
            WHERE timestamp > ? 
            ORDER BY timestamp ASC
        ''', (cutoff,))
        return [dict(row) for row in cursor.fetchall()]

def get_source_counts(conn=None):
    """
    Returns a dictionary mapping source_name to indicator count.
    """
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('SELECT source_name, COUNT(*) as count FROM indicator_sources GROUP BY source_name')
            return {row['source_name']: row['count'] for row in cursor.fetchall()}
        except Exception as e:
            logger.error(f"Error getting source counts: {e}")
            return {}

def get_sources_for_indicator(indicator, conn=None):
    """
    Returns a list of dictionaries with source info for a specific indicator.
    """
    with db_transaction(conn) as db:
        try:
            # Join with indicator_sources to get source info
            # We can also get last_seen from the link table
            cursor = db.execute('''
                SELECT source_name, last_seen 
                FROM indicator_sources 
                WHERE indicator = ?
                ORDER BY last_seen DESC
            ''', (indicator,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting sources for indicator {indicator}: {e}")
            return []
