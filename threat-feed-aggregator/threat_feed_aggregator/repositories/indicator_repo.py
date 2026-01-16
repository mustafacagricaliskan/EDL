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

def get_sources_for_indicators_batch(indicators, conn=None):
    """
    Optimized: Returns a dictionary {indicator: [{'source_name': ...}, ...]} for a list of indicators.
    Solves N+1 query problem.
    """
    if not indicators:
        return {}
    
    with db_transaction(conn) as db:
        try:
            placeholders = ','.join(['?'] * len(indicators))
            cursor = db.execute(f'''
                SELECT indicator, source_name, last_seen 
                FROM indicator_sources 
                WHERE indicator IN ({placeholders})
                ORDER BY last_seen DESC
            ''', indicators)
            
            result = {ind: [] for ind in indicators}
            for row in cursor.fetchall():
                result[row['indicator']].append({'source_name': row['source_name'], 'last_seen': row['last_seen']})
            return result
        except Exception as e:
            logger.error(f"Error batch fetching sources: {e}")
            return {}

def get_indicators_paginated(start=0, length=10, search_value=None, filters=None, order_col='risk_score', order_dir='desc', conn=None):
    """
    Retrieves indicators with pagination, global filtering, and column-specific filtering.
    filters: dict of {column_name: filter_value}
    """
    with db_transaction(conn) as db:
        # 1. Base Query construction
        # We might need to join if filtering by source
        base_query = "SELECT DISTINCT i.indicator, i.type, i.country, i.risk_score, i.source_count, i.last_seen FROM indicators i"
        count_query = "SELECT COUNT(DISTINCT i.indicator) FROM indicators i"
        
        joins = []
        conditions = []
        params = []

        # 2. Global Filtering (Quick Search)
        if search_value:
            conditions.append("(i.indicator LIKE ? OR i.country LIKE ? OR i.type LIKE ?)")
            search_param = f"%{search_value}%"
            params.extend([search_param, search_param, search_param])

        # 3. Column Specific Filtering
        if filters:
            for col, val in filters.items():
                if not val: continue
                
                if col == 'type':
                    conditions.append("i.type = ?")
                    params.append(val)
                elif col == 'country':
                    conditions.append("i.country LIKE ?") # Use LIKE for country to allow partial match
                    params.append(f"%{val}%")
                elif col == 'level':
                    if val == 'Critical': conditions.append("i.risk_score >= 90")
                    elif val == 'High': conditions.append("i.risk_score >= 70 AND i.risk_score < 90")
                    elif val == 'Medium': conditions.append("i.risk_score >= 40 AND i.risk_score < 70")
                    elif val == 'Low': conditions.append("i.risk_score < 40")
                elif col == 'risk_score':
                    # Enhanced Risk Score Logic:
                    # If just a number '80' -> score >= 80
                    # If '>80' -> score > 80
                    # If '<50' -> score < 50
                    # If '=50' -> score = 50
                    val_str = str(val).strip()
                    operator = ">="
                    limit = 0
                    
                    if val_str.startswith('>='):
                        operator = ">="
                        limit = val_str[2:]
                    elif val_str.startswith('<='):
                        operator = "<="
                        limit = val_str[2:]
                    elif val_str.startswith('>'):
                        operator = ">"
                        limit = val_str[1:]
                    elif val_str.startswith('<'):
                        operator = "<"
                        limit = val_str[1:]
                    elif val_str.startswith('='):
                        operator = "="
                        limit = val_str[1:]
                    else:
                        operator = ">="
                        limit = val_str
                    
                    try:
                        limit_int = int(limit)
                        conditions.append(f"i.risk_score {operator} ?")
                        params.append(limit_int)
                    except ValueError:
                        pass # Ignore invalid number format
                elif col == 'source':
                    # Join needed
                    if "JOIN indicator_sources s ON i.indicator = s.indicator" not in joins:
                        joins.append("JOIN indicator_sources s ON i.indicator = s.indicator")
                    conditions.append("s.source_name LIKE ?")
                    params.append(f"%{val}%")
                elif col == 'tag':
                    # Filtering by tag is tricky because tags are derived from source names in app logic.
                    # We can approximate by filtering source names that map to these tags.
                    # Mapping: Feodo->Botnet/C2, URLHaus->Malware, USOM->Phishing etc.
                    if "JOIN indicator_sources s ON i.indicator = s.indicator" not in joins:
                        joins.append("JOIN indicator_sources s ON i.indicator = s.indicator")
                    
                    val_lower = val.lower()
                    if 'botnet' in val_lower or 'c2' in val_lower:
                        conditions.append("s.source_name LIKE '%feodo%'")
                    elif 'malware' in val_lower:
                        conditions.append("s.source_name LIKE '%urlhaus%'")
                    elif 'phishing' in val_lower:
                        conditions.append("(s.source_name LIKE '%usom%' OR s.source_name LIKE '%phishtank%' OR s.source_name LIKE '%openphish%')")
                    else:
                        # Fallback generic search in source name
                        conditions.append("s.source_name LIKE ?")
                        params.append(f"%{val}%")

        if joins:
            join_clause = " " + " ".join(joins)
            base_query += join_clause
            count_query += join_clause

        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)
            base_query += where_clause
            count_query += where_clause

        # 4. Total Counts
        # Calculate filtered count
        if conditions:
            cursor = db.execute(count_query, params)
            filtered_records = cursor.fetchone()[0]
        
        # Calculate total records (unfiltered)
        cursor = db.execute("SELECT COUNT(*) FROM indicators")
        total_records = cursor.fetchone()[0]
        
        if not conditions:
            filtered_records = total_records

        # 5. Sorting
        allowed_cols = {
            'indicator': 'i.indicator', 
            'type': 'i.type', 
            'country': 'i.country', 
            'risk_score': 'i.risk_score', 
            'source_count': 'i.source_count', 
            'last_seen': 'i.last_seen'
        }
        
        db_order_col = allowed_cols.get(order_col, 'i.risk_score')
        
        if order_dir.lower() not in ['asc', 'desc']:
            order_dir = 'desc'
        
        base_query += f" ORDER BY {db_order_col} {order_dir}"

        # 6. Pagination
        base_query += " LIMIT ? OFFSET ?"
        params.extend([length, start])

        # 7. Execution
        cursor = db.execute(base_query, params)
        items = [dict(row) for row in cursor.fetchall()]

        return total_records, filtered_records, items

def get_filter_options(column, search_term=None, limit=20, conn=None):
    """
    Returns distinct values for a specific column to support autocomplete.
    Supports columns: source, country, type, tag (derived).
    """
    with db_transaction(conn) as db:
        results = []
        search_param = f"%{search_term}%" if search_term else "%"
        
        if column == 'source':
            # Query indicator_sources.source_name
            query = "SELECT DISTINCT source_name FROM indicator_sources WHERE source_name LIKE ? ORDER BY source_name LIMIT ?"
            cursor = db.execute(query, (search_param, limit))
            results = [row[0] for row in cursor.fetchall()]
            
        elif column == 'country':
            query = "SELECT DISTINCT country FROM indicators WHERE country LIKE ? ORDER BY country LIMIT ?"
            cursor = db.execute(query, (search_param, limit))
            results = [row[0] for row in cursor.fetchall() if row[0]]
            
        elif column == 'type':
            # Usually static, but can fetch from DB
            query = "SELECT DISTINCT type FROM indicators WHERE type LIKE ? ORDER BY type LIMIT ?"
            cursor = db.execute(query, (search_param, limit))
            results = [row[0] for row in cursor.fetchall()]
            
        # Tags are application logic, difficult to query DISTINCT from DB without a tag table.
        # We can skip tag autocomplete or return hardcoded common tags.
        
        return results
