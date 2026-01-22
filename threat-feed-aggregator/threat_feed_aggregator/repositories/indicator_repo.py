import logging
import time
from datetime import UTC, datetime, timedelta

from ..database.connection import DB_WRITE_LOCK, db_transaction, DB_TYPE

logger = logging.getLogger(__name__)

# --- CACHING LOGIC ---
_STATS_CACHE = {}
_STATS_CACHE_TTL = 300  # 5 minutes

def invalidate_stats_cache():
    """Invalidates the in-memory stats cache."""
    global _STATS_CACHE
    _STATS_CACHE.clear()
    logger.debug("Stats cache invalidated.")

def _get_cached_stat(key, fetch_func, *args, **kwargs):
    """Helper to get a stat from cache or fetch it."""
    global _STATS_CACHE
    now = time.time()
    
    # Check cache
    if key in _STATS_CACHE:
        val, timestamp = _STATS_CACHE[key]
        if now - timestamp < _STATS_CACHE_TTL:
            return val
    
    # Cache miss
    val = fetch_func(*args, **kwargs)
    _STATS_CACHE[key] = (val, now)
    return val

# --- SCORING & UPSERT LOGIC ---

def upsert_indicators_bulk(indicators, source_name="Unknown", conn=None):
    """
    Highly optimized bulk upsert with scoring logic.
    indicators: list of (indicator, country, type)
    """
    # Deduplicate input list based on indicator (tuple[0]) to avoid "ON CONFLICT DO UPDATE command cannot affect row a second time"
    # Keep the last occurrence
    unique_indicators_map = {item[0]: item for item in indicators}
    deduplicated_indicators = list(unique_indicators_map.values())

    with db_transaction(conn) as db:
        try:
            now_iso = datetime.now(UTC).isoformat()

            # Speed Optimization: Use a temporary table for bulk operations
            db.execute('CREATE TEMPORARY TABLE IF NOT EXISTS temp_bulk_indicators (indicator TEXT, country TEXT, type TEXT)')
            db.execute('DELETE FROM temp_bulk_indicators')

            # The wrapper will handle ? -> %s conversion
            db.executemany('INSERT INTO temp_bulk_indicators VALUES (?, ?, ?)', deduplicated_indicators)

            # Step 1: Bulk Upsert into main indicators table
            if DB_TYPE == 'postgres':
                # Postgres UPSERT
                db.execute('''
                    INSERT INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                    SELECT indicator, %s, country, type, 50, 1 FROM temp_bulk_indicators
                    ON CONFLICT (indicator) 
                    DO UPDATE SET last_seen = EXCLUDED.last_seen
                ''', (now_iso,))
            else:
                # SQLite UPSERT (INSERT OR REPLACE)
                db.execute('''
                    INSERT OR REPLACE INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                    SELECT indicator, ?, country, type, 50, 1 FROM temp_bulk_indicators
                ''', (now_iso,))

            # Step 2: Bulk Update indicator_sources
            if DB_TYPE == 'postgres':
                db.execute('''
                    INSERT INTO indicator_sources (indicator, source_name, last_seen)
                    SELECT indicator, %s, %s FROM temp_bulk_indicators
                    ON CONFLICT (indicator, source_name) 
                    DO UPDATE SET last_seen = EXCLUDED.last_seen
                ''', (source_name, now_iso))
            else:
                db.execute('''
                    INSERT OR REPLACE INTO indicator_sources (indicator, source_name, last_seen)
                    SELECT indicator, ?, ? FROM temp_bulk_indicators
                ''', (source_name, now_iso))

            db.commit()
            invalidate_stats_cache() # Invalidate cache on update
        except Exception as e:
            logger.error(f"Error bulk upserting indicators: {e}")
            raise

# ...

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
                # ... (part 1 & 2 same) ...
                # 1. Update source_count accurately
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

                # Handle DB differences for MIN/MAX vs LEAST/GREATEST
                if DB_TYPE == 'postgres':
                    # Postgres uses LEAST/GREATEST
                    score_calc = "LEAST(100, GREATEST(COALESCE(sc.score, 50), 0) + ((indicators.source_count - 1) * 5))"
                else:
                    # SQLite uses MIN/MAX with multiple args
                    score_calc = "MIN(100, MAX(COALESCE(sc.score, 50)) + ((indicators.source_count - 1) * 5))"

                query = f'''
                    UPDATE indicators
                    SET risk_score = (
                        SELECT {score_calc}
                        FROM indicator_sources src
                        LEFT JOIN temp_source_conf sc ON src.source_name = sc.name
                        WHERE src.indicator = indicators.indicator
                    )
                    {score_where_clause}
                '''
                
                # Replace ? with %s if postgres (handled by wrapper usually but this is f-string)
                # Actually wrapper handles execute params, but this query has no params in the subquery logic
                # Only score_params for WHERE clause.
                
                db.execute(query, score_params)

                db.commit()
                invalidate_stats_cache()
                logger.info(f"Scores recalculated efficiently ({'Target: ' + target_source if target_source else 'Full'}).")
            except Exception as e:
                logger.error(f"Error recalculating scores: {e}")
                db.rollback()

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

                # Handle DB differences for MIN/MAX vs LEAST/GREATEST
                if DB_TYPE == 'postgres':
                    # Postgres uses LEAST/GREATEST. We aggregate MAX(sc.score) to handle multiple sources per indicator.
                    score_calc = "LEAST(100, GREATEST(MAX(COALESCE(sc.score, 50)), 0) + ((indicators.source_count - 1) * 5))"
                else:
                    # SQLite uses MIN/MAX with multiple args
                    score_calc = "MIN(100, MAX(MAX(COALESCE(sc.score, 50))) + ((indicators.source_count - 1) * 5))"

                query = f'''
                    UPDATE indicators
                    SET risk_score = (
                        SELECT {score_calc}
                        FROM indicator_sources src
                        LEFT JOIN temp_source_conf sc ON src.source_name = sc.name
                        WHERE src.indicator = indicators.indicator
                    )
                    {score_where_clause}
                '''
                
                db.execute(query, score_params)

                db.commit()
                invalidate_stats_cache()
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
                    invalidate_stats_cache()
                    logger.info(f"Cleanup: Removed {total_deleted_sources} expired source links and {orphans_deleted} orphaned indicators.")

                return orphans_deleted
            except Exception as e:
                logger.error(f"Error removing old indicators: {e}")
                return 0

def _fetch_unique_indicator_count(indicator_type, conn):
    with db_transaction(conn) as db:
        if indicator_type:
            cursor = db.execute('SELECT COUNT(*) FROM indicators WHERE type = ?', (indicator_type,))
        else:
            cursor = db.execute('SELECT COUNT(*) FROM indicators')
        return cursor.fetchone()[0]

def get_unique_indicator_count(indicator_type=None, conn=None):
    key = f"unique_count_{indicator_type}"
    return _get_cached_stat(key, _fetch_unique_indicator_count, indicator_type, conn)

def _fetch_indicator_counts_by_type(conn):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT type, COUNT(*) as count FROM indicators GROUP BY type')
        return {row['type']: row['count'] for row in cursor.fetchall()}

def get_indicator_counts_by_type(conn=None):
    return _get_cached_stat("counts_by_type", _fetch_indicator_counts_by_type, conn)

def _fetch_country_stats(conn):
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('''
                SELECT COALESCE(country, 'Unknown') as country_code, COUNT(*) as count 
                FROM indicators 
                WHERE type = 'ip'
                GROUP BY country_code 
                ORDER BY count DESC
                LIMIT 250
            ''')
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting country stats: {e}")
            return []

def get_country_stats(conn=None):
    return _get_cached_stat("country_stats", _fetch_country_stats, conn)

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

# --- DNS RESOLUTION CACHE LOGIC ---

def get_domains_for_resolution(limit=100, retry_days=7, conn=None):
    """
    Fetches domains that are either not in the cache or have expired cache entries.
    """
    with db_transaction(conn) as db:
        cutoff_date = (datetime.now(UTC) - timedelta(days=retry_days)).isoformat()
        
        # We want domains from 'indicators' table that need resolution
        # 1. Not in cache
        # 2. OR In cache but old
        # AND type is domain or url
        
        query = '''
            SELECT i.indicator, i.type 
            FROM indicators i
            LEFT JOIN dns_resolution_cache c ON i.indicator = c.domain
            WHERE (i.type = 'domain' OR i.type = 'url')
            AND (c.domain IS NULL OR c.last_resolved < ?)
            LIMIT ?
        '''
        
        cursor = db.execute(query, (cutoff_date, limit))
        return [{'indicator': row['indicator'], 'type': row['type']} for row in cursor.fetchall()]

def update_dns_cache_batch(results, conn=None):
    """
    Updates the DNS resolution cache with new results.
    results: list of {'domain': str, 'resolved_ips': str, 'last_resolved': str}
    """
    with db_transaction(conn) as db:
        query = '''
            INSERT INTO dns_resolution_cache (domain, resolved_ips, last_resolved)
            VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                resolved_ips = excluded.resolved_ips,
                last_resolved = excluded.last_resolved
        '''
        
        data = [(r['domain'], r['resolved_ips'], r['last_resolved']) for r in results]
        
        if DB_TYPE == 'postgres':
            # Adapt query for postgres syntax if needed (usually %s vs ?)
            # But the wrapper might handle it. If not, we use the standard 'replace' logic of upsert_indicators_bulk
             query = '''
                INSERT INTO dns_resolution_cache (domain, resolved_ips, last_resolved)
                VALUES (%s, %s, %s)
                ON CONFLICT (domain) DO UPDATE SET
                    resolved_ips = EXCLUDED.resolved_ips,
                    last_resolved = EXCLUDED.last_resolved
            '''
        
        db.executemany(query, data)
        db.commit()

def get_dns_resolution_cache_iter(conn=None):
    """
    Yields (domain, resolved_ips) from the cache table.
    """
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT domain, resolved_ips FROM dns_resolution_cache')
        for row in cursor:
            yield row

def delete_indicators(indicators_list, conn=None):
    """
    Deletes a list of indicators from the database.
    """
    if not indicators_list:
        return 0
        
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            placeholders = ','.join(['?'] * len(indicators_list))
            
            # 1. Delete from indicator_sources
            db.execute(f"DELETE FROM indicator_sources WHERE indicator IN ({placeholders})", indicators_list)
            
            # 2. Delete from indicators
            cursor = db.execute(f"DELETE FROM indicators WHERE indicator IN ({placeholders})", indicators_list)
            
            db.commit()
            invalidate_stats_cache()
            return cursor.rowcount

def get_existing_ips(ip_list, conn=None):
    """
    Checks which IPs from the provided list exist in the database.
    Returns a set of existing IPs.
    """
    if not ip_list:
        return set()
        
    with db_transaction(conn) as db:
        # Batch checks to avoid huge SQL queries
        existing = set()
        chunk_size = 900
        for i in range(0, len(ip_list), chunk_size):
            chunk = ip_list[i:i+chunk_size]
            placeholders = ','.join(['?'] * len(chunk))
            cursor = db.execute(f"SELECT indicator FROM indicators WHERE type='ip' AND indicator IN ({placeholders})", chunk)
            existing.update(row['indicator'] for row in cursor.fetchall())
            
        return existing
