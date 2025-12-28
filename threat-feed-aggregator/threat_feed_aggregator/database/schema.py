import json
import logging

from ..database.connection import DB_WRITE_LOCK, db_transaction

logger = logging.getLogger(__name__)

def init_db(conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # 1. Indicators Table (Expanded)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS indicators (
                        indicator TEXT PRIMARY KEY,
                        last_seen TEXT NOT NULL,
                        country TEXT,
                        type TEXT NOT NULL DEFAULT 'ip',
                        risk_score INTEGER DEFAULT 50, -- New: Risk Score
                        source_count INTEGER DEFAULT 1 -- New: Source Count
                    )
                ''')

                # Schema Migration for existing tables
                cursor = db.execute("PRAGMA table_info(indicators)")
                columns = [info[1] for info in cursor.fetchall()]
                if 'country' not in columns: db.execute('ALTER TABLE indicators ADD COLUMN country TEXT')
                if 'type' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN type TEXT NOT NULL DEFAULT 'ip'")
                if 'risk_score' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN risk_score INTEGER DEFAULT 50")
                if 'source_count' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN source_count INTEGER DEFAULT 1")

                # 2. Indicator Sources Table (New: Many-to-Many Relationship)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS indicator_sources (
                        indicator TEXT,
                        source_name TEXT,
                        last_seen TEXT,
                        PRIMARY KEY (indicator, source_name),
                        FOREIGN KEY(indicator) REFERENCES indicators(indicator) ON DELETE CASCADE
                    )
                ''')

                # Indexes for Performance
                db.execute('CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)')
                db.execute('CREATE INDEX IF NOT EXISTS idx_indicator_sources_name_seen ON indicator_sources(source_name, last_seen)')

                # Whitelist Table
                db.execute('''
                    CREATE TABLE IF NOT EXISTS whitelist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        item TEXT NOT NULL UNIQUE,
                        description TEXT,
                        added_at TEXT NOT NULL
                    )
                ''')

                # API Blacklist Table (For SOAR Integration)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS api_blacklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        item TEXT NOT NULL UNIQUE,
                        type TEXT NOT NULL DEFAULT 'ip',
                        comment TEXT,
                        added_at TEXT NOT NULL
                    )
                ''')

                # Users Table
                db.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL
                    )
                ''')

                # Job History Table
                db.execute('''
                    CREATE TABLE IF NOT EXISTS job_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_name TEXT NOT NULL,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        status TEXT NOT NULL, 
                        items_processed INTEGER DEFAULT 0,
                        message TEXT
                    )
                ''')

                # Stats History Table (New for Trend Graphs)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS stats_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        total_indicators INTEGER,
                        ip_count INTEGER,
                        domain_count INTEGER,
                        url_count INTEGER
                    )
                ''')

                # --- Admin Profiles (RBAC) ---
                db.execute('''
                    CREATE TABLE IF NOT EXISTS admin_profiles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        description TEXT,
                        permissions TEXT NOT NULL -- JSON string: {"module": "access_level"}
                    )
                ''')

                # --- LDAP Group Mappings ---
                db.execute('''
                    CREATE TABLE IF NOT EXISTS ldap_group_mappings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_dn TEXT NOT NULL UNIQUE,
                        profile_id INTEGER NOT NULL,
                        FOREIGN KEY(profile_id) REFERENCES admin_profiles(id) ON DELETE CASCADE
                    )
                ''')

                # Seed Default Profiles FIRST (to satisfy FK constraints when migrating users)
                cursor = db.execute("SELECT COUNT(*) FROM admin_profiles")
                if cursor.fetchone()[0] == 0:
                    # 1. Super_User (Full Access)
                    db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                               ('Super_User', 'Full access to all modules', json.dumps({
                                   "dashboard": "rw", "system": "rw", "tools": "rw"
                               })))
                    # 2. Standard_User (Limited System Access)
                    db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                               ('Standard_User', 'Can manage feeds but not system settings', json.dumps({
                                   "dashboard": "rw", "system": "r", "tools": "rw"
                               })))
                    # 3. Read_Only (View Only)
                    db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                               ('Read_Only', 'View access only', json.dumps({
                                   "dashboard": "r", "system": "r", "tools": "r"
                               })))

                # Users Table Migration (Add profile_id)
                cursor = db.execute("PRAGMA table_info(users)")
                user_columns = [info[1] for info in cursor.fetchall()]
                if 'profile_id' not in user_columns:
                    try:
                        # SQLite limitation: Cannot add REFERENCES in ALTER TABLE easily.
                        # Adding column without FK constraint for migration.
                        db.execute('ALTER TABLE users ADD COLUMN profile_id INTEGER DEFAULT 1')
                    except Exception as ex:
                        logger.error(f"Migration error (profile_id): {ex}")

                    # Ensure admin has correct profile
                    db.execute("UPDATE users SET profile_id = 1 WHERE username = 'admin'")

                db.commit()
            except Exception as e:
                logger.error(f"Error initializing database: {e}")
