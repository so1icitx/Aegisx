import sqlite3
from datetime import datetime


# Get database connection for DB operations
def get_db_connection():
    conn = sqlite3.connect("passwords.db", timeout=10.0, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Initialize the main passwords database with required tables
def init_db():
    conn = sqlite3.connect("passwords.db")
    cur = conn.cursor()
    # Create passwords table with all necessary columns
    cur.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        url TEXT,
        totp_secret TEXT,
        last_modified TEXT,
        first_created TEXT,
        is_favorite INTEGER DEFAULT 0,
        category TEXT DEFAULT 'Uncategorized',
        is_deleted INTEGER DEFAULT 0,
        deleted_at TEXT
    )
    """)
    # Create password history table to track password changes
    cur.execute("""
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_id INTEGER NOT NULL,
        old_password TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE
    )
    """)
    # Create passkeys table to track passkey support for websites
    cur.execute("""
    CREATE TABLE IF NOT EXISTS passkeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_id INTEGER NOT NULL,
        has_passkey INTEGER DEFAULT 0,
        passkey_available INTEGER DEFAULT 0,
        last_checked TEXT,
        FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS passkey_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        username TEXT,
        credential_id TEXT NOT NULL,
        public_key TEXT,
        url TEXT,
        category TEXT DEFAULT 'Uncategorized',
        first_created TEXT,
        last_modified TEXT,
        is_favorite INTEGER DEFAULT 0,
        is_deleted INTEGER DEFAULT 0,
        deleted_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# Migrate existing database to add missing columns for backward compatibility
def migrate_db():
    conn = sqlite3.connect("passwords.db")
    cur = conn.cursor()

    # Get existing columns
    cur.execute("PRAGMA table_info(passwords)")
    columns = [row[1] for row in cur.fetchall()]

    # Add missing columns if they don't exist
    if 'title' not in columns:
        print("[AegisX] Adding 'title' column to database...")
        cur.execute("ALTER TABLE passwords ADD COLUMN title TEXT")

    if 'email' in columns and 'username' not in columns:
        print("[AegisX] Renaming 'email' column to 'username'...")
        cur.execute("ALTER TABLE passwords ADD COLUMN username TEXT")
        cur.execute("UPDATE passwords SET username = email")

    if 'totp_secret' not in columns:
        print("[AegisX] Adding 'totp_secret' column to database...")
        cur.execute("ALTER TABLE passwords ADD COLUMN totp_secret TEXT")

    if 'is_favorite' not in columns:
        print("[AegisX] Adding 'is_favorite' column to database...")
        cur.execute("ALTER TABLE passwords ADD COLUMN is_favorite INTEGER DEFAULT 0")

    if 'category' not in columns:
        print("[AegisX] Adding 'category' column to database...")
        cur.execute("ALTER TABLE passwords ADD COLUMN category TEXT DEFAULT 'Uncategorized'")

    if 'is_deleted' not in columns:
        print("[AegisX] Adding 'is_deleted' column to database...")
        cur.execute("ALTER TABLE passwords ADD COLUMN is_deleted INTEGER DEFAULT 0")

    if 'deleted_at' not in columns:
        print("[AegisX] Adding 'deleted_at' column to database...")
        cur.execute("ALTER TABLE passwords ADD COLUMN deleted_at TEXT")

    # Check if passkeys table exists
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passkeys'")
    if not cur.fetchone():
        print("[AegisX] Creating 'passkeys' table...")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS passkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_id INTEGER NOT NULL,
            has_passkey INTEGER DEFAULT 0,
            passkey_available INTEGER DEFAULT 0,
            last_checked TEXT,
            FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE
        )
        """)

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passkey_credentials'")
    if not cur.fetchone():
        print("[AegisX] Creating 'passkey_credentials' table...")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS passkey_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            username TEXT,
            credential_id TEXT NOT NULL,
            public_key TEXT,
            url TEXT,
            category TEXT DEFAULT 'Uncategorized',
            first_created TEXT,
            last_modified TEXT,
            is_favorite INTEGER DEFAULT 0,
            is_deleted INTEGER DEFAULT 0,
            deleted_at TEXT
        )
        """)

    conn.commit()
    conn.close()
    print("[AegisX] Database migration completed.")
