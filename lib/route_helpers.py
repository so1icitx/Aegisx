from datetime import datetime
import sqlite3

# Get database connection
def get_db_connection():
    conn = sqlite3.connect("passwords.db", timeout=10.0, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Format entry dates for display
def format_entry_dates(last_modified_raw, first_created_raw):
    last_modified = last_modified_raw if last_modified_raw else None
    first_created = first_created_raw if first_created_raw else None

    # Format dates if they exist
    if last_modified:
        try:
            d = datetime.strptime(last_modified, "%Y-%m-%d %H:%M:%S")
            last_modified = d.strftime("%b %d, %Y — %H:%M")
        except Exception:
            pass
    else:
        last_modified = "N/A"

    if first_created:
        try:
            d = datetime.strptime(first_created, "%Y-%m-%d %H:%M:%S")
            first_created = d.strftime("%b %d, %Y — %H:%M")
        except Exception:
            pass
    else:
        first_created = "N/A"

    return last_modified, first_created

# Get passkey opportunities
def get_passkey_opportunities(decrypt_func):
    conn = get_db_connection()
    cur = conn.cursor()

    # Only get passwords where we've explicitly checked and found passkey support
    cur.execute("""
        SELECT p.id, p.title, p.username, p.url, pk.last_checked
        FROM passwords p
        INNER JOIN passkeys pk ON p.id = pk.password_id
        WHERE p.is_deleted = 0
        AND pk.passkey_available = 1
        AND pk.has_passkey = 0
    """)
    rows = cur.fetchall()
    conn.close()

    opportunities = []
    for row in rows:
        opportunities.append({
            "id": row[0],
            "title": decrypt_func(row[1]) if row[1] else "Untitled",
            "username": decrypt_func(row[2]) if row[2] else "",
            "url": decrypt_func(row[3]) if row[3] else "",
            "last_checked": row[4] if row[4] else None
        })

    return opportunities
