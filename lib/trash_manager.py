import sqlite3
from flask import session

# Get database connection for trash operations
def get_db_connection():
    conn = sqlite3.connect("passwords.db", timeout=10.0, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Get all trash items from the database
def get_all_trash_items(decrypt_func):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, title, username, url, deleted_at, category FROM passwords WHERE is_deleted=1 ORDER BY deleted_at DESC")
    rows = cur.fetchall()
    conn.close()

    trash_items = []
    for row in rows:
        trash_items.append({
            "id": row[0],
            "title": decrypt_func(row[1]) if row[1] else "",
            "username": decrypt_func(row[2]) if row[2] else "",
            "url": decrypt_func(row[3]) if row[3] else "",
            "deleted_at": row[4] if row[4] else "N/A",
            "category": row[5] if row[5] else "Uncategorized"
        })

    return trash_items

# Get a single trash item by ID with decrypted data
def get_trash_item_by_id(item_id, decrypt_func):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, title, username, url, deleted_at, category FROM passwords WHERE id=? AND is_deleted=1", (item_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "title": decrypt_func(row[1]) if row[1] else "",
        "username": decrypt_func(row[2]) if row[2] else "",
        "url": decrypt_func(row[3]) if row[3] else "",
        "deleted_at": row[4] if row[4] else "N/A",
        "category": row[5] if row[5] else "Uncategorized"
    }

# Restore an item from trash
def restore_from_trash(item_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE passwords SET is_deleted=0, deleted_at=NULL WHERE id=?", (item_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[AegisX] Restore error: {e}")
        return False

# Permanently delete an item from trash
def delete_permanent(item_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM passwords WHERE id=? AND is_deleted=1", (item_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[AegisX] Permanent delete error: {e}")
        return False

# Empty all items from trash
def empty_trash():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM passwords WHERE is_deleted=1")
        deleted_count = cur.rowcount
        conn.commit()
        conn.close()
        return deleted_count
    except Exception as e:
        print(f"[AegisX] Empty trash error: {e}")
        return 0

# Auto-delete trash items older than the configured days on login
def auto_delete_trash_on_login():
    try:
        days = session.get('trash_auto_delete_days', 30)

        if days == 0:
            return

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            DELETE FROM passwords
            WHERE is_deleted=1
            AND datetime(deleted_at) <= datetime('now', '-' || ? || ' days')
        """, (days,))

        deleted_count = cur.rowcount
        conn.commit()
        conn.close()

        if deleted_count > 0:
            print(f"[AegisX] Auto-deleted {deleted_count} old trash items (older than {days} days)")
    except Exception as e:
        print(f"[AegisX] Auto-delete trash error: {e}")
