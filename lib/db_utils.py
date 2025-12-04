import sqlite3
from datetime import datetime

# Open a SQLite database connection safely with timeout
def get_db_connection():
    conn = sqlite3.connect('passwords.db', timeout=10.0, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def safe_decrypt(decrypt_func, data):
    if data is None:
        print(f"[AegisX] safe_decrypt: data is None")
        return None
    if data == '':
        print(f"[AegisX] safe_decrypt: data is empty string")
        return ''
    try:
        decrypted = decrypt_func(data)
        print(f"[AegisX] safe_decrypt: successfully decrypted, length: {len(decrypted) if decrypted else 0}")
        return decrypted if decrypted is not None else ''
    except Exception as e:
        print(f"[AegisX] Decryption error: {e}")
        return ''

# Convert SQLite datetime into readable format
def format_date(raw_date):
    if not raw_date:
        return 'N/A'
    try:
        d = datetime.strptime(raw_date, "%Y-%m-%d %H:%M:%S")
        return d.strftime("%b %d, %Y — %H:%M")
    except Exception:
        return raw_date if raw_date else 'N/A'

def fetch_all_passwords(decrypt_func):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM passwords ORDER BY is_favorite DESC, id DESC")
        rows = cur.fetchall()

    data = []
    for row in rows:
        title_decrypted = safe_decrypt(decrypt_func, row[1]) if len(row) > 1 else None
        username_decrypted = safe_decrypt(decrypt_func, row[2]) if len(row) > 2 else None
        url_decrypted = safe_decrypt(decrypt_func, row[4]) if len(row) > 4 else None

        print(f"[AegisX] Entry {row[0]}: title={title_decrypted}, username={username_decrypted}, url={url_decrypted}")

        entry = {
            "id": row[0],
            "title": title_decrypted if title_decrypted else "Untitled",
            "username": username_decrypted if username_decrypted else "No username",
            "password": safe_decrypt(decrypt_func, row[3]) if len(row) > 3 else "",
            "url": url_decrypted if url_decrypted else "No URL",
            "totp_secret": safe_decrypt(decrypt_func, row[5]) if len(row) > 5 and row[5] else "",
            "last_modified": format_date(row[6]) if len(row) > 6 else "N/A",
            "first_created": format_date(row[7]) if len(row) > 7 else "N/A",
            "is_favorite": row[8] if len(row) > 8 else 0,
            "category": row[9] if len(row) > 9 else "Uncategorized",
            "is_deleted": row[10] if len(row) > 10 else 0,
            "deleted_at": format_date(row[11]) if len(row) > 11 and row[11] else None,
        }
        data.append(entry)
    return data

def get_entry_by_id(id_num, decrypt_func):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM passwords WHERE id=?", (id_num,))
        row = cur.fetchone()
        if not row:
            return None

    title_decrypted = safe_decrypt(decrypt_func, row[1]) if len(row) > 1 else None
    username_decrypted = safe_decrypt(decrypt_func, row[2]) if len(row) > 2 else None
    url_decrypted = safe_decrypt(decrypt_func, row[4]) if len(row) > 4 else None

    print(f"[AegisX] get_entry_by_id {id_num}: title={title_decrypted}, username={username_decrypted}, url={url_decrypted}")

    return {
        "id": row[0],
        "title": title_decrypted if title_decrypted else "Untitled",
        "username": username_decrypted if username_decrypted else "No username",
        "password": safe_decrypt(decrypt_func, row[3]) if len(row) > 3 else "",
        "url": url_decrypted if url_decrypted else "No URL",
        "totp_secret": safe_decrypt(decrypt_func, row[5]) if len(row) > 5 and row[5] else "",
        "last_modified": format_date(row[6]) if len(row) > 6 else "N/A",
        "first_created": format_date(row[7]) if len(row) > 7 else "N/A",
        "is_favorite": row[8] if len(row) > 8 else 0,
        "category": row[9] if len(row) > 9 else "Uncategorized",
        "is_deleted": row[10] if len(row) > 10 else 0,
        "deleted_at": format_date(row[11]) if len(row) > 11 and row[11] else None,
    }
