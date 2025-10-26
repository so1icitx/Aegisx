# lib/db_utils.py
import sqlite3

def fetch_all_passwords(decrypt_func):
    """Fetch and decrypt all passwords from database."""
    conn = sqlite3.connect('passwords.db')
    cur = conn.cursor()
    cur.execute('SELECT * FROM passwords')
    rows = cur.fetchall()
    conn.close()
    
    decrypted_data = []
    for row in rows:
        decrypted_data.append({
            "id": row[0],
            "email": decrypt_func(row[1].decode()) if row[1] else "",
            "password": decrypt_func(row[2].decode()) if row[2] else "",
            "url": decrypt_func(row[3].decode()) if row[3] else "",
            "last_modified": row[4],
            "first_created": row[5]
        })
    
    return decrypted_data
