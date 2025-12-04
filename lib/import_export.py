import json
import csv
import io
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import sqlite3

# Get database connection for import/export operations
def get_db_connection():
    conn = sqlite3.connect("passwords.db", timeout=10.0, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Import passwords from file (JSON, CSV, or PGP)
def import_passwords_from_file(file, manager_type, encrypt_func, decryption_password=None):
    try:
        if not file.filename:
            return (False, 0, "No file selected")

        if not (file.filename.endswith('.json') or file.filename.endswith('.csv') or file.filename.endswith('.pgp')):
            return (False, 0, "Only JSON, CSV, and PGP files are supported")

        content = file.read()
        data = []

        if file.filename.endswith('.pgp') or manager_type == 'aegisx-pgp':
            if not decryption_password:
                return (False, 0, "Decryption password is required for PGP files")

            try:
                encrypted_data = base64.b64decode(content)
                salt = encrypted_data[:16]
                encrypted_content = encrypted_data[16:]

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(decryption_password.encode()))

                f = Fernet(key)
                decrypted_json = f.decrypt(encrypted_content).decode('utf-8')
                data = json.loads(decrypted_json)

            except Exception as e:
                print(f"[AegisX] PGP decryption error: {e}")
                return (False, 0, "Failed to decrypt PGP file. Check your password.")

        elif file.filename.endswith('.json'):
            content_str = content.decode('utf-8')
            data = json.loads(content_str)
            if not isinstance(data, list):
                return (False, 0, "Invalid JSON format. Expected an array of objects.")

        elif file.filename.endswith('.csv'):
            content_str = content.decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(content_str))
            data = list(csv_reader)
            if not data:
                return (False, 0, "CSV file is empty or has no valid data.")

        conn = get_db_connection()
        cur = conn.cursor()
        imported_count = 0

        for entry in data:
            if not isinstance(entry, dict):
                continue

            title = ''
            email = ''
            username = ''
            password = ''
            url = ''
            totp = ''
            category = 'Uncategorized'

            if manager_type == 'aegisx-pgp':
                title = entry.get('title', '').strip()
                username = entry.get('username', '').strip()
                password = entry.get('password', '').strip()
                url = entry.get('url', '').strip()
                totp = entry.get('totp_secret', '').strip()
                category = entry.get('category', 'Uncategorized').strip()
            elif manager_type == '1password':
                title = entry.get('title', entry.get('name', '')).strip()
                email = entry.get('email', '').strip()
                username = entry.get('username', '').strip()
                password = entry.get('password', '').strip()
                url = entry.get('url', entry.get('website', '')).strip()
                totp = entry.get('totp', entry.get('one-time password', '')).strip()
            elif manager_type == 'lastpass':
                title = entry.get('name', '').strip()
                email = entry.get('username', '').strip()
                username = entry.get('username', '').strip()
                password = entry.get('password', '').strip()
                url = entry.get('url', '').strip()
                totp = entry.get('totp', '').strip()
            elif manager_type == 'bitwarden':
                title = entry.get('name', '').strip()
                email = entry.get('login_username', '').strip()
                username = entry.get('login_username', '').strip()
                password = entry.get('login_password', '').strip()
                url = entry.get('login_uri', '').strip()
                totp = entry.get('login_totp', '').strip()
            elif manager_type in ['chrome', 'brave']:
                title = entry.get('name', '').strip()
                email = entry.get('username', '').strip()
                username = entry.get('username', '').strip()
                password = entry.get('password', '').strip()
                url = entry.get('url', '').strip()
            elif manager_type == 'firefox':
                title = entry.get('url', '').strip()
                email = entry.get('username', '').strip()
                username = entry.get('username', '').strip()
                password = entry.get('password', '').strip()
                url = entry.get('url', '').strip()
            elif manager_type == 'safari':
                title = entry.get('Title', '').strip()
                email = entry.get('Username', '').strip()
                username = entry.get('Username', '').strip()
                password = entry.get('Password', '').strip()
                url = entry.get('URL', '').strip()
                totp = entry.get('OTPAuth', '').strip()
            else:
                title = entry.get('title', entry.get('name', '')).strip()
                email = entry.get('email', entry.get('username', '')).strip()
                username = entry.get('username', '').strip()
                password = entry.get('password', '').strip()
                url = entry.get('url', entry.get('website', '')).strip()
                totp = entry.get('totp', entry.get('otp', '')).strip()

            login_field = email if email else username

            if not login_field or not password:
                continue

            cur.execute(
                "INSERT INTO passwords (title, username, password, url, totp_secret, category, first_created, last_modified) VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'), datetime('now','localtime'))",
                (encrypt_func(title or url), encrypt_func(login_field), encrypt_func(password), encrypt_func(url), encrypt_func(totp) if totp else None, category)
            )
            imported_count += 1

        conn.commit()
        conn.close()

        return (True, imported_count, None)

    except json.JSONDecodeError:
        return (False, 0, "Invalid JSON file format")
    except csv.Error as e:
        return (False, 0, f"Invalid CSV file format: {str(e)}")
    except Exception as e:
        print(f"[AegisX] Import error: {e}")
        return (False, 0, f"Import failed: {str(e)}")

# Export passwords in specified format
def export_passwords(ids, export_format, decrypt_func, encryption_password=None):
    try:
        if not ids or not isinstance(ids, list):
            return (False, None, None, None, "Invalid request")

        conn = get_db_connection()
        cur = conn.cursor()

        placeholders = ','.join('?' * len(ids))
        cur.execute(f"SELECT id, title, username, password, url, totp_secret, category FROM passwords WHERE id IN ({placeholders})", ids)
        rows = cur.fetchall()
        conn.close()

        decrypted_data = []
        for row in rows:
            decrypted_data.append({
                "id": row[0],
                "title": decrypt_func(row[1]) if row[1] else "",
                "username": decrypt_func(row[2]),
                "password": decrypt_func(row[3]),
                "url": decrypt_func(row[4]) if row[4] else "",
                "totp_secret": decrypt_func(row[5]) if row[5] else "",
                "category": row[6] if row[6] else "Uncategorized"
            })

        if export_format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["title", "username", "password", "url", "totp_secret", "category"])
            for entry in decrypted_data:
                writer.writerow([
                    entry["title"],
                    entry["username"],
                    entry["password"],
                    entry["url"],
                    entry["totp_secret"],
                    entry["category"]
                ])
            return (True, output.getvalue(), "text/csv", f"aegisx_export_{len(ids)}_items.csv", None)

        elif export_format == "pgp":
            if not encryption_password:
                return (False, None, None, None, "Encryption password is required for PGP export")

            json_data = json.dumps(decrypted_data, indent=2)

            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(encryption_password.encode()))

            f = Fernet(key)
            encrypted_data = f.encrypt(json_data.encode())

            pgp_data = base64.b64encode(salt + encrypted_data).decode()

            return (True, pgp_data, "application/pgp-encrypted", f"aegisx_export_{len(ids)}_items.pgp", None)

        else:
            json_data = json.dumps(decrypted_data, indent=2)
            return (True, json_data, "application/json", f"aegisx_export_{len(ids)}_items.json", None)

    except Exception as e:
        print(f"[AegisX] Export error: {e}")
        return (False, None, None, None, "Failed to export passwords")
