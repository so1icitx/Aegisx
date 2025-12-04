import hashlib
import json
import sqlite3
import requests
import os

# Initialize breach cache database to store HIBP check results
def init_breach_cache_db():
    conn = sqlite3.connect("breach_cache.db")
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS breach_cache (
        password_hash TEXT PRIMARY KEY,
        is_breached INTEGER NOT NULL,
        breach_count INTEGER DEFAULT 0,
        checked_at TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_checked_at ON breach_cache(checked_at)
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS email_breaches (
        email_hash TEXT PRIMARY KEY,
        is_breached INTEGER NOT NULL,
        breach_count INTEGER DEFAULT 0,
        breach_data TEXT,
        checked_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

# Check if password has been breached using HIBP API with k-anonymity
def check_password_breach(password, use_cache=True):
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        if use_cache:
            conn = sqlite3.connect("breach_cache.db")
            cur = conn.cursor()

            cur.execute("""
                SELECT is_breached, breach_count
                FROM breach_cache
                WHERE password_hash = ?
                AND datetime(checked_at) > datetime('now', '-30 days')
            """, (sha1_hash,))

            cached = cur.fetchone()
            conn.close()

            if cached:
                print(f"[AegisX] Using cached breach result for password")
                return (bool(cached[0]), cached[1])

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)

        is_breached = False
        breach_count = 0

        if response.status_code == 200:
            hashes = response.text.split('\r\n')
            for hash_line in hashes:
                if ':' not in hash_line:
                    continue
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    is_breached = True
                    breach_count = int(count)
                    break

        if use_cache:
            try:
                conn = sqlite3.connect("breach_cache.db")
                cur = conn.cursor()
                cur.execute("""
                    INSERT OR REPLACE INTO breach_cache (password_hash, is_breached, breach_count, checked_at)
                    VALUES (?, ?, ?, datetime('now'))
                """, (sha1_hash, int(is_breached), breach_count))
                conn.commit()
                conn.close()
                print(f"[AegisX] Cached breach result for password (breached: {is_breached}, count: {breach_count})")
            except Exception as cache_error:
                print(f"[AegisX] Failed to cache breach result: {cache_error}")

        return (is_breached, breach_count)
    except Exception as e:
        print(f"[AegisX] HIBP check error: {e}")
        return (False, 0)

# Check if email has been found in data breaches using HIBP API
def check_email_breach(email, use_cache=True):
    try:
        email_hash = hashlib.sha256(email.lower().encode('utf-8')).hexdigest()

        if use_cache:
            conn = sqlite3.connect("breach_cache.db")
            cur = conn.cursor()

            cur.execute("""
            CREATE TABLE IF NOT EXISTS email_breaches (
                email_hash TEXT PRIMARY KEY,
                is_breached INTEGER NOT NULL,
                breach_count INTEGER DEFAULT 0,
                breach_data TEXT,
                checked_at TEXT NOT NULL
            )
            """)

            cur.execute("""
                SELECT is_breached, breach_count, breach_data
                FROM email_breaches
                WHERE email_hash = ?
                AND datetime(checked_at) > datetime('now', '-7 days')
            """, (email_hash,))

            cached = cur.fetchone()
            conn.close()

            if cached:
                print(f"[AegisX] Using cached email breach result")
                breaches = json.loads(cached[2]) if cached[2] else []
                return (bool(cached[0]), cached[1], breaches)

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {
            'User-Agent': 'AegisX-Password-Manager',
            'hibp-api-key': os.getenv('HIBP_API_KEY', '')
        }

        response = requests.get(url, headers=headers, timeout=5)

        is_breached = False
        breach_count = 0
        breaches = []

        if response.status_code == 200:
            breaches = response.json()
            is_breached = True
            breach_count = len(breaches)
        elif response.status_code == 404:
            is_breached = False

        if use_cache:
            try:
                conn = sqlite3.connect("breach_cache.db")
                cur = conn.cursor()
                cur.execute("""
                    INSERT OR REPLACE INTO email_breaches (email_hash, is_breached, breach_count, breach_data, checked_at)
                    VALUES (?, ?, ?, ?, datetime('now'))
                """, (email_hash, int(is_breached), breach_count, json.dumps(breaches)))
                conn.commit()
                conn.close()
                print(f"[AegisX] Cached email breach result (breached: {is_breached}, count: {breach_count})")
            except Exception as cache_error:
                print(f"[AegisX] Failed to cache email breach result: {cache_error}")

        return (is_breached, breach_count, breaches)
    except Exception as e:
        print(f"[AegisX] Email breach check error: {e}")
        return (False, 0, [])

init_breach_cache_db()
