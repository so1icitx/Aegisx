import sqlite3

# Get database connection for security analysis
def get_db_connection():
    conn = sqlite3.connect("passwords.db", timeout=10.0, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Analyze all passwords for security issues
def analyze_password_security(decrypt_func, check_strength_func, check_breach_func, check_email_breach_func):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, title, username, password, url, is_deleted FROM passwords")
    rows = cur.fetchall()
    conn.close()

    stats = {
        'total': 0,
        'weak': 0,
        'breached': 0,
        'strong': 0,
        'duplicates': 0,
        'breached_emails': 0,
        'weak_passwords': [],
        'breached_passwords': [],
        'duplicate_passwords': [],
        'breached_emails_list': []
    }

    password_map = {}
    email_set = set()

    for row in rows:
        if row[5]:
            continue

        pwd_id = row[0]
        encrypted_title = row[1]
        encrypted_username = row[2]
        encrypted_pwd = row[3]
        encrypted_url = row[4]

        try:
            decrypted_pwd = decrypt_func(encrypted_pwd)
            decrypted_title = decrypt_func(encrypted_title) if encrypted_title else ""
            decrypted_username = decrypt_func(encrypted_username) if encrypted_username else ""
            decrypted_url = decrypt_func(encrypted_url) if encrypted_url else ""

            stats['total'] += 1

            strength = check_strength_func(decrypted_pwd, check_breach_func)

            if strength == 'weak':
                stats['weak'] += 1
                stats['weak_passwords'].append({
                    'id': pwd_id,
                    'title': decrypted_title or decrypted_url or 'Untitled',
                    'username': decrypted_username,
                    'strength': strength
                })
            elif strength == 'breached':
                is_breached, breach_count = check_breach_func(decrypted_pwd)
                stats['breached'] += 1
                stats['breached_passwords'].append({
                    'id': pwd_id,
                    'title': decrypted_title or decrypted_url or 'Untitled',
                    'username': decrypted_username,
                    'strength': strength,
                    'breach_count': breach_count
                })
            else:
                stats['strong'] += 1

            if decrypted_pwd in password_map:
                if len(password_map[decrypted_pwd]) == 1:
                    original_id = password_map[decrypted_pwd][0]
                    temp_conn = get_db_connection()
                    cur_dup = temp_conn.cursor()
                    cur_dup.execute("SELECT id, title, username, url FROM passwords WHERE id=?", (original_id,))
                    orig_row = cur_dup.fetchone()
                    if orig_row:
                        stats['duplicate_passwords'].append({
                            'id': orig_row[0],
                            'title': decrypt_func(orig_row[1]) if orig_row[1] else decrypt_func(orig_row[3]) if orig_row[3] else 'Untitled',
                            'username': decrypt_func(orig_row[2]) if orig_row[2] else ''
                        })
                    cur_dup.close()
                    temp_conn.close()

                password_map[decrypted_pwd].append(pwd_id)
                stats['duplicate_passwords'].append({
                    'id': pwd_id,
                    'title': decrypted_title or decrypted_url or 'Untitled',
                    'username': decrypted_username
                })
            else:
                password_map[decrypted_pwd] = [pwd_id]

            if decrypted_username and '@' in decrypted_username:
                email_lower = decrypted_username.lower()
                if email_lower not in email_set:
                    email_set.add(email_lower)
                    is_email_breached, breach_count, breaches = check_email_breach_func(decrypted_username)
                    if is_email_breached:
                        stats['breached_emails'] += 1
                        stats['breached_emails_list'].append({
                            'email': decrypted_username,
                            'breach_count': breach_count,
                            'breaches': breaches,
                            'password_ids': [pwd_id]
                        })

        except Exception as e:
            print(f"[AegisX] Error analyzing password {pwd_id}: {e}")
            continue

    unique_duplicate_ids = set()
    final_duplicate_passwords = []
    for dup_entry in stats['duplicate_passwords']:
        if dup_entry['id'] not in unique_duplicate_ids:
            final_duplicate_passwords.append(dup_entry)
            unique_duplicate_ids.add(dup_entry['id'])
    stats['duplicate_passwords'] = final_duplicate_passwords
    stats['duplicates'] = len(stats['duplicate_passwords'])

    stats['hibp_breaches'] = []
    for email_breach in stats.get('breached_emails_list', []):
        for breach in email_breach.get('breaches', []):
            if isinstance(breach, dict):
                stats['hibp_breaches'].append(breach)

    return stats
