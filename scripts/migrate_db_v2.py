import sqlite3

def migrate_database():
    """Add new columns to passwords table for login_type, totp_secret, and title"""
    conn = sqlite3.connect('passwords.db')
    cur = conn.cursor()
    
    # Check if columns already exist
    cur.execute("PRAGMA table_info(passwords)")
    columns = [column[1] for column in cur.fetchall()]
    
    # Add login_type column if it doesn't exist
    if 'login_type' not in columns:
        cur.execute("ALTER TABLE passwords ADD COLUMN login_type TEXT DEFAULT 'both'")
        print("[Migration] Added login_type column")
    
    # Add totp_secret column if it doesn't exist
    if 'totp_secret' not in columns:
        cur.execute("ALTER TABLE passwords ADD COLUMN totp_secret TEXT DEFAULT ''")
        print("[Migration] Added totp_secret column")
    
    # Add title column if it doesn't exist
    if 'title' not in columns:
        cur.execute("ALTER TABLE passwords ADD COLUMN title TEXT DEFAULT ''")
        print("[Migration] Added title column")
    
    conn.commit()
    conn.close()
    print("[Migration] Database migration completed successfully")

if __name__ == "__main__":
    migrate_database()
