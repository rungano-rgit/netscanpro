# fix_db.py - Run this to add missing columns
import sqlite3

conn = sqlite3.connect('scanner.db')
c = conn.cursor()

# Check and add missing columns to devices table
c.execute("PRAGMA table_info(devices)")
existing_columns = [col[1] for col in c.fetchall()]
print("Existing columns:", existing_columns)

# Add missing columns
missing_columns = []
for col in ['is_blocked', 'blocked_at', 'firewall_rule_name']:
    if col not in existing_columns:
        missing_columns.append(col)
        if col == 'is_blocked':
            c.execute("ALTER TABLE devices ADD COLUMN is_blocked BOOLEAN DEFAULT 0")
            print("✅ Added is_blocked column")
        elif col == 'blocked_at':
            c.execute("ALTER TABLE devices ADD COLUMN blocked_at TEXT DEFAULT NULL")
            print("✅ Added blocked_at column")
        elif col == 'firewall_rule_name':
            c.execute("ALTER TABLE devices ADD COLUMN firewall_rule_name TEXT DEFAULT NULL")
            print("✅ Added firewall_rule_name column")

# Also check users table
c.execute("PRAGMA table_info(users)")
user_columns = [col[1] for col in c.fetchall()]
if 'email' not in user_columns:
    c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    print("✅ Added email column to users")
    
    # Copy username to email if needed
    c.execute("SELECT id, username FROM users")
    users = c.fetchall()
    for user_id, username in users:
        c.execute("UPDATE users SET email = ? WHERE id = ?", (username, user_id))
    print("✅ Updated email addresses")

# Add role column if missing
if 'role' not in user_columns:
    c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    print("✅ Added role column to users")
    # Set first user as admin if exists
    c.execute("SELECT id FROM users ORDER BY id LIMIT 1")
    first_user = c.fetchone()
    if first_user:
        c.execute("UPDATE users SET role = 'admin' WHERE id = ?", (first_user[0],))
        print("✅ Set first user as admin")

conn.commit()
conn.close()
print("\n✅ Database migration complete!")
print("Restart your application now.")