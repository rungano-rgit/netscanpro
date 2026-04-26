"""
NETSCANPRO ENTERPRISE - Complete Production Version
Multi-User Network Scanner with Firewall Block Feature
Compatible with: Render.com, Heroku, Local Development
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from flask_cors import CORS
import subprocess
import socket
import ipaddress
import platform
import threading
import sqlite3
import time
import hashlib
import os
import ctypes
import logging
import sys
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse
from dotenv import load_dotenv

# Optional imports for PostgreSQL
try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ==================== CONFIGURATION ====================

app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-in-production-2024')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('FLASK_ENV', 'development') == 'production',
    JSON_SORT_KEYS=False
)

CORS(app)

# Initialize database on app startup (before routes are registered)
@app.before_request
def init_db_on_startup():
    """Initialize database on first request if not already done"""
    if not hasattr(app, '_db_initialized'):
        try:
            safe_init_db()
            app._db_initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            app._db_initialized = False

# Environment detection
IS_PRODUCTION = os.getenv('FLASK_ENV') == 'production' or os.getenv('RENDER') == 'true'
IS_RENDER = os.getenv('RENDER') == 'true'
IS_HEROKU = os.getenv('HEROKU') == 'true'
IS_LOCAL = not (IS_RENDER or IS_HEROKU)

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and ('postgres' in DATABASE_URL or 'postgresql' in DATABASE_URL):
    DB_BACKEND = 'postgres'
    DB_SOURCE = DATABASE_URL
else:
    DB_BACKEND = 'sqlite'
    DB_SOURCE = os.getenv('SCANNER_DB', 'scanner.db')
    # Ensure directory exists for SQLite
    db_dir = os.path.dirname(DB_SOURCE)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

# Logging configuration
LOG_FILE = os.getenv('SCANNER_LOG', 'audit.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('netscanpro')

print(f"🔧 Configuration: DB_BACKEND={DB_BACKEND}, IS_PRODUCTION={IS_PRODUCTION}")

# ==================== HELPER FUNCTIONS ====================

def safe_init_db():
    """Initialize database with retry logic and error handling"""
    try:
        init_db()
        logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        if IS_PRODUCTION:
            # In production, log the error but don't crash the app
            logger.warning("App starting without database initialized - table creation will be attempted on first request")
        else:
            # In development, raise the error for visibility
            raise

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_db():
    """Get database connection"""
    if DB_BACKEND == 'postgres':
        if not POSTGRES_AVAILABLE:
            raise ImportError("PostgreSQL support not available. Install psycopg2-binary.")
        conn = psycopg2.connect(DB_SOURCE)
        return conn
    else:
        conn = sqlite3.connect(DB_SOURCE)
        conn.row_factory = sqlite3.Row
        return conn

def convert_query(query):
    """Convert SQLite ? placeholders to PostgreSQL %s placeholders"""
    return query.replace('?', '%s') if DB_BACKEND == 'postgres' else query

def get_cursor(conn):
    """Get database cursor (works for both SQLite and PostgreSQL)"""
    if DB_BACKEND == 'postgres':
        if not POSTGRES_AVAILABLE:
            raise ImportError("PostgreSQL support not available. Install psycopg2-binary.")
        
        class PostgresCursorWrapper:
            def __init__(self, cursor):
                self._cursor = cursor
            
            def execute(self, query, params=None):
                converted_query = convert_query(query)
                if params is None:
                    return self._cursor.execute(converted_query)
                else:
                    return self._cursor.execute(converted_query, params)
            
            def executemany(self, query, params_list):
                converted_query = convert_query(query)
                return self._cursor.executemany(converted_query, params_list)
            
            def fetchone(self):
                return self._cursor.fetchone()
            
            def fetchall(self):
                return self._cursor.fetchall()
            
            def close(self):
                return self._cursor.close()
            
            def __getattr__(self, name):
                return getattr(self._cursor, name)
        
        raw_cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return PostgresCursorWrapper(raw_cursor)
    else:
        return conn.cursor()

def get_table_columns(conn, table_name):
    """Get column names for a table (works for both SQLite and PostgreSQL)"""
    if DB_BACKEND == 'postgres':
        c = get_cursor(conn)
        c.execute("SELECT column_name FROM information_schema.columns WHERE table_name = %s", (table_name,))
        columns = [row['column_name'] for row in c.fetchall()]
        c.close()
        return columns
    else:
        c = get_cursor(conn)
        c.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in c.fetchall()]
        c.close()
        return columns

def is_admin():
    """Check if running as administrator (Windows)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_windows():
    """Check if running on Windows"""
    return platform.system().lower() == 'windows'

def log_audit_event(user_id, event_type, description):
    """Record an audit event and log it to file."""
    try:
        conn = get_db()
        c = get_cursor(conn)
        if DB_BACKEND == 'postgres':
            c.execute('''INSERT INTO audit_logs (user_id, event_type, description, created_at)
                         VALUES (%s, %s, %s, %s)''',
                      (user_id, event_type, description, datetime.now().isoformat()))
        else:
            c.execute('''INSERT INTO audit_logs (user_id, event_type, description, created_at)
                         VALUES (?, ?, ?, ?)''',
                      (user_id, event_type, description, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        logger.info(f"{event_type} | user_id={user_id} | {description}")
    except Exception as e:
        logger.error(f"Audit log error: {e}")

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize all database tables with proper error handling"""
    try:
        conn = get_db()
        c = get_cursor(conn)
        
        # Users table
        if DB_BACKEND == 'postgres':
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE,
                username TEXT UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        else:
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                username TEXT UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )''')
        
        # Check and add missing columns
        columns = get_table_columns(conn, 'users')
        
        if 'email' not in columns and 'username' in columns:
            if DB_BACKEND == 'postgres':
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            else:
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            c.execute("UPDATE users SET email = username WHERE email IS NULL")
            print("✅ Migrated users table: added email column")
        elif 'email' not in columns:
            if DB_BACKEND == 'postgres':
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            else:
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            print("✅ Added email column to users table")
        
        if 'role' not in columns:
            if DB_BACKEND == 'postgres':
                c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            else:
                c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            print("✅ Added role column to users table")
        
        # Ensure existing users have a role value
        c.execute("UPDATE users SET role = 'user' WHERE role IS NULL")
        
        # Ensure at least one admin exists
        if DB_BACKEND == 'postgres':
            c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_count = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_count = c.fetchone()[0]
        
        if admin_count == 0:
            if DB_BACKEND == 'postgres':
                c.execute("SELECT id FROM users ORDER BY id LIMIT 1")
            else:
                c.execute("SELECT id FROM users ORDER BY id LIMIT 1")
            first_user = c.fetchone()
            if first_user:
                if DB_BACKEND == 'postgres':
                    c.execute("UPDATE users SET role = 'admin' WHERE id = %s", (first_user['id'],))
                else:
                    c.execute("UPDATE users SET role = 'admin' WHERE id = ?", (first_user['id'],))
                print("✅ Set first user as admin")
        
        # Scans table
        if DB_BACKEND == 'postgres':
            c.execute('''CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                target_range TEXT NOT NULL,
                device_count INTEGER DEFAULT 0,
                duration REAL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        else:
            c.execute('''CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                target_range TEXT NOT NULL,
                device_count INTEGER DEFAULT 0,
                duration REAL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        
        # Devices table
        if DB_BACKEND == 'postgres':
            c.execute('''CREATE TABLE IF NOT EXISTS devices (
                id SERIAL PRIMARY KEY,
                scan_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT DEFAULT 'Active',
                response_time TEXT DEFAULT '-',
                hostname TEXT DEFAULT 'Unknown',
                operating_system TEXT DEFAULT 'Unknown',
                device_status TEXT DEFAULT 'Unknown',
                notes TEXT DEFAULT '',
                flagged BOOLEAN DEFAULT FALSE,
                is_blocked BOOLEAN DEFAULT FALSE,
                blocked_at TIMESTAMP,
                firewall_rule_name TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        else:
            c.execute('''CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT DEFAULT 'Active',
                response_time TEXT DEFAULT '-',
                hostname TEXT DEFAULT 'Unknown',
                operating_system TEXT DEFAULT 'Unknown',
                device_status TEXT DEFAULT 'Unknown',
                notes TEXT DEFAULT '',
                flagged BOOLEAN DEFAULT 0,
                is_blocked BOOLEAN DEFAULT 0,
                blocked_at TEXT DEFAULT NULL,
                firewall_rule_name TEXT DEFAULT NULL,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        
        # Audit logs table
        if DB_BACKEND == 'postgres':
            c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        else:
            c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        
        # Create default admin user if no users exist
        if DB_BACKEND == 'postgres':
            c.execute("SELECT COUNT(*) FROM users")
            count = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) FROM users")
            count = c.fetchone()[0]
        
        if count == 0:
            default_password = hash_password("admin123")
            if DB_BACKEND == 'postgres':
                c.execute("INSERT INTO users (email, username, password, role) VALUES (%s, %s, %s, %s)",
                          ("admin@netscanpro.com", "admin", default_password, "admin"))
            else:
                c.execute("INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)",
                          ("admin@netscanpro.com", "admin", default_password, "admin"))
            print("✅ Created default admin user: admin@netscanpro.com / admin123")
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully!")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise

# ==================== FIREWALL FUNCTIONS ====================

def add_firewall_block_rule(ip_address, rule_name=None):
    """Create Windows Firewall rules to block a specific IP address"""
    if not is_windows():
        return False, "Firewall blocking only available on Windows"
    
    if not is_admin():
        return False, "Administrator privileges required. Run Python as Administrator."
    
    if IS_PRODUCTION:
        return False, "Firewall blocking disabled in cloud environment"
    
    if rule_name is None:
        rule_name = f"Block_Device_{ip_address.replace('.', '_')}"
    
    results = []
    
    inbound_cmd = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_address} protocol=any'
    outbound_cmd = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_address} protocol=any'
    
    try:
        result_in = subprocess.run(inbound_cmd, shell=True, capture_output=True, text=True)
        if result_in.returncode == 0:
            results.append("Inbound rule created")
        else:
            results.append(f"Inbound failed: {result_in.stderr}")
        
        result_out = subprocess.run(outbound_cmd, shell=True, capture_output=True, text=True)
        if result_out.returncode == 0:
            results.append("Outbound rule created")
        else:
            results.append(f"Outbound failed: {result_out.stderr}")
        
        return True, " | ".join(results)
    except Exception as e:
        return False, f"Error: {str(e)}"

def remove_firewall_block_rule(ip_address):
    """Remove Windows Firewall rules for a specific IP address"""
    if not is_windows():
        return False, "Firewall blocking only available on Windows"
    
    rule_name = f"Block_Device_{ip_address.replace('.', '_')}"
    
    delete_inbound = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
    delete_outbound = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
    
    try:
        subprocess.run(delete_inbound, shell=True, capture_output=True, text=True)
        subprocess.run(delete_outbound, shell=True, capture_output=True, text=True)
        return True, f"Firewall rules removed for {ip_address}"
    except Exception as e:
        return False, f"Error: {str(e)}"

# ==================== NETWORK SCANNING FUNCTIONS ====================

def ping_host(ip, timeout=2):
    """Ping a single IP address"""
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except:
        return False

def get_hostname(ip):
    """Get hostname from IP address"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_ttl(ip):
    """Extract TTL from ping response"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(
            ['ping', param, '1', ip],
            capture_output=True,
            text=True,
            timeout=3
        )
        output = result.stdout.lower()
        if 'ttl=' in output:
            return int(output.split('ttl=')[1].split()[0])
    except:
        pass
    return 128

def detect_os_from_ttl(ttl):
    """Detect OS based on TTL value"""
    if ttl <= 64:
        return "Linux/Unix/macOS"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Router/Network Device"
    return "Unknown"

def scan_network_range(target, timeout=2, progress_callback=None):
    """Scan a network range and return discovered devices"""
    results = []
    try:
        network = ipaddress.ip_network(target, strict=False)
        total = sum(1 for _ in network.hosts())
        scanned = 0
        
        for ip in network.hosts():
            ip_str = str(ip)
            scanned += 1
            
            if progress_callback:
                progress_callback(scanned, total, len(results))
            
            if ping_host(ip_str, timeout):
                hostname = get_hostname(ip_str)
                ttl = get_ttl(ip_str)
                os_guess = detect_os_from_ttl(ttl)
                
                results.append({
                    'ip': ip_str,
                    'status': 'Active',
                    'response_time': '<1ms',
                    'hostname': hostname,
                    'os': os_guess
                })
        
        return results
    except Exception as e:
        return {'error': str(e)}

# ==================== DATABASE OPERATIONS ====================

def save_scan_to_db(scan_id, user_id, target_range, devices, duration):
    """Save scan results to database"""
    conn = get_db()
    c = get_cursor(conn)
    
    if DB_BACKEND == 'postgres':
        c.execute('''INSERT INTO scans (scan_id, user_id, timestamp, target_range, device_count, duration)
                     VALUES (%s, %s, %s, %s, %s, %s)''',
                  (scan_id, user_id, datetime.now().isoformat(), target_range, len(devices), duration))
        for device in devices:
            c.execute('''INSERT INTO devices (scan_id, user_id, ip_address, status, response_time, hostname, operating_system)
                         VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                      (scan_id, user_id, device['ip'], device['status'], 
                       device.get('response_time', '-'), device.get('hostname', 'Unknown'), 
                       device.get('os', 'Unknown')))
    else:
        c.execute('''INSERT INTO scans (scan_id, user_id, timestamp, target_range, device_count, duration)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (scan_id, user_id, datetime.now().isoformat(), target_range, len(devices), duration))
        for device in devices:
            c.execute('''INSERT INTO devices (scan_id, user_id, ip_address, status, response_time, hostname, operating_system)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (scan_id, user_id, device['ip'], device['status'], 
                       device.get('response_time', '-'), device.get('hostname', 'Unknown'), 
                       device.get('os', 'Unknown')))
    
    conn.commit()
    conn.close()

def get_user_scans(user_id, limit=50):
    """Get all scans for a specific user"""
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('''SELECT scan_id, timestamp, target_range, device_count, duration 
                     FROM scans WHERE user_id=%s ORDER BY timestamp DESC LIMIT %s''', 
                  (user_id, limit))
    else:
        c.execute('''SELECT scan_id, timestamp, target_range, device_count, duration 
                     FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT ?''', 
                  (user_id, limit))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_devices_by_user(user_id, scan_id=None):
    """Get all devices for a user"""
    conn = get_db()
    c = get_cursor(conn)
    if scan_id:
        if DB_BACKEND == 'postgres':
            c.execute('''SELECT * FROM devices WHERE user_id=%s AND scan_id=%s ORDER BY ip_address''', 
                      (user_id, scan_id))
        else:
            c.execute('''SELECT * FROM devices WHERE user_id=? AND scan_id=? ORDER BY ip_address''', 
                      (user_id, scan_id))
    else:
        if DB_BACKEND == 'postgres':
            c.execute('''SELECT * FROM devices WHERE user_id=%s ORDER BY last_seen DESC''', 
                      (user_id,))
        else:
            c.execute('''SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC''', 
                      (user_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_device_info(device_id, user_id, device_status=None, notes=None, flagged=None):
    """Update device status, notes, or flag"""
    conn = get_db()
    c = get_cursor(conn)
    updates = []
    params = []
    
    if device_status is not None:
        updates.append('device_status = ?' if DB_BACKEND == 'sqlite' else 'device_status = %s')
        params.append(device_status)
    if notes is not None:
        updates.append('notes = ?' if DB_BACKEND == 'sqlite' else 'notes = %s')
        params.append(notes)
    if flagged is not None:
        updates.append('flagged = ?' if DB_BACKEND == 'sqlite' else 'flagged = %s')
        params.append(1 if flagged else 0)
    
    if not updates:
        conn.close()
        return
    
    query = f"UPDATE devices SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
    query = query.replace('?', '%s') if DB_BACKEND == 'postgres' else query
    params.extend([device_id, user_id])
    c.execute(query, params)
    conn.commit()
    conn.close()

def update_device_block_status(device_id, user_id, is_blocked, rule_name=None):
    """Update device block status in database"""
    conn = get_db()
    c = get_cursor(conn)
    
    columns = get_table_columns(conn, 'devices')
    
    if 'is_blocked' not in columns:
        if DB_BACKEND == 'postgres':
            c.execute("ALTER TABLE devices ADD COLUMN is_blocked BOOLEAN DEFAULT FALSE")
            c.execute("ALTER TABLE devices ADD COLUMN blocked_at TIMESTAMP")
            c.execute("ALTER TABLE devices ADD COLUMN firewall_rule_name TEXT")
        else:
            c.execute("ALTER TABLE devices ADD COLUMN is_blocked BOOLEAN DEFAULT 0")
            c.execute("ALTER TABLE devices ADD COLUMN blocked_at TEXT DEFAULT NULL")
            c.execute("ALTER TABLE devices ADD COLUMN firewall_rule_name TEXT DEFAULT NULL")
        conn.commit()
    
    if is_blocked:
        if DB_BACKEND == 'postgres':
            c.execute('''UPDATE devices SET is_blocked = TRUE, blocked_at = %s, firewall_rule_name = %s 
                         WHERE id = %s AND user_id = %s''',
                      (datetime.now().isoformat(), rule_name, device_id, user_id))
        else:
            c.execute('''UPDATE devices SET is_blocked = 1, blocked_at = ?, firewall_rule_name = ? 
                         WHERE id = ? AND user_id = ?''',
                      (datetime.now().isoformat(), rule_name, device_id, user_id))
    else:
        if DB_BACKEND == 'postgres':
            c.execute('''UPDATE devices SET is_blocked = FALSE, blocked_at = NULL, firewall_rule_name = NULL 
                         WHERE id = %s AND user_id = %s''',
                      (device_id, user_id))
        else:
            c.execute('''UPDATE devices SET is_blocked = 0, blocked_at = NULL, firewall_rule_name = NULL 
                         WHERE id = ? AND user_id = ?''',
                      (device_id, user_id))
    conn.commit()
    conn.close()

def delete_scan(scan_id, user_id):
    """Delete a scan and all its devices"""
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('DELETE FROM devices WHERE scan_id=%s AND user_id=%s', (scan_id, user_id))
        c.execute('DELETE FROM scans WHERE scan_id=%s AND user_id=%s', (scan_id, user_id))
    else:
        c.execute('DELETE FROM devices WHERE scan_id=? AND user_id=?', (scan_id, user_id))
        c.execute('DELETE FROM scans WHERE scan_id=? AND user_id=?', (scan_id, user_id))
    conn.commit()
    conn.close()

# ==================== AUTHENTICATION DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('user_role') != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== FLASK ROUTES ====================

active_scans = {}

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        
        conn = get_db()
        c = get_cursor(conn)
        if DB_BACKEND == 'postgres':
            c.execute('SELECT id, email, role FROM users WHERE email=%s AND password=%s', (email, password))
        else:
            c.execute('SELECT id, email, role FROM users WHERE email=? AND password=?', (email, password))
        user = c.fetchone()
        
        if not user:
            if DB_BACKEND == 'postgres':
                c.execute('SELECT id, username, role FROM users WHERE username=%s AND password=%s', (email, password))
            else:
                c.execute('SELECT id, username, role FROM users WHERE username=? AND password=?', (email, password))
            user = c.fetchone()
            if user:
                if DB_BACKEND == 'postgres':
                    c.execute('UPDATE users SET email = %s WHERE id = %s', (email, user['id']))
                else:
                    c.execute('UPDATE users SET email = ? WHERE id = ?', (email, user['id']))
                conn.commit()
        
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['user_email'] = user['email'] if user['email'] else email
            session['user_role'] = user.get('role') or 'user'
            log_audit_event(user['id'], 'login', 'User logged in successfully')
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Login failed for email={email}")
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])
        
        conn = get_db()
        c = get_cursor(conn)
        try:
            if DB_BACKEND == 'postgres':
                c.execute('INSERT INTO users (email, password, role) VALUES (%s, %s, %s)', (email, password, 'user'))
            else:
                c.execute('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', (email, password, 'user'))
            conn.commit()
            if DB_BACKEND == 'postgres':
                c.execute('SELECT id FROM users WHERE email=%s', (email,))
                user_row = c.fetchone()
                user_id = user_row['id'] if user_row else None
            else:
                user_id = c.lastrowid
            log_audit_event(user_id, 'register', 'New user registered')
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Email already registered', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit_event(session['user_id'], 'logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', 
                         email=session.get('user_email', 'User'),
                         user_role=session.get('user_role', 'user'),
                         is_admin=session.get('user_role') == 'admin')

@app.route('/devices')
@login_required
def device_manager():
    return render_template('devices.html', 
                         email=session.get('user_email', 'User'), 
                         user_role=session.get('user_role', 'user'),
                         is_admin=session.get('user_role') == 'admin')

# ==================== API ENDPOINTS ====================

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    if IS_PRODUCTION and IS_RENDER:
        return jsonify({'error': 'Network scanning is not supported from cloud hosting. Run the app locally to scan your LAN.'}), 400

    data = request.get_json()
    target = data.get('target')
    timeout = int(data.get('timeout', 2))
    user_id = session['user_id']
    
    try:
        ipaddress.ip_network(target, strict=False)
    except:
        return jsonify({'error': 'Invalid IP range format'}), 400
    
    scan_id = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    active_scans[scan_id] = {'user_id': user_id, 'status': 'starting', 'progress': 0}
    
    def run_scan():
        start_time = time.time()
        
        def update_progress(scanned, total, found):
            active_scans[scan_id] = {
                'user_id': user_id, 
                'status': 'running', 
                'progress': (scanned / total) * 100, 
                'active_count': found
            }
        
        results = scan_network_range(target, timeout, update_progress)
        duration = time.time() - start_time
        
        if not isinstance(results, dict):
            save_scan_to_db(scan_id, user_id, target, results, duration)
            active_scans[scan_id] = {
                'user_id': user_id, 
                'status': 'complete', 
                'results': results, 
                'active_count': len(results)
            }
            log_audit_event(user_id, 'scan_complete', f'Scanned {target}, found {len(results)} devices')
        else:
            active_scans[scan_id] = {'user_id': user_id, 'status': 'error', 'error': results.get('error')}
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    log_audit_event(user_id, 'scan_start', f'Scan started for {target} with id {scan_id}')
    
    return jsonify({'scan_id': scan_id})

@app.route('/api/scan/<scan_id>/status')
@login_required
def scan_status(scan_id):
    if scan_id in active_scans:
        data = active_scans[scan_id].copy()
        if 'results' in data:
            del data['results']
        return jsonify(data)
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scan/<scan_id>/results')
@login_required
def scan_results(scan_id):
    user_id = session['user_id']
    
    if scan_id in active_scans and active_scans[scan_id].get('status') == 'complete':
        return jsonify({'results': active_scans[scan_id].get('results', [])})
    
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('''SELECT ip_address, status, response_time, hostname, operating_system 
                     FROM devices WHERE scan_id=%s AND user_id=%s''', 
                  (scan_id, user_id))
    else:
        c.execute('''SELECT ip_address, status, response_time, hostname, operating_system 
                     FROM devices WHERE scan_id=? AND user_id=?''', 
                  (scan_id, user_id))
    rows = c.fetchall()
    conn.close()
    
    if rows:
        results = [{
            'ip': r['ip_address'],
            'status': r['status'],
            'response_time': r['response_time'],
            'hostname': r['hostname'],
            'os': r['operating_system']
        } for r in rows]
        return jsonify({'results': results})
    
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/history')
@login_required
def get_history():
    user_id = session['user_id']
    scans = get_user_scans(user_id)
    return jsonify(scans)

@app.route('/api/history/<scan_id>', methods=['DELETE'])
@login_required
def delete_scan_route(scan_id):
    user_id = session['user_id']
    delete_scan(scan_id, user_id)
    log_audit_event(user_id, 'scan_delete', f'Scan {scan_id} deleted')
    return jsonify({'message': 'Scan deleted successfully'})

@app.route('/api/devices')
@login_required
def get_all_devices():
    user_id = session['user_id']
    devices = get_devices_by_user(user_id)
    return jsonify(devices)

@app.route('/api/devices/<int:device_id>', methods=['PUT'])
@login_required
def update_device(device_id):
    data = request.get_json()
    user_id = session['user_id']
    
    device_status = data.get('device_status')
    notes = data.get('notes')
    flagged = data.get('flagged')
    
    update_device_info(device_id, user_id, device_status, notes, flagged)
    log_audit_event(user_id, 'device_update', f'Device {device_id} updated')
    return jsonify({'message': 'Device updated successfully'})

@app.route('/api/devices/<int:device_id>/block', methods=['POST'])
@login_required
@admin_required
def block_device(device_id):
    """Block a device by creating Windows Firewall rules"""
    user_id = session['user_id']
    
    if IS_PRODUCTION:
        return jsonify({'success': False, 'error': 'Firewall blocking not available in cloud deployment'}), 400
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        if DB_BACKEND == 'postgres':
            c.execute('SELECT ip_address, hostname FROM devices WHERE id=%s AND user_id=%s', (device_id, user_id))
        else:
            c.execute('SELECT ip_address, hostname FROM devices WHERE id=? AND user_id=?', (device_id, user_id))
        device = c.fetchone()
        
        if not device:
            conn.close()
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        
        ip_address = device['ip_address']
        
        if DB_BACKEND == 'postgres':
            c.execute('SELECT is_blocked FROM devices WHERE id=%s', (device_id,))
        else:
            c.execute('SELECT is_blocked FROM devices WHERE id=?', (device_id,))
        current = c.fetchone()
        if current and current['is_blocked'] == 1:
            conn.close()
            return jsonify({'success': False, 'error': f'Device {ip_address} is already blocked'}), 400
        
        success, message = add_firewall_block_rule(ip_address)
        
        if success:
            rule_name = f"Block_Device_{ip_address.replace('.', '_')}"
            update_device_block_status(device_id, user_id, True, rule_name)
            log_audit_event(user_id, 'device_block', f'Device {ip_address} blocked')
            conn.close()
            return jsonify({'success': True, 'message': message, 'ip': ip_address})
        else:
            conn.close()
            return jsonify({'success': False, 'error': message}), 500
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>/unblock', methods=['POST'])
@login_required
@admin_required
def unblock_device(device_id):
    """Unblock a device by removing Windows Firewall rules"""
    user_id = session['user_id']
    
    if IS_PRODUCTION:
        return jsonify({'success': False, 'error': 'Firewall management not available in cloud deployment'}), 400
    
    try:
        conn = get_db()
        c = get_cursor(conn)
        if DB_BACKEND == 'postgres':
            c.execute('SELECT ip_address FROM devices WHERE id=%s AND user_id=%s', (device_id, user_id))
        else:
            c.execute('SELECT ip_address FROM devices WHERE id=? AND user_id=?', (device_id, user_id))
        device = c.fetchone()
        
        if not device:
            conn.close()
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        
        ip_address = device['ip_address']
        
        success, message = remove_firewall_block_rule(ip_address)
        
        if success:
            update_device_block_status(device_id, user_id, False)
            log_audit_event(user_id, 'device_unblock', f'Device {ip_address} unblocked')
            conn.close()
            return jsonify({'success': True, 'message': message, 'ip': ip_address})
        else:
            conn.close()
            return jsonify({'success': False, 'error': message}), 500
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/blocked', methods=['GET'])
@login_required
def get_blocked_devices():
    user_id = session['user_id']
    conn = get_db()
    c = get_cursor(conn)
    
    columns = get_table_columns(conn, 'devices')
    
    if 'is_blocked' not in columns:
        conn.close()
        return jsonify([])
    
    if DB_BACKEND == 'postgres':
        c.execute('''SELECT id, ip_address, hostname, operating_system, blocked_at 
                     FROM devices WHERE user_id=%s AND is_blocked=TRUE''', (user_id,))
    else:
        c.execute('''SELECT id, ip_address, hostname, operating_system, blocked_at 
                     FROM devices WHERE user_id=? AND is_blocked=1''', (user_id,))
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/export/<scan_id>')
@login_required
def export_scan(scan_id):
    user_id = session['user_id']
    format_type = request.args.get('format', 'json')
    
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('''SELECT ip_address, hostname, operating_system, device_status, notes, is_blocked
                     FROM devices WHERE scan_id=%s AND user_id=%s''', (scan_id, user_id))
    else:
        c.execute('''SELECT ip_address, hostname, operating_system, device_status, notes, 
                    COALESCE(is_blocked, 0) as is_blocked
                    FROM devices WHERE scan_id=? AND user_id=?''', (scan_id, user_id))
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        return jsonify({'error': 'No data found'}), 404
    
    log_audit_event(user_id, 'export', f'Scan {scan_id} exported as {format_type}')
    
    if format_type == 'csv':
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP Address', 'Hostname', 'Operating System', 'Device Status', 'Notes', 'Blocked'])
        for r in rows:
            writer.writerow([r['ip_address'], r['hostname'], r['operating_system'], 
                           r['device_status'], r['notes'], 'Yes' if r['is_blocked'] else 'No'])
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv', 
            'Content-Disposition': f'attachment; filename=scan_{scan_id}.csv'
        }
    else:
        return jsonify([dict(r) for r in rows])

@app.route('/api/stats')
@login_required
def get_stats():
    user_id = session['user_id']
    conn = get_db()
    c = get_cursor(conn)
    
    if DB_BACKEND == 'postgres':
        c.execute('SELECT COUNT(*) FROM scans WHERE user_id=%s', (user_id,))
        total_scans = c.fetchone()['count']
        c.execute('SELECT COUNT(*) FROM devices WHERE user_id=%s', (user_id,))
        total_devices = c.fetchone()['count']
        c.execute('SELECT COUNT(*) FROM devices WHERE user_id=%s AND is_blocked=TRUE', (user_id,))
        blocked_devices = c.fetchone()['count']
        c.execute('SELECT timestamp FROM scans WHERE user_id=%s ORDER BY timestamp DESC LIMIT 1', (user_id,))
    else:
        c.execute('SELECT COUNT(*) FROM scans WHERE user_id=?', (user_id,))
        total_scans = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM devices WHERE user_id=?', (user_id,))
        total_devices = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM devices WHERE user_id=? AND is_blocked=1', (user_id,))
        blocked_devices = c.fetchone()[0]
        c.execute('SELECT timestamp FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT 1', (user_id,))
    last = c.fetchone()
    conn.close()
    
    return jsonify({
        'total_scans': total_scans,
        'total_devices': total_devices,
        'blocked_devices': blocked_devices,
        'last_scan': last['timestamp'] if last else None
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint for Render.com"""
    try:
        get_db()
        return jsonify({
            'status': 'healthy',
            'database': DB_BACKEND,
            'environment': 'production' if IS_PRODUCTION else 'development',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/environment')
def get_environment():
    """Get current environment info"""
    return jsonify({
        'environment': 'production' if IS_PRODUCTION else 'development',
        'platform': platform.system(),
        'database_type': DB_BACKEND,
        'render': IS_RENDER,
        'heroku': IS_HEROKU,
        'local': IS_LOCAL
    })

@app.route('/api/docs')
def api_docs():
    """API Documentation"""
    docs = {
        'name': 'NetscanPro API',
        'version': '2.0.0',
        'endpoints': [
            {'path': '/api/scan', 'method': 'POST', 'description': 'Start a network scan'},
            {'path': '/api/scan/<scan_id>/status', 'method': 'GET', 'description': 'Check scan progress'},
            {'path': '/api/scan/<scan_id>/results', 'method': 'GET', 'description': 'Retrieve scan results'},
            {'path': '/api/history', 'method': 'GET', 'description': 'List scan history'},
            {'path': '/api/export/<scan_id>', 'method': 'GET', 'description': 'Export scan results'},
            {'path': '/api/devices', 'method': 'GET', 'description': 'List all devices'},
            {'path': '/api/devices/<id>', 'method': 'PUT', 'description': 'Update device'},
            {'path': '/api/devices/<id>/block', 'method': 'POST', 'description': 'Block device (admin)'},
            {'path': '/api/devices/<id>/unblock', 'method': 'POST', 'description': 'Unblock device (admin)'},
            {'path': '/api/stats', 'method': 'GET', 'description': 'System statistics'},
            {'path': '/api/health', 'method': 'GET', 'description': 'Health check'},
            {'path': '/api/environment', 'method': 'GET', 'description': 'Environment info'},
        ]
    }
    return jsonify(docs)

@app.route('/api/reports/summary')
@login_required
def report_summary():
    user_id = session['user_id']
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('SELECT COUNT(*) as total_scans, COALESCE(SUM(device_count),0) as total_devices FROM scans WHERE user_id=%s', (user_id,))
        summary = c.fetchone()
        c.execute('SELECT COUNT(*) FROM devices WHERE user_id=%s AND is_blocked=TRUE', (user_id,))
        blocked_count = c.fetchone()['count']
        c.execute('''SELECT ip_address, COUNT(*) AS occurrences
                     FROM devices WHERE user_id=%s
                     GROUP BY ip_address ORDER BY occurrences DESC LIMIT 5''', (user_id,))
    else:
        c.execute('SELECT COUNT(*) as total_scans, COALESCE(SUM(device_count),0) as total_devices FROM scans WHERE user_id=?', (user_id,))
        summary = c.fetchone()
        c.execute('SELECT COUNT(*) FROM devices WHERE user_id=? AND is_blocked=1', (user_id,))
        blocked_count = c.fetchone()[0]
        c.execute('''SELECT ip_address, COUNT(*) AS occurrences
                     FROM devices WHERE user_id=?
                     GROUP BY ip_address ORDER BY occurrences DESC LIMIT 5''', (user_id,))
    top_hosts = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({
        'total_scans': summary['total_scans'],
        'total_devices': summary['total_devices'],
        'blocked_devices': blocked_count,
        'top_targets': top_hosts
    })

@app.route('/api/notifications')
@login_required
def get_notifications():
    user_id = session['user_id']
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('''SELECT event_type, description, created_at FROM audit_logs
                     WHERE user_id=%s ORDER BY created_at DESC LIMIT 10''', (user_id,))
    else:
        c.execute('''SELECT event_type, description, created_at FROM audit_logs
                     WHERE user_id=? ORDER BY created_at DESC LIMIT 10''', (user_id,))
    notifications = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(notifications)

@app.route('/api/audit')
@login_required
@admin_required
def get_audit_logs():
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('SELECT id, user_id, event_type, description, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100')
    else:
        c.execute('SELECT id, user_id, event_type, description, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100')
    logs = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/api/backup/db')
@login_required
@admin_required
def backup_database():
    if DB_BACKEND == 'postgres':
        return jsonify({'error': 'Postgres backup is managed through your database provider'}), 400
    log_audit_event(session['user_id'], 'backup', 'Database backup downloaded')
    return send_file(DB_SOURCE, as_attachment=True, download_name=os.path.basename(DB_SOURCE))

@app.route('/api/admin/check')
@login_required
def check_admin_status():
    return jsonify({'is_admin': session.get('user_role') == 'admin', 'is_windows': is_windows()})

@app.route('/api/users')
@login_required
@admin_required
def get_users():
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('SELECT id, email, role, created_at FROM users')
    else:
        c.execute('SELECT id, email, role, created_at FROM users')
    users = c.fetchall()
    conn.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@login_required
@admin_required
def update_user_role(user_id):
    data = request.get_json()
    role = data.get('role')
    if role not in ['user', 'admin']:
        return jsonify({'error': 'Invalid role'}), 400
    
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('UPDATE users SET role = %s WHERE id = %s', (role, user_id))
    else:
        c.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    conn.commit()
    conn.close()
    log_audit_event(session['user_id'], 'role_update', f'User {user_id} role changed to {role}')
    return jsonify({'message': 'Role updated'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    conn = get_db()
    c = get_cursor(conn)
    if DB_BACKEND == 'postgres':
        c.execute('DELETE FROM audit_logs WHERE user_id=%s', (user_id,))
        c.execute('DELETE FROM devices WHERE user_id=%s', (user_id,))
        c.execute('DELETE FROM scans WHERE user_id=%s', (user_id,))
        c.execute('DELETE FROM users WHERE id=%s', (user_id,))
    else:
        c.execute('DELETE FROM audit_logs WHERE user_id=?', (user_id,))
        c.execute('DELETE FROM devices WHERE user_id=?', (user_id,))
        c.execute('DELETE FROM scans WHERE user_id=?', (user_id,))
        c.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    log_audit_event(session['user_id'], 'user_delete', f'User {user_id} deleted')
    return jsonify({'message': 'User deleted'})

# ==================== MAIN ENTRY POINT ====================

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("🔐 NETSCANPRO ENTERPRISE")
    print("="*60)
    print(f"📍 Server running at: http://localhost:5000")
    print(f"📍 Press CTRL+C to stop")
    print("="*60)
    print(f"🌍 Environment: {'Production' if IS_PRODUCTION else 'Development'}")
    print(f"🗄️ Database: {DB_BACKEND.upper()}")
    if IS_RENDER:
        print(f"☁️ Running on Render.com")
    elif IS_HEROKU:
        print(f"☁️ Running on Heroku")
    else:
        print(f"💻 Running locally")
    
    if is_windows():
        if is_admin():
            print("✅ Running as Administrator - Firewall blocking available")
        else:
            print("⚠️ NOT running as Administrator - Firewall blocking will NOT work")
    print("="*60 + "\n")
    
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)