from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Thread
import sqlite3
import time
import os
import logging
import sys
from flask_socketio import SocketIO, emit

# Check for verbose mode argument
VERBOSE_MODE = '--verbose' in sys.argv or '-v' in sys.argv

# Configure logging based on verbose mode
if VERBOSE_MODE:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
else:
    # Silent mode - disable console output
    logging.basicConfig(
        level=logging.WARNING,  # Only show warnings and errors
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            # Uncomment the line below if you want to log to a file instead of console
            # logging.FileHandler('network_guardian.log'),
        ]
    )

# Suppress specific logger outputs
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('scapy.loading').setLevel(logging.ERROR)

from detector.arp_detector import start_arp_detection

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # Change this in production!

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_PATH = 'database.db'

class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attack_type TEXT,
            description TEXT,
            source_ip TEXT
        )
    ''')
    
    # Create users table with role
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'manager',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if role column exists, if not add it
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'role' not in columns:
        print("Adding 'role' column to existing users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'manager'")
        # Update existing users to have 'admin' role (assuming they were created before roles)
        cursor.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = ''")
    
    # Create default admin user if no users exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_password = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ('admin', 'admin@networkguardian.com', admin_password, 'admin')
        )
        print("Default admin user created: username='admin', password='admin123'")
    
    conn.commit()
    conn.close()

def admin_required(f):
    """Decorator to require admin role"""
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
@login_required
def index():
    # Redirect based on user role
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('manager_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill in all fields', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, password_hash, role FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[3], password):
            user = User(user_data[0], user_data[1], user_data[2], user_data[4])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

# Admin routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not username or not email or not password or not role:
            flash('Please fill in all fields', 'error')
            return render_template('admin_add_user.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('admin_add_user.html')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            flash('Username already exists', 'error')
            return render_template('admin_add_user.html')
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            flash('Email already exists', 'error')
            return render_template('admin_add_user.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role)
        )
        conn.commit()
        conn.close()
        
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_add_user.html')

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        new_password = request.form.get('new_password')
        
        if not username or not email or not role:
            flash('Please fill in all required fields', 'error')
            return render_template('admin_edit_user.html', user=None)
        
        # Check if username exists for other users
        cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id))
        if cursor.fetchone():
            conn.close()
            flash('Username already exists', 'error')
            return render_template('admin_edit_user.html', user=None)
        
        # Check if email exists for other users
        cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id))
        if cursor.fetchone():
            conn.close()
            flash('Email already exists', 'error')
            return render_template('admin_edit_user.html', user=None)
        
        # Update user
        if new_password:
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long', 'error')
                return render_template('admin_edit_user.html', user=None)
            password_hash = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET username = ?, email = ?, password_hash = ?, role = ? WHERE id = ?",
                (username, email, password_hash, role, user_id)
            )
        else:
            cursor.execute(
                "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
                (username, email, role, user_id)
            )
        
        conn.commit()
        conn.close()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    # Get user data for editing
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if not user_data:
        flash('User not found', 'error')
        return redirect(url_for('admin_users'))
    
    user = {'id': user_data[0], 'username': user_data[1], 'email': user_data[2], 'role': user_data[3]}
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('User not found', 'error')
        return redirect(url_for('admin_users'))
    
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    flash(f'User "{user[0]}" deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

# Manager routes
@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role != 'manager':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    return render_template('manager_dashboard.html')

@app.route('/alerts')
@login_required
def alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, attack_type, description, source_ip FROM alerts WHERE attack_type = 'ARP' ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return render_template('alerts.html', alerts=rows)

@app.route('/api/data')
@login_required
def api_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT attack_type, COUNT(*) FROM alerts WHERE attack_type = 'ARP' GROUP BY attack_type")
    data = cursor.fetchall()
    conn.close()
    result = {row[0]: row[1] for row in data}
    return jsonify(result)

def broadcast_arp_alert(alert):
    # alert: (timestamp, attack_type, description, source_ip)
    socketio.emit('new_arp_alert', {
        'timestamp': alert[0],
        'attack_type': alert[1],
        'description': alert[2],
        'source_ip': alert[3]
    }, broadcast=True)

def run_detectors():
    Thread(target=start_arp_detection, daemon=True).start()

if __name__ == '__main__':
    init_db()
    socketio = SocketIO(app)
    run_detectors()
    
    if not VERBOSE_MODE:
        print("Network Guardian starting in silent mode...")
        print("Use --verbose or -v flag to enable console output")
        print("Web interface available at: http://localhost:5000")
        print("Default admin credentials: admin / admin123")
        print("Press Ctrl+C to stop")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
