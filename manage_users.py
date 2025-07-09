#!/usr/bin/env python3
"""
Network Guardian User Management Script
This script helps manage users in the Network Guardian system.
"""

import sqlite3
import sys
from werkzeug.security import generate_password_hash

DB_PATH = 'database.db'

def init_db():
    """Initialize the database if it doesn't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
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
    
    conn.commit()
    conn.close()

def list_users():
    """List all users in the system"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id")
    users = cursor.fetchall()
    conn.close()
    
    if not users:
        print("No users found in the system.")
        return
    
    print("\n" + "="*70)
    print("NETWORK GUARDIAN USERS")
    print("="*70)
    print(f"{'ID':<5} {'Username':<15} {'Email':<25} {'Role':<10} {'Created At'}")
    print("-"*70)
    
    for user in users:
        print(f"{user[0]:<5} {user[1]:<15} {user[2]:<25} {user[3]:<10} {user[4]}")
    
    print("="*70)

def add_user(username, email, password, role='manager'):
    """Add a new user to the system"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            print(f"Error: Username '{username}' already exists.")
            return False
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            print(f"Error: Email '{email}' already exists.")
            return False
        
        # Validate role
        if role not in ['admin', 'manager']:
            print(f"Error: Invalid role '{role}'. Must be 'admin' or 'manager'.")
            return False
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role)
        )
        conn.commit()
        print(f"Successfully created user '{username}' with email '{email}' and role '{role}'")
        return True
        
    except Exception as e:
        print(f"Error creating user: {e}")
        return False
    finally:
        conn.close()

def delete_user(user_id):
    """Delete a user from the system"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"Error: User with ID {user_id} not found.")
            return False
        
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        print(f"Successfully deleted user '{user[0]}' (ID: {user_id})")
        return True
        
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False
    finally:
        conn.close()

def change_password(username, new_password):
    """Change a user's password"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            print(f"Error: User '{username}' not found.")
            return False
        
        password_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        conn.commit()
        print(f"Successfully changed password for user '{username}'")
        return True
        
    except Exception as e:
        print(f"Error changing password: {e}")
        return False
    finally:
        conn.close()

def change_role(username, new_role):
    """Change a user's role"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            print(f"Error: User '{username}' not found.")
            return False
        
        if new_role not in ['admin', 'manager']:
            print(f"Error: Invalid role '{new_role}'. Must be 'admin' or 'manager'.")
            return False
        
        cursor.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
        conn.commit()
        print(f"Successfully changed role for user '{username}' to '{new_role}'")
        return True
        
    except Exception as e:
        print(f"Error changing role: {e}")
        return False
    finally:
        conn.close()

def show_help():
    """Show help information"""
    print("""
Network Guardian User Management Script

Usage:
    python manage_users.py [command] [options]

Commands:
    list                                    - List all users
    add <username> <email> <password> [role] - Add a new user (role defaults to 'manager')
    delete <user_id>                        - Delete a user by ID
    password <username> <new_password>      - Change user password
    role <username> <new_role>              - Change user role (admin/manager)
    help                                    - Show this help message

Examples:
    python manage_users.py list
    python manage_users.py add john john@example.com mypassword
    python manage_users.py add admin2 admin2@example.com securepass123 admin
    python manage_users.py delete 2
    python manage_users.py password john newpassword
    python manage_users.py role john admin
    """)

def main():
    """Main function"""
    init_db()
    
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_users()
    
    elif command == "add":
        if len(sys.argv) < 5:
            print("Error: add command requires username, email, and password")
            print("Usage: python manage_users.py add <username> <email> <password> [role]")
            return
        username = sys.argv[2]
        email = sys.argv[3]
        password = sys.argv[4]
        role = sys.argv[5] if len(sys.argv) > 5 else 'manager'
        add_user(username, email, password, role)
    
    elif command == "delete":
        if len(sys.argv) != 3:
            print("Error: delete command requires user ID")
            print("Usage: python manage_users.py delete <user_id>")
            return
        try:
            user_id = int(sys.argv[2])
            delete_user(user_id)
        except ValueError:
            print("Error: User ID must be a number")
    
    elif command == "password":
        if len(sys.argv) != 4:
            print("Error: password command requires username and new password")
            print("Usage: python manage_users.py password <username> <new_password>")
            return
        change_password(sys.argv[2], sys.argv[3])
    
    elif command == "role":
        if len(sys.argv) != 4:
            print("Error: role command requires username and new role")
            print("Usage: python manage_users.py role <username> <new_role>")
            return
        change_role(sys.argv[2], sys.argv[3])
    
    elif command == "help":
        show_help()
    
    else:
        print(f"Unknown command: {command}")
        show_help()

if __name__ == "__main__":
    main() 