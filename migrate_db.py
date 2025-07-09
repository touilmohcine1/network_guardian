#!/usr/bin/env python3
"""
Database Migration Script for Network Guardian
This script migrates existing databases to include the role column.
"""

import sqlite3
import os

DB_PATH = 'database.db'

def migrate_database():
    """Migrate the database to include the role column"""
    if not os.path.exists(DB_PATH):
        print("Database file not found. Creating new database...")
        return
    
    print("Starting database migration...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            print("Users table not found. Creating new table...")
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'manager',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            print("Users table created successfully!")
            return
        
        # Check if role column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'role' not in columns:
            print("Adding 'role' column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'manager'")
            
            # Update existing users to have 'admin' role
            cursor.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = ''")
            
            conn.commit()
            print("Successfully added 'role' column and updated existing users!")
        else:
            print("Role column already exists. No migration needed.")
        
        # Display current users
        cursor.execute("SELECT id, username, email, role FROM users")
        users = cursor.fetchall()
        
        if users:
            print("\nCurrent users in database:")
            print("-" * 50)
            for user in users:
                print(f"ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}")
            print("-" * 50)
        else:
            print("No users found in database.")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database() 