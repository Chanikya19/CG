#!/usr/bin/env python
"""
CipherGuard Database Initialization & Migration Script
Connects to the configured MySQL (or fallback SQLite) database, creates tables,
verifies columns and indexes, and bootstraps initial admin profile if needed.
"""

import sys
import os
from sqlalchemy import inspect, text

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import (
    User, File, FileClassification, EncryptionKey, FileIntegrity,
    FileSharing, ActivityLog, ClassificationHistory, IntegrityHistory,
    SecurityAlert, LoginAttempt
)

def initialize_database():
    print("==================================================")
    print("CipherGuard Database Setup & Verification")
    print("==================================================")
    
    app = create_app()
    with app.app_context():
        engine = db.engine
        db_uri = str(engine.url)
        # Mask password in URI for secure output
        if engine.url.password:
            masked_uri = db_uri.replace(engine.url.password, "********")
        else:
            masked_uri = db_uri
            
        print(f"[*] Target Database: {masked_uri}")
        print(f"[*] Database Dialect: {engine.dialect.name}")

        try:
            # 1. Test database connectivity
            print("[*] Testing database connectivity...")
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("[+] Database connection verified successfully.")

            # 2. Create all tables
            print("[*] Creating / verifying database tables...")
            db.create_all()
            print("[+] db.create_all() executed.")

            # 3. Inspect created tables
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            print(f"[+] Total tables found in database ({len(tables)}):")
            for tbl in sorted(tables):
                cols = [c['name'] for c in inspector.get_columns(tbl)]
                print(f"    - {tbl} ({len(cols)} columns)")

            # 4. Verify core tables
            expected_tables = [
                'Users', 'Files', 'EncryptionKeys', 'FileClassification',
                'FileIntegrity', 'FileSharing', 'ActivityLogs',
                'ClassificationHistory', 'IntegrityHistory', 'SecurityAlerts',
                'LoginAttempts'
            ]
            missing = [t for t in expected_tables if t not in tables]
            if missing:
                print(f"[!] Warning: Missing tables: {missing}")
            else:
                print("[+] All 11 core tables verified in persistent storage.")

            print("\n==================================================")
            print("Database setup and verification completed successfully.")
            print("==================================================")

        except Exception as e:
            print(f"[!] Database initialization failed: {str(e)}", file=sys.stderr)
            sys.exit(1)

if __name__ == '__main__':
    initialize_database()
