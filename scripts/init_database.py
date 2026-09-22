#!/usr/bin/env python3
"""
CYBER-14: Database Initialization Script
Safely creates the `cyber14_ddos` MySQL database, tables, and indexes.
Preserves existing data (never drops tables or deletes data).
"""
import os
import sys
from urllib.parse import urlparse

import sqlalchemy
from sqlalchemy import inspect, text

# Add backend to path for module imports
sys.path.insert(0, os.path.abspath("backend"))

from app.core.config import get_settings
from app.db.models import Base


def init_database() -> bool:
    print("=" * 60)
    print("CYBER-14: MYSQL DATABASE INITIALIZATION")
    print("=" * 60)

    settings = get_settings()
    db_url = getattr(settings, "database_url", "mysql+pymysql://root:root@127.0.0.1:3306/cyber14_ddos")

    parsed = urlparse(db_url.replace("mysql+pymysql://", "http://"))
    db_name = parsed.path.lstrip("/") or "cyber14_ddos"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 3306
    user = parsed.username or "root"
    password = parsed.password or "root"

    print(f"Connecting to MySQL server at {host}:{port} as user '{user}'...")

    # Step 1: Connect to server root to ensure database exists
    server_url = f"mysql+pymysql://{user}:{password}@{host}:{port}/"
    try:
        server_engine = sqlalchemy.create_engine(server_url, pool_pre_ping=True)
        with server_engine.connect() as conn:
            version = conn.execute(text("SELECT VERSION()")).scalar()
            print(f"[OK] Connected to MySQL Server version {version}")
            print(f"Ensuring database '{db_name}' exists...")
            conn.execute(
                text(f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            )
            conn.commit()
            print(f"[OK] Database '{db_name}' ready.")
        server_engine.dispose()
    except Exception as exc:
        print(f"[ERROR] Failed to connect or create database: {exc}")
        return False

    # Step 2: Connect directly to the database and create tables
    print(f"\nConnecting to database '{db_name}'...")
    try:
        target_engine = sqlalchemy.create_engine(db_url, pool_pre_ping=True)
        print("Creating all tables and indexes (if not already existing)...")
        Base.metadata.create_all(bind=target_engine)
        print("[OK] Schema synchronized successfully.")

        # Step 3: Verify created schema and indexes
        print("\nVerifying database schema...")
        inspector = inspect(target_engine)
        existing_tables = set(inspector.get_table_names())

        required_tables = [
            "traffic_events",
            "detections",
            "attack_incidents",
            "mitigation_actions",
            "audit_logs",
        ]

        all_valid = True
        total_indexes = 0

        for table in required_tables:
            if table in existing_tables:
                columns = inspector.get_columns(table)
                indexes = inspector.get_indexes(table)
                pk = inspector.get_pk_constraint(table)
                total_indexes += len(indexes)
                print(f"  [TABLE OK] {table:<20} | Columns: {len(columns):<2} | Indexes: {len(indexes):<2} | PK: {pk.get('constrained_columns')}")
            else:
                print(f"  [MISSING]  {table:<20}")
                all_valid = False

        if all_valid:
            print("\n" + "=" * 60)
            print(f"DATABASE INITIALIZATION SUCCESSFUL!")
            print(f"Database: {db_name}")
            print(f"Tables Verified: {len(required_tables)} / {len(required_tables)}")
            print(f"Total Indexes:  {total_indexes}")
            print("=" * 60)
            target_engine.dispose()
            return True
        else:
            print("\n[FAIL] Some tables could not be verified.")
            target_engine.dispose()
            return False

    except Exception as exc:
        print(f"\n[ERROR] Failed to synchronize schema: {exc}")
        return False


if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
