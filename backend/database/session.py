"""
CyberGuard AI - Database Session Factory
Supports PostgreSQL & SQLite via SQLAlchemy when available, with pure Python SQLite3 fallback.
"""

import os
import sqlite3
import logging

logger = logging.getLogger("CyberGuard.Database")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///cyberguard_enterprise.db")

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.database.models import Base

    connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    SessionLocal = None
    engine = None

def init_db():
    if HAS_SQLALCHEMY and engine is not None:
        Base.metadata.create_all(bind=engine)
    else:
        # Fallback raw SQLite initialization
        db_path = "cyberguard_enterprise.db"
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at REAL,
                title TEXT,
                threat_actor TEXT,
                severity TEXT,
                risk_score REAL,
                confidence REAL,
                affected_assets TEXT,
                status TEXT,
                threat_confirmed INTEGER,
                containment_successful INTEGER,
                human_approval_required INTEGER,
                report_markdown TEXT
            )
            """)
            conn.commit()

def get_db():
    if HAS_SQLALCHEMY and SessionLocal is not None:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
    else:
        conn = sqlite3.connect("cyberguard_enterprise.db")
        try:
            yield conn
        finally:
            conn.close()
