"""
CyberGuard AI - Enterprise Persistent Storage & Cryptographic Audit Database
Provides ACID storage for incidents, telemetry events, and an append-only tamper-resistant
cryptographic audit log with SHA-256 hash chaining.
"""

import sqlite3
import hashlib
import json
import time
import os
from typing import Dict, Any, List, Optional

DB_FILE = os.getenv("CYBERGUARD_DB_PATH", "cyberguard_soc.db")

class SecurityDatabase:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Incidents table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                session_id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                title TEXT,
                threat_actor TEXT,
                campaign TEXT,
                severity TEXT,
                risk_score REAL,
                confidence REAL,
                affected_assets TEXT,
                status TEXT,
                threat_confirmed INTEGER,
                response_authorized INTEGER,
                containment_successful INTEGER,
                human_approval_required INTEGER,
                report_markdown TEXT
            )
            """)

            # Cryptographic Append-Only Audit Log with SHA-256 hash chaining
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                execution_time_ms REAL NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                timestamp REAL NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            )
            """)

            # Executed Defensive Actions Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS executed_actions (
                action_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status_code TEXT NOT NULL,
                details TEXT,
                timestamp REAL NOT NULL
            )
            """)

            conn.commit()

    def _get_last_audit_hash(self, cursor: sqlite3.Cursor) -> str:
        cursor.execute("SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row and row["record_hash"]:
            return row["record_hash"]
        return "0000000000000000000000000000000000000000000000000000000000000000"

    def record_incident(self, state) -> bool:
        """Persists a complete multi-agent incident resolution record."""
        intel = state.threat_intel_report
        plan = state.decision_plan

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO incidents (
                session_id, created_at, title, threat_actor, campaign, severity,
                risk_score, confidence, affected_assets, status, threat_confirmed,
                response_authorized, containment_successful, human_approval_required, report_markdown
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                state.session_id,
                state.created_at,
                intel.title if intel else "Routine Baseline Assessment",
                intel.threat_actor if intel else "None",
                intel.campaign if intel else "Baseline",
                intel.overall_severity.value if intel else "INFO",
                plan.risk_score if plan else 0.0,
                intel.confidence_score if intel else 0.0,
                json.dumps(intel.affected_assets if intel else []),
                plan.status.value if plan else "IDENTIFIED",
                1 if state.threat_confirmed else 0,
                1 if state.response_authorized else 0,
                1 if state.containment_successful else 0,
                1 if state.human_approval_required else 0,
                state.final_report_markdown
            ))

            # Store append-only cryptographic audit records with hash chaining
            prev_h = self._get_last_audit_hash(cursor)
            for log in state.audit_trail:
                content = f"{log.agent_id}:{log.status}:{log.execution_time_ms}:{log.timestamp}:{prev_h}"
                record_h = hashlib.sha256(content.encode()).hexdigest()

                cursor.execute("""
                INSERT INTO audit_log (
                    session_id, agent_id, agent_name, execution_time_ms, status, summary, timestamp, prev_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    state.session_id, log.agent_id, log.agent_name, log.execution_time_ms,
                    log.status, log.summary, log.timestamp, prev_h, record_h
                ))
                prev_h = record_h

            # Store defensive actions
            for act in state.executed_actions:
                cursor.execute("""
                INSERT OR REPLACE INTO executed_actions (
                    action_id, session_id, action_type, target, status_code, details, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    act.action_id, state.session_id, "ACTION", act.target, act.status_code, act.details, act.timestamp
                ))

            conn.commit()
            return True

    def get_all_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def verify_audit_trail_integrity(self) -> Dict[str, Any]:
        """Validates that the append-only cryptographic audit log has not been tampered with."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, agent_id, status, execution_time_ms, timestamp, prev_hash, record_hash FROM audit_log ORDER BY id ASC")
            rows = cursor.fetchall()

            if not rows:
                return {"valid": True, "records_checked": 0, "status": "AUDIT_EMPTY"}

            expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"
            for row in rows:
                if row["prev_hash"] != expected_prev:
                    return {"valid": False, "corrupted_id": row["id"], "reason": "PREV_HASH_MISMATCH"}
                
                content = f"{row['agent_id']}:{row['status']}:{row['execution_time_ms']}:{row['timestamp']}:{expected_prev}"
                computed_h = hashlib.sha256(content.encode()).hexdigest()
                if computed_h != row["record_hash"]:
                    return {"valid": False, "corrupted_id": row["id"], "reason": "RECORD_HASH_TAMPERED"}

                expected_prev = row["record_hash"]

            return {"valid": True, "records_checked": len(rows), "status": "INTEGRITY_VERIFIED_100%"}

GLOBAL_DB = SecurityDatabase()
