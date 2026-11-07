"""
CyberGuard AI - Master LangGraph-Style Multi-Agent Orchestrator
Coordinates all 10 specialized agents, executes error recovery, records database state,
and generates real-time SOC incident output.
"""

import time
import json
import sqlite3
import logging
from typing import Dict, Any, List
from backend.agents.collection_agent import SecurityDataCollectionAgent
from backend.agents.analysis_agent import SecurityDataAnalysisAgent
from backend.agents.threat_detection_agent import ThreatDetectionAgent
from backend.agents.vulnerability_agent import VulnerabilityAssessmentAgent
from backend.agents.network_agent import NetworkMonitoringAgent
from backend.agents.malware_agent import MalwareAnalysisAgent
from backend.agents.intelligence_agent import ThreatIntelligenceAgent
from backend.agents.decision_agent import SecurityDecisionAgent
from backend.agents.response_agent import AutomatedIncidentResponseAgent
from backend.agents.learning_agent import MonitoringAndLearningAgent
from backend.orchestrator.state import create_initial_state
from backend.database.session import SessionLocal, HAS_SQLALCHEMY

logger = logging.getLogger("CyberGuard.Workflow")

class MasterAgentOrchestrator:
    def __init__(self):
        self.agent1 = SecurityDataCollectionAgent()
        self.agent2 = SecurityDataAnalysisAgent()
        self.agent3 = ThreatDetectionAgent()
        self.agent4 = VulnerabilityAssessmentAgent()
        self.agent5 = NetworkMonitoringAgent()
        self.agent6 = MalwareAnalysisAgent()
        self.agent7 = ThreatIntelligenceAgent()
        self.agent8 = SecurityDecisionAgent()
        self.agent9 = AutomatedIncidentResponseAgent()
        self.agent10 = MonitoringAndLearningAgent()

    def run_pipeline(self, raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Executes the full end-to-end 10-agent autonomous cybersecurity cycle."""
        state = create_initial_state(raw_events)
        logger.info(f"==> Initiating CyberGuard Autonomous Pipeline [Session: {state['session_id']}]")

        # Step 1: Data Collection Agent
        out1 = self.agent1.execute(state)
        state["normalized_events"] = out1["data"].get("normalized_events", [])
        state["audit_trail"].append(out1)

        # Step 2: Data Analysis Agent
        out2 = self.agent2.execute(state)
        state["filtered_events"] = out2["data"].get("filtered_events", [])
        state["anomalies"] = out2["data"].get("anomalies", [])
        state["audit_trail"].append(out2)

        # Step 3: Parallel Domain Detection Mesh (Agents 3, 4, 5, 6)
        out3 = self.agent3.execute(state)
        state["threats"] = out3["data"].get("threats", [])
        state["audit_trail"].append(out3)

        out4 = self.agent4.execute(state)
        state["vulnerabilities"] = out4["data"].get("vulnerabilities", [])
        state["audit_trail"].append(out4)

        out5 = self.agent5.execute(state)
        state["network_anomalies"] = out5["data"].get("network_anomalies", [])
        state["audit_trail"].append(out5)

        out6 = self.agent6.execute(state)
        state["malware_reports"] = out6["data"].get("malware_reports", [])
        state["audit_trail"].append(out6)

        # Step 4: Threat Intelligence Synthesis (Agent 7)
        out7 = self.agent7.execute(state)
        state["threat_intelligence"] = out7["data"]
        state["audit_trail"].append(out7)

        # Step 5: Risk Evaluation & Policy Gating (Agent 8)
        out8 = self.agent8.execute(state)
        state["decision"] = out8["data"]
        state["audit_trail"].append(out8)

        # Step 6: Incident Response (Agent 9)
        if state["decision"].get("response_authorized", False):
            out9 = self.agent9.execute(state)
            state["response"] = out9["data"]
            state["audit_trail"].append(out9)

        # Step 7: Monitoring & Continuous Learning (Agent 10)
        out10 = self.agent10.execute(state)
        state["monitoring"] = out10["data"]
        state["audit_trail"].append(out10)

        # Persist to database
        self._persist_session(state)

        logger.info(f"<== Completed CyberGuard Autonomous Pipeline [Session: {state['session_id']}]")
        return state

    def _persist_session(self, state: Dict[str, Any]):
        """Persists the session findings to the database (SQLAlchemy or raw SQLite fallback)."""
        intel = state.get("threat_intelligence", {})
        decision = state.get("decision", {})
        resp = state.get("response", {})

        if HAS_SQLALCHEMY and SessionLocal is not None:
            from backend.database.models import Incident, Threat, Vulnerability, ResponseAction, AuditLog
            db = SessionLocal()
            try:
                inc = Incident(
                    id=state["session_id"],
                    created_at=state["created_at"],
                    title=intel.get("title", "Baseline Assessment"),
                    threat_actor=intel.get("threat_actor", "None"),
                    severity=intel.get("overall_severity", "LOW"),
                    risk_score=decision.get("risk_score", 0.0),
                    confidence=intel.get("confidence_score", 0.0),
                    affected_assets=intel.get("affected_assets", []),
                    status="RESOLVED" if resp.get("containment_successful") else ("AWAITING_APPROVAL" if decision.get("human_approval_required") else "NEW"),
                    threat_confirmed=intel.get("threat_confirmed", False),
                    containment_successful=resp.get("containment_successful", False),
                    human_approval_required=decision.get("human_approval_required", False),
                    report_markdown=intel.get("narrative", "")
                )
                db.merge(inc)
                db.commit()
            except Exception as e:
                logger.warning(f"SQLAlchemy persistence error: {e}")
                db.rollback()
            finally:
                db.close()
        else:
            # Native SQLite fallback
            try:
                with sqlite3.connect("cyberguard_enterprise.db") as conn:
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
                    cursor.execute("""
                    INSERT OR REPLACE INTO incidents (
                        id, created_at, title, threat_actor, severity, risk_score, confidence,
                        affected_assets, status, threat_confirmed, containment_successful, human_approval_required, report_markdown
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        state["session_id"],
                        state["created_at"],
                        intel.get("title", "Baseline Assessment"),
                        intel.get("threat_actor", "None"),
                        intel.get("overall_severity", "LOW"),
                        decision.get("risk_score", 0.0),
                        intel.get("confidence_score", 0.0),
                        json.dumps(intel.get("affected_assets", [])),
                        "RESOLVED" if resp.get("containment_successful") else "NEW",
                        1 if intel.get("threat_confirmed") else 0,
                        1 if resp.get("containment_successful") else 0,
                        1 if decision.get("human_approval_required") else 0,
                        intel.get("narrative", "")
                    ))
                    conn.commit()
            except Exception as e:
                logger.warning(f"Raw SQLite persistence error: {e}")

GLOBAL_ORCHESTRATOR = MasterAgentOrchestrator()
