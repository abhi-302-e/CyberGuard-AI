"""
CyberGuard AI - Enterprise Database Schema (SQLAlchemy Models)
Defines all 12 database entities specified in the master specification.
"""

import time
import uuid
from typing import Dict, Any, List
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="SOC_ANALYST_TIER1") # ADMIN, INCIDENT_COMMANDER, etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(Float, default=time.time)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(Float, default=time.time, index=True)
    source = Column(String(50), nullable=False) # FIREWALL, SYSLOG, EDR, ZEEK
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String(20), default="TCP")
    host = Column(String(255), default="unknown")
    user = Column(String(100), nullable=True)
    action = Column(String(50), default="ALLOW")
    message = Column(Text)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    event_metadata = Column(JSON, default=dict)

class AgentRecord(Base):
    __tablename__ = "agents"

    id = Column(String(50), primary_key=True) # e.g. AGENT-01-INGEST
    name = Column(String(100), nullable=False)
    role = Column(String(150), nullable=False)
    status = Column(String(30), default="ACTIVE") # ACTIVE, RUNNING, IDLE, ERROR
    last_run_timestamp = Column(Float, default=time.time)
    execution_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    avg_latency_ms = Column(Float, default=0.0)

class Threat(Base):
    __tablename__ = "threats"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(Float, default=time.time, index=True)
    category = Column(String(100), nullable=False)
    mitre_technique = Column(String(50))
    mitre_tactic = Column(String(50))
    severity = Column(String(20), default="MEDIUM")
    confidence = Column(Float, default=0.85)
    affected_asset = Column(String(255))
    attacker_ip = Column(String(45))
    matched_rule = Column(String(100))
    evidence = Column(JSON, default=list)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id = Column(String(50), index=True)
    title = Column(String(255))
    cvss_score = Column(Float, default=5.0)
    severity = Column(String(20), default="MEDIUM")
    affected_software = Column(String(255))
    affected_asset = Column(String(255))
    description = Column(Text)
    remediation = Column(Text)
    is_actively_exploited = Column(Boolean, default=False)

class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(Float, default=time.time)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    port = Column(Integer)
    anomaly_type = Column(String(50)) # C2_BEACONING, EXFILTRATION, PORT_SCAN
    traffic_bytes = Column(Integer, default=0)
    evidence = Column(Text)
    confidence = Column(Float, default=0.85)

class MalwareReport(Base):
    __tablename__ = "malware_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(Float, default=time.time)
    file_name = Column(String(255))
    sha256 = Column(String(64), index=True)
    malware_family = Column(String(100))
    matched_yara_rules = Column(JSON, default=list)
    verdict = Column(String(30), default="MALICIOUS")
    quarantine_recommended = Column(Boolean, default=True)

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(Float, default=time.time)
    threat_actor = Column(String(100))
    campaign = Column(String(150))
    severity = Column(String(20))
    confidence = Column(Float)
    indicators = Column(JSON, default=list)
    narrative = Column(Text)
    stix_bundle = Column(JSON, default=dict)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(Float, default=time.time, index=True)
    title = Column(String(255))
    threat_actor = Column(String(100))
    severity = Column(String(20))
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    affected_assets = Column(JSON, default=list)
    status = Column(String(30), default="NEW") # NEW, INVESTIGATING, AWAITING_APPROVAL, CONTAINMENT, RESOLVED
    threat_confirmed = Column(Boolean, default=False)
    containment_successful = Column(Boolean, default=False)
    human_approval_required = Column(Boolean, default=False)
    report_markdown = Column(Text)

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True)
    action_type = Column(String(50))
    target = Column(String(255))
    status = Column(String(30), default="EXECUTED") # EXECUTED, PENDING_APPROVAL, FAILED
    details = Column(Text)
    timestamp = Column(Float, default=time.time)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(36), index=True)
    actor = Column(String(100)) # Agent name or user
    action = Column(String(100))
    status = Column(String(30))
    details = Column(Text)
    timestamp = Column(Float, default=time.time)
    prev_hash = Column(String(64))
    record_hash = Column(String(64))

class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(Float, default=time.time)
    title = Column(String(255))
    report_type = Column(String(50), default="INCIDENT_RESOLUTION")
    summary = Column(Text)
    markdown_content = Column(Text)
    download_url = Column(String(255), nullable=True)
