"""
Security Event, Log, Anomaly, and Vulnerability Models
"""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LogSource(str, Enum):
    FIREWALL = "FIREWALL"
    ROUTER = "ROUTER"
    ENDPOINT_EDR = "ENDPOINT_EDR"
    SYSLOG = "SYSLOG"
    SIEM = "SIEM"
    DNS = "DNS"
    ZEEK = "ZEEK"
    SURICATA = "SURICATA"
    CLOUD_TRAIL = "CLOUD_TRAIL"
    HONEYPOT = "HONEYPOT"

@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    source_type: LogSource = LogSource.FIREWALL
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"
    host: str = "unknown"
    user: Optional[str] = None
    event_action: str = "unknown"
    raw_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_anomaly: bool = False
    anomaly_score: float = 0.0

@dataclass
class ThreatDetection:
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    threat_category: str = "General Threat" # e.g., BruteForce, Ransomware, Phishing, RCE, LateralMovement
    mitre_technique_id: str = "T1000"
    mitre_tactic: str = "Initial Access"
    confidence: float = 0.85
    affected_asset: str = "unknown"
    attacker_indicators: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    matched_rule: str = "SIGMA-GENERIC"

@dataclass
class VulnerabilityFinding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: str = "CVE-XXXX-XXXX"
    cvss_score: float = 5.0
    severity: Severity = Severity.MEDIUM
    affected_software: str = ""
    affected_version: str = ""
    asset_host: str = ""
    asset_ip: str = ""
    description: str = ""
    remediation_guidance: str = ""
    is_actively_exploited: bool = False

@dataclass
class NetworkAnomaly:
    anomaly_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    source_ip: str = ""
    destination_ip: str = ""
    port: int = 0
    protocol: str = "TCP"
    anomaly_type: str = "BEACONING" # BEACONING, DATA_EXFILTRATION, PORT_SCAN, DNS_TUNNELING
    traffic_volume_bytes: int = 0
    connection_rate: float = 0.0
    evidence: str = ""
    confidence: float = 0.80

@dataclass
class MalwareAnalysisResult:
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    file_name: str = ""
    file_hash_sha256: str = ""
    file_type: str = "PE32"
    is_malicious: bool = False
    malware_family: str = "Benign"
    matched_yara_rules: List[str] = field(default_factory=list)
    behavioral_indicators: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    sandbox_verdict: str = "CLEAN"
    recommended_quarantine: bool = False
