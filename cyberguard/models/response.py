"""
Incident Response, Actions, Decisions, and Mitigation Models
"""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional
from cyberguard.models.events import Severity

class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    RATE_LIMIT_IP = "RATE_LIMIT_IP"
    QUARANTINE_HOST = "QUARANTINE_HOST"
    REVOKE_SESSION = "REVOKE_SESSION"
    KILL_PROCESS = "KILL_PROCESS"
    APPLY_FIREWALL_RULE = "APPLY_FIREWALL_RULE"
    CREATE_TICKET = "CREATE_TICKET"
    DISPATCH_ALERT = "DISPATCH_ALERT"
    ISOLATE_CRITICAL_DATABASE_SERVER = "ISOLATE_CRITICAL_DATABASE_SERVER"
    MANUAL_APPROVAL_REQUIRED = "MANUAL_APPROVAL_REQUIRED"

class IncidentStatus(str, Enum):
    IDENTIFIED = "IDENTIFIED"
    ANALYZING = "ANALYZING"
    CONTAINMENT_IN_PROGRESS = "CONTAINMENT_IN_PROGRESS"
    CONTAINED = "CONTAINED"
    RECOVERY_VERIFIED = "RECOVERY_VERIFIED"
    ESCALATED = "ESCALATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

@dataclass
class ThreatIntelligenceReport:
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    title: str = ""
    threat_actor: Optional[str] = "Unknown"
    campaign: Optional[str] = "Unattributed"
    overall_severity: Severity = Severity.MEDIUM
    confidence_score: float = 0.85
    affected_assets: List[str] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    corroborating_agents: List[str] = field(default_factory=list)
    attack_narrative: str = ""
    raw_stix_bundle: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DefensiveAction:
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType = ActionType.BLOCK_IP
    target: str = "" # IP, host, username, or hash
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    requires_human_approval: bool = False
    approved: bool = False
    executed: bool = False
    execution_status: str = "PENDING"
    execution_timestamp: Optional[float] = None
    output_message: str = ""

@dataclass
class SecurityDecisionPlan:
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    incident_id: str = ""
    risk_score: float = 0.0 # 0 - 100
    overall_confidence: float = 0.0
    threat_confirmed: bool = False
    actions: List[DefensiveAction] = field(default_factory=list)
    requires_human_signoff: bool = False
    policy_compliance_notes: List[str] = field(default_factory=list)
    status: IncidentStatus = IncidentStatus.IDENTIFIED

@dataclass
class ActionResult:
    action_id: str
    target: str
    success: bool
    status_code: str
    details: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class MonitoringMetrics:
    verification_passed: bool = True
    post_containment_traffic_stopped: bool = True
    false_positive_detected: bool = False
    mean_time_to_detect_ms: float = 120.0
    mean_time_to_respond_ms: float = 45.0
    feedback_notes: List[str] = field(default_factory=list)
    rule_updates_proposed: List[Dict[str, Any]] = field(default_factory=list)

