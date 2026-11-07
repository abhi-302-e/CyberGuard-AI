"""
Shared Multi-Agent State Schema for LangGraph
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from cyberguard.models.events import (
    SecurityEvent,
    ThreatDetection,
    VulnerabilityFinding,
    NetworkAnomaly,
    MalwareAnalysisResult
)
from cyberguard.models.response import (
    ThreatIntelligenceReport,
    SecurityDecisionPlan,
    ActionResult,
    MonitoringMetrics
)

@dataclass
class AgentAuditLog:
    agent_id: str
    agent_name: str
    execution_time_ms: float
    status: str
    summary: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class CyberGuardState:
    """
    Unified state representing the complete lifecycle of telemetry through
    all 10 specialized agents.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    
    # Agent 1: Ingestion
    raw_events: List[Dict[str, Any]] = field(default_factory=list)
    normalized_events: List[SecurityEvent] = field(default_factory=list)
    
    # Agent 2: Analysis & Filtering
    filtered_events: List[SecurityEvent] = field(default_factory=list)
    anomaly_events: List[SecurityEvent] = field(default_factory=list)
    duplicate_count: int = 0
    noise_reduction_ratio: float = 0.0
    
    # Parallel Detection Agents (Agents 3 - 6)
    threat_detections: List[ThreatDetection] = field(default_factory=list)
    vulnerability_findings: List[VulnerabilityFinding] = field(default_factory=list)
    network_anomalies: List[NetworkAnomaly] = field(default_factory=list)
    malware_analyses: List[MalwareAnalysisResult] = field(default_factory=list)
    
    # Agent 7: Correlation
    threat_intel_report: Optional[ThreatIntelligenceReport] = None
    threat_confirmed: bool = False
    
    # Agent 8: Decision & Risk Assessment
    decision_plan: Optional[SecurityDecisionPlan] = None
    response_authorized: bool = False
    human_approval_required: bool = False
    
    # Agent 9: Incident Response
    executed_actions: List[ActionResult] = field(default_factory=list)
    containment_successful: bool = False
    
    # Agent 10: Monitoring & Self-Learning
    monitoring_metrics: Optional[MonitoringMetrics] = None
    final_report_markdown: str = ""
    workflow_completed: bool = False
    
    # Resilience & Tracing
    audit_trail: List[AgentAuditLog] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    escalated_to_human: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to a serializable dictionary for logging/UI."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "raw_events_count": len(self.raw_events),
            "normalized_events_count": len(self.normalized_events),
            "filtered_events_count": len(self.filtered_events),
            "threat_detections_count": len(self.threat_detections),
            "vulnerabilities_count": len(self.vulnerability_findings),
            "network_anomalies_count": len(self.network_anomalies),
            "malware_analyses_count": len(self.malware_analyses),
            "threat_confirmed": self.threat_confirmed,
            "response_authorized": self.response_authorized,
            "human_approval_required": self.human_approval_required,
            "containment_successful": self.containment_successful,
            "workflow_completed": self.workflow_completed,
            "executed_actions": [a.__dict__ for a in self.executed_actions],
            "audit_trail": [a.__dict__ for a in self.audit_trail],
            "errors": self.errors
        }

