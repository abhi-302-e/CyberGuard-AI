"""
CyberGuard AI - Unified Orchestrator State Contract
"""

import time
import uuid
from typing import Dict, Any, List

def create_initial_state(raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "session_id": str(uuid.uuid4()),
        "created_at": time.time(),
        "raw_events": raw_events,
        "normalized_events": [],
        "filtered_events": [],
        "anomalies": [],
        "threats": [],
        "vulnerabilities": [],
        "network_anomalies": [],
        "malware_reports": [],
        "threat_intelligence": {},
        "decision": {},
        "response": {},
        "monitoring": {},
        "audit_trail": [],
        "errors": []
    }

