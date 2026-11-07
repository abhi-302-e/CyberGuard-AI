"""
Agent 1: Security Data Collection Agent
Collects, validates, and normalizes security logs from enterprise boundary appliances.
"""

import time
import uuid
from typing import Dict, Any, List
from backend.agents.base_agent import BaseCyberAgent

class SecurityDataCollectionAgent(BaseCyberAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-01-COLLECTION",
            agent_name="Data Collection Agent",
            responsibility="Collect, validate, and normalize enterprise security events"
        )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        raw_events = state.get("raw_events", [])
        normalized = []
        invalid_count = 0

        for item in raw_events:
            # Validate schema
            if not isinstance(item, dict) or ("src_ip" not in item and "message" not in item):
                invalid_count += 1
                continue

            normalized.append({
                "id": item.get("id", str(uuid.uuid4())),
                "timestamp": float(item.get("timestamp", time.time())),
                "source": str(item.get("source", "FIREWALL")).upper(),
                "src_ip": item.get("src_ip", "0.0.0.0"),
                "dst_ip": item.get("dst_ip", "0.0.0.0"),
                "src_port": int(item.get("src_port", 0)),
                "dst_port": int(item.get("dst_port", 0)),
                "protocol": str(item.get("protocol", "TCP")).upper(),
                "host": item.get("host", "unknown-host"),
                "user": item.get("user"),
                "action": str(item.get("action", "OBSERVED")).upper(),
                "message": item.get("message", ""),
                "metadata": item.get("metadata", {})
            })

        evidence = [
            f"Ingested {len(normalized)} normalized security telemetry events across enterprise boundary sources.",
            f"Identified and rejected {invalid_count} corrupt or unparseable telemetry frames."
        ]

        return {
            "finding": f"Ingested {len(normalized)} valid security events",
            "severity": "low" if invalid_count == 0 else "medium",
            "confidence": 0.98,
            "evidence": evidence,
            "recommendations": ["Forward normalized event queue to Security Data Analysis Agent"],
            "data": {"normalized_events": normalized, "invalid_count": invalid_count}
        }

