"""
Agent 1: Security Data Collection Agent
Input Agent: Ingests raw security logs from firewalls, routers, servers, EDR, and SIEM.
Normalizes incoming events into structured SecurityEvent models.
"""

import time
import uuid
from typing import Dict, Any, List
from cyberguard.agents.base_agent import BaseAgent
from cyberguard.models.state import CyberGuardState
from cyberguard.models.events import SecurityEvent, LogSource

class SecurityDataCollectionAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-01-INGEST",
            name="Security Data Collection Agent",
            role="Enterprise Security Data Ingestion & Normalization"
        )

    def process(self, state: CyberGuardState) -> CyberGuardState:
        normalized_events: List[SecurityEvent] = []
        raw_items = state.raw_events or []

        for item in raw_items:
            # Parse and map source type
            raw_src = str(item.get("source", "FIREWALL")).upper()
            try:
                src_type = LogSource[raw_src]
            except KeyError:
                src_type = LogSource.FIREWALL

            # Standardize and normalize
            event = SecurityEvent(
                event_id=item.get("id", str(uuid.uuid4())),
                timestamp=float(item.get("timestamp", time.time())),
                source_type=src_type,
                source_ip=item.get("src_ip", "0.0.0.0"),
                destination_ip=item.get("dst_ip", "0.0.0.0"),
                source_port=int(item.get("src_port", 0)),
                destination_port=int(item.get("dst_port", 0)),
                protocol=item.get("protocol", "TCP").upper(),
                host=item.get("host", "unknown-host"),
                user=item.get("user"),
                event_action=item.get("action", "OBSERVED"),
                raw_message=item.get("message", ""),
                metadata=item.get("metadata", {})
            )
            normalized_events.append(event)

        state.normalized_events = normalized_events
        self.logger.info(f"Ingested and normalized {len(normalized_events)} security telemetry events.")
        return state

