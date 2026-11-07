"""
Agent 2: Security Data Analysis Agent
Filters noise, removes duplicates, detects statistical deviations, and labels suspicious events.
Prepares filtered queues for parallel analysis by Agents 3-6.
"""

from typing import List, Set
from cyberguard.agents.base_agent import BaseAgent
from cyberguard.models.state import CyberGuardState
from cyberguard.models.events import SecurityEvent

class SecurityDataAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-02-ANALYSIS",
            name="Security Data Analysis Agent",
            role="Noise Filtering, De-duplication & Anomaly Flagging"
        )

    def process(self, state: CyberGuardState) -> CyberGuardState:
        seen_fingerprints: Set[str] = set()
        filtered: List[SecurityEvent] = []
        anomalies: List[SecurityEvent] = []
        duplicates = 0

        # Known noise patterns (e.g. routine NTP, local broadcast, internal heartbeat)
        noise_dest_ports = {123, 5353, 5355}

        for ev in state.normalized_events:
            # Fingerprint for de-duplication within same 5-second window
            time_window = int(ev.timestamp // 5)
            fingerprint = f"{time_window}_{ev.source_ip}_{ev.destination_ip}_{ev.destination_port}_{ev.event_action}"

            if fingerprint in seen_fingerprints:
                duplicates += 1
                continue
            seen_fingerprints.add(fingerprint)

            # Filter trivial noise
            if ev.destination_port in noise_dest_ports and ev.event_action in ("ALLOW", "IGNORE"):
                continue

            # Flag suspicious patterns / anomalies
            is_suspicious = False
            score = 0.0

            # Heuristics:
            # 1. High non-standard destination ports or sensitive administrative ports
            if ev.destination_port in (22, 3389, 445, 5985, 8080, 8443) and "FAIL" in ev.event_action.upper():
                is_suspicious = True
                score += 0.45

            # 2. Suspicious process names or keywords in raw message
            msg_lower = ev.raw_message.lower()
            suspicious_keywords = [
                "failed password", "exploit", "unauthorized", "powershell", "w3wp.exe",
                "certutil", "bypass", "has", "dharma", "mimikatz", "toolshell", "rce", "cve-"
            ]
            for kw in suspicious_keywords:
                if kw in msg_lower:
                    is_suspicious = True
                    score += 0.50
                    break

            # 3. High anomaly metadata flags
            if ev.metadata.get("failed_attempts", 0) > 3:
                is_suspicious = True
                score += 0.35

            ev.is_anomaly = is_suspicious
            ev.anomaly_score = min(score, 1.0)

            filtered.append(ev)
            if is_suspicious:
                anomalies.append(ev)

        state.filtered_events = filtered
        state.anomaly_events = anomalies
        state.duplicate_count = duplicates
        
        total_in = len(state.normalized_events)
        state.noise_reduction_ratio = round((duplicates + (total_in - len(filtered))) / max(total_in, 1), 3)

        self.logger.info(
            f"Filtered events: {len(filtered)} retained, {duplicates} duplicates dropped. "
            f"Noise reduction: {state.noise_reduction_ratio * 100:.1f}%. "
            f"Flagged {len(anomalies)} anomalies for specialized inspection."
        )
        return state

