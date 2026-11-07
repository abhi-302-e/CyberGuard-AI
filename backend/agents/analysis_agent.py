"""
Agent 2: Security Data Analysis Agent
Deduplicates alert storms, suppresses routine heartbeat noise, and flags statistical deviations.
"""

from typing import Dict, Any, List, Set
from backend.agents.base_agent import BaseCyberAgent

class SecurityDataAnalysisAgent(BaseCyberAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-02-ANALYSIS",
            agent_name="Data Analysis Agent",
            responsibility="Clean, deduplicate, filter noise, and tag suspicious events"
        )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        normalized = state.get("normalized_events", [])
        seen_fingerprints: Set[str] = set()
        filtered = []
        anomalies = []
        duplicate_count = 0

        noise_ports = {123, 5353, 5355}

        for ev in normalized:
            time_bucket = int(ev.get("timestamp", 0) // 5)
            fp = f"{time_bucket}_{ev.get('src_ip')}_{ev.get('dst_ip')}_{ev.get('dst_port')}_{ev.get('action')}"
            
            if fp in seen_fingerprints:
                duplicate_count += 1
                continue
            seen_fingerprints.add(fp)

            # Drop routine benign broadcast
            if ev.get("dst_port") in noise_ports and ev.get("action") in ("ALLOW", "IGNORE"):
                continue

            # Flag suspicious indicators
            msg = ev.get("message", "").lower()
            dst_port = ev.get("dst_port", 0)
            score = 0.0

            if dst_port in (22, 3389, 445, 5985, 8080, 8443) and "FAIL" in ev.get("action", ""):
                score += 0.45

            suspicious_kw = ["failed password", "exploit", "unauthorized", "powershell", "w3wp.exe", "cve-", "rce", "toolshell", "has", "dharma"]
            if any(k in msg for k in suspicious_kw):
                score += 0.50

            ev["anomaly_score"] = min(score, 1.0)
            ev["is_anomaly"] = score >= 0.40

            filtered.append(ev)
            if ev["is_anomaly"]:
                anomalies.append(ev)

        noise_ratio = round((duplicate_count / max(len(normalized), 1)) * 100, 1)

        return {
            "finding": f"Filtered {len(filtered)} clean events, flagged {len(anomalies)} anomalies",
            "severity": "medium" if len(anomalies) > 0 else "low",
            "confidence": 0.95,
            "evidence": [
                f"Suppressed {duplicate_count} duplicated event records ({noise_ratio}% noise reduction).",
                f"Flagged {len(anomalies)} anomalous telemetry records requiring domain inspection."
            ],
            "recommendations": ["Dispatch prioritized anomaly queues to parallel Detection Mesh"],
            "data": {
                "filtered_events": filtered,
                "anomalies": anomalies,
                "duplicate_count": duplicate_count,
                "noise_reduction_pct": noise_ratio
            }
        }
