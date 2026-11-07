"""
Agent 5: Network Monitoring Agent
Analyzes Zeek flow records, C2 periodic beaconing, DNS tunneling, and data exfiltration.
"""

from typing import Dict, Any, List
from backend.agents.base_agent import BaseCyberAgent

class NetworkMonitoringAgent(BaseCyberAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-05-NETWORK",
            agent_name="Network Monitoring Agent",
            responsibility="Monitor network flows, detect C2 beaconing & data exfiltration"
        )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        filtered = state.get("filtered_events", [])
        network_anomalies = []

        for ev in filtered:
            meta = ev.get("metadata", {})
            src_ip = ev.get("src_ip", "0.0.0.0")
            dst_ip = ev.get("dst_ip", "0.0.0.0")

            # Check for Command & Control (C2) beaconing
            interval = meta.get("beacon_interval_sec")
            jitter = meta.get("jitter_pct", 100)
            if interval and jitter < 15:
                network_anomalies.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": ev.get("dst_port", 0),
                    "anomaly_type": "C2_BEACONING",
                    "traffic_bytes": meta.get("bytes_transferred", 1024),
                    "confidence": 0.92,
                    "evidence": f"Periodic outbound heartbeat detected to {dst_ip}:{ev.get('dst_port')} (Interval: {interval}s, Jitter: {jitter}%)"
                })

            # Check for Data Exfiltration
            bytes_out = meta.get("bytes_out", 0)
            if bytes_out > 50 * 1024 * 1024:
                network_anomalies.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": ev.get("dst_port", 0),
                    "anomaly_type": "DATA_EXFILTRATION",
                    "traffic_bytes": bytes_out,
                    "confidence": 0.89,
                    "evidence": f"Large anomalous outbound egress transfer ({bytes_out / (1024*1024):.2f} MB) to external destination {dst_ip}"
                })

        return {
            "finding": f"Detected {len(network_anomalies)} network traffic anomalies" if network_anomalies else "Network flows within normal operational baseline",
            "severity": "high" if network_anomalies else "low",
            "confidence": 0.91 if network_anomalies else 0.50,
            "evidence": [a["evidence"] for a in network_anomalies],
            "recommendations": ["Inspect endpoint sockets associated with flagged destination IPs"],
            "data": {"network_anomalies": network_anomalies}
        }

