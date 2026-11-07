"""
Agent 5: Network Monitoring Agent
Analyzes network flows, DNS queries, egress spikes, and C2 beaconing.
"""

from typing import List
from cyberguard.agents.base_agent import BaseAgent
from cyberguard.models.state import CyberGuardState
from cyberguard.models.events import NetworkAnomaly

class NetworkMonitoringAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-05-NETWORK",
            name="Network Monitoring Agent",
            role="Traffic Flow, C2 Beaconing & Protocol Anomaly Detection"
        )

    def process(self, state: CyberGuardState) -> CyberGuardState:
        anomalies: List[NetworkAnomaly] = []

        for ev in state.filtered_events:
            # 1. Check for Command & Control (C2) beaconing
            interval = ev.metadata.get("beacon_interval_sec")
            jitter = ev.metadata.get("jitter_pct", 100)
            if interval and interval in (30, 60, 120) and jitter < 10:
                anomalies.append(NetworkAnomaly(
                    source_ip=ev.source_ip,
                    destination_ip=ev.destination_ip,
                    port=ev.destination_port,
                    protocol=ev.protocol,
                    anomaly_type="C2_BEACONING",
                    traffic_volume_bytes=ev.metadata.get("bytes_transferred", 512),
                    connection_rate=1.0 / interval,
                    evidence=f"Periodic heartbeat detected to external destination {ev.destination_ip}:{ev.destination_port} with low jitter ({jitter}%).",
                    confidence=0.91
                ))

            # 2. Check for unexpected high-volume outbound data transfer (exfiltration)
            bytes_out = ev.metadata.get("bytes_out", 0)
            if bytes_out > 50 * 1024 * 1024: # > 50MB
                anomalies.append(NetworkAnomaly(
                    source_ip=ev.source_ip,
                    destination_ip=ev.destination_ip,
                    port=ev.destination_port,
                    protocol=ev.protocol,
                    anomaly_type="DATA_EXFILTRATION",
                    traffic_volume_bytes=bytes_out,
                    connection_rate=float(ev.metadata.get("packets", 1000)),
                    evidence=f"Large volume egress transfer ({bytes_out / (1024*1024):.2f} MB) to external IP {ev.destination_ip}.",
                    confidence=0.88
                ))

            # 3. Check for horizontal port scanning / internal reconnaissance
            ports_scanned = ev.metadata.get("distinct_ports_contacted", 0)
            if ports_scanned > 20:
                anomalies.append(NetworkAnomaly(
                    source_ip=ev.source_ip,
                    destination_ip=ev.destination_ip,
                    port=0,
                    protocol=ev.protocol,
                    anomaly_type="PORT_SCAN",
                    traffic_volume_bytes=ports_scanned * 64,
                    connection_rate=float(ports_scanned),
                    evidence=f"Internal IP {ev.source_ip} probed {ports_scanned} distinct ports on {ev.destination_ip} within 60s.",
                    confidence=0.85
                ))

            # 4. Check for DNS Tunneling
            dns_query_len = ev.metadata.get("dns_query_length", 0)
            if dns_query_len > 180:
                anomalies.append(NetworkAnomaly(
                    source_ip=ev.source_ip,
                    destination_ip=ev.destination_ip,
                    port=53,
                    protocol="UDP",
                    anomaly_type="DNS_TUNNELING",
                    traffic_volume_bytes=dns_query_len,
                    connection_rate=10.0,
                    evidence=f"Extremely high entropy/length DNS lookup ({dns_query_len} chars) indicating data tunneling.",
                    confidence=0.87
                ))

        state.network_anomalies = anomalies
        self.logger.info(f"Network Monitoring Agent detected {len(anomalies)} traffic anomalies.")
        return state

