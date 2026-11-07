"""
Agent 3: Threat Detection Agent
Evaluates filtered security anomalies against Sigma behavioral rules, attack patterns,
and intrusion signatures.
"""

from typing import List
from cyberguard.agents.base_agent import BaseAgent
from cyberguard.models.state import CyberGuardState
from cyberguard.models.events import ThreatDetection, Severity
from cyberguard.rules.threat_db import SIGMA_RULES

class ThreatDetectionAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-03-DETECTION",
            name="Threat Detection Agent",
            role="Signature & Anomaly-Based Attack Detection"
        )

    def process(self, state: CyberGuardState) -> CyberGuardState:
        detections: List[ThreatDetection] = []
        target_events = state.anomaly_events or state.filtered_events

        for ev in target_events:
            msg_lower = ev.raw_message.lower()

            # Rule 1: Storm-2603 SharePoint ToolShell Exploitation
            if "w3wp.exe" in msg_lower and any(sub in msg_lower for sub in ["powershell", "cmd.exe", "toolshell"]):
                detections.append(ThreatDetection(
                    threat_category="Exploitation of Public-Facing Application / Remote Code Execution",
                    mitre_technique_id="T1190",
                    mitre_tactic="Initial Access & Execution",
                    confidence=0.95,
                    affected_asset=ev.host or ev.destination_ip,
                    attacker_indicators=[ev.source_ip],
                    evidence=[
                        f"IIS worker w3wp.exe spawned abnormal sub-shell: '{ev.raw_message}'",
                        f"Target host: {ev.host} ({ev.destination_ip})"
                    ],
                    severity=Severity.CRITICAL,
                    matched_rule="SIGMA-001 (Storm-2603 ToolShell IIS Spawning)"
                ))

            # Rule 2: SSH Brute Force and SSHole Auth Bypass (CVE-2026-123158)
            if "failed password" in msg_lower or ("ssh" in msg_lower and ev.destination_port == 22):
                pwd_len = ev.metadata.get("password_length", 0)
                if pwd_len >= 256:
                    detections.append(ThreatDetection(
                        threat_category="Authentication Bypass Attempt (SSHole - CVE-2026-123158)",
                        mitre_technique_id="T1078",
                        mitre_tactic="Initial Access / Credential Access",
                        confidence=0.92,
                        affected_asset=ev.host or ev.destination_ip,
                        attacker_indicators=[ev.source_ip],
                        evidence=[
                            f"Abnormal SSH password length {pwd_len} bytes sent from {ev.source_ip}",
                            "Matches CVE-2026-123158 musl libc SSHole authentication bypass pattern"
                        ],
                        severity=Severity.HIGH,
                        matched_rule="SIGMA-002 (SSH Long Password Probe)"
                    ))
                elif ev.metadata.get("failed_attempts", 0) >= 4 or "failed password" in msg_lower:
                    detections.append(ThreatDetection(
                        threat_category="SSH Credential Brute Force",
                        mitre_technique_id="T1110",
                        mitre_tactic="Credential Access",
                        confidence=0.88,
                        affected_asset=ev.host or ev.destination_ip,
                        attacker_indicators=[ev.source_ip],
                        evidence=[
                            f"Repeated authentication failures detected from {ev.source_ip}",
                            f"Target account: {ev.user or 'root'}"
                        ],
                        severity=Severity.HIGH,
                        matched_rule="SIGMA-002-BRUTE"
                    ))

            # Rule 3: Ransomware Execution Pattern (Dharma / Has / info.txt)
            if any(ext in msg_lower for ext in [".has", ".dharma", "info.txt", "ransom note"]):
                detections.append(ThreatDetection(
                    threat_category="Ransomware Activity (Dharma / Has Variant)",
                    mitre_technique_id="T1486",
                    mitre_tactic="Impact",
                    confidence=0.98,
                    affected_asset=ev.host or ev.destination_ip,
                    attacker_indicators=[ev.source_ip],
                    evidence=[
                        f"Ransomware telemetry identified: '{ev.raw_message}'",
                        "Files undergoing mass encryption with .has extension"
                    ],
                    severity=Severity.CRITICAL,
                    matched_rule="SIGMA-003 (Ransomware Canary Modification)"
                ))

            # Rule 4: Rogue AI Agent Unauthorized Internal API Enumeration
            if "ai-security-agent" in msg_lower or ev.metadata.get("requests_per_min", 0) > 100:
                detections.append(ThreatDetection(
                    threat_category="Rogue AI Agent / Automated Crawling of Internal APIs",
                    mitre_technique_id="T1595",
                    mitre_tactic="Reconnaissance & Discovery",
                    confidence=0.85,
                    affected_asset=ev.destination_ip,
                    attacker_indicators=[ev.source_ip],
                    evidence=[
                        f"High-frequency internal endpoint traversal from {ev.source_ip}",
                        f"User-Agent: {ev.metadata.get('user_agent', 'ai-agent-bot')}"
                    ],
                    severity=Severity.MEDIUM,
                    matched_rule="SIGMA-004 (Rogue Agent Detection)"
                ))

        state.threat_detections = detections
        self.logger.info(f"Threat Detection Agent identified {len(detections)} potential attack threats.")
        return state
