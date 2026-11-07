"""
Agent 3: Threat Detection Agent
Identifies brute force, public-facing exploits, fileless executions, and ransomware indicators.
"""

from typing import Dict, Any, List
from backend.agents.base_agent import BaseCyberAgent

class ThreatDetectionAgent(BaseCyberAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-03-DETECTION",
            agent_name="Threat Detection Agent",
            responsibility="Detect brute-force, web exploits, unauthorized access & lateral movement"
        )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        anomalies = state.get("anomalies") or state.get("filtered_events") or []
        detected_threats = []

        for ev in anomalies:
            msg = ev.get("message", "").lower()
            src_ip = ev.get("src_ip", "0.0.0.0")
            dst_ip = ev.get("dst_ip", "0.0.0.0")
            host = ev.get("host", dst_ip)

            # Check 1: ToolShell / Web App RCE Exploitation (Storm-2603)
            if "w3wp.exe" in msg and any(s in msg for s in ["powershell", "cmd.exe", "toolshell"]):
                detected_threats.append({
                    "category": "Remote Code Execution / IIS Process Hijack",
                    "mitre_technique": "T1190",
                    "mitre_tactic": "Initial Access & Execution",
                    "severity": "CRITICAL",
                    "confidence": 0.96,
                    "affected_asset": host,
                    "attacker_ip": src_ip,
                    "matched_rule": "SIGMA-001-IIS-SUBSHELL",
                    "evidence": [f"Web daemon w3wp.exe spawned interactive shell: {ev.get('message')}"]
                })

            # Check 2: Brute Force & SSHole Authentication Bypass
            if "failed password" in msg or (ev.get("dst_port") == 22 and "FAIL" in ev.get("action", "")):
                meta = ev.get("metadata", {})
                if meta.get("password_length", 0) > 256:
                    detected_threats.append({
                        "category": "Authentication Bypass Attempt (SSHole Buffer Exploit)",
                        "mitre_technique": "T1078",
                        "mitre_tactic": "Initial Access",
                        "severity": "HIGH",
                        "confidence": 0.92,
                        "affected_asset": host,
                        "attacker_ip": src_ip,
                        "matched_rule": "SIGMA-002-SSHOLE",
                        "evidence": [f"Abnormal password length {meta.get('password_length')} bytes from {src_ip}"]
                    })
                else:
                    detected_threats.append({
                        "category": "Credential Access / Brute Force",
                        "mitre_technique": "T1110",
                        "mitre_tactic": "Credential Access",
                        "severity": "HIGH",
                        "confidence": 0.88,
                        "affected_asset": host,
                        "attacker_ip": src_ip,
                        "matched_rule": "SIGMA-002-BRUTEFORCE",
                        "evidence": [f"Repeated authentication failures detected against account '{ev.get('user', 'root')}'"]
                    })

            # Check 3: Ransomware Activity (.has / info.txt)
            if any(ext in msg for ext in [".has", ".dharma", "info.txt", "ransom note"]):
                detected_threats.append({
                    "category": "Ransomware Mass Encryption (Dharma / Has Variant)",
                    "mitre_technique": "T1486",
                    "mitre_tactic": "Impact",
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                    "affected_asset": host,
                    "attacker_ip": src_ip,
                    "matched_rule": "SIGMA-003-RANSOMWARE",
                    "evidence": [f"High-velocity file extension modification: {ev.get('message')}"]
                })

        severity_rank = "low"
        if any(t["severity"] == "CRITICAL" for t in detected_threats):
            severity_rank = "critical"
        elif any(t["severity"] == "HIGH" for t in detected_threats):
            severity_rank = "high"

        return {
            "finding": f"Identified {len(detected_threats)} active attack indicators" if detected_threats else "No attack signatures matched",
            "severity": severity_rank,
            "confidence": 0.94 if detected_threats else 0.40,
            "evidence": [f"{t['category']} against {t['affected_asset']} (Rule: {t['matched_rule']})" for t in detected_threats],
            "recommendations": ["Correlate threat detections with CVE vulnerabilities and network flows"],
            "data": {"threats": detected_threats}
        }
