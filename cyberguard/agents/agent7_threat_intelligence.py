"""
Agent 7: Threat Intelligence Agent (Correlation Engine)
Aggregates findings from Agents 3, 4, 5, and 6. Correlates multi-source telemetry,
maps to MITRE ATT&CK enterprise matrices, and builds a consolidated Threat Intelligence Report.
"""

from typing import List, Set, Dict, Any
from cyberguard.agents.base_agent import BaseAgent
from cyberguard.models.state import CyberGuardState
from cyberguard.models.events import Severity
from cyberguard.models.response import ThreatIntelligenceReport

class ThreatIntelligenceAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-07-INTEL",
            name="Threat Intelligence Agent",
            role="Multi-Source Threat Correlation & ATT&CK Mapping"
        )

    def process(self, state: CyberGuardState) -> CyberGuardState:
        corroborating: List[str] = []
        affected_assets: Set[str] = set()
        iocs: Set[str] = set()
        mitre_list: List[Dict[str, str]] = []
        evidence_points: List[str] = []

        total_confidence = 0.0
        confidence_count = 0
        severity_score = 0 # 0=INFO, 1=LOW, 2=MED, 3=HIGH, 4=CRIT

        # 1. Process Threat Detections (Agent 3)
        if state.threat_detections:
            corroborating.append("Agent 3 (Threat Detection)")
            for det in state.threat_detections:
                affected_assets.add(det.affected_asset)
                for ind in det.attacker_indicators:
                    iocs.add(ind)
                mitre_list.append({"technique_id": det.mitre_technique_id, "tactic": det.mitre_tactic, "category": det.threat_category})
                evidence_points.extend(det.evidence)
                total_confidence += det.confidence
                confidence_count += 1
                if det.severity == Severity.CRITICAL:
                    severity_score = max(severity_score, 4)
                elif det.severity == Severity.HIGH:
                    severity_score = max(severity_score, 3)

        # 2. Process Vulnerability Findings (Agent 4)
        if state.vulnerability_findings:
            corroborating.append("Agent 4 (Vulnerability Assessment)")
            for v in state.vulnerability_findings:
                if v.asset_host:
                    affected_assets.add(v.asset_host)
                if v.asset_ip:
                    affected_assets.add(v.asset_ip)
                evidence_points.append(f"Host vulnerable to {v.cve_id} (CVSS {v.cvss_score}) - {v.description}")
                if v.cvss_score >= 9.0:
                    severity_score = max(severity_score, 4)
                elif v.cvss_score >= 7.0:
                    severity_score = max(severity_score, 3)

        # 3. Process Network Anomalies (Agent 5)
        if state.network_anomalies:
            corroborating.append("Agent 5 (Network Monitoring)")
            for net in state.network_anomalies:
                iocs.add(net.destination_ip)
                affected_assets.add(net.source_ip)
                evidence_points.append(f"Network Anomaly ({net.anomaly_type}): {net.evidence}")
                total_confidence += net.confidence
                confidence_count += 1
                severity_score = max(severity_score, 3)

        # 4. Process Malware Analysis (Agent 6)
        if state.malware_analyses:
            corroborating.append("Agent 6 (Malware Analysis)")
            for mal in state.malware_analyses:
                if mal.is_malicious:
                    iocs.add(mal.file_hash_sha256)
                    evidence_points.append(f"Malware Flagged: {mal.file_name} ({mal.malware_family}) matches {', '.join(mal.matched_yara_rules)}")
                    total_confidence += 0.95
                    confidence_count += 1
                    severity_score = max(severity_score, 4)

        # Calculate composite confidence
        mean_confidence = round(total_confidence / max(confidence_count, 1), 2)
        if confidence_count == 0:
            mean_confidence = 0.30

        # Map severity score to enum
        severity_map = {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH, 4: Severity.CRITICAL}
        overall_sev = severity_map.get(severity_score, Severity.MEDIUM)

        # Threat Actor / Campaign Attribution heuristics
        threat_actor = "Unattributed Threat"
        campaign = "Opportunistic Exploitation"
        ev_text = " ".join(evidence_points).lower()

        if "storm-2603" in ev_text or "toolshell" in ev_text or "warlock" in ev_text:
            threat_actor = "Storm-2603"
            campaign = "SharePoint ToolShell Fileless Ransomware Campaign"
        elif "has" in ev_text or "dharma" in ev_text:
            threat_actor = "Dharma Ransomware Syndicate"
            campaign = "Has Ransomware Extortion Campaign"
        elif "civn-2026-0539" in ev_text or "kernel use-after-free" in ev_text:
            threat_actor = "Advanced Local Privilege Escalation Actor"
            campaign = "Enterprise Linux Infrastructure Intrusion"
        elif "cve-2026-123158" in ev_text or "sshole" in ev_text:
            threat_actor = "Automated SSH Exploitation Scanner"
            campaign = "OpenSSH SSHole Musl libc Exposure Probe"

        # Determine if threat is genuinely confirmed
        is_threat_confirmed = (len(corroborating) >= 2 and mean_confidence >= 0.70) or (overall_sev == Severity.CRITICAL)

        narrative = (
            f"Multi-source correlation synthesized {confidence_count} signals across {len(corroborating)} specialized agents. "
            f"Attributed to {threat_actor} under '{campaign}'. Target systems: {', '.join(affected_assets) or 'None'}. "
            f"Severity evaluated as {overall_sev.value} with confidence {mean_confidence * 100:.1f}%."
        )

        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{state.session_id}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": f"[network-traffic:dst_ref.value IN ({', '.join(iocs)})]",
                    "confidence": int(mean_confidence * 100)
                },
                {
                    "type": "threat-actor",
                    "name": threat_actor
                }
            ]
        }

        report = ThreatIntelligenceReport(
            title=f"Incident Brief: {threat_actor} - {overall_sev.value} Risk Detection",
            threat_actor=threat_actor,
            campaign=campaign,
            overall_severity=overall_sev,
            confidence_score=mean_confidence,
            affected_assets=list(affected_assets),
            indicators_of_compromise=list(iocs),
            mitre_techniques=mitre_list,
            corroborating_agents=corroborating,
            attack_narrative=narrative,
            raw_stix_bundle=stix_bundle
        )

        state.threat_intel_report = report
        state.threat_confirmed = is_threat_confirmed
        self.logger.info(
            f"Threat Intelligence Agent generated consolidated report. "
            f"Threat Confirmed: {is_threat_confirmed} | Severity: {overall_sev.value} | Confidence: {mean_confidence:.2f}"
        )
        return state

