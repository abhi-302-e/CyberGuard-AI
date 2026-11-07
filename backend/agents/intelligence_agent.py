"""
Agent 7: Threat Intelligence Agent
Synthesizes multi-source telemetry from Agents 3-6, attributes adversary groups,
and maps findings to MITRE ATT&CK techniques.
"""

from typing import Dict, Any, List, Set
from backend.agents.base_agent import BaseCyberAgent

class ThreatIntelligenceAgent(BaseCyberAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-07-INTEL",
            agent_name="Threat Intelligence Agent",
            responsibility="Correlate multi-agent findings, attribute threat campaigns & map MITRE ATT&CK matrix"
        )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        threats = state.get("threats", [])
        vulns = state.get("vulnerabilities", [])
        network = state.get("network_anomalies", [])
        malware = state.get("malware_reports", [])

        corroborating_sources = []
        affected_assets: Set[str] = set()
        indicators: Set[str] = set()
        mitre_list = []
        evidence_chain = []
        conf_scores = []

        if threats:
            corroborating_sources.append("Threat Detection Agent")
            for t in threats:
                affected_assets.add(t.get("affected_asset", "unknown"))
                if t.get("attacker_ip"):
                    indicators.add(t["attacker_ip"])
                mitre_list.append({"technique": t.get("mitre_technique", "T1000"), "tactic": t.get("mitre_tactic", "Initial Access")})
                evidence_chain.extend(t.get("evidence", []))
                conf_scores.append(t.get("confidence", 0.85))

        if vulns:
            corroborating_sources.append("Vulnerability Assessment Agent")
            for v in vulns:
                affected_assets.add(v.get("affected_asset", "unknown"))
                evidence_chain.append(f"Host vulnerable to {v.get('cve_id')} ({v.get('title')}) - CVSS {v.get('cvss_score')}")
                conf_scores.append(0.95)

        if network:
            corroborating_sources.append("Network Monitoring Agent")
            for n in network:
                indicators.add(n.get("dst_ip", "0.0.0.0"))
                evidence_chain.append(n.get("evidence", ""))
                conf_scores.append(n.get("confidence", 0.90))

        if malware:
            corroborating_sources.append("Malware Analysis Agent")
            for m in malware:
                if m.get("quarantine_recommended"):
                    indicators.add(m.get("sha256"))
                    evidence_chain.append(f"Malware payload identified: {m.get('file_name')} ({m.get('malware_family')})")
                    conf_scores.append(0.96)

        avg_conf = round(sum(conf_scores) / max(len(conf_scores), 1), 2) if conf_scores else 0.30

        # Attribution logic
        actor = "Unattributed Adversary"
        campaign = "Opportunistic Network Intrusion"
        ev_str = " ".join(evidence_chain).lower()

        if "storm-2603" in ev_str or "toolshell" in ev_str:
            actor = "Storm-2603"
            campaign = "SharePoint ToolShell Fileless Ransomware Campaign"
        elif "has" in ev_str or "dharma" in ev_str:
            actor = "Dharma Ransomware Syndicate"
            campaign = "Has Ransomware Extortion Campaign"
        elif "civn-2026-0539" in ev_str:
            actor = "Advanced Privilege Escalation Operator"
            campaign = "Enterprise Linux Host Takeover"

        severity = "CRITICAL" if any("CRITICAL" in str(x).upper() for x in [threats, vulns, malware]) else ("HIGH" if threats or network else "LOW")
        threat_confirmed = len(corroborating_sources) >= 2 or severity == "CRITICAL"

        narrative = (
            f"Multi-agent synthesis correlated {len(evidence_chain)} indicators across {len(corroborating_sources)} specialized agents. "
            f"Attributed to {actor} ({campaign}) impacting systems: {', '.join(affected_assets) or 'None'}. "
            f"Evaluated as {severity} with {avg_conf * 100:.1f}% confidence."
        )

        stix_bundle = {
            "type": "bundle",
            "spec_version": "2.1",
            "objects": [
                {"type": "indicator", "pattern": f"[network-traffic:dst_ref.value IN ({', '.join(indicators)})]", "confidence": int(avg_conf * 100)},
                {"type": "threat-actor", "name": actor}
            ]
        }

        return {
            "finding": f"Synthesized intelligence: {actor} - {severity} Risk" if threat_confirmed else "Routine operational baseline confirmed",
            "severity": severity.lower(),
            "confidence": avg_conf,
            "evidence": evidence_chain,
            "recommendations": ["Forward consolidated incident profile to Security Decision Agent for risk assessment"],
            "data": {
                "title": f"Incident Brief: {actor} - {severity} Activity",
                "threat_actor": actor,
                "campaign": campaign,
                "overall_severity": severity,
                "confidence_score": avg_conf,
                "affected_assets": list(affected_assets),
                "indicators": list(indicators),
                "mitre_techniques": mitre_list,
                "corroborating_sources": corroborating_sources,
                "narrative": narrative,
                "stix_bundle": stix_bundle,
                "threat_confirmed": threat_confirmed
            }
        }
