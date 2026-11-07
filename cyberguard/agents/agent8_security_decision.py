"""
Agent 8: Security Decision and Risk Assessment Agent (Core Decision Brain)
Evaluates threat intelligence, computes composite risk scores ($Risk = Severity \times AssetCriticality \times Confidence$),
enforces policy guardrails, and constructs a validated Defensive Action Plan.
"""

from typing import List
from cyberguard.agents.base_agent import BaseAgent
from cyberguard.models.state import CyberGuardState
from cyberguard.models.events import Severity
from cyberguard.models.response import (
    SecurityDecisionPlan,
    DefensiveAction,
    ActionType,
    IncidentStatus
)
from cyberguard.config import CONFIG

class SecurityDecisionAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-08-DECISION",
            name="Security Decision & Risk Assessment Agent",
            role="Risk Quantification, Response Strategy & Authorization Gate"
        )

    def process(self, state: CyberGuardState) -> CyberGuardState:
        intel = state.threat_intel_report
        if not intel or not state.threat_confirmed:
            self.logger.info("Threat is unconfirmed or negligible. Escalation skipped.")
            state.decision_plan = SecurityDecisionPlan(
                risk_score=10.0,
                overall_confidence=intel.confidence_score if intel else 0.2,
                threat_confirmed=False,
                actions=[],
                requires_human_signoff=False,
                policy_compliance_notes=["Telemetry within normal baseline limits. Continuous monitoring active."],
                status=IncidentStatus.FALSE_POSITIVE if intel and intel.confidence_score < 0.4 else IncidentStatus.IDENTIFIED
            )
            state.response_authorized = False
            return state

        # 1. Compute Asset Criticality Multiplier
        is_critical_asset_impacted = False
        criticality_weight = 1.0 # 1.0 standard, 1.5 high, 2.0 critical tier

        for asset in intel.affected_assets:
            if any(crit in asset.lower() for crit in CONFIG.policy.critical_assets):
                is_critical_asset_impacted = True
                criticality_weight = 2.0
                break

        # 2. Compute Base Severity Multiplier
        severity_multiplier = {
            Severity.INFO: 10.0,
            Severity.LOW: 25.0,
            Severity.MEDIUM: 50.0,
            Severity.HIGH: 75.0,
            Severity.CRITICAL: 95.0
        }.get(intel.overall_severity, 50.0)

        # Risk Score Calculation: (Severity * Criticality * Confidence) normalized to 100
        raw_risk = (severity_multiplier * criticality_weight * intel.confidence_score)
        risk_score = min(round(raw_risk, 1), 100.0)

        # 3. Formulate Defensive Action Plan
        actions: List[DefensiveAction] = []
        policy_notes: List[str] = []
        requires_human_approval = False

        # Action: Block Attacker IPs (Autonomous)
        for ioc in intel.indicators_of_compromise:
            if any(char.isdigit() for char in ioc) and "." in ioc: # IPv4
                actions.append(DefensiveAction(
                    action_type=ActionType.BLOCK_IP,
                    target=ioc,
                    parameters={"direction": "ingress", "firewall": "edge-pfsense-01", "timeout_sec": 86400},
                    rationale=f"Automated edge drop for verified malicious IOC associated with {intel.threat_actor}.",
                    requires_human_approval=False,
                    approved=True
                ))

        # Action: Host Quarantine / Endpoint Isolation
        for asset in intel.affected_assets:
            # If asset is a Tier-0 critical server (DC, DB cluster), policy FORBIDS autonomous full network disconnect!
            if any(crit in asset.lower() for crit in CONFIG.policy.critical_assets):
                requires_human_approval = True
                actions.append(DefensiveAction(
                    action_type=ActionType.ISOLATE_CRITICAL_DATABASE_SERVER,
                    target=asset,
                    parameters={"edr_agent": "crowdstrike", "scope": "isolation-with-soc-rfc"},
                    rationale=f"High-impact asset {asset} exhibits critical exploit activity ({intel.campaign}). Requires Human Incident Commander approval.",
                    requires_human_approval=True,
                    approved=False
                ))
                policy_notes.append(f"SAFETY POLICY GUARD: Automatic isolation of Tier-0 asset '{asset}' gated for human authorization.")
            else:
                # Standard workstation or non-critical DMZ host can be isolated autonomously
                actions.append(DefensiveAction(
                    action_type=ActionType.QUARANTINE_HOST,
                    target=asset,
                    parameters={"edr_agent": "crowdstrike", "allow_dhcp": False},
                    rationale=f"Autonomous endpoint containment to halt lateral movement and ransomware spread.",
                    requires_human_approval=False,
                    approved=True
                ))

        # Action: Revoke compromised user sessions
        for ev in state.anomaly_events:
            if ev.user and ev.user not in ("root", "SYSTEM", "Administrator"):
                actions.append(DefensiveAction(
                    action_type=ActionType.REVOKE_SESSION,
                    target=ev.user,
                    parameters={"idp": "Okta", "force_mfa_reset": True},
                    rationale=f"Compromised credential revocation for user {ev.user}.",
                    requires_human_approval=False,
                    approved=True
                ))

        # Action: Open SOC Incident Ticket & Send Alerts
        actions.append(DefensiveAction(
            action_type=ActionType.CREATE_TICKET,
            target="JIRA-SOC-QUEUE",
            parameters={"priority": "P1" if risk_score >= 80 else "P2", "title": intel.title},
            rationale="Record auditable case record in SOC ticketing system.",
            requires_human_approval=False,
            approved=True
        ))

        actions.append(DefensiveAction(
            action_type=ActionType.DISPATCH_ALERT,
            target="SOC-PagerDuty-Channel",
            parameters={"urgency": "HIGH", "summary": intel.attack_narrative},
            rationale="Real-time SOC notification via Slack / PagerDuty webhook.",
            requires_human_approval=False,
            approved=True
        ))

        # Check autonomous authorization criteria
        response_authorized = True
        if requires_human_approval:
            policy_notes.append("One or more actions require explicit Human SOC sign-off.")
        else:
            policy_notes.append("All proposed actions conform strictly to autonomous enterprise security policy.")

        decision = SecurityDecisionPlan(
            incident_id=intel.report_id,
            risk_score=risk_score,
            overall_confidence=intel.confidence_score,
            threat_confirmed=True,
            actions=actions,
            requires_human_signoff=requires_human_approval,
            policy_compliance_notes=policy_notes,
            status=IncidentStatus.CONTAINMENT_IN_PROGRESS
        )

        state.decision_plan = decision
        state.response_authorized = response_authorized
        state.human_approval_required = requires_human_approval
        
        self.logger.info(
            f"Decision Agent formulated response plan. Risk Score: {risk_score}/100 | "
            f"Proposed Actions: {len(actions)} | Gated for Human Signoff: {requires_human_approval}"
        )
        return state
