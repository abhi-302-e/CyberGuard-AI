"""
Agent 8: Security Decision and Risk Assessment Agent
Calculates composite mathematical risk, applies policy guardrails, and authorizes response actions.
"""

from typing import Dict, Any, List
from backend.agents.base_agent import BaseCyberAgent

TIER0_CRITICAL_ASSETS = ["10.0.0.1", "10.0.0.2", "dc-01.corp.internal", "db-primary.prod.internal"]

class SecurityDecisionAgent(BaseCyberAgent):
    def __init__(self):
        super().__init__(
            agent_id="AGENT-08-DECISION",
            agent_name="Security Decision Agent",
            responsibility="Quantify risk score, enforce policy constraints & construct authorized action plan"
        )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        intel = state.get("threat_intelligence", {})
        threat_confirmed = intel.get("threat_confirmed", False)

        if not threat_confirmed:
            return {
                "finding": "Telemetry confirmed benign; active containment waived",
                "severity": "low",
                "confidence": 0.95,
                "evidence": ["Signals remain within baseline enterprise parameters"],
                "recommendations": ["Continue continuous passive telemetry monitoring"],
                "data": {
                    "risk_score": 10.0,
                    "threat_confirmed": False,
                    "response_authorized": False,
                    "actions": [],
                    "human_approval_required": False
                }
            }

        # Calculate Risk Score
        sev = intel.get("overall_severity", "MEDIUM")
        sev_multiplier = {"CRITICAL": 95.0, "HIGH": 75.0, "MEDIUM": 50.0, "LOW": 25.0, "INFO": 10.0}.get(sev, 50.0)
        
        # Check if Tier-0 critical infrastructure is impacted
        impacts_tier0 = False
        for asset in intel.get("affected_assets", []):
            if any(crit in asset.lower() for crit in TIER0_CRITICAL_ASSETS):
                impacts_tier0 = True
                break

        criticality_weight = 2.0 if impacts_tier0 else 1.0
        confidence = intel.get("confidence_score", 0.85)

        risk_score = min(round(sev_multiplier * criticality_weight * confidence, 1), 100.0)

        # Build prioritized action plan
        actions = []
        policy_notes = []

        # Action: Block malicious indicators
        for ind in intel.get("indicators", []):
            if "." in ind and any(c.isdigit() for c in ind):
                actions.append({
                    "action_type": "BLOCK_IP",
                    "target": ind,
                    "rationale": f"Boundary null-route for confirmed C2 indicator ({intel.get('threat_actor')})",
                    "requires_approval": False,
                    "approved": True
                })

        # Action: Host isolation with safety gating
        for asset in intel.get("affected_assets", []):
            if any(crit in asset.lower() for crit in TIER0_CRITICAL_ASSETS):
                policy_notes.append(f"SAFETY GATE: Containment of Tier-0 asset '{asset}' held for manual Human Commander signoff.")
                actions.append({
                    "action_type": "ISOLATE_CRITICAL_SERVER",
                    "target": asset,
                    "rationale": "High-risk exploitation observed on mission-critical system. Requires cryptographic human approval.",
                    "requires_approval": True,
                    "approved": False
                })
            else:
                actions.append({
                    "action_type": "QUARANTINE_HOST",
                    "target": asset,
                    "rationale": "Automated EDR endpoint isolation to halt lateral movement",
                    "requires_approval": False,
                    "approved": True
                })

        # Action: Create SOC Ticket
        actions.append({
            "action_type": "CREATE_TICKET",
            "target": "JIRA-SOC-QUEUE",
            "rationale": f"P1 incident ticket for {intel.get('title')}",
            "requires_approval": False,
            "approved": True
        })

        return {
            "finding": f"Risk evaluated at {risk_score}/100. Formulated {len(actions)} defensive actions.",
            "severity": "critical" if risk_score >= 80 else "high",
            "confidence": confidence,
            "evidence": [f"Risk Score: {risk_score} (Severity {sev}, Criticality {criticality_weight}x)"] + policy_notes,
            "recommendations": ["Execute authorized autonomous containment immediately; gate Tier-0 actions"],
            "data": {
                "risk_score": risk_score,
                "threat_confirmed": True,
                "response_authorized": True,
                "human_approval_required": impacts_tier0,
                "actions": actions,
                "policy_notes": policy_notes
            }
        }
