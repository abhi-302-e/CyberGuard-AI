"""
CyberGuard AI - LangGraph Multi-Agent Orchestrator
Defines the directed execution graph, state transitions, conditional branching,
and error handling.
"""

import logging
from typing import Dict, Any, Callable
from cyberguard.models.state import CyberGuardState
from cyberguard.agents.agent1_data_collection import SecurityDataCollectionAgent
from cyberguard.agents.agent2_data_analysis import SecurityDataAnalysisAgent
from cyberguard.agents.agent3_threat_detection import ThreatDetectionAgent
from cyberguard.agents.agent4_vulnerability_assessment import VulnerabilityAssessmentAgent
from cyberguard.agents.agent5_network_monitoring import NetworkMonitoringAgent
from cyberguard.agents.agent6_malware_analysis import MalwareAnalysisAgent
from cyberguard.agents.agent7_threat_intelligence import ThreatIntelligenceAgent
from cyberguard.agents.agent8_security_decision import SecurityDecisionAgent
from cyberguard.agents.agent9_incident_response import IncidentResponseAgent
from cyberguard.agents.agent10_monitoring_learning import MonitoringAndLearningAgent
from cyberguard.orchestrator.error_recovery import ErrorRecoveryManager

logger = logging.getLogger("CyberGuard.Orchestrator")

class CyberGuardGraph:
    """
    Orchestrates the 10-agent autonomous cybersecurity pipeline.
    Maintains LangGraph compatible node signatures and conditional transitions.
    """

    def __init__(self):
        self.recovery = ErrorRecoveryManager()
        
        # Instantiate 10 specialized agents
        self.agent1 = SecurityDataCollectionAgent()
        self.agent2 = SecurityDataAnalysisAgent()
        self.agent3 = ThreatDetectionAgent()
        self.agent4 = VulnerabilityAssessmentAgent()
        self.agent5 = NetworkMonitoringAgent()
        self.agent6 = MalwareAnalysisAgent()
        self.agent7 = ThreatIntelligenceAgent()
        self.agent8 = SecurityDecisionAgent()
        self.agent9 = IncidentResponseAgent()
        self.agent10 = MonitoringAndLearningAgent()

    # --- Graph Node Callables ---

    def node_data_collection(self, state: CyberGuardState) -> CyberGuardState:
        return self.recovery.execute_with_resilience(
            self.agent1.agent_id, self.agent1.execute, state
        )

    def node_data_analysis(self, state: CyberGuardState) -> CyberGuardState:
        return self.recovery.execute_with_resilience(
            self.agent2.agent_id, self.agent2.execute, state
        )

    def node_parallel_detection(self, state: CyberGuardState) -> CyberGuardState:
        """
        Executes parallel domain-specific detection agents (Agents 3, 4, 5, 6).
        """
        state = self.recovery.execute_with_resilience(self.agent3.agent_id, self.agent3.execute, state)
        state = self.recovery.execute_with_resilience(self.agent4.agent_id, self.agent4.execute, state)
        state = self.recovery.execute_with_resilience(self.agent5.agent_id, self.agent5.execute, state)
        state = self.recovery.execute_with_resilience(self.agent6.agent_id, self.agent6.execute, state)
        return state

    def node_threat_intelligence(self, state: CyberGuardState) -> CyberGuardState:
        return self.recovery.execute_with_resilience(
            self.agent7.agent_id, self.agent7.execute, state
        )

    def node_security_decision(self, state: CyberGuardState) -> CyberGuardState:
        return self.recovery.execute_with_resilience(
            self.agent8.agent_id, self.agent8.execute, state
        )

    def node_incident_response(self, state: CyberGuardState) -> CyberGuardState:
        return self.recovery.execute_with_resilience(
            self.agent9.agent_id, self.agent9.execute, state
        )

    def node_monitoring_and_learning(self, state: CyberGuardState) -> CyberGuardState:
        return self.recovery.execute_with_resilience(
            self.agent10.agent_id, self.agent10.execute, state
        )

    def node_record_continue_monitoring(self, state: CyberGuardState) -> CyberGuardState:
        logger.info("[Workflow Branch] Threat is NOT confirmed. Telemetry recorded to baseline memory.")
        state.workflow_completed = True
        state.final_report_markdown = (
            f"# CyberGuard AI - Baseline Monitoring Log\n"
            f"**Session:** `{state.session_id}`\n\n"
            f"Events analyzed: {len(state.normalized_events)}. All activities were within acceptable operational limits."
        )
        return state

    def node_escalate_human_approval(self, state: CyberGuardState) -> CyberGuardState:
        logger.warning("[Workflow Branch] Safety Gating: High-impact actions require human incident commander sign-off.")
        state.escalated_to_human = True
        return state

    def node_recovery_and_escalate(self, state: CyberGuardState) -> CyberGuardState:
        logger.error("[Workflow Branch] Containment verification failed. Escalating incident to Tier-3 SecOps on-call.")
        state.escalated_to_human = True
        return state

    # --- Conditional Routing Logic ---

    def condition_is_threat_confirmed(self, state: CyberGuardState) -> str:
        return "YES" if state.threat_confirmed else "NO"

    def condition_is_response_authorized(self, state: CyberGuardState) -> str:
        if state.human_approval_required:
            return "REQUIRE_HUMAN_APPROVAL"
        return "APPROVED" if state.response_authorized else "REJECTED"

    def condition_is_threat_contained(self, state: CyberGuardState) -> str:
        return "YES" if state.containment_successful else "NO"

    # --- End-to-End Autonomous Runner ---

    def run(self, state: CyberGuardState) -> CyberGuardState:
        """
        Executes the entire end-to-end directed graph autonomously without human intervention.
        """
        logger.info(f"=== Starting CyberGuard AI Autonomous Workflow [Session: {state.session_id}] ===")

        # Step 1: Collect Enterprise Security Data
        state = self.node_data_collection(state)

        # Step 2: Validate and Analyze Events
        state = self.node_data_analysis(state)

        # Step 3: Fan-out to Specialized Detection Agents (Agents 3, 4, 5, 6)
        state = self.node_parallel_detection(state)

        # Step 4: Threat Intelligence Correlation (Agent 7)
        state = self.node_threat_intelligence(state)

        # Step 5: Threat Decision & Risk Assessment (Agent 8)
        state = self.node_security_decision(state)

        # Conditional Check 1: Threat Confirmed?
        if self.condition_is_threat_confirmed(state) == "NO":
            state = self.node_record_continue_monitoring(state)
            logger.info("=== Autonomous Workflow Completed: Baseline Normal ===")
            return state

        # Conditional Check 2: Response Authorized?
        auth_decision = self.condition_is_response_authorized(state)
        if auth_decision == "REQUIRE_HUMAN_APPROVAL":
            state = self.node_escalate_human_approval(state)
            # Execute non-critical actions while awaiting human decision on gated action
            state = self.node_incident_response(state)
        elif auth_decision == "APPROVED":
            # Step 6: Automated Incident Response (Agent 9)
            state = self.node_incident_response(state)
        else:
            logger.warning("Defensive response rejected by enterprise policy constraints.")
            return state

        # Conditional Check 3: Verify Threat Containment
        if self.condition_is_threat_contained(state) == "YES":
            # Step 7: Monitoring & Continuous Self-Learning (Agent 10)
            state = self.node_monitoring_and_learning(state)
        else:
            state = self.node_recovery_and_escalate(state)

        logger.info(f"=== CyberGuard AI Autonomous Workflow Completed [Session: {state.session_id}] ===")
        return state

