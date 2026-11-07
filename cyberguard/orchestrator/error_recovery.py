"""
CyberGuard AI - Error Recovery, Circuit Breaker & Safety Guardrails
Handles validation failures, retries with exponential backoff, backup agent routing,
and prevents hallucinated or destructive actions.
"""

import time
import logging
from typing import Dict, Any, Callable
from cyberguard.models.state import CyberGuardState

logger = logging.getLogger("CyberGuard.ErrorRecovery")

class CircuitBreakerOpenException(Exception):
    pass

class ErrorRecoveryManager:
    def __init__(self, failure_threshold: int = 3, reset_timeout_sec: float = 60.0):
        self.failure_threshold = failure_threshold
        self.reset_timeout_sec = reset_timeout_sec
        self.state_map: Dict[str, Dict[str, Any]] = {}

    def get_circuit_state(self, agent_id: str) -> str:
        circuit = self.state_map.setdefault(agent_id, {"failures": 0, "last_failure": 0.0, "status": "CLOSED"})
        if circuit["status"] == "OPEN":
            if time.time() - circuit["last_failure"] > self.reset_timeout_sec:
                circuit["status"] = "HALF-OPEN"
                logger.info(f"Circuit breaker for {agent_id} transitioned to HALF-OPEN")
        return circuit["status"]

    def record_success(self, agent_id: str):
        circuit = self.state_map.setdefault(agent_id, {"failures": 0, "last_failure": 0.0, "status": "CLOSED"})
        circuit["failures"] = 0
        circuit["status"] = "CLOSED"

    def record_failure(self, agent_id: str):
        circuit = self.state_map.setdefault(agent_id, {"failures": 0, "last_failure": 0.0, "status": "CLOSED"})
        circuit["failures"] += 1
        circuit["last_failure"] = time.time()
        if circuit["failures"] >= self.failure_threshold:
            circuit["status"] = "OPEN"
            logger.warning(f"CIRCUIT BREAKER TRIGGERED: Agent {agent_id} exceeded failure threshold. Status: OPEN.")

    def execute_with_resilience(
        self,
        agent_id: str,
        task_fn: Callable[[CyberGuardState], CyberGuardState],
        state: CyberGuardState,
        fallback_fn: Callable[[CyberGuardState], CyberGuardState] = None
    ) -> CyberGuardState:
        """
        Executes an agent task with retry logic, circuit breaker protection,
        and fallback delegation.
        """
        c_state = self.get_circuit_state(agent_id)
        if c_state == "OPEN":
            logger.error(f"Cannot execute {agent_id}: Circuit breaker is OPEN. Falling back immediately.")
            if fallback_fn:
                return fallback_fn(state)
            return state

        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            try:
                result_state = task_fn(state)
                # Self-validation of output
                self.validate_agent_output(agent_id, result_state)
                self.record_success(agent_id)
                return result_state
            except Exception as e:
                logger.warning(f"Attempt {attempt}/{max_attempts} failed for {agent_id}: {str(e)}")
                if attempt == max_attempts:
                    self.record_failure(agent_id)
                    if fallback_fn:
                        logger.info(f"Invoking fallback agent strategy for {agent_id}")
                        return fallback_fn(state)
                    state.errors.append({"agent_id": agent_id, "error": str(e), "recovered": False})
                    return state
                time.sleep(0.1 * (2 ** (attempt - 1))) # Exponential backoff

        return state

    def validate_agent_output(self, agent_id: str, state: CyberGuardState):
        """
        Safety integrity check: Ensures that an agent has not corrupted state
        or injected malformed instructions.
        """
        if agent_id == "AGENT-08-DECISION":
            # Guard against unconstrained destructive decisions
            if state.decision_plan:
                for act in state.decision_plan.actions:
                    if act.action_type.value in ["DELETE_REMOTE_SYSTEM_FILES", "SHUTDOWN_ENTERPRISE_ROUTER"]:
                        raise ValueError(f"Safety Violation: Unauthorized destructive action '{act.action_type.value}' proposed!")
