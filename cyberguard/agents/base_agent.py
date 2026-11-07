"""
CyberGuard AI - Base Agent Definition
Implements safety boundaries, execution timers, circuit breakers, and audit logging.
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from cyberguard.models.state import CyberGuardState, AgentAuditLog

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")

class BaseAgent(ABC):
    def __init__(self, agent_id: str, name: str, role: str):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.logger = logging.getLogger(self.name)
        self.failure_count = 0
        self.max_retries = 3

    def execute(self, state: CyberGuardState) -> CyberGuardState:
        """
        Executes the agent logic with safety wrapping, performance metrics,
        and audit trail recording.
        """
        start_time = time.time()
        self.logger.info(f"==> Starting execution of {self.name} ({self.role})")
        
        try:
            # Execute concrete agent implementation
            updated_state = self.process(state)
            
            elapsed_ms = (time.time() - start_time) * 1000
            audit_entry = AgentAuditLog(
                agent_id=self.agent_id,
                agent_name=self.name,
                execution_time_ms=round(elapsed_ms, 2),
                status="SUCCESS",
                summary=f"Processed successfully in {elapsed_ms:.2f}ms"
            )
            updated_state.audit_trail.append(audit_entry)
            self.failure_count = 0
            self.logger.info(f"<== Finished {self.name} in {elapsed_ms:.2f}ms")
            return updated_state

        except Exception as exc:
            self.failure_count += 1
            elapsed_ms = (time.time() - start_time) * 1000
            self.logger.error(f"Error in {self.name}: {str(exc)}", exc_info=True)
            
            error_record = {
                "agent_id": self.agent_id,
                "agent_name": self.name,
                "error": str(exc),
                "timestamp": time.time(),
                "retry_count": self.failure_count
            }
            state.errors.append(error_record)
            
            audit_entry = AgentAuditLog(
                agent_id=self.agent_id,
                agent_name=self.name,
                execution_time_ms=round(elapsed_ms, 2),
                status="ERROR",
                summary=f"Failed: {str(exc)}"
            )
            state.audit_trail.append(audit_entry)
            
            # Delegate to error recovery strategy
            return self.handle_failure(state, exc)

    @abstractmethod
    def process(self, state: CyberGuardState) -> CyberGuardState:
        """Core logic to be implemented by each specialized agent."""
        pass

    def handle_failure(self, state: CyberGuardState, exc: Exception) -> CyberGuardState:
        """Graceful degradation / fallback strategy."""
        self.logger.warning(f"Executing default fallback policy for {self.name}")
        return state

