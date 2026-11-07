"""
CyberGuard AI - Enterprise Base Agent Definition
Standard interface adhering to the master specification:
Returns structured dictionary containing agent_name, status, finding, severity, confidence, evidence, recommendations.
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")

class BaseCyberAgent(ABC):
    def __init__(self, agent_id: str, agent_name: str, responsibility: str):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.responsibility = responsibility
        self.logger = logging.getLogger(self.agent_name)
        self.execution_count = 0
        self.failure_count = 0
        self.status = "ACTIVE"

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        start_time = time.time()
        self.status = "RUNNING"
        self.logger.info(f"[{self.agent_id}] Starting task: {self.responsibility}")

        try:
            result = self.process(state)
            elapsed_ms = (time.time() - start_time) * 1000
            self.execution_count += 1
            self.status = "ACTIVE"
            
            # Ensure structured standard output format
            structured_output = {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "status": "completed",
                "finding": result.get("finding", "Task completed normally"),
                "severity": result.get("severity", "low"),
                "confidence": result.get("confidence", 0.90),
                "evidence": result.get("evidence", []),
                "recommendations": result.get("recommendations", []),
                "data": result.get("data", {}),
                "execution_time_ms": round(elapsed_ms, 2)
            }
            self.logger.info(f"[{self.agent_id}] Finished in {elapsed_ms:.2f}ms with verdict: {structured_output['finding']}")
            return structured_output

        except Exception as exc:
            self.failure_count += 1
            self.status = "ERROR"
            elapsed_ms = (time.time() - start_time) * 1000
            self.logger.error(f"[{self.agent_id}] Failed: {str(exc)}", exc_info=True)
            return {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "status": "error",
                "finding": f"Execution error: {str(exc)}",
                "severity": "high",
                "confidence": 0.0,
                "evidence": [str(exc)],
                "recommendations": ["Initiate agent retry or assign secondary fallback agent"],
                "data": {},
                "execution_time_ms": round(elapsed_ms, 2)
            }

    @abstractmethod
    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Core specialized processing logic."""
        pass

