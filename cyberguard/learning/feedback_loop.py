"""
CyberGuard AI - Continuous Self-Improvement & Closed-Loop Learning Engine
Maintains adaptive rule weights, detects false positives, evaluates drift, and updates model policies.
"""

import time
import json
import os
from typing import Dict, Any, List

class LearningEngine:
    def __init__(self, persistence_file: str = "cyberguard_learned_weights.json"):
        self.persistence_file = persistence_file
        self.rule_weights: Dict[str, float] = self._load_weights()
        self.incident_history: List[Dict[str, Any]] = []

    def _load_weights(self) -> Dict[str, float]:
        if os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "SIGMA-001": 1.0, # Storm-2603 IIS Child Execution
            "SIGMA-002": 1.0, # SSH Long Password & Brute Force
            "SIGMA-003": 1.0, # Ransomware Canary
            "SIGMA-004": 1.0, # Rogue AI Agent
            "YARA-WARLOCK": 1.0,
            "YARA-DHARMA": 1.0,
            "YARA-ASYNCRAT": 1.0
        }

    def save_weights(self):
        try:
            with open(self.persistence_file, "w") as f:
                json.dump(self.rule_weights, f, indent=2)
        except Exception as e:
            pass

    def record_incident_outcome(
        self,
        session_id: str,
        rules_triggered: List[str],
        verified_true_positive: bool,
        mean_response_time_ms: float
    ):
        """
        Closed feedback loop: Adjusts rule confidence multipliers based on verified outcomes.
        """
        record = {
            "session_id": session_id,
            "timestamp": time.time(),
            "rules": rules_triggered,
            "true_positive": verified_true_positive,
            "response_time_ms": mean_response_time_ms
        }
        self.incident_history.append(record)

        for rule in rules_triggered:
            current_weight = self.rule_weights.get(rule, 1.0)
            if verified_true_positive:
                # Reward reliable true positive detections (up to max 1.5)
                self.rule_weights[rule] = min(round(current_weight + 0.05, 3), 1.50)
            else:
                # Penalize noisy false positive alerts (down to min 0.4)
                self.rule_weights[rule] = max(round(current_weight - 0.10, 3), 0.40)

        self.save_weights()

    def get_effective_rule_confidence(self, rule_id: str, base_confidence: float) -> float:
        """Returns dynamically tuned confidence score based on historical reinforcement."""
        weight = self.rule_weights.get(rule_id, 1.0)
        return min(round(base_confidence * weight, 3), 1.0)

    def get_performance_metrics(self) -> Dict[str, Any]:
        total = len(self.incident_history)
        if total == 0:
            return {"total_incidents": 0, "accuracy_rate": 1.0, "false_positive_rate": 0.0}
        
        tp_count = sum(1 for inc in self.incident_history if inc.get("true_positive", True))
        return {
            "total_incidents": total,
            "accuracy_rate": round(tp_count / total, 3),
            "false_positive_rate": round((total - tp_count) / total, 3),
            "rule_weights": self.rule_weights
        }

GLOBAL_LEARNING_ENGINE = LearningEngine()
