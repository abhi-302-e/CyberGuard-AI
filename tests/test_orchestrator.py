"""
End-to-End Orchestrator and Circuit-Breaker Tests
"""

import unittest
from cyberguard.models.state import CyberGuardState
from cyberguard.orchestrator.graph import CyberGuardGraph
from cyberguard.orchestrator.error_recovery import ErrorRecoveryManager
from cyberguard.simulation.scenarios import (
    get_scenario_storm_2603_sharepoint,
    get_scenario_sshole_cve_2026_123158,
    get_scenario_benign_baseline
)

class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.orchestrator = CyberGuardGraph()

    def test_end_to_end_storm_2603_containment(self):
        events = get_scenario_storm_2603_sharepoint()
        state = CyberGuardState(raw_events=events)
        final_state = self.orchestrator.run(state)

        self.assertTrue(final_state.workflow_completed)
        self.assertTrue(final_state.threat_confirmed)
        self.assertTrue(final_state.containment_successful)
        self.assertEqual(len(final_state.audit_trail), 10) # All 10 agents recorded
        self.assertGreater(len(final_state.executed_actions), 0)

    def test_end_to_end_benign_baseline_no_false_positive(self):
        events = get_scenario_benign_baseline()
        state = CyberGuardState(raw_events=events)
        final_state = self.orchestrator.run(state)

        self.assertTrue(final_state.workflow_completed)
        self.assertFalse(final_state.threat_confirmed)
        self.assertEqual(len(final_state.executed_actions), 0)

    def test_end_to_end_sshole_exploit(self):
        events = get_scenario_sshole_cve_2026_123158()
        state = CyberGuardState(raw_events=events)
        final_state = self.orchestrator.run(state)

        self.assertTrue(final_state.workflow_completed)
        self.assertTrue(final_state.threat_confirmed)
        self.assertEqual(final_state.decision_plan.actions[0].action_type.value, "BLOCK_IP")

    def test_error_recovery_circuit_breaker(self):
        recovery = ErrorRecoveryManager(failure_threshold=1)
        agent_id = "TEST-AGENT"

        def failing_task(s):
            raise RuntimeError("Simulated API failure")

        def fallback_task(s):
            s.workflow_completed = True
            return s

        state = CyberGuardState()
        # First attempt -> fail and record 1 failure (tripping threshold=1 to OPEN)
        recovery.execute_with_resilience(agent_id, failing_task, state)
        self.assertEqual(recovery.get_circuit_state(agent_id), "OPEN")

        # Second execution -> trips circuit breaker immediately to fallback
        res = recovery.execute_with_resilience(agent_id, failing_task, state, fallback_fn=fallback_task)
        self.assertTrue(res.workflow_completed)

if __name__ == "__main__":
    unittest.main()
