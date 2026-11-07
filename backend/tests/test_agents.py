"""
Tests for Master Agent Orchestrator & All 10 Specialized Agents
"""

import unittest
from backend.orchestrator.workflow import MasterAgentOrchestrator
from backend.simulation.scenarios import (
    get_scenario_storm_2603_sharepoint,
    get_scenario_sshole_cve_2026_123158,
    get_scenario_has_ransomware,
    get_scenario_benign_baseline
)

class TestMasterBackend(unittest.TestCase):
    def setUp(self):
        self.orchestrator = MasterAgentOrchestrator()

    def test_storm2603_full_pipeline(self):
        raw = get_scenario_storm_2603_sharepoint()
        result = self.orchestrator.run_pipeline(raw)

        self.assertIsNotNone(result["session_id"])
        self.assertEqual(len(result["audit_trail"]), 10) # All 10 agents executed
        self.assertTrue(result["threat_intelligence"]["threat_confirmed"])
        self.assertEqual(result["threat_intelligence"]["threat_actor"], "Storm-2603")
        self.assertTrue(result["response"]["containment_successful"])
        self.assertTrue(result["monitoring"]["metrics"]["containment_verified"])

    def test_benign_baseline(self):
        raw = get_scenario_benign_baseline()
        result = self.orchestrator.run_pipeline(raw)

        self.assertFalse(result["threat_intelligence"]["threat_confirmed"])
        self.assertEqual(len(result["response"].get("executed_actions", [])), 0)

    def test_sshole_auth_bypass(self):
        raw = get_scenario_sshole_cve_2026_123158()
        result = self.orchestrator.run_pipeline(raw)

        self.assertTrue(result["threat_intelligence"]["threat_confirmed"])
        self.assertGreater(len(result["threats"]), 0)

if __name__ == "__main__":
    unittest.main()

