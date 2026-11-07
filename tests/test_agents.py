"""
Unit Tests for Individual CyberGuard AI Agents
"""

import unittest
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
from cyberguard.simulation.scenarios import get_scenario_storm_2603_sharepoint

class TestCyberGuardAgents(unittest.TestCase):
    def setUp(self):
        self.raw_events = get_scenario_storm_2603_sharepoint()
        self.state = CyberGuardState(raw_events=self.raw_events)

    def test_agent1_data_collection(self):
        agent = SecurityDataCollectionAgent()
        res = agent.execute(self.state)
        self.assertEqual(len(res.normalized_events), len(self.raw_events))
        self.assertTrue(res.audit_trail[-1].status == "SUCCESS")

    def test_agent2_data_analysis(self):
        a1 = SecurityDataCollectionAgent()
        a2 = SecurityDataAnalysisAgent()
        s = a2.execute(a1.execute(self.state))
        self.assertGreater(len(s.filtered_events), 0)
        self.assertGreater(len(s.anomaly_events), 0)

    def test_detection_pipeline(self):
        a1 = SecurityDataCollectionAgent()
        a2 = SecurityDataAnalysisAgent()
        a3 = ThreatDetectionAgent()
        a5 = NetworkMonitoringAgent()
        a6 = MalwareAnalysisAgent()

        s = a1.execute(self.state)
        s = a2.execute(s)
        s = a3.execute(s)
        s = a5.execute(s)
        s = a6.execute(s)

        self.assertGreater(len(s.threat_detections), 0)
        self.assertGreater(len(s.network_anomalies), 0)
        self.assertGreater(len(s.malware_analyses), 0)

    def test_agent7_threat_intelligence(self):
        a1 = SecurityDataCollectionAgent()
        a2 = SecurityDataAnalysisAgent()
        a3 = ThreatDetectionAgent()
        a7 = ThreatIntelligenceAgent()

        s = a3.execute(a2.execute(a1.execute(self.state)))
        s = a7.execute(s)

        self.assertIsNotNone(s.threat_intel_report)
        self.assertTrue(s.threat_confirmed)
        self.assertEqual(s.threat_intel_report.threat_actor, "Storm-2603")

    def test_agent8_decision_gating(self):
        a1 = SecurityDataCollectionAgent()
        a2 = SecurityDataAnalysisAgent()
        a3 = ThreatDetectionAgent()
        a7 = ThreatIntelligenceAgent()
        a8 = SecurityDecisionAgent()

        s = a8.execute(a7.execute(a3.execute(a2.execute(a1.execute(self.state)))))
        self.assertIsNotNone(s.decision_plan)
        self.assertGreater(s.decision_plan.risk_score, 70.0)
        self.assertGreater(len(s.decision_plan.actions), 0)

    def test_agent9_and_10_execution(self):
        a1 = SecurityDataCollectionAgent()
        a2 = SecurityDataAnalysisAgent()
        a3 = ThreatDetectionAgent()
        a7 = ThreatIntelligenceAgent()
        a8 = SecurityDecisionAgent()
        a9 = IncidentResponseAgent()
        a10 = MonitoringAndLearningAgent()

        s = a1.execute(self.state)
        s = a2.execute(s)
        s = a3.execute(s)
        s = a7.execute(s)
        s = a8.execute(s)
        s = a9.execute(s)
        s = a10.execute(s)

        self.assertTrue(s.containment_successful)
        self.assertTrue(s.workflow_completed)
        self.assertIn("CyberGuard AI - Autonomous Incident Resolution Report", s.final_report_markdown)

if __name__ == "__main__":
    unittest.main()

