"""
Unit & Integration Tests for Report Generation, Background Queue, Scanner & Sandbox
"""

import unittest
import os
from backend.services.report_generator import SecurityReportGenerator
from backend.services.task_queue import BackgroundTaskQueue
from backend.integrations.nmap_scanner import SafeVulnerabilityScanner
from backend.integrations.sandbox import IsolatedMalwareSandbox

class TestServicesAndIntegrations(unittest.TestCase):
    def setUp(self):
        self.reporter = SecurityReportGenerator(output_dir="test_reports_dir")
        self.queue = BackgroundTaskQueue(max_workers=2)
        self.scanner = SafeVulnerabilityScanner()
        self.sandbox = IsolatedMalwareSandbox()

    def tearDown(self):
        self.queue.is_running = False
        if os.path.exists("test_reports_dir"):
            for f in os.listdir("test_reports_dir"):
                try:
                    os.remove(os.path.join("test_reports_dir", f))
                except Exception:
                    pass
            try:
                os.rmdir("test_reports_dir")
            except Exception:
                pass

    def test_report_generator_markdown_output(self):
        dummy_state = {
            "session_id": "test-rep-01",
            "created_at": 1700000000.0,
            "threat_intelligence": {
                "threat_actor": "Storm-2603",
                "campaign": "SharePoint ToolShell Fileless Campaign",
                "overall_severity": "CRITICAL"
            },
            "decision": {"risk_score": 89.3},
            "threats": [{"category": "RCE", "mitre_technique": "T1190", "affected_asset": "sharepoint-01"}],
            "vulnerabilities": [{"cve_id": "CVE-2025-53770", "title": "ToolShell RCE", "cvss_score": 9.8, "remediation": "Patch immediately"}],
            "response": {"executed_actions": [{"action_type": "BLOCK_IP", "target": "185.220.101.55", "status": "SUCCESS", "details": "Applied drop"}]}
        }

        res = self.reporter.generate_incident_report(dummy_state)
        self.assertTrue(os.path.exists(res["file_path"]))
        self.assertIn("Storm-2603", res["markdown"])
        self.assertIn("CVE-2025-53770", res["markdown"])

    def test_task_queue_async_dispatch(self):
        def sample_add(a, b):
            return a + b

        job_id = self.queue.submit_task(sample_add, 10, 20)
        self.assertTrue(job_id.startswith("job-"))

    def test_safe_scanner_scope_enforcement(self):
        # Authorized target should be allowed
        self.assertTrue(self.scanner.is_target_authorized("10.0.1.20"))
        self.assertTrue(self.scanner.is_target_authorized("app.corp.internal"))
        self.assertTrue(self.scanner.is_target_authorized("127.0.0.1"))

        # Arbitrary public IP should be BLOCKED
        self.assertFalse(self.scanner.is_target_authorized("8.8.8.8"))
        self.assertFalse(self.scanner.is_target_authorized("1.1.1.1"))

        with self.assertRaises(PermissionError):
            self.scanner.scan_target("8.8.8.8")

    def test_isolated_malware_sandbox(self):
        payload_bytes = b"powershell.exe -enc ToolShell w3wp_inject certutil"
        res = self.sandbox.analyze_file_bytes("exploit.ps1", payload_bytes)

        self.assertEqual(res["file_name"], "exploit.ps1")
        self.assertEqual(res["verdict"], "MALICIOUS_CRITICAL")
        self.assertTrue(res["quarantine_recommended"])
        self.assertIn("powershell", res["suspicious_strings_found"])
        self.assertIn("toolshell", res["suspicious_strings_found"])
        self.assertEqual(len(res["hashes"]["sha256"]), 64)

if __name__ == "__main__":
    unittest.main()
