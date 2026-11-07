"""
Tests for ACID Storage, Cryptographic Audit Trail, RBAC, and Rate Limiting
"""

import unittest
import os
import uuid
from cyberguard.models.state import CyberGuardState
from cyberguard.orchestrator.graph import CyberGuardGraph
from cyberguard.simulation.scenarios import get_scenario_storm_2603_sharepoint
from cyberguard.storage.db import SecurityDatabase
from cyberguard.auth.rbac import RBACManager, UserRole
from cyberguard.middleware.rate_limiter import TokenBucketRateLimiter

class TestStorageAndSecurity(unittest.TestCase):
    def setUp(self):
        self.db_name = f"test_cyberguard_{uuid.uuid4().hex[:8]}.db"
        self.db = SecurityDatabase(db_path=self.db_name)
        self.rbac = RBACManager(secret_key="test-key-2026")
        self.limiter = TokenBucketRateLimiter(capacity=5, refill_rate_per_sec=1.0)

    def tearDown(self):
        if hasattr(self, "db_name") and os.path.exists(self.db_name):
            try:
                os.remove(self.db_name)
            except Exception:
                pass

    def test_database_incident_and_audit_chain(self):
        events = get_scenario_storm_2603_sharepoint()
        state = CyberGuardState(raw_events=events)
        orchestrator = CyberGuardGraph()
        final_state = orchestrator.run(state)

        # Store in test DB
        self.db.record_incident(final_state)
        incidents = self.db.get_all_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["threat_actor"], "Storm-2603")

        # Verify cryptographic audit hash chain
        integrity = self.db.verify_audit_trail_integrity()
        self.assertTrue(integrity["valid"])
        self.assertGreater(integrity["records_checked"], 0)
        self.assertEqual(integrity["status"], "INTEGRITY_VERIFIED_100%")

    def test_rbac_permissions(self):
        # Admin key has full permissions
        self.assertTrue(self.rbac.has_permission("cg-key-adm-9912", "APPROVE_TIER0_CONTAINMENT"))
        # Ingestion pipeline key cannot approve Tier0
        self.assertFalse(self.rbac.has_permission("cg-key-ing-6645", "APPROVE_TIER0_CONTAINMENT"))
        # Invalid key fails
        self.assertFalse(self.rbac.has_permission("invalid-key", "VIEW_INCIDENTS"))

    def test_tier0_approval_token_cryptography(self):
        session_id = "sess-abc-123"
        asset = "dc-01.corp.internal"
        approver = "incident.commander"

        token = self.rbac.generate_tier0_approval_token(session_id, asset, approver)
        self.assertIsNotNone(token)

        # Verify valid token
        self.assertTrue(self.rbac.verify_tier0_approval_token(token, session_id, asset))

        # Tampered asset should fail
        self.assertFalse(self.rbac.verify_tier0_approval_token(token, session_id, "other-server.corp.internal"))

    def test_rate_limiter_token_bucket(self):
        client_ip = "192.168.1.50"
        # Consume 5 tokens
        for _ in range(5):
            self.assertTrue(self.limiter.is_allowed(client_ip))

        # 6th immediate request should be throttled
        self.assertFalse(self.limiter.is_allowed(client_ip))

if __name__ == "__main__":
    unittest.main()
