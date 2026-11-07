"""
CyberGuard AI - Enterprise Role-Based Access Control (RBAC) & Security Gate
Enforces least-privilege API access, cryptographic token generation for Tier-0 asset approval,
and role authorization.
"""

import hmac
import hashlib
import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from cyberguard.config import CONFIG

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    INCIDENT_COMMANDER = "INCIDENT_COMMANDER"
    SOC_ANALYST_TIER2 = "SOC_ANALYST_TIER2"
    SOC_ANALYST_TIER1 = "SOC_ANALYST_TIER1"
    READONLY_AUDITOR = "READONLY_AUDITOR"

# Role permissions matrix
ROLE_PERMISSIONS: Dict[UserRole, List[str]] = {
    UserRole.ADMIN: [
        "INGEST_TELEMETRY", "VIEW_INCIDENTS", "APPROVE_TIER0_CONTAINMENT",
        "EXECUTE_CONTAINMENT", "MODIFY_POLICIES", "VIEW_AUDIT_LOG", "TUNE_RULES"
    ],
    UserRole.INCIDENT_COMMANDER: [
        "INGEST_TELEMETRY", "VIEW_INCIDENTS", "APPROVE_TIER0_CONTAINMENT",
        "EXECUTE_CONTAINMENT", "VIEW_AUDIT_LOG"
    ],
    UserRole.SOC_ANALYST_TIER2: [
        "INGEST_TELEMETRY", "VIEW_INCIDENTS", "EXECUTE_CONTAINMENT", "VIEW_AUDIT_LOG"
    ],
    UserRole.SOC_ANALYST_TIER1: [
        "INGEST_TELEMETRY", "VIEW_INCIDENTS"
    ],
    UserRole.READONLY_AUDITOR: [
        "VIEW_INCIDENTS", "VIEW_AUDIT_LOG"
    ]
}

# Pre-configured authorized API credentials for enterprise SOC services
REGISTERED_API_KEYS: Dict[str, Dict[str, Any]] = {
    "cg-key-adm-9912": {"user": "edulakanti.admin", "role": UserRole.ADMIN, "desc": "Enterprise Admin Key"},
    "cg-key-cmd-8821": {"user": "commander.karthik", "role": UserRole.INCIDENT_COMMANDER, "desc": "SOC Incident Commander Key"},
    "cg-key-soc-7734": {"user": "analyst.tier2", "role": UserRole.SOC_ANALYST_TIER2, "desc": "SecOps Automation Key"},
    "cg-key-ing-6645": {"user": "siem.ingestor", "role": UserRole.SOC_ANALYST_TIER1, "desc": "Telemetry Ingestion Pipeline Key"}
}

class RBACManager:
    def __init__(self, secret_key: str = CONFIG.secret_key):
        self.secret_key = secret_key

    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validates API key and returns identity with assigned permissions."""
        if api_key in REGISTERED_API_KEYS:
            user_info = REGISTERED_API_KEYS[api_key]
            perms = ROLE_PERMISSIONS.get(user_info["role"], [])
            return {
                "authenticated": True,
                "user": user_info["user"],
                "role": user_info["role"],
                "permissions": perms
            }
        return None

    def has_permission(self, api_key: str, required_permission: str) -> bool:
        auth_data = self.verify_api_key(api_key)
        if not auth_data:
            return False
        return required_permission in auth_data["permissions"]

    def generate_tier0_approval_token(self, session_id: str, asset: str, approver_user: str) -> str:
        """
        Generates an HMAC-SHA256 authorization token required to execute
        quarantined actions on Tier-0 critical servers.
        """
        timestamp = int(time.time())
        nonce = str(uuid.uuid4())[:8]
        msg = f"{session_id}:{asset}:{approver_user}:{timestamp}:{nonce}"
        signature = hmac.new(self.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
        return f"{msg}:{signature}"

    def verify_tier0_approval_token(self, token: str, session_id: str, asset: str) -> bool:
        """Cryptographically verifies that a human Incident Commander signed off."""
        try:
            parts = token.split(":")
            if len(parts) != 6:
                return False
            t_session, t_asset, t_user, t_ts, t_nonce, signature = parts
            
            # Verify target match
            if t_session != session_id or t_asset != asset:
                return False

            # Verify token freshness (valid for 15 minutes)
            if time.time() - int(t_ts) > 900:
                return False

            msg = f"{t_session}:{t_asset}:{t_user}:{t_ts}:{t_nonce}"
            expected_sig = hmac.new(self.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_sig, signature)
        except Exception:
            return False

GLOBAL_RBAC = RBACManager()
