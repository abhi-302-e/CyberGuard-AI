"""
CyberGuard AI - Global Configuration & Policy Guardrails
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class PolicyConfig:
    # Autonomous execution thresholds (0.0 to 1.0)
    auto_response_confidence_threshold: float = 0.80
    high_risk_threshold: float = 75.0
    critical_risk_threshold: float = 90.0

    # Actions allowed to run autonomously without human sign-off
    autonomous_allowed_actions: List[str] = field(default_factory=lambda: [
        "BLOCK_IP",
        "RATE_LIMIT_IP",
        "REVOKE_ACTIVE_SESSION",
        "APPLY_DEFENSIVE_ACL",
        "QUARANTINE_NON_CRITICAL_ENDPOINT",
        "GENERATE_INCIDENT_TICKET",
        "DISPATCH_SOC_ALERT"
    ])

    # Actions STRICTLY requiring human operator approval
    human_approval_required_actions: List[str] = field(default_factory=lambda: [
        "ISOLATE_CRITICAL_DATABASE_SERVER",
        "FLUSH_PRODUCTION_FIREWALL_RULES",
        "DELETE_REMOTE_SYSTEM_FILES",
        "DISABLE_ACTIVE_DIRECTORY_ROOT_ADMIN",
        "SHUTDOWN_ENTERPRISE_ROUTER"
    ])

    # Critical asset indicators (IPs, hostnames, or tags)
    critical_assets: List[str] = field(default_factory=lambda: [
        "dc-01.corp.internal",
        "10.0.0.1",
        "10.0.0.2",
        "db-primary.prod.internal",
        "10.0.1.50",
        "pki-ca.corp.internal"
    ])

@dataclass
class SystemConfig:
    environment: str = os.getenv("CYBERGUARD_ENV", "production")
    log_level: str = os.getenv("CYBERGUARD_LOG_LEVEL", "INFO")
    api_port: int = int(os.getenv("CYBERGUARD_API_PORT", 8080))
    ui_port: int = int(os.getenv("CYBERGUARD_UI_PORT", 5000))
    secret_key: str = os.getenv("CYBERGUARD_SECRET", "cg-autonomous-defense-key-2026")
    
    # Self-learning weights
    learning_rate: float = 0.05
    min_confidence_floor: float = 0.40
    rule_optimization_batch_size: int = 10

    policy: PolicyConfig = field(default_factory=PolicyConfig)

CONFIG = SystemConfig()
