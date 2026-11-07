"""
CyberGuard AI - Enterprise Threat Intelligence & CVE Database
Contains signature sets, CVE profiles, MITRE ATT&CK techniques, and YARA signatures.
"""

from typing import Dict, Any, List

KNOWN_CVES: Dict[str, Dict[str, Any]] = {
    "CVE-2025-53770": {
        "cve_id": "CVE-2025-53770",
        "title": "Microsoft SharePoint ToolShell Remote Code Execution",
        "cvss": 9.8,
        "affected_software": "Microsoft SharePoint Server",
        "threat_actor": "Storm-2603",
        "mitre_technique": "T1190", # Exploit Public-Facing Application
        "description": "Fileless backdoor execution inside IIS worker process (w3wp.exe) leading to persistence, tunneling, and Warlock ransomware deployment.",
        "remediation": "Apply Microsoft SharePoint security updates immediately. Restrict w3wp.exe process spawning and inspect IIS child processes."
    },
    "CIVN-2026-0539": {
        "cve_id": "CIVN-2026-0539",
        "title": "Linux Kernel Use-After-Free Privilege Escalation",
        "cvss": 8.8,
        "affected_software": "Linux Kernel (5.10, 5.15, 6.1, 6.6, 6.12, 6.18)",
        "threat_actor": "Local Privilege Escalation Attackers",
        "mitre_technique": "T1068", # Exploitation for Privilege Escalation
        "description": "Use-after-free flaw in core kernel memory management subsystem allowing arbitrary local code execution and system takeover.",
        "remediation": "Upgrade to patched kernel distribution release and reboot server. Monitor dmesg and auditd for anomalous ring buffer crashes."
    },
    "CIVN-2026-0540": {
        "cve_id": "CIVN-2026-0540",
        "title": "Drupal Contributed Module Remote Code Execution",
        "cvss": 9.2,
        "affected_software": "Drupal 9/10 Contributed Modules",
        "threat_actor": "Web Application Exploiters",
        "mitre_technique": "T1190",
        "description": "Unsanitized user input leading to unauthorized deserialization and arbitrary PHP remote code execution.",
        "remediation": "Update affected contributed modules to latest stable releases. Enforce strict web application firewall (WAF) filtering."
    },
    "CVE-2026-123158": {
        "cve_id": "CVE-2026-123158",
        "title": "OpenSSH SSHole Authentication Bypass",
        "cvss": 8.1,
        "affected_software": "OpenSSH on musl libc systems without PAM (Alpine, OpenWrt, Yocto)",
        "threat_actor": "Network Intrusion Operators",
        "mitre_technique": "T1078", # Valid Accounts / Auth Bypass
        "description": "Buffer handling anomaly in password authentication accepting lengths between 257 and 1024 characters, triggering auth bypass.",
        "remediation": "Upgrade OpenSSH to version 10.6p2 or apply vendor backports. Enable PAM where feasible."
    },
    "CVE-2026-19868": {
        "cve_id": "CVE-2026-19868",
        "title": "SonicWall SSL-VPN SAML MFA Bypass",
        "cvss": 7.1,
        "affected_software": "SonicOS Gen7 (7.3.4-7013) and Gen8 (8.2.3-8015)",
        "threat_actor": "Initial Access Brokers",
        "mitre_technique": "T1556", # Modify Authentication Process
        "description": "Flaw allowing attackers with secondary valid credentials to circumvent SAML-enforced multi-factor authentication.",
        "remediation": "Apply SonicOS fixed releases 7.3.4-7013+ / 8.2.3-8015+. Review all authentication fallback vectors."
    }
}

SIGMA_RULES: List[Dict[str, Any]] = [
    {
        "id": "SIGMA-001",
        "title": "Storm-2603 IIS Worker Process Abnormal Child Execution",
        "technique": "T1059",
        "severity": "CRITICAL",
        "match": {
            "parent_process": "w3wp.exe",
            "child_processes": ["cmd.exe", "powershell.exe", "curl.exe", "certutil.exe"]
        }
    },
    {
        "id": "SIGMA-002",
        "title": "SSH Brute Force and Long Password SSHole Probe",
        "technique": "T1110",
        "severity": "HIGH",
        "match": {
            "service": "sshd",
            "failed_threshold": 5,
            "password_length_gt": 256
        }
    },
    {
        "id": "SIGMA-003",
        "title": "Ransomware Canary File Modification or Dharma/Has Extension",
        "technique": "T1486", # Data Encrypted for Impact
        "severity": "CRITICAL",
        "match": {
            "extension": [".has", ".dharma", ".encrypted", ".locked"],
            "ransom_note": "info.txt"
        }
    },
    {
        "id": "SIGMA-004",
        "title": "Rogue AI Agent Unauthorized Internal API Enumeration",
        "technique": "T1595", # Active Scanning / Discovery
        "severity": "HIGH",
        "match": {
            "user_agent_contains": ["ai-security-agent", "autonomous-crawler", "llm-probe"],
            "requests_per_minute_gt": 120
        }
    }
]

YARA_RULES: List[Dict[str, Any]] = [
    {
        "rule_name": "Warlock_Storm2603_Payload",
        "strings": ["ToolShell", "w3wp_inject", "powershell -enc JABzAH"],
        "severity": "CRITICAL",
        "family": "Storm-2603 Backdoor"
    },
    {
        "rule_name": "Has_Dharma_Ransomware_Marker",
        "strings": ["YOUR_FILES_ARE_ENCRYPTED", "info.txt", "has_decryptor"],
        "severity": "CRITICAL",
        "family": "Dharma.Has"
    },
    {
        "rule_name": "AsyncRAT_Malicious_GitHub_Tool",
        "strings": ["AsyncClient", "Pastebin_C2", "AntiAnalysis_VM"],
        "severity": "HIGH",
        "family": "AsyncRAT Trojan"
    }
]

