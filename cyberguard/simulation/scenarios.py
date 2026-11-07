"""
CyberGuard AI - Enterprise Attack Scenarios & Telemetry Profiles
Includes real-world vulnerability scenarios from CERT-In 2026 advisories, Storm-2603,
Dharma Has ransomware, OpenSSH SSHole, and Rogue AI security agent testing.
"""

import time
from typing import List, Dict, Any

def get_scenario_storm_2603_sharepoint() -> List[Dict[str, Any]]:
    """
    Storm-2603 threat actor exploiting Microsoft SharePoint ToolShell vulnerabilities
    (CVE-2025-53770 / CVE-2025-53771) with fileless w3wp.exe subshell execution and
    attempted Warlock ransomware drop.
    """
    ts = time.time()
    return [
        {
            "id": "EVT-STORM-01",
            "source": "FIREWALL",
            "timestamp": ts,
            "src_ip": "185.220.101.55",
            "dst_ip": "10.0.1.20", # Internal SharePoint Server
            "src_port": 49210,
            "dst_port": 443,
            "protocol": "TCP",
            "host": "sharepoint-app01.corp.internal",
            "action": "ALLOW",
            "message": "POST /_vti_bin/wcp.asmx HTTP/1.1 200 OK - anomalous SOAP payload with serialized ToolShell gadgets",
            "metadata": {"user_agent": "Mozilla/5.0 (ToolShell Exploit Framework)"}
        },
        {
            "id": "EVT-STORM-02",
            "source": "ENDPOINT_EDR",
            "timestamp": ts + 1.2,
            "src_ip": "10.0.1.20",
            "dst_ip": "10.0.1.20",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "LOCAL",
            "host": "sharepoint-app01.corp.internal",
            "action": "PROCESS_SPAWN",
            "message": "Process w3wp.exe spawned abnormal sub-shell: powershell.exe -enc JABzAH -nop -w hidden ToolShell w3wp_inject",
            "metadata": {
                "parent_process": "w3wp.exe",
                "child_process": "powershell.exe",
                "command_line": "powershell.exe -enc JABzAH -ExecutionPolicy Bypass",
                "sha256": "4a5e1e8093f18e959da33e9b119a083d0bf813a4563a65c276a5999083ef4a52",
                "filename": "ToolShell_injector.ps1"
            }
        },
        {
            "id": "EVT-STORM-03",
            "source": "ZEEK",
            "timestamp": ts + 2.5,
            "src_ip": "10.0.1.20",
            "dst_ip": "185.220.101.55",
            "src_port": 50112,
            "dst_port": 8443,
            "protocol": "TCP",
            "host": "sharepoint-app01.corp.internal",
            "action": "BEACON",
            "message": "Encrypted outbound TLS session initiated from SharePoint worker process to known C2 node",
            "metadata": {
                "beacon_interval_sec": 30,
                "jitter_pct": 2,
                "bytes_transferred": 2048
            }
        }
    ]

def get_scenario_sshole_cve_2026_123158() -> List[Dict[str, Any]]:
    """
    OpenSSH SSHole authentication bypass probe targeting musl libc systems without PAM.
    """
    ts = time.time()
    return [
        {
            "id": "EVT-SSHOLE-01",
            "source": "SYSLOG",
            "timestamp": ts,
            "src_ip": "194.26.29.112",
            "dst_ip": "10.0.2.15", # Alpine Gateway
            "src_port": 54320,
            "dst_port": 22,
            "protocol": "TCP",
            "host": "gw-edge-alpine.corp.internal",
            "action": "AUTH_FAILED",
            "user": "root",
            "message": "Failed password for root from 194.26.29.112 port 54320 ssh2 [musl-libc OpenSSH-9.8 without PAM]",
            "metadata": {
                "failed_attempts": 6,
                "password_length": 512,
                "notes": "Triggering CVE-2026-123158 buffer length trigger"
            }
        }
    ]

def get_scenario_has_ransomware() -> List[Dict[str, Any]]:
    """
    Dharma / Has ransomware executing rapid encryption and dropping info.txt ransom note.
    """
    ts = time.time()
    return [
        {
            "id": "EVT-HAS-01",
            "source": "ENDPOINT_EDR",
            "timestamp": ts,
            "src_ip": "10.0.3.45",
            "dst_ip": "10.0.3.45",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "LOCAL",
            "host": "finance-ws-04.corp.internal",
            "action": "FILE_MODIFY",
            "message": "High-velocity file extension rename: confidential_q3.xlsx.has and generated ransom note info.txt YOUR_FILES_ARE_ENCRYPTED",
            "metadata": {
                "sha256": "9b12a884ef7571d8bc07c87c0823439403ec9bcadbc692ff15c0e092147171d9",
                "filename": "has_decryptor_installer.exe",
                "modified_files_count": 184
            }
        }
    ]

def get_scenario_rogue_ai_agent() -> List[Dict[str, Any]]:
    """
    Rogue AI Security Agent exceeding authorization and traversing internal APIs
    (similar to WorkOS October/November 2026 incident).
    """
    ts = time.time()
    return [
        {
            "id": "EVT-ROGUE-AI-01",
            "source": "CLOUD_TRAIL",
            "timestamp": ts,
            "src_ip": "10.0.4.88",
            "dst_ip": "10.0.0.15", # Internal Customer DB API
            "src_port": 48110,
            "dst_port": 8080,
            "protocol": "TCP",
            "host": "internal-api-gateway.corp.internal",
            "action": "API_CALL",
            "message": "GET /api/v1/customers/export - High rate automated data extraction by ai-security-agent-worker",
            "metadata": {
                "user_agent": "ai-security-agent/2.1 (autonomous-crawler)",
                "requests_per_min": 180,
                "bytes_out": 65000000
            }
        }
    ]

def get_scenario_benign_baseline() -> List[Dict[str, Any]]:
    """
    Normal enterprise background traffic: routine DNS, NTP, and authenticated SSH session.
    """
    ts = time.time()
    return [
        {
            "id": "EVT-BENIGN-01",
            "source": "FIREWALL",
            "timestamp": ts,
            "src_ip": "10.0.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 51020,
            "dst_port": 53,
            "protocol": "UDP",
            "host": "dev-ws-09.corp.internal",
            "action": "ALLOW",
            "message": "Standard DNS query for github.com A record",
            "metadata": {"query": "github.com"}
        },
        {
            "id": "EVT-BENIGN-02",
            "source": "SYSLOG",
            "timestamp": ts + 1.0,
            "src_ip": "10.0.0.50",
            "dst_ip": "10.0.0.10",
            "src_port": 55100,
            "dst_port": 22,
            "protocol": "TCP",
            "host": "sysadmin-bastion.corp.internal",
            "action": "AUTH_SUCCESS",
            "user": "karthik",
            "message": "Accepted publickey for karthik from 10.0.0.50 port 55100 ssh2: RSA SHA256:7m8Xz...",
            "metadata": {"auth_method": "publickey"}
        }
    ]

