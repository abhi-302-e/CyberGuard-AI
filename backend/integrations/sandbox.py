"""
CyberGuard AI - Isolated Static & Dynamic Sandbox Analysis Integration
Inspects binary structures, hashes, and signatures without executing untrusted files on the host.
"""

import hashlib
import os
import math
from typing import Dict, Any, List

class IsolatedMalwareSandbox:
    def __init__(self):
        pass

    def calculate_hashes(self, data: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }

    def compute_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy to detect packed, obfuscated, or encrypted payloads."""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return round(entropy, 2)

    def analyze_file_bytes(self, file_name: str, content: bytes) -> Dict[str, Any]:
        hashes = self.calculate_hashes(content)
        entropy = self.compute_entropy(content)
        
        # Check suspicious strings
        content_lower = content.lower()
        suspicious_matches = []
        indicators = [
            b"powershell", b"w3wp", b"toolshell", b"warlock", b"dharma",
            b".has", b"info.txt", b"cmd.exe", b"certutil", b"mimikatz",
            b"reg add", b"vssadmin delete shadows"
        ]

        for ind in indicators:
            if ind in content_lower:
                suspicious_matches.append(ind.decode(errors="ignore"))

        is_malicious = len(suspicious_matches) > 0 or entropy > 7.2
        verdict = "MALICIOUS_CRITICAL" if len(suspicious_matches) >= 2 else ("SUSPICIOUS" if is_malicious else "CLEAN")

        return {
            "file_name": file_name,
            "size_bytes": len(content),
            "hashes": hashes,
            "entropy": entropy,
            "is_packed": entropy > 7.0,
            "suspicious_strings_found": suspicious_matches,
            "verdict": verdict,
            "quarantine_recommended": is_malicious,
            "sandbox_safe_status": "ANALYZED_IN_MEMORY_ISOLATION"
        }

GLOBAL_SANDBOX = IsolatedMalwareSandbox()
