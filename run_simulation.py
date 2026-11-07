"""
CyberGuard AI - Terminal Simulation Runner
Executes an end-to-end multi-agent cybersecurity scenario directly in the CLI.
"""

import sys
import time
from cyberguard.models.state import CyberGuardState
from cyberguard.orchestrator.graph import CyberGuardGraph
from cyberguard.simulation.scenarios import (
    get_scenario_storm_2603_sharepoint,
    get_scenario_sshole_cve_2026_123158,
    get_scenario_has_ransomware,
    get_scenario_rogue_ai_agent,
    get_scenario_benign_baseline
)

def run_cli_scenario(name: str = "storm_2603"):
    print("\n" + "="*80)
    print("   CYBERGUARD AI : AUTONOMOUS MULTI-AGENT CYBERSECURITY SYSTEM")
    print("="*80)
    print(f"[*] Scenario Selected: {name.upper()}")

    scenarios = {
        "storm_2603": ("Storm-2603 SharePoint ToolShell Exploit", get_scenario_storm_2603_sharepoint),
        "sshole": ("OpenSSH SSHole Auth Bypass (CVE-2026-123158)", get_scenario_sshole_cve_2026_123158),
        "has_ransomware": ("Dharma / Has Ransomware Encryption", get_scenario_has_ransomware),
        "rogue_ai": ("Rogue AI Agent API Crawler", get_scenario_rogue_ai_agent),
        "benign": ("Benign Baseline Operations", get_scenario_benign_baseline)
    }

    title, generator = scenarios.get(name, scenarios["storm_2603"])
    print(f"[*] Target Vector: {title}")
    
    events = generator()
    print(f"[*] Ingesting {len(events)} telemetry events into Agent 1...")

    state = CyberGuardState(raw_events=events)
    orchestrator = CyberGuardGraph()

    start_time = time.time()
    result = orchestrator.run(state)
    duration_ms = (time.time() - start_time) * 1000

    print("\n" + "-"*80)
    print(f"   WORKFLOW EXECUTION SUMMARY (Elapsed: {duration_ms:.2f} ms)")
    print("-"*80)
    print(f"Session ID            : {result.session_id}")
    print(f"Threat Confirmed?     : {'YES - CRITICAL ATTACK' if result.threat_confirmed else 'NO - BENIGN'}")
    print(f"Response Authorized?  : {result.response_authorized}")
    print(f"Gated for Human Signoff: {result.human_approval_required}")
    print(f"Containment Verified? : {result.containment_successful}")

    print("\n[+] 10-Agent Audit Execution Trail:")
    for log in result.audit_trail:
        status_sym = "[OK]" if log.status == "SUCCESS" else "[FAIL]"
        print(f"    {status_sym} {log.agent_name:<36} | {log.execution_time_ms:>6.2f} ms | {log.summary}")

    if result.executed_actions:
        print("\n[+] Active Defensive Actions Executed:")
        for action in result.executed_actions:
            print(f"    [*] Action: {action.status_code:<18} Target: {action.target:<25} -> {action.details}")

    print("\n[+] Incident Report Output:")
    print(result.final_report_markdown)
    print("\n" + "="*80)
    print("   AUTONOMOUS CYCLE COMPLETED WITHOUT HUMAN INTERVENTION")
    print("="*80 + "\n")

if __name__ == "__main__":
    chosen = sys.argv[1] if len(sys.argv) > 1 else "storm_2603"
    run_cli_scenario(chosen)

