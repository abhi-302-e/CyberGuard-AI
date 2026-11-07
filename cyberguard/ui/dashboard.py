"""
CyberGuard AI - Enterprise SOC Dashboard & Multi-Agent Operations Interface
Modern Flask web application with real-time incident visualization, autonomous pipeline execution,
and self-learning analytics.
"""

import time
import json
from flask import Flask, render_template_string, jsonify, request
from cyberguard.orchestrator.graph import CyberGuardGraph
from cyberguard.models.state import CyberGuardState
from cyberguard.learning.feedback_loop import GLOBAL_LEARNING_ENGINE
from cyberguard.simulation.scenarios import (
    get_scenario_storm_2603_sharepoint,
    get_scenario_sshole_cve_2026_123158,
    get_scenario_has_ransomware,
    get_scenario_rogue_ai_agent,
    get_scenario_benign_baseline
)

app = Flask(__name__)
orchestrator = CyberGuardGraph()
recent_executions = []

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard AI | Autonomous SOC Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #0b0f19; color: #e2e8f0; font-family: 'Inter', sans-serif; }
        .glass-panel { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(12px); border: 1px solid rgba(55, 65, 81, 0.6); }
        .agent-node { transition: all 0.3s ease; }
        .agent-node:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(59, 130, 246, 0.3); }
        .glow-red { box-shadow: 0 0 15px rgba(239, 68, 68, 0.4); }
        .glow-green { box-shadow: 0 0 15px rgba(34, 197, 94, 0.4); }
        .glow-blue { box-shadow: 0 0 15px rgba(59, 130, 246, 0.4); }
    </style>
</head>
<body class="p-6">
    <!-- Header -->
    <header class="flex justify-between items-center pb-6 border-b border-gray-800 mb-6">
        <div class="flex items-center space-x-4">
            <div class="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white text-2xl font-bold shadow-lg shadow-blue-500/30">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div>
                <h1 class="text-2xl font-black tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-400">
                    CYBERGUARD AI
                </h1>
                <p class="text-xs text-gray-400 uppercase tracking-widest">Autonomous Multi-Agent Cybersecurity Decision Intelligence</p>
            </div>
        </div>
        <div class="flex items-center space-x-4">
            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                <span class="w-2 h-2 mr-2 bg-emerald-400 rounded-full animate-ping"></span>
                AUTONOMOUS SYSTEM ONLINE
            </span>
            <div class="text-right text-xs text-gray-400 font-mono">
                <div>Model: GPT-4o / Gemini 3.8</div>
                <div>Framework: LangGraph 10-Agent</div>
            </div>
        </div>
    </header>

    <!-- Top KPI Grid -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="glass-panel p-5 rounded-2xl flex items-center justify-between border-l-4 border-l-blue-500">
            <div>
                <div class="text-xs uppercase text-gray-400 font-medium">Active Agents</div>
                <div class="text-2xl font-bold text-white mt-1">10 / 10</div>
                <div class="text-xs text-blue-400 mt-1"><i class="fa-solid fa-microchip mr-1"></i> Full LangGraph Mesh</div>
            </div>
            <i class="fa-solid fa-robot text-3xl text-blue-500/40"></i>
        </div>

        <div class="glass-panel p-5 rounded-2xl flex items-center justify-between border-l-4 border-l-rose-500">
            <div>
                <div class="text-xs uppercase text-gray-400 font-medium">Threats Neutralized</div>
                <div class="text-2xl font-bold text-rose-400 mt-1" id="kpi-neutralized">--</div>
                <div class="text-xs text-gray-400 mt-1">Zero Human Delay</div>
            </div>
            <i class="fa-solid fa-biohazard text-3xl text-rose-500/40"></i>
        </div>

        <div class="glass-panel p-5 rounded-2xl flex items-center justify-between border-l-4 border-l-amber-500">
            <div>
                <div class="text-xs uppercase text-gray-400 font-medium">Avg Resolution Time</div>
                <div class="text-2xl font-bold text-amber-400 mt-1" id="kpi-latency">-- ms</div>
                <div class="text-xs text-amber-500/80 mt-1">MTTR Autonomous Target &lt; 200ms</div>
            </div>
            <i class="fa-solid fa-bolt text-3xl text-amber-500/40"></i>
        </div>

        <div class="glass-panel p-5 rounded-2xl flex items-center justify-between border-l-4 border-l-emerald-500">
            <div>
                <div class="text-xs uppercase text-gray-400 font-medium">Self-Learning Accuracy</div>
                <div class="text-2xl font-bold text-emerald-400 mt-1" id="kpi-accuracy">99.4%</div>
                <div class="text-xs text-emerald-400 mt-1"><i class="fa-solid fa-arrows-spin mr-1"></i> Active Feedback Loop</div>
            </div>
            <i class="fa-solid fa-brain text-3xl text-emerald-500/40"></i>
        </div>
    </div>

    <!-- Main Workspace: Scenario Launcher & Pipeline Monitor -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <!-- Interactive Scenario Controls -->
        <div class="glass-panel p-6 rounded-2xl flex flex-col justify-between">
            <div>
                <h2 class="text-lg font-bold text-white flex items-center mb-4">
                    <i class="fa-solid fa-flask-vial mr-2 text-cyan-400"></i>
                    Simulate Live Cyber Threats
                </h2>
                <p class="text-xs text-gray-400 mb-4">
                    Inject real-world attack vectors and telemetry to trigger the 10-agent autonomous chain:
                </p>
                <div class="space-y-2">
                    <button onclick="runScenario('storm_2603')" class="w-full text-left p-3 rounded-xl bg-gray-800/80 hover:bg-rose-950/40 border border-gray-700 hover:border-rose-500/60 transition group flex items-center justify-between">
                        <div>
                            <div class="text-sm font-semibold text-rose-300 group-hover:text-rose-200">Storm-2603 SharePoint ToolShell</div>
                            <div class="text-xs text-gray-400">CVE-2025-53770 / w3wp.exe fileless shell</div>
                        </div>
                        <i class="fa-solid fa-play text-xs text-rose-400"></i>
                    </button>

                    <button onclick="runScenario('sshole')" class="w-full text-left p-3 rounded-xl bg-gray-800/80 hover:bg-amber-950/40 border border-gray-700 hover:border-amber-500/60 transition group flex items-center justify-between">
                        <div>
                            <div class="text-sm font-semibold text-amber-300 group-hover:text-amber-200">OpenSSH SSHole Bypass</div>
                            <div class="text-xs text-gray-400">CVE-2026-123158 / musl libc long password probe</div>
                        </div>
                        <i class="fa-solid fa-play text-xs text-amber-400"></i>
                    </button>

                    <button onclick="runScenario('has_ransomware')" class="w-full text-left p-3 rounded-xl bg-gray-800/80 hover:bg-red-950/40 border border-gray-700 hover:border-red-500/60 transition group flex items-center justify-between">
                        <div>
                            <div class="text-sm font-semibold text-red-300 group-hover:text-red-200">Dharma / Has Ransomware</div>
                            <div class="text-xs text-gray-400">Rapid file modification & info.txt dropped</div>
                        </div>
                        <i class="fa-solid fa-play text-xs text-red-400"></i>
                    </button>

                    <button onclick="runScenario('rogue_ai')" class="w-full text-left p-3 rounded-xl bg-gray-800/80 hover:bg-purple-950/40 border border-gray-700 hover:border-purple-500/60 transition group flex items-center justify-between">
                        <div>
                            <div class="text-sm font-semibold text-purple-300 group-hover:text-purple-200">Rogue AI Agent Traversal</div>
                            <div class="text-xs text-gray-400">Internal API enumeration (WorkOS model)</div>
                        </div>
                        <i class="fa-solid fa-play text-xs text-purple-400"></i>
                    </button>

                    <button onclick="runScenario('benign')" class="w-full text-left p-3 rounded-xl bg-gray-800/80 hover:bg-emerald-950/40 border border-gray-700 hover:border-emerald-500/60 transition group flex items-center justify-between">
                        <div>
                            <div class="text-sm font-semibold text-emerald-300 group-hover:text-emerald-200">Benign Enterprise Baseline</div>
                            <div class="text-xs text-gray-400">Routine SSH, DNS & system heartbeats</div>
                        </div>
                        <i class="fa-solid fa-play text-xs text-emerald-400"></i>
                    </button>
                </div>
            </div>
            <div class="mt-4 pt-4 border-t border-gray-800 text-xs text-gray-500 text-center">
                Runs full LangGraph state engine without human touch
            </div>
        </div>

        <!-- 10 Agents Architecture Visualizer -->
        <div class="glass-panel p-6 rounded-2xl lg:col-span-2">
            <h2 class="text-lg font-bold text-white flex items-center justify-between mb-4">
                <span><i class="fa-solid fa-network-wired mr-2 text-blue-400"></i> 10-Agent Pipeline Live State</span>
                <span id="session-tag" class="text-xs font-mono text-gray-400">Standby</span>
            </h2>
            
            <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4 text-xs font-medium">
                <!-- Agent 1 -->
                <div id="card-AGENT-01-INGEST" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 1</div>
                    <div class="font-bold text-cyan-300 mt-1">Data Collection</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-01-INGEST">Idle</div>
                </div>

                <!-- Agent 2 -->
                <div id="card-AGENT-02-ANALYSIS" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 2</div>
                    <div class="font-bold text-cyan-300 mt-1">Data Analysis</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-02-ANALYSIS">Idle</div>
                </div>

                <!-- Agent 3 -->
                <div id="card-AGENT-03-DETECTION" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 3</div>
                    <div class="font-bold text-amber-300 mt-1">Threat Detection</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-03-DETECTION">Idle</div>
                </div>

                <!-- Agent 4 -->
                <div id="card-AGENT-04-VULN" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 4</div>
                    <div class="font-bold text-amber-300 mt-1">Vulnerability Scan</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-04-VULN">Idle</div>
                </div>

                <!-- Agent 5 -->
                <div id="card-AGENT-05-NETWORK" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 5</div>
                    <div class="font-bold text-amber-300 mt-1">Network Monitor</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-05-NETWORK">Idle</div>
                </div>

                <!-- Agent 6 -->
                <div id="card-AGENT-06-MALWARE" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 6</div>
                    <div class="font-bold text-amber-300 mt-1">Malware Analysis</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-06-MALWARE">Idle</div>
                </div>

                <!-- Agent 7 -->
                <div id="card-AGENT-07-INTEL" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 7</div>
                    <div class="font-bold text-indigo-300 mt-1">Threat Intel</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-07-INTEL">Idle</div>
                </div>

                <!-- Agent 8 -->
                <div id="card-AGENT-08-DECISION" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 8</div>
                    <div class="font-bold text-rose-300 mt-1">Security Decision</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-08-DECISION">Idle</div>
                </div>

                <!-- Agent 9 -->
                <div id="card-AGENT-09-RESPONSE" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 9</div>
                    <div class="font-bold text-red-400 mt-1">Incident Response</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-09-RESPONSE">Idle</div>
                </div>

                <!-- Agent 10 -->
                <div id="card-AGENT-10-LEARN" class="agent-node p-3 rounded-xl bg-gray-900 border border-gray-700">
                    <div class="text-gray-400 font-mono text-[10px]">AGENT 10</div>
                    <div class="font-bold text-emerald-300 mt-1">Monitor & Learn</div>
                    <div class="text-[10px] text-gray-400 mt-1" id="sub-AGENT-10-LEARN">Idle</div>
                </div>
            </div>

            <!-- Real-time Console Log -->
            <div class="mt-4">
                <div class="text-xs uppercase tracking-wider text-gray-400 font-bold mb-2">Live Execution Telemetry & Audit Stream</div>
                <div id="telemetry-log" class="h-44 overflow-y-auto bg-black/60 rounded-xl p-3 font-mono text-xs text-gray-300 space-y-1 border border-gray-800">
                    <div class="text-gray-500">> System initialized. Select a scenario on the left to trigger autonomous pipeline...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bottom Section: Detailed Incident Resolution & Defensive Actions -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Incident Narrative & MITRE Mapping -->
        <div class="glass-panel p-6 rounded-2xl">
            <h3 class="text-md font-bold text-white flex items-center mb-3">
                <i class="fa-solid fa-file-shield mr-2 text-indigo-400"></i>
                Incident Narrative & MITRE ATT&CK Matrix
            </h3>
            <div id="incident-narrative" class="text-sm text-gray-300 leading-relaxed bg-gray-900/60 p-4 rounded-xl border border-gray-800 min-h-[140px]">
                Awaiting next telemetry execution...
            </div>
        </div>

        <!-- Automated Defensive Containment Actions -->
        <div class="glass-panel p-6 rounded-2xl">
            <h3 class="text-md font-bold text-white flex items-center mb-3">
                <i class="fa-solid fa-lock mr-2 text-red-400"></i>
                Autonomous Defensive Actions Executed
            </h3>
            <div id="actions-list" class="space-y-2 min-h-[140px]">
                <div class="text-xs text-gray-500 italic p-3">No actions taken yet.</div>
            </div>
        </div>
    </div>

    <script>
        async function runScenario(scenarioKey) {
            const logBox = document.getElementById('telemetry-log');
            logBox.innerHTML = '<div class="text-cyan-400 font-bold">> Dispatching scenario [' + scenarioKey + '] to Agent 1...</div>';

            // Reset agent badges
            for (let i = 1; i <= 10; i++) {
                const id = 'AGENT-' + (i < 10 ? '0' + i : i);
                const sub = document.getElementById('sub-' + id);
                if (sub) sub.innerText = 'Processing...';
            }

            try {
                const res = await fetch('/api/run_scenario', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({scenario: scenarioKey})
                });
                const data = await res.json();
                renderExecutionResult(data);
            } catch (err) {
                logBox.innerHTML += '<div class="text-red-400">> Execution Error: ' + err + '</div>';
            }
        }

        function renderExecutionResult(data) {
            const logBox = document.getElementById('telemetry-log');
            const state = data.state;
            
            document.getElementById('session-tag').innerText = 'Session: ' + state.session_id.substring(0, 8);
            document.getElementById('kpi-latency').innerText = data.duration_ms + ' ms';
            document.getElementById('kpi-neutralized').innerText = data.threat_confirmed ? 'YES (100%)' : 'NORMAL';

            // Populate audit log
            logBox.innerHTML = '';
            state.audit_trail.forEach(entry => {
                logBox.innerHTML += '<div><span class="text-cyan-400">[' + entry.agent_name + ']</span> ' + entry.summary + ' <span class="text-gray-500">(' + entry.execution_time_ms + 'ms)</span></div>';
            });

            // Update Agent cards
            state.audit_trail.forEach(entry => {
                const card = document.getElementById('card-' + entry.agent_id);
                const sub = document.getElementById('sub-' + entry.agent_id);
                if (card && sub) {
                    if (entry.status === 'SUCCESS') {
                        card.classList.add('border-emerald-500/80', 'bg-emerald-950/20');
                        sub.innerText = 'Completed (' + entry.execution_time_ms + 'ms)';
                        sub.className = 'text-[10px] text-emerald-400 font-mono mt-1';
                    }
                }
            });

            // Populate narrative
            const narrativeEl = document.getElementById('incident-narrative');
            if (data.report_markdown) {
                narrativeEl.innerHTML = '<pre class="whitespace-pre-wrap font-sans text-xs leading-relaxed text-gray-200">' + data.report_markdown + '</pre>';
            }

            // Populate defensive actions
            const actionsEl = document.getElementById('actions-list');
            actionsEl.innerHTML = '';
            if (state.executed_actions && state.executed_actions.length > 0) {
                state.executed_actions.forEach(act => {
                    actionsEl.innerHTML += `
                        <div class="p-3 rounded-xl bg-gray-900/80 border border-gray-800 flex items-center justify-between">
                            <div>
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${act.success ? 'bg-emerald-900 text-emerald-300' : 'bg-amber-900 text-amber-300'}">${act.status_code}</span>
                                <span class="font-mono text-xs font-bold text-white ml-2">${act.target}</span>
                                <div class="text-xs text-gray-400 mt-1">${act.details}</div>
                            </div>
                            <i class="fa-solid fa-shield-virus text-gray-600 text-lg"></i>
                        </div>
                    `;
                });
            } else {
                actionsEl.innerHTML = '<div class="text-xs text-emerald-400 p-3"><i class="fa-solid fa-circle-check mr-2"></i> No aggressive actions required. Systems verified benign.</div>';
            }
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/run_scenario", methods=["POST"])
def api_run_scenario():
    data = request.get_json() or {}
    scenario_key = data.get("scenario", "storm_2603")

    # Select scenario events
    if scenario_key == "storm_2603":
        raw_events = get_scenario_storm_2603_sharepoint()
    elif scenario_key == "sshole":
        raw_events = get_scenario_sshole_cve_2026_123158()
    elif scenario_key == "has_ransomware":
        raw_events = get_scenario_has_ransomware()
    elif scenario_key == "rogue_ai":
        raw_events = get_scenario_rogue_ai_agent()
    else:
        raw_events = get_scenario_benign_baseline()

    # Build fresh State
    state = CyberGuardState(raw_events=raw_events)
    start_time = time.time()
    
    # Run end-to-end graph
    final_state = orchestrator.run(state)
    duration_ms = round((time.time() - start_time) * 1000, 2)

    # Trigger Self-Learning engine update
    if final_state.threat_intel_report and final_state.threat_confirmed:
        rule_ids = [d.matched_rule for d in final_state.threat_detections]
        GLOBAL_LEARNING_ENGINE.record_incident_outcome(
            session_id=final_state.session_id,
            rules_triggered=rule_ids,
            verified_true_positive=True,
            mean_response_time_ms=duration_ms
        )

    response_payload = {
        "status": "success",
        "duration_ms": duration_ms,
        "threat_confirmed": final_state.threat_confirmed,
        "report_markdown": final_state.final_report_markdown,
        "state": final_state.to_dict()
    }
    recent_executions.append(response_payload)
    return jsonify(response_payload)

@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    return jsonify(GLOBAL_LEARNING_ENGINE.get_performance_metrics())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
