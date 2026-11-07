import React, { useState, useEffect } from 'react';

export default function Dashboard({ onTriggerScenario, onNavigate }) {
  const [stats, setStats] = useState({
    total_security_events: 142850,
    detected_threats: 38,
    critical_incidents: 4,
    vulnerabilities_identified: 12,
    active_ai_agents: 10,
    resolved_incidents: 34,
    mean_time_to_detect_ms: 38.5,
    mean_time_to_respond_ms: 112.0,
    accuracy_rate: 0.994
  });

  const alerts = [
    { id: 'EVT-STORM-01', threat: 'Storm-2603 SharePoint ToolShell RCE', src_ip: '185.220.101.55', dst: 'sharepoint-app01', severity: 'CRITICAL', time: '2m ago', status: 'CONTAINED' },
    { id: 'EVT-SSHOLE-02', threat: 'OpenSSH SSHole Auth Bypass (CVE-2026-123158)', src_ip: '194.26.29.112', dst: 'gw-edge-alpine', severity: 'HIGH', time: '14m ago', status: 'CONTAINED' },
    { id: 'EVT-DHARMA-03', threat: 'Dharma / Has Ransomware Canary Write', src_ip: '10.0.3.45', dst: 'finance-ws-04', severity: 'CRITICAL', time: '45m ago', status: 'CONTAINED' },
    { id: 'EVT-ROGUE-04', threat: 'Rogue AI Agent API Crawler Traversal', src_ip: '10.0.4.88', dst: 'internal-api-gw', severity: 'MEDIUM', time: '1h ago', status: 'RESOLVED' },
    { id: 'EVT-BENIGN-05', threat: 'Routine Admin Publickey SSH Session', src_ip: '10.0.0.50', dst: 'sysadmin-bastion', severity: 'INFO', time: '2h ago', status: 'VERIFIED_BASELINE' }
  ];

  return (
    <div className="space-y-6">
      {/* Page Title & Controls */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">SOC COMMAND INTELLIGENCE</h2>
          <p className="text-xs text-slate-400">Autonomous Multi-Agent Threat Detection, Correlation & Active Containment</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => onTriggerScenario('storm_2603')}
            className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-xs font-bold text-white shadow-lg shadow-blue-500/20 flex items-center space-x-2 transition"
          >
            <i className="fa-solid fa-play text-xs"></i>
            <span>Simulate Live Attack</span>
          </button>
        </div>
      </div>

      {/* Top 6 KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="soc-card p-4 rounded-2xl border-l-4 border-l-blue-500">
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Total Events</div>
          <div className="text-xl font-bold text-white mt-1">142,850</div>
          <div className="text-[10px] text-blue-400 mt-1"><i className="fa-solid fa-arrow-trend-up mr-1"></i> Continuous Stream</div>
        </div>

        <div className="soc-card p-4 rounded-2xl border-l-4 border-l-rose-500">
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Threats Detected</div>
          <div className="text-xl font-bold text-rose-400 mt-1">38</div>
          <div className="text-[10px] text-slate-400 mt-1">Sigma & ATT&CK Match</div>
        </div>

        <div className="soc-card p-4 rounded-2xl border-l-4 border-l-red-600">
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Critical Incidents</div>
          <div className="text-xl font-bold text-red-500 mt-1">4</div>
          <div className="text-[10px] text-red-400 mt-1">All Neutralized</div>
        </div>

        <div className="soc-card p-4 rounded-2xl border-l-4 border-l-amber-500">
          <div className="text-[10px] text-slate-400 uppercase font-semibold">CVE Weaknesses</div>
          <div className="text-xl font-bold text-amber-400 mt-1">12</div>
          <div className="text-[10px] text-slate-400 mt-1">CERT-In 2026 Aligned</div>
        </div>

        <div className="soc-card p-4 rounded-2xl border-l-4 border-l-cyan-500">
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Active AI Agents</div>
          <div className="text-xl font-bold text-cyan-400 mt-1">10 / 10</div>
          <div className="text-[10px] text-cyan-400 mt-1">LangGraph Mesh</div>
        </div>

        <div className="soc-card p-4 rounded-2xl border-l-4 border-l-emerald-500">
          <div className="text-[10px] text-slate-400 uppercase font-semibold">Avg Response (MTTR)</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">112 ms</div>
          <div className="text-[10px] text-emerald-400 mt-1">Zero Human Delay</div>
        </div>
      </div>

      {/* 10-Agent Pipeline Mesh Live Status */}
      <div className="soc-card p-5 rounded-2xl">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <i className="fa-solid fa-microchip text-cyan-400 text-sm"></i>
            <h3 className="text-xs font-bold uppercase tracking-wider text-white">10-Agent Autonomous Pipeline State</h3>
          </div>
          <button onClick={() => onNavigate('agents')} className="text-[11px] text-cyan-400 hover:underline">
            View Agent Specifications &rarr;
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-2.5">
          {[
            { id: '1', name: 'Data Collection', role: 'Telemetry Ingest', status: 'ACTIVE', time: '0.36ms' },
            { id: '2', name: 'Data Analysis', role: 'Deduplication & Noise', status: 'ACTIVE', time: '0.14ms' },
            { id: '3', name: 'Threat Detection', role: 'Sigma Signatures', status: 'ACTIVE', time: '0.29ms' },
            { id: '4', name: 'Vulnerability Scan', role: 'CVE Correlation', status: 'ACTIVE', time: '0.15ms' },
            { id: '5', name: 'Network Monitor', role: 'C2 Flow & Exfil', status: 'ACTIVE', time: '0.17ms' },
            { id: '6', name: 'Malware Analysis', role: 'YARA & Hash Sandbox', status: 'ACTIVE', time: '0.61ms' },
            { id: '7', name: 'Threat Intel', role: 'Cross-Agent Synthesis', status: 'ACTIVE', time: '0.27ms' },
            { id: '8', name: 'Security Decision', role: 'Risk & Policy Gate', status: 'ACTIVE', time: '0.28ms' },
            { id: '9', name: 'Incident Response', role: 'Active Containment', status: 'ACTIVE', time: '0.54ms' },
            { id: '10', name: 'Monitor & Learn', role: 'Rule Optimization', status: 'ACTIVE', time: '0.20ms' },
          ].map((agent) => (
            <div key={agent.id} className="p-3 rounded-xl bg-[#090e1b] border border-slate-800 hover:border-cyan-500/40 transition">
              <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono">
                <span>AGENT 0{agent.id}</span>
                <span className="text-emerald-400 font-bold">{agent.status}</span>
              </div>
              <div className="text-xs font-bold text-slate-100 mt-1">{agent.name}</div>
              <div className="text-[10px] text-slate-400 mt-0.5 truncate">{agent.role}</div>
              <div className="text-[10px] font-mono text-cyan-400 mt-1">Latency: {agent.time}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Split: Recent Incident Alerts & Active Response Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Alerts Table (2 Columns) */}
        <div className="soc-card p-5 rounded-2xl lg:col-span-2">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center">
              <i className="fa-solid fa-list-check mr-2 text-blue-400"></i>
              Correlated Threat Alerts & Automated Actions
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Live Ingestion Active</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px]">
                  <th className="pb-2">ALERT ID</th>
                  <th className="pb-2">THREAT NAME</th>
                  <th className="pb-2">ATTACKER IP</th>
                  <th className="pb-2">SEVERITY</th>
                  <th className="pb-2">STATUS</th>
                  <th className="pb-2">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium">
                {alerts.map((al) => (
                  <tr key={al.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-2.5 font-mono text-cyan-400 text-[11px]">{al.id}</td>
                    <td className="py-2.5 text-slate-200">{al.threat}</td>
                    <td className="py-2.5 font-mono text-slate-400 text-[11px]">{al.src_ip}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        al.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        al.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {al.severity}
                      </span>
                    </td>
                    <td className="py-2.5">
                      <span className="text-[11px] text-emerald-400 font-semibold flex items-center">
                        <i className="fa-solid fa-shield-halved mr-1 text-[10px]"></i> {al.status}
                      </span>
                    </td>
                    <td className="py-2.5">
                      <button onClick={() => onNavigate('response')} className="text-cyan-400 hover:text-cyan-300 text-[11px] font-bold">
                        Inspect &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Closed-Loop Learning & Mitigation Status (1 Column) */}
        <div className="soc-card p-5 rounded-2xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center">
                <i className="fa-solid fa-brain mr-2 text-indigo-400"></i>
                Self-Learning Loop
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                99.4% Precision
              </span>
            </div>

            <p className="text-xs text-slate-400 mb-4 leading-relaxed">
              Agent 10 continuously evaluates post-containment telemetry against verified true-positives to dynamically adjust detection weights.
            </p>

            <div className="space-y-3">
              <div className="p-3 rounded-xl bg-[#090e1b] border border-slate-800">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300 font-semibold">SIGMA-001 (ToolShell IIS)</span>
                  <span className="text-cyan-400 font-mono">1.15x Weight</span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div className="bg-cyan-400 h-full rounded-full" style={{ width: '85%' }}></div>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#090e1b] border border-slate-800">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300 font-semibold">SIGMA-002 (SSHole Buffer)</span>
                  <span className="text-amber-400 font-mono">1.05x Weight</span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div className="bg-amber-400 h-full rounded-full" style={{ width: '75%' }}></div>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#090e1b] border border-slate-800">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300 font-semibold">SIGMA-003 (Has Ransomware)</span>
                  <span className="text-rose-400 font-mono">1.20x Weight</span>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                  <div className="bg-rose-400 h-full rounded-full" style={{ width: '90%' }}></div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-800/80 text-center">
            <button onClick={() => onNavigate('reports')} className="text-xs text-cyan-400 hover:underline font-bold">
              Generate Downloadable PDF Executive Report &rarr;
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

