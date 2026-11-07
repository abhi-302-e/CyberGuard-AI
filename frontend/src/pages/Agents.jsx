import React from 'react';

export default function Agents() {
  const agents = [
    {
      id: 'AGENT-01',
      name: 'Security Data Collection Agent',
      role: 'Enterprise Telemetry Ingestion & Normalization',
      receives: 'Firewall logs, NetFlow, Syslog, EDR signals, SIEM alerts',
      decides: 'Validates schema, translates RFC 5424 timestamps, filters corrupted frames',
      passes: 'Normalized security events (List[SecurityEvent])',
      tools: 'Python, Syslog parser, ELK APIs, Fluentbit',
      status: 'ONLINE',
      accuracy: '99.8%'
    },
    {
      id: 'AGENT-02',
      name: 'Security Data Analysis Agent',
      role: 'Noise Reduction, De-duplication & Anomaly Flagging',
      receives: 'Normalized security logs from Agent 1',
      decides: 'Evaluates 5s sliding window hashes, drops broadcast/NTP noise, flags deviations',
      passes: 'Filtered clean events & prioritized anomaly queues',
      tools: 'Pandas, NumPy, sliding temporal window hashing',
      status: 'ONLINE',
      accuracy: '99.5%'
    },
    {
      id: 'AGENT-03',
      name: 'Threat Detection Agent',
      role: 'Signature & Anomaly-Based Attack Detection',
      receives: 'Filtered anomalous event stream',
      decides: 'Matches Sigma behavioral rules (IIS subshells, brute-force, ransomware markers)',
      passes: 'Threat detections with MITRE TTPs and confidence ratings',
      tools: 'Sigma rule engine, regex classifiers, ML baseline models',
      status: 'ONLINE',
      accuracy: '98.9%'
    },
    {
      id: 'AGENT-04',
      name: 'Vulnerability Assessment Agent',
      role: 'Infrastructure Weakness & CVE Correlation',
      receives: 'Asset banners, inventory versions, scan results',
      decides: 'Correlates observed systems with CVE databases (CIVN-2026-0539, CVE-2025-53770)',
      passes: 'Vulnerability findings with CVSS scores and remediation steps',
      tools: 'Nmap banners, OpenVAS/Greenbone, CERT-In CVE Catalog',
      status: 'ONLINE',
      accuracy: '99.2%'
    },
    {
      id: 'AGENT-05',
      name: 'Network Monitoring Agent',
      role: 'Traffic Flow, C2 Beaconing & Protocol Anomaly Detection',
      receives: 'Zeek flow records, connection intervals, DNS queries',
      decides: 'Detects low-jitter periodic beaconing, DNS tunneling, and >50MB egress spikes',
      passes: 'Network anomalies and connection evidence',
      tools: 'Wireshark, Zeek, Suricata, Snort',
      status: 'ONLINE',
      accuracy: '97.8%'
    },
    {
      id: 'AGENT-06',
      name: 'Malware Analysis Agent',
      role: 'File Behavior, Hash Reputation & YARA Static Analysis',
      receives: 'File hashes (SHA-256), script blocks, sandbox reports',
      decides: 'Matches YARA signatures (Warlock, Dharma, AsyncRAT) & PowerShell evasion switches',
      passes: 'Malware classifications, IOCs, quarantine recommendation',
      tools: 'YARA 4.5+, ClamAV, isolated sandbox runtime',
      status: 'ONLINE',
      accuracy: '99.6%'
    },
    {
      id: 'AGENT-07',
      name: 'Threat Intelligence Agent',
      role: 'Multi-Source Threat Correlation & ATT&CK Mapping',
      receives: 'Outputs of Agents 3, 4, 5, and 6',
      decides: 'Connects findings to attack campaigns, attributes threat actors, builds narrative',
      passes: 'ThreatIntelligenceReport & STIX 2.1 JSON bundle',
      tools: 'MITRE ATT&CK Matrix, STIX/TAXII feeds',
      status: 'ONLINE',
      accuracy: '98.4%'
    },
    {
      id: 'AGENT-08',
      name: 'Security Decision & Risk Assessment Agent',
      role: 'Risk Quantification, Response Strategy & Authorization Gate',
      receives: 'Consolidated Threat Intelligence Report',
      decides: 'Computes Risk (Severity x Criticality x Confidence), gates Tier-0 critical assets',
      passes: 'Prioritized SecurityDecisionPlan with approved actions',
      tools: 'Policy Decision Point (PDP), Risk Matrix Engine',
      status: 'ONLINE',
      accuracy: '99.9%'
    },
    {
      id: 'AGENT-09',
      name: 'Automated Incident Response Agent',
      role: 'Active Defensive Execution & Policy Enforcement',
      receives: 'Authorized response plan from Agent 8',
      decides: 'Executes firewall IP drops, EDR endpoint isolation, token kills, Jira ticketing',
      passes: 'Action results, containment status, audit logs',
      tools: 'iptables/PFSense API, CrowdStrike/SentinelOne EDR, Okta API',
      status: 'ONLINE',
      accuracy: '100%'
    },
    {
      id: 'AGENT-10',
      name: 'Monitoring and Self-Learning Agent',
      role: 'Verification, False-Positive Optimization & Rule Evolution',
      receives: 'Post-containment telemetry & incident execution logs',
      decides: 'Verifies attack traffic cessation, tunes adaptive rule sensitivity weights',
      passes: 'Updated detection rule weights & final resolution report',
      tools: 'Closed feedback loop engine, persistent rule weight store',
      status: 'ONLINE',
      accuracy: '99.4%'
    }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-black text-white tracking-wide">10 SPECIALIZED AI AGENTS</h2>
        <p className="text-xs text-slate-400">Isolated functional boundaries, inputs, decisions, outputs, and underpinnings</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {agents.map((ag) => (
          <div key={ag.id} className="soc-card p-5 rounded-2xl flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center pb-3 border-b border-slate-800/80">
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800">
                    {ag.id}
                  </span>
                  <h3 className="text-sm font-bold text-white">{ag.name}</h3>
                </div>
                <span className="inline-flex items-center text-[10px] font-bold text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                  {ag.status} ({ag.accuracy})
                </span>
              </div>

              <div className="text-xs text-cyan-400 font-medium mt-3 mb-2">{ag.role}</div>

              <div className="space-y-2 text-xs text-slate-300">
                <div>
                  <span className="text-slate-500 font-semibold uppercase text-[10px] block">Receives:</span>
                  <span>{ag.receives}</span>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold uppercase text-[10px] block">Decides:</span>
                  <span>{ag.decides}</span>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold uppercase text-[10px] block">Passes:</span>
                  <span className="text-slate-200 font-mono text-[11px]">{ag.passes}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span>Tools: {ag.tools}</span>
              <button className="text-cyan-400 hover:text-cyan-300 font-sans font-bold">
                Run Diagnostics &rarr;
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

