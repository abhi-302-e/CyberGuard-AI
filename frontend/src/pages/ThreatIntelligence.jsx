import React from 'react';

export default function ThreatIntelligence() {
  const campaigns = [
    {
      actor: 'Storm-2603',
      campaign: 'SharePoint ToolShell Fileless Ransomware Campaign',
      threat_level: 'CRITICAL',
      confidence: '94%',
      ttps: ['T1190 (Exploit Public-Facing App)', 'T1059.001 (PowerShell)', 'T1071.001 (Web Protocols)', 'T1486 (Data Encrypted)'],
      narrative: 'Threat actor Storm-2603 leverages ToolShell zero-day serialization gadgets inside IIS worker process w3wp.exe to establish persistence, tunnel out over TLS, and deploy Warlock ransomware payloads.'
    },
    {
      actor: 'Dharma Syndicate',
      campaign: 'Has Ransomware Extortion Campaign',
      threat_level: 'CRITICAL',
      confidence: '98%',
      ttps: ['T1110 (Brute Force)', 'T1490 (Inhibit System Recovery)', 'T1486 (Data Encrypted for Impact)'],
      narrative: 'Automated extortion group deploying Has ransomware variants following credential brute force on exposed RDP/VPN gateways, encrypting local shares with victim-specific extensions.'
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">THREAT INTELLIGENCE & MITRE ATT&CK CORRELATION</h2>
          <p className="text-xs text-slate-400">Agent 7: Cross-agent synthesis, STIX 2.1 bundles, actor attribution & technique heatmaps</p>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
          STIX 2.1 Feeds Synced
        </span>
      </div>

      <div className="space-y-4">
        {campaigns.map((c) => (
          <div key={c.actor} className="soc-card p-5 rounded-2xl">
            <div className="flex justify-between items-center pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 rounded-lg bg-indigo-950 flex items-center justify-center text-indigo-400 font-bold border border-indigo-800">
                  <i className="fa-solid fa-skull"></i>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">{c.actor}</h3>
                  <div className="text-xs text-slate-400">{c.campaign}</div>
                </div>
              </div>
              <div className="text-right">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800 block">
                  {c.threat_level}
                </span>
                <span className="text-[10px] text-emerald-400 font-mono mt-0.5 block">Confidence: {c.confidence}</span>
              </div>
            </div>

            <div className="mt-3 text-xs text-slate-300 leading-relaxed bg-[#090e1b] p-3 rounded-xl border border-slate-800">
              <span className="text-slate-500 font-bold block mb-1">Intelligence Assessment & Narrative:</span>
              {c.narrative}
            </div>

            <div className="mt-3">
              <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1.5">Correlated MITRE ATT&CK Techniques:</span>
              <div className="flex flex-wrap gap-2">
                {c.ttps.map((ttp) => (
                  <span key={ttp} className="px-2 py-1 rounded-lg text-xs font-mono font-medium bg-slate-800/80 text-cyan-300 border border-slate-700">
                    {ttp}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

