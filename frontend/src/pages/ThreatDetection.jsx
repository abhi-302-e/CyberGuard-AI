import React, { useState } from 'react';

export default function ThreatDetection() {
  const [threats] = useState([
    {
      id: 'THR-STORM-01',
      category: 'Remote Code Execution / IIS Sub-shell',
      mitre_id: 'T1190',
      tactic: 'Initial Access & Execution',
      severity: 'CRITICAL',
      confidence: '96%',
      target: 'sharepoint-app01.corp.internal',
      attacker: '185.220.101.55',
      rule: 'SIGMA-001 (w3wp.exe spawned powershell.exe -enc ToolShell)',
      status: 'CONTAINED'
    },
    {
      id: 'THR-SSHOLE-02',
      category: 'Authentication Bypass Attempt',
      mitre_id: 'T1078',
      tactic: 'Initial Access',
      severity: 'HIGH',
      confidence: '92%',
      target: 'gw-edge-alpine.corp.internal',
      attacker: '194.26.29.112',
      rule: 'SIGMA-002 (OpenSSH SSHole CVE-2026-123158 length 512)',
      status: 'CONTAINED'
    },
    {
      id: 'THR-DHARMA-03',
      category: 'Ransomware Mass Encryption',
      mitre_id: 'T1486',
      tactic: 'Impact',
      severity: 'CRITICAL',
      confidence: '98%',
      target: 'finance-ws-04.corp.internal',
      attacker: '10.0.3.45',
      rule: 'SIGMA-003 (.has extension rename & info.txt dropped)',
      status: 'CONTAINED'
    }
  ]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">THREAT DETECTION ENGINE</h2>
          <p className="text-xs text-slate-400">Agent 3: Real-time Sigma behavioral rule evaluation & MITRE technique identification</p>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-rose-950 text-rose-300 border border-rose-800">
          3 Active Exploitation Signatures Flagged
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {threats.map((t) => (
          <div key={t.id} className="soc-card p-5 rounded-2xl border-l-4 border-l-rose-500">
            <div className="flex justify-between items-start">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-cyan-400 text-xs font-bold">{t.id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300">
                    MITRE {t.mitre_id} ({t.tactic})
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    {t.severity}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-1.5">{t.category}</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Target Asset: <span className="font-mono text-slate-200">{t.target}</span> • Attacker IP: <span className="font-mono text-rose-400">{t.attacker}</span>
                </p>
              </div>

              <div className="text-right">
                <span className="text-xs font-mono text-emerald-400 font-bold block">Confidence: {t.confidence}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 mt-1 inline-block">
                  {t.status}
                </span>
              </div>
            </div>

            <div className="mt-3 p-3 rounded-xl bg-[#090e1b] border border-slate-800/80 font-mono text-xs text-slate-300">
              <span className="text-slate-500 font-bold">Rule Triggered:</span> {t.rule}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
