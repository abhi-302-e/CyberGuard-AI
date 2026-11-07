import React from 'react';

export default function Reports() {
  const reports = [
    {
      id: 'REP-2026-001',
      title: 'Storm-2603 SharePoint ToolShell Exploitation Incident Resolution Report',
      date: '2026-11-07',
      type: 'Executive Incident Brief',
      status: 'VERIFIED_CONTAINMENT',
      summary: 'Automated 10-agent response neutralized fileless subshell execution, blocked external C2 185.220.101.55, and isolated target server sharepoint-app01 with 112ms MTTR.'
    },
    {
      id: 'REP-2026-002',
      title: 'Weekly SOC Multi-Agent Continuous Learning & Metric Optimization Report',
      date: '2026-11-01',
      type: 'Operational Analytics',
      status: 'PUBLISHED',
      summary: 'Analysis of 142,850 events showing 99.4% precision, 0.006% false positive rate, and closed-loop reinforcement for Sigma detection rules.'
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">EXECUTIVE INCIDENT & AUDIT REPORTS</h2>
          <p className="text-xs text-slate-400">Downloadable executive summaries, technical forensics & mitigation compliance documents</p>
        </div>
      </div>

      <div className="space-y-4">
        {reports.map((r) => (
          <div key={r.id} className="soc-card p-5 rounded-2xl flex justify-between items-center">
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-cyan-400 text-xs font-bold">{r.id}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300">
                  {r.type}
                </span>
                <span className="text-xs text-slate-500 font-mono">{r.date}</span>
              </div>
              <h3 className="text-sm font-bold text-white mt-1">{r.title}</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">{r.summary}</p>
            </div>

            <div>
              <button
                onClick={() => alert(`Downloading signed PDF report: ${r.title}`)}
                className="px-4 py-2 rounded-xl bg-blue-600/30 border border-blue-500/50 hover:bg-blue-600/50 text-xs font-bold text-cyan-300 flex items-center space-x-2 transition"
              >
                <i className="fa-solid fa-file-pdf text-rose-400"></i>
                <span>Download PDF</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
