import React, { useState } from 'react';

export default function IncidentResponse() {
  const [incidents, setIncidents] = useState([
    {
      id: 'INC-2026-001',
      title: 'Storm-2603 SharePoint ToolShell Exploitation',
      severity: 'CRITICAL',
      asset: 'sharepoint-app01.corp.internal (10.0.1.20)',
      risk_score: 89.3,
      status: 'RESOLVED',
      actions: [
        { type: 'BLOCK_IP', target: '185.220.101.55', status: 'EXECUTED', details: 'Applied boundary drop rule' },
        { type: 'QUARANTINE_HOST', target: 'sharepoint-app01.corp.internal', status: 'EXECUTED', details: 'CrowdStrike EDR network isolation' }
      ]
    },
    {
      id: 'INC-2026-002',
      title: 'Tier-0 Domain Controller Intrusive Scan',
      severity: 'CRITICAL',
      asset: 'dc-01.corp.internal (10.0.0.1)',
      risk_score: 95.0,
      status: 'AWAITING_APPROVAL',
      actions: [
        { type: 'ISOLATE_CRITICAL_SERVER', target: 'dc-01.corp.internal', status: 'PENDING_APPROVAL', details: 'Gated: Tier-0 Asset isolation requires Incident Commander signature' }
      ]
    }
  ]);

  const [approvalAlert, setApprovalAlert] = useState(null);

  const handleApprove = (incidentId) => {
    setIncidents(incidents.map((inc) => {
      if (inc.id === incidentId) {
        return {
          ...inc,
          status: 'RESOLVED',
          actions: inc.actions.map(a => ({ ...a, status: 'EXECUTED', details: 'Cryptographic approval verified by Incident Commander' }))
        };
      }
      return inc;
    }));
    setApprovalAlert(`Incident ${incidentId}: Cryptographic token signed. Defensive containment executed on Tier-0 target.`);
    setTimeout(() => setApprovalAlert(null), 5000);
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">INCIDENT RESPONSE & CONTAINMENT WORKFLOW</h2>
          <p className="text-xs text-slate-400">Agent 9: Active defensive execution, EDR host isolation, IP blocking, and Tier-0 human safety gating</p>
        </div>
      </div>

      {approvalAlert && (
        <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-800 text-xs font-semibold text-emerald-300 flex items-center space-x-2">
          <i className="fa-solid fa-circle-check"></i>
          <span>{approvalAlert}</span>
        </div>
      )}

      <div className="space-y-4">
        {incidents.map((inc) => (
          <div key={inc.id} className="soc-card p-5 rounded-2xl">
            <div className="flex justify-between items-start pb-3 border-b border-slate-800">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-cyan-400 text-xs font-bold">{inc.id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">
                    {inc.severity}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">Risk Score: {inc.risk_score}/100</span>
                </div>
                <h3 className="text-base font-bold text-white mt-1">{inc.title}</h3>
                <p className="text-xs text-slate-400 mt-0.5">Affected Asset: <span className="font-mono text-slate-200">{inc.asset}</span></p>
              </div>

              <div className="text-right">
                <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                  inc.status === 'RESOLVED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                  inc.status === 'AWAITING_APPROVAL' ? 'bg-amber-950 text-amber-300 border border-amber-800 animate-pulse' :
                  'bg-blue-950 text-blue-300'
                }`}>
                  {inc.status}
                </span>
              </div>
            </div>

            {/* Actions List */}
            <div className="mt-3 space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-500 block">Defensive Playbook Actions:</span>
              {inc.actions.map((act, idx) => (
                <div key={idx} className="p-3 rounded-xl bg-[#090e1b] border border-slate-800 flex justify-between items-center text-xs">
                  <div>
                    <span className="font-mono font-bold text-cyan-300 mr-2">{act.type}</span>
                    <span className="font-mono text-slate-400 mr-3">Target: {act.target}</span>
                    <span className="text-slate-300">{act.details}</span>
                  </div>
                  <div>
                    {act.status === 'PENDING_APPROVAL' ? (
                      <button
                        onClick={() => handleApprove(inc.id)}
                        className="px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs shadow-md shadow-emerald-500/20 transition"
                      >
                        Sign & Approve Action &rarr;
                      </button>
                    ) : (
                      <span className="text-emerald-400 font-mono font-bold text-[11px] flex items-center">
                        <i className="fa-solid fa-check mr-1"></i> {act.status}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
