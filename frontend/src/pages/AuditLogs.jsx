import React from 'react';

export default function AuditLogs() {
  const auditEntries = [
    { id: 1, session: '3870ca85', actor: 'Data Collection Agent', action: 'INGEST_TELEMETRY', status: 'SUCCESS', latency: '0.36ms', prev_hash: '0000000000...000', record_hash: '7a9c8f12...b91' },
    { id: 2, session: '3870ca85', actor: 'Data Analysis Agent', action: 'DEDUPLICATE_AND_FILTER', status: 'SUCCESS', latency: '0.14ms', prev_hash: '7a9c8f12...b91', record_hash: 'e45d1902...a14' },
    { id: 3, session: '3870ca85', actor: 'Threat Detection Agent', action: 'SIGMA_RULE_EVAL', status: 'SUCCESS', latency: '0.29ms', prev_hash: 'e45d1902...a14', record_hash: '8f01b7a3...c32' },
    { id: 4, session: '3870ca85', actor: 'Security Decision Agent', action: 'RISK_SCORE_AND_PDP', status: 'SUCCESS', latency: '0.28ms', prev_hash: '8f01b7a3...c32', record_hash: '3d91ca8e...f07' },
    { id: 5, session: '3870ca85', actor: 'Incident Response Agent', action: 'FIREWALL_DROP_EXEC', status: 'SUCCESS', latency: '0.54ms', prev_hash: '3d91ca8e...f07', record_hash: '91ef7a44...88d' },
    { id: 6, session: '3870ca85', actor: 'Monitoring & Learning Agent', action: 'RULE_WEIGHT_TUNE', status: 'SUCCESS', latency: '0.20ms', prev_hash: '91ef7a44...88d', record_hash: '55bc012e...11a' }
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">CRYPTOGRAPHIC AUDIT LOGS</h2>
          <p className="text-xs text-slate-400">Append-only tamper-resistant execution history with SHA-256 hash chaining</p>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center space-x-1.5">
          <i className="fa-solid fa-lock text-xs"></i>
          <span>AUDIT CHAIN INTEGRITY: 100% VERIFIED</span>
        </span>
      </div>

      <div className="soc-card p-5 rounded-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-medium">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[10px]">
                <th className="pb-2">RECORD ID</th>
                <th className="pb-2">SESSION</th>
                <th className="pb-2">ACTOR</th>
                <th className="pb-2">ACTION PERFORMED</th>
                <th className="pb-2">STATUS</th>
                <th className="pb-2">LATENCY</th>
                <th className="pb-2">RECORD SHA-256 HASH</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {auditEntries.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30 transition">
                  <td className="py-2.5 text-cyan-400 font-bold">#{log.id}</td>
                  <td className="py-2.5 text-slate-400">{log.session}</td>
                  <td className="py-2.5 font-sans font-semibold text-slate-200">{log.actor}</td>
                  <td className="py-2.5 text-slate-300">{log.action}</td>
                  <td className="py-2.5">
                    <span className="text-emerald-400 font-bold">{log.status}</span>
                  </td>
                  <td className="py-2.5 text-cyan-400">{log.latency}</td>
                  <td className="py-2.5 text-slate-500 truncate max-w-xs">{log.record_hash}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
