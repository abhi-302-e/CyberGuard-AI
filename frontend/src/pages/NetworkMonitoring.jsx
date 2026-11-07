import React from 'react';

export default function NetworkMonitoring() {
  const flows = [
    {
      id: 'NET-01',
      type: 'C2_BEACONING',
      src: '10.0.1.20',
      dst: '185.220.101.55',
      port: 8443,
      proto: 'TCP',
      interval: '30s (Jitter 2%)',
      volume: '2.0 KB',
      confidence: '92%',
      severity: 'CRITICAL',
      evidence: 'Low-jitter TLS heartbeat initiated from SharePoint IIS worker process'
    },
    {
      id: 'NET-02',
      type: 'DATA_EXFILTRATION',
      src: '10.0.4.88',
      dst: '10.0.0.15',
      port: 8080,
      proto: 'TCP',
      interval: 'Continuous Stream',
      volume: '65.0 MB',
      confidence: '89%',
      severity: 'HIGH',
      evidence: 'High-rate internal API customer export by unauthorized ai-security-agent'
    },
    {
      id: 'NET-03',
      type: 'PORT_SCANNING',
      src: '194.26.29.112',
      dst: '10.0.2.15',
      port: 22,
      proto: 'TCP',
      interval: 'Rapid Burst',
      volume: '128 KB',
      confidence: '94%',
      severity: 'HIGH',
      evidence: 'Horizontal port probing across management perimeter interfaces'
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-white tracking-wide">NETWORK TRAFFIC & FLOW MONITORING</h2>
          <p className="text-xs text-slate-400">Agent 5: Zeek flow records, C2 beaconing analysis, DNS tunneling & egress anomalies</p>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-amber-950 text-amber-300 border border-amber-800">
          Flow Anomaly Engine Active
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {flows.map((f) => (
          <div key={f.id} className="soc-card p-5 rounded-2xl flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                <span className="font-mono text-cyan-400 text-xs font-bold">{f.id}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">
                  {f.type}
                </span>
              </div>

              <div className="mt-3 space-y-1.5 text-xs">
                <div className="flex justify-between text-slate-400">
                  <span>Source:</span>
                  <span className="font-mono text-slate-200">{f.src}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Destination:</span>
                  <span className="font-mono text-rose-400">{f.dst}:{f.port}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Pattern:</span>
                  <span className="font-mono text-slate-300">{f.interval}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Transferred:</span>
                  <span className="font-mono text-cyan-400">{f.volume}</span>
                </div>
              </div>

              <div className="mt-3 p-2.5 rounded-xl bg-[#090e1b] text-slate-300 text-xs leading-relaxed">
                {f.evidence}
              </div>
            </div>

            <div className="mt-4 pt-2 border-t border-slate-800 text-[11px] flex justify-between items-center">
              <span className="text-emerald-400 font-bold font-mono">Confidence: {f.confidence}</span>
              <span className="text-rose-400 font-semibold">{f.severity}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
