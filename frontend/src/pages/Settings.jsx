import React from 'react';

export default function Settings({ user }) {
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-xl font-black text-white tracking-wide">SYSTEM CONFIGURATION & GOVERNANCE</h2>
        <p className="text-xs text-slate-400">Manage security thresholds, asset criticality mappings, API tokens, and integrations</p>
      </div>

      <div className="space-y-4">
        {/* Policy Guardrails Card */}
        <div className="soc-card p-5 rounded-2xl">
          <h3 className="text-sm font-bold text-white mb-2">Autonomous Policy Guardrails</h3>
          <p className="text-xs text-slate-400 mb-4">
            Define autonomous action boundaries. High-impact operations on Tier-0 assets always trigger human gating.
          </p>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between items-center p-3 rounded-xl bg-[#090e1b] border border-slate-800">
              <div>
                <div className="font-semibold text-slate-200">Autonomous Edge IP Null-Routing</div>
                <div className="text-slate-500 text-[11px]">Automatically inject drop rules for confirmed C2 IPs (Confidence &ge; 0.80)</div>
              </div>
              <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                ENABLED
              </span>
            </div>

            <div className="flex justify-between items-center p-3 rounded-xl bg-[#090e1b] border border-slate-800">
              <div>
                <div className="font-semibold text-slate-200">Tier-0 Asset Isolation Gate</div>
                <div className="text-slate-500 text-[11px]">Strictly gate network isolation for Domain Controllers and Primary DBs</div>
              </div>
              <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-blue-950 text-cyan-400 border border-blue-800">
                MANDATORY GATE
              </span>
            </div>
          </div>
        </div>

        {/* API Integration Keys */}
        <div className="soc-card p-5 rounded-2xl">
          <h3 className="text-sm font-bold text-white mb-2">API Security & Secret Credentials</h3>
          <div className="space-y-2 text-xs font-mono">
            <div className="p-3 rounded-xl bg-[#090e1b] border border-slate-800 flex justify-between items-center">
              <div>
                <div className="text-slate-400 text-[10px]">INCIDENT COMMANDER API TOKEN</div>
                <div className="text-cyan-300">cg-key-cmd-8821****************************</div>
              </div>
              <span className="text-emerald-400 font-sans font-bold text-[10px]">ACTIVE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

