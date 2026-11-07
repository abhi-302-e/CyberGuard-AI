import React from 'react';

export default function Header({ user, alert, onTriggerScenario }) {
  return (
    <header className="h-16 bg-[#090e1b] border-b border-slate-800/80 px-6 flex items-center justify-between z-10">
      {/* Search / Global Filter */}
      <div className="flex items-center space-x-4">
        <div className="relative w-80">
          <i className="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
          <input
            type="text"
            placeholder="Search CVEs, IOCs, Hostnames, IPs, Agents..."
            className="w-full bg-[#0d1424] border border-slate-800 rounded-xl pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
      </div>

      {/* Scenario Trigger Pills */}
      <div className="flex items-center space-x-2">
        <span className="text-[10px] text-slate-400 font-mono uppercase tracking-wider mr-1">Simulate:</span>
        <button
          onClick={() => onTriggerScenario('storm_2603')}
          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60 hover:bg-rose-900/60 transition"
        >
          <i className="fa-solid fa-bug mr-1"></i> Storm-2603
        </button>
        <button
          onClick={() => onTriggerScenario('sshole')}
          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-950/60 text-amber-300 border border-amber-800/60 hover:bg-amber-900/60 transition"
        >
          <i className="fa-solid fa-key mr-1"></i> SSHole
        </button>
        <button
          onClick={() => onTriggerScenario('has_ransomware')}
          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-red-950/60 text-red-300 border border-red-800/60 hover:bg-red-900/60 transition"
        >
          <i className="fa-solid fa-lock mr-1"></i> Ransomware
        </button>
        <button
          onClick={() => onTriggerScenario('benign')}
          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/60 transition"
        >
          <i className="fa-solid fa-circle-check mr-1"></i> Benign
        </button>
      </div>

      {/* Status Pill */}
      <div className="flex items-center space-x-3">
        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
          <span className="w-1.5 h-1.5 mr-1.5 bg-emerald-400 rounded-full animate-ping"></span>
          10 AGENTS SYNCHRONIZED
        </span>
      </div>
    </header>
  );
}

