import React from 'react';

export default function Sidebar({ currentPage, setCurrentPage, user }) {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: 'fa-shield-halved', badge: 'LIVE' },
    { id: 'agents', label: '10 AI Agents', icon: 'fa-robot', badge: '10' },
    { id: 'threats', label: 'Threat Detection', icon: 'fa-triangle-exclamation', badge: '3' },
    { id: 'network', label: 'Network Monitoring', icon: 'fa-network-wired' },
    { id: 'vulnerabilities', label: 'Vulnerability Scanner', icon: 'fa-bug' },
    { id: 'malware', label: 'Malware Analysis', icon: 'fa-biohazard' },
    { id: 'intelligence', label: 'Threat Intelligence', icon: 'fa-brain' },
    { id: 'response', label: 'Incident Response', icon: 'fa-bolt-lightning' },
    { id: 'reports', label: 'Security Reports', icon: 'fa-file-lines' },
    { id: 'audit', label: 'Audit Logs', icon: 'fa-clock-rotate-left' },
    { id: 'settings', label: 'System Settings', icon: 'fa-gear' },
  ];

  return (
    <aside className="w-64 bg-[#0a0f1d] border-r border-slate-800/80 flex flex-col justify-between select-none z-20">
      <div>
        {/* Brand Logo */}
        <div className="p-5 flex items-center space-x-3 border-b border-slate-800/60">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-blue-500/20">
            <i className="fa-solid fa-shield-cat text-xl"></i>
          </div>
          <div>
            <h1 className="text-base font-extrabold tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-blue-400">
              CYBERGUARD AI
            </h1>
            <p className="text-[10px] text-slate-400 tracking-widest uppercase font-mono">Autonomous SOC v2.0</p>
          </div>
        </div>

        {/* Nav Links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const active = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                  active
                    ? 'bg-blue-600/20 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <i className={`fa-solid ${item.icon} text-sm w-4 text-center ${active ? 'text-cyan-400' : 'text-slate-500'}`}></i>
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      active
                        ? 'bg-cyan-400/20 text-cyan-300'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* User / Session Footer */}
      <div className="p-4 border-t border-slate-800/60 bg-[#080d19]">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-xs font-bold text-cyan-400 border border-slate-700">
            {user.username.substring(0, 2).toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-semibold text-slate-200 truncate">{user.username}</div>
            <div className="text-[10px] text-emerald-400 font-mono truncate">{user.role}</div>
          </div>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
        </div>
      </div>
    </aside>
  );
}
