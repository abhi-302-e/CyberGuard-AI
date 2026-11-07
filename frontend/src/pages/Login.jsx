import React, { useState } from 'react';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('karthik.admin');
  const [password, setPassword] = useState('••••••••••••');

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin();
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#070b14] p-4 font-sans">
      <div className="soc-card p-8 rounded-3xl max-w-md w-full border border-slate-800 shadow-2xl">
        <div className="flex flex-col items-center text-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-white text-3xl shadow-lg shadow-blue-500/30 mb-3">
            <i className="fa-solid fa-shield-halved"></i>
          </div>
          <h1 className="text-xl font-black tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-indigo-400">
            CYBERGUARD AI
          </h1>
          <p className="text-xs text-slate-400 mt-1 uppercase font-mono tracking-widest">Autonomous SOC Command Gateway</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-400 font-semibold mb-1">Username / Operator Handle</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[#090e1b] border border-slate-800 rounded-xl px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-semibold mb-1">Security Token / Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#090e1b] border border-slate-800 rounded-xl px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <button
            type="submit"
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold shadow-lg shadow-blue-500/20 transition mt-2"
          >
            Authenticate & Access SOC &rarr;
          </button>
        </form>

        <div className="mt-6 pt-4 border-t border-slate-800/80 text-center text-[10px] text-slate-500 font-mono">
          Protected by Append-Only Cryptographic Audit Logging
        </div>
      </div>
    </div>
  );
}

