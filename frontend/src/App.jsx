import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import Agents from './pages/Agents';
import ThreatDetection from './pages/ThreatDetection';
import NetworkMonitoring from './pages/NetworkMonitoring';
import VulnerabilityAssessment from './pages/VulnerabilityAssessment';
import MalwareAnalysis from './pages/MalwareAnalysis';
import ThreatIntelligence from './pages/ThreatIntelligence';
import IncidentResponse from './pages/IncidentResponse';
import Reports from './pages/Reports';
import AuditLogs from './pages/AuditLogs';
import Settings from './pages/Settings';
import Login from './pages/Login';

export default function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(true);
  const [user, setUser] = useState({ username: 'karthik.admin', role: 'INCIDENT_COMMANDER' });
  const [systemAlert, setSystemAlert] = useState(null);

  const handleTriggerScenario = async (scenarioName) => {
    setSystemAlert({ type: 'info', message: `Executing scenario: ${scenarioName.toUpperCase()} across 10 agents...` });
    try {
      const res = await fetch(`/api/simulation/run?scenario=${scenarioName}`, { method: 'POST' });
      const data = await res.json();
      setSystemAlert({
        type: 'success',
        message: `Scenario ${scenarioName} completed: ${data.threat_confirmed ? 'CRITICAL THREAT CONTAINED' : 'NORMAL BASELINE RECORDED'}`
      });
    } catch (e) {
      setSystemAlert({ type: 'warning', message: `Simulation executed in standalone demo mode.` });
    }
    setTimeout(() => setSystemAlert(null), 6000);
  };

  const renderPage = () => {
    if (!isAuthenticated) return <Login onLogin={() => setIsAuthenticated(true)} />;

    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onTriggerScenario={handleTriggerScenario} onNavigate={setCurrentPage} />;
      case 'agents':
        return <Agents />;
      case 'threats':
        return <ThreatDetection />;
      case 'network':
        return <NetworkMonitoring />;
      case 'vulnerabilities':
        return <VulnerabilityAssessment />;
      case 'malware':
        return <MalwareAnalysis />;
      case 'intelligence':
        return <ThreatIntelligence />;
      case 'response':
        return <IncidentResponse />;
      case 'reports':
        return <Reports />;
      case 'audit':
        return <AuditLogs />;
      case 'settings':
        return <Settings user={user} />;
      default:
        return <Dashboard onTriggerScenario={handleTriggerScenario} onNavigate={setCurrentPage} />;
    }
  };

  return (
    <div className="flex h-screen bg-[#070b14] text-slate-100 overflow-hidden font-sans">
      <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} user={user} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header user={user} alert={systemAlert} onTriggerScenario={handleTriggerScenario} />
        <main className="flex-1 overflow-y-auto p-6 bg-gradient-to-b from-[#070b14] via-[#090f1d] to-[#0b1325]">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}

