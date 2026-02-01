
import React from 'react';
import { Role } from '../types';

interface SidebarProps {
  currentTab: string;
  setTab: (tab: string) => void;
  userRole: Role;
  setUserRole: (role: Role) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ currentTab, setTab, userRole, setUserRole }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'identity', label: 'Identity & Keys', icon: '🔑' },
    { id: 'ca', label: 'CA Console', icon: '🛡️' },
    { id: 'secure-exchange', label: 'Secure Exchange', icon: '📩' },
    { id: 'logs', label: 'Security Logs', icon: '📜' },
  ];

  return (
    <div className="w-64 bg-slate-800 border-r border-slate-700 flex flex-col h-full overflow-hidden">
      <div className="p-6 border-b border-slate-700">
        <h1 className="text-xl font-bold text-blue-400 flex items-center gap-2">
          <span>🔒</span> Secure Client
        </h1>
        <p className="text-xs text-slate-400 mt-1 uppercase tracking-widest font-semibold">PKI Utility Tool</p>
      </div>

      <div className="p-4 border-b border-slate-700">
        <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block">Current Persona</label>
        <select 
          value={userRole}
          onChange={(e) => setUserRole(e.target.value as Role)}
          className="w-full bg-slate-900 border border-slate-600 rounded p-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value={Role.DOCTOR}>Dr. Alice (Doctor)</option>
          <option value={Role.PATIENT}>Mr. Bob (Patient)</option>
          <option value={Role.CA}>Root Admin (CA)</option>
        </select>
      </div>

      <nav className="flex-1 overflow-y-auto p-4 space-y-1">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setTab(item.id)}
            className={`w-full text-left px-4 py-3 rounded-lg flex items-center gap-3 transition-colors ${
              currentTab === item.id 
                ? 'bg-blue-600 text-white shadow-lg' 
                : 'text-slate-400 hover:bg-slate-700 hover:text-slate-100'
            }`}
          >
            <span className="text-lg">{item.icon}</span>
            <span className="font-medium text-sm">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="p-4 border-t border-slate-700 bg-slate-800/50">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
          <span>PKI System Active</span>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
