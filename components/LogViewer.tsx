
import React from 'react';
import { LogEntry } from '../types';

interface LogViewerProps {
  logs: LogEntry[];
}

const LogViewer: React.FC<LogViewerProps> = ({ logs }) => {
  return (
    <div className="bg-slate-950 rounded-xl border border-slate-800 flex flex-col h-full overflow-hidden shadow-2xl">
      <div className="p-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">Cryptographic Operations Log</h2>
        <span className="text-[10px] bg-blue-900/40 text-blue-400 px-2 py-0.5 rounded border border-blue-800">REALTIME</span>
      </div>
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-2">
        {logs.length === 0 && <div className="text-slate-600 italic">No operations recorded...</div>}
        {logs.slice().reverse().map((log) => (
          <div key={log.id} className="border-l-2 border-slate-800 pl-3 py-1 animate-in fade-in slide-in-from-left-2 duration-300">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-slate-500 text-[10px]">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
              <span className={`font-bold px-1.5 rounded-[2px] ${
                log.type === 'SUCCESS' ? 'text-green-400 bg-green-950/40' :
                log.type === 'ERROR' ? 'text-red-400 bg-red-950/40' :
                log.type === 'CRYPTO' ? 'text-blue-400 bg-blue-950/40' :
                'text-slate-400 bg-slate-800'
              }`}>
                {log.type}
              </span>
            </div>
            <div className="text-slate-300 leading-relaxed">{log.message}</div>
            {log.details && (
              <div className="text-slate-500 mt-1 break-all bg-slate-900/50 p-1.5 rounded border border-slate-800">
                {log.details}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default LogViewer;
