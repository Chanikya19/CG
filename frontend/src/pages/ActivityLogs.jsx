import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Search, 
  Filter, 
  DownloadCloud, 
  AlertCircle, 
  CheckCircle2, 
  ShieldAlert,
  Loader2,
  Printer
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { auditAPI } from '../services/api';

export default function ActivityLogs() {
  const [filterModule, setFilterModule] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState([]);
  const [exporting, setExporting] = useState(false);

  const loadLogs = async () => {
    setLoading(true);
    try {
      const data = await auditAPI.getLogs(searchQuery, filterModule, filterStatus);
      setLogs(data);
    } catch (err) {
      console.error("Failed to query audit logs from REST API.", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delayDebounce = setTimeout(() => {
      loadLogs();
    }, 400);

    return () => clearTimeout(delayDebounce);
  }, [searchQuery, filterModule, filterStatus]);

  const getStatusIcon = (status) => {
    switch (status) {
      case 'success': return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      case 'failed': return <AlertCircle className="w-4 h-4 text-amber-400" />;
      case 'blocked': return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      default: return null;
    }
  };

  const getStatusClass = (status) => {
    switch (status) {
      case 'success': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'failed': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'blocked': return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      default: return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    }
  };

  const handleExportCSV = () => {
    setExporting(true);
    try {
      const headers = ['Timestamp', 'User', 'Action', 'File Name', 'Module', 'Status', 'IP Address'];
      const rows = logs.map(l => [
        l.time,
        l.user,
        l.action,
        l.file_name,
        l.module,
        l.status,
        l.ip
      ]);

      const csvContent = "data:text/csv;charset=utf-8," 
        + [headers.join(','), ...rows.map(r => r.map(cell => `"${cell}"`).join(','))].join('\n');
      
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", `cipherguard_audit_trail_${new Date().toISOString().slice(0,10)}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      console.error(err);
    } finally {
      setExporting(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-8 animate-fadeIn printable-area">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 non-printable">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-8 h-8 text-purple-400" /> Audit Logs
          </h2>
          <p className="text-gray-400 text-sm mt-1">Granular logging parameters mapping logins, decryptions, key rotation and DLP triggers.</p>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-gray-800 text-xs font-semibold text-gray-300 transition-all"
          >
            <Printer className="w-3.5 h-3.5" /> Print Logs
          </button>
          <button 
            onClick={handleExportCSV}
            disabled={exporting || logs.length === 0}
            className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold text-white transition-all disabled:opacity-50"
          >
            <DownloadCloud className="w-3.5 h-3.5" /> Export CSV
          </button>
        </div>
      </div>

      <GlassCard className="p-4 grid grid-cols-1 md:grid-cols-4 gap-4 items-center non-printable">
        <div className="relative md:col-span-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input 
            type="text" 
            placeholder="Search by action, file name, IP..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 text-xs rounded-xl glass-input text-gray-200"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500 shrink-0" />
          <select 
            value={filterModule} 
            onChange={(e) => setFilterModule(e.target.value)}
            className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300"
          >
            <option value="ALL">All Modules</option>
            <option value="Authentication">Authentication</option>
            <option value="Cryptographic Vault">Cryptographic Vault</option>
            <option value="DLP Classifier">DLP Classifier</option>
            <option value="File Integrity">File Integrity</option>
            <option value="Delegated Sharing">Delegated Sharing</option>
            <option value="General">General</option>
          </select>
        </div>

        <div>
          <select 
            value={filterStatus} 
            onChange={(e) => setFilterStatus(e.target.value)}
            className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300"
          >
            <option value="ALL">All Statuses</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
            <option value="blocked">Blocked</option>
          </select>
        </div>
      </GlassCard>

      <GlassCard className="p-0 overflow-hidden">
        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center gap-2 text-gray-400">
            <Loader2 className="w-8 h-8 text-purple-500 animate-spin" />
            <span className="text-xs uppercase tracking-widest text-gray-500">Querying audit logs database...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 text-xs font-semibold uppercase tracking-wider bg-white/[0.01]">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">User</th>
                  <th className="p-4">Action</th>
                  <th className="p-4">File Name</th>
                  <th className="p-4">Module</th>
                  <th className="p-4">IP Address</th>
                  <th className="p-4">Event Details</th>
                  <th className="p-4 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/40">
                {logs.length > 0 ? (
                  logs.map((log) => (
                    <tr key={log.id} className="hover:bg-white/5 transition-all">
                      <td className="p-4 font-mono text-[10px] text-gray-400 whitespace-nowrap">{log.time}</td>
                      <td className="p-4 font-semibold text-white whitespace-nowrap">{log.user}</td>
                      <td className="p-4 font-mono text-[10px] text-purple-300 whitespace-nowrap">{log.action}</td>
                      <td className="p-4 text-gray-300 max-w-[120px] truncate" title={log.file_name}>{log.file_name}</td>
                      <td className="p-4 text-gray-400 font-semibold">{log.module}</td>
                      <td className="p-4 font-mono text-[10px] text-gray-500 whitespace-nowrap">{log.ip}</td>
                      <td className="p-4 leading-normal text-gray-300 min-w-[200px]">{log.details}</td>
                      <td className="p-4 text-right whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold inline-flex items-center gap-1 w-fit ${getStatusClass(log.status)}`}>
                          {getStatusIcon(log.status)}
                          <span>{log.status}</span>
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-gray-500">
                      No audit records matching parameters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
