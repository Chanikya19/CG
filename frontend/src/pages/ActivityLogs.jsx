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
  Printer,
  Calendar
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { auditAPI } from '../services/api';

export default function ActivityLogs() {
  const [filterModule, setFilterModule] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [filterUser, setFilterUser] = useState('ALL');
  const [filterAction, setFilterAction] = useState('ALL');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Pagination states
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [totalPages, setTotalPages] = useState(1);
  const [totalItems, setTotalItems] = useState(0);

  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState([]);
  const [usersList, setUsersList] = useState([]);
  const [exporting, setExporting] = useState(false);

  const currentUser = JSON.parse(sessionStorage.getItem('cipherguard_user') || localStorage.getItem('cipherguard_user') || '{}');
  const isAdmin = currentUser.role === 'admin';

  // Load user records for filter dropdown if operator is admin
  useEffect(() => {
    if (isAdmin) {
      const fetchUsers = async () => {
        try {
          const list = await auditAPI.getUsers();
          setUsersList(list || []);
        } catch (err) {
          console.error("Failed to load users list:", err);
        }
      };
      fetchUsers();
    }
  }, [isAdmin]);

  const loadLogs = async () => {
    setLoading(true);
    try {
      const data = await auditAPI.getLogs(
        searchQuery,
        filterModule,
        filterStatus,
        filterUser,
        filterAction,
        startDate,
        endDate,
        page,
        perPage
      );
      setLogs(data.logs || []);
      setTotalPages(data.pages || 1);
      setTotalItems(data.total || 0);
    } catch (err) {
      console.error("Failed to query audit logs from REST API.", err);
    } finally {
      setLoading(false);
    }
  };

  // Reset page when any filter inputs change
  useEffect(() => {
    setPage(1);
  }, [searchQuery, filterModule, filterStatus, filterUser, filterAction, startDate, endDate, perPage]);

  // Load logs on filter change or page navigation
  useEffect(() => {
    const delayDebounce = setTimeout(() => {
      loadLogs();
    }, 400);

    return () => clearTimeout(delayDebounce);
  }, [searchQuery, filterModule, filterStatus, filterUser, filterAction, startDate, endDate, page, perPage]);

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

      {/* Audit Filtering System */}
      <GlassCard className="p-5 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 items-center non-printable">
        <div className="relative col-span-1 sm:col-span-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input 
            type="text" 
            placeholder="Search by action, file name, IP..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 text-xs rounded-xl glass-input text-gray-200"
          />
        </div>

        {isAdmin && (
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-bold text-gray-500 shrink-0">User:</span>
            <select 
              value={filterUser} 
              onChange={(e) => setFilterUser(e.target.value)}
              className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300"
            >
              <option value="ALL">All Users</option>
              {usersList.map(u => (
                <option key={u.id} value={u.id}>{u.full_name}</option>
              ))}
            </select>
          </div>
        )}

        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-gray-500 shrink-0">Module:</span>
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

        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-gray-500 shrink-0">Status:</span>
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

        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-gray-500 shrink-0">Action:</span>
          <select 
            value={filterAction} 
            onChange={(e) => setFilterAction(e.target.value)}
            className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300"
          >
            <option value="ALL">All Actions</option>
            <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
            <option value="LOGIN_FAILED">LOGIN_FAILED</option>
            <option value="LOGOUT">LOGOUT</option>
            <option value="FILE_UPLOAD">FILE_UPLOAD</option>
            <option value="FILE_CLASSIFIED">FILE_CLASSIFIED</option>
            <option value="FILE_ENCRYPTED">FILE_ENCRYPTED</option>
            <option value="FILE_DECRYPTED">FILE_DECRYPTED</option>
            <option value="FILE_SHARED">FILE_SHARED</option>
            <option value="SHARE_ACCESSED">SHARE_ACCESSED</option>
            <option value="SHARE_REVOKED">SHARE_REVOKED</option>
            <option value="FILE_VERIFIED">FILE_VERIFIED</option>
            <option value="FILE_TAMPERED">FILE_TAMPERED</option>
            <option value="UNAUTHORIZED_ACCESS">UNAUTHORIZED_ACCESS</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-gray-500 shrink-0">Start:</span>
          <input 
            type="date" 
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase font-bold text-gray-500 shrink-0">End:</span>
          <input 
            type="date" 
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300"
          />
        </div>
      </GlassCard>

      <GlassCard className="p-0 overflow-hidden">
        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center gap-3 text-gray-400">
            <Loader2 className="w-10 h-10 text-purple-500 animate-spin" />
            <span className="text-xs uppercase tracking-widest font-bold text-gray-550">Querying Audit Trail Registry...</span>
          </div>
        ) : (
          <div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 text-xs font-semibold uppercase tracking-wider bg-white/[0.01]">
                    <th className="p-4">Timestamp</th>
                    <th className="p-4">User</th>
                    <th className="p-4">Action</th>
                    <th className="p-4">File ID</th>
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
                        <td className="p-4 font-mono text-[10px] text-gray-400 whitespace-nowrap">{log.file_id || 'None'}</td>
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
                      <td colSpan={9} className="p-8 text-center text-gray-500">
                        <div className="flex flex-col items-center justify-center gap-3 py-8">
                          <div className="p-3 bg-white/5 border border-gray-800 text-gray-650 rounded-full">
                            <FileText className="w-8 h-8" />
                          </div>
                          <div className="space-y-0.5 text-center">
                            <span className="block font-semibold text-gray-400">No Matching Audit Logs</span>
                            <span className="block text-[10px] text-gray-650">Modify your filtering parameters or search query to locate items.</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination UI Controls */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 px-4 py-4 border-t border-gray-800/60 bg-white/[0.005] non-printable">
              <div className="flex items-center gap-2 text-xs text-gray-400">
                <span>Show</span>
                <select 
                  value={perPage} 
                  onChange={(e) => setPerPage(Number(e.target.value))}
                  className="py-1 px-2 text-xs rounded-lg glass-input text-gray-300"
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                </select>
                <span>entries</span>
                <span className="ml-4 text-gray-500">
                  Showing {totalItems === 0 ? 0 : (page - 1) * perPage + 1} to {Math.min(page * perPage, totalItems)} of {totalItems} entries
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <button 
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1.5 rounded-lg bg-white/5 border border-gray-800 text-xs font-semibold text-gray-300 hover:bg-white/10 transition-all disabled:opacity-30 disabled:hover:bg-white/5"
                >
                  Previous
                </button>
                
                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => {
                    if (p === 1 || p === totalPages || Math.abs(p - page) <= 1) {
                      return (
                        <button 
                          key={p}
                          onClick={() => setPage(p)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${p === page ? 'bg-purple-600 text-white' : 'bg-white/5 text-gray-400 hover:bg-white/10'}`}
                        >
                          {p}
                        </button>
                      );
                    } else if (p === page - 2 || p === page + 2) {
                      return <span key={p} className="text-gray-600 px-1 text-xs">...</span>;
                    }
                    return null;
                  })}
                </div>

                <button 
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="px-3 py-1.5 rounded-lg bg-white/5 border border-gray-800 text-xs font-semibold text-gray-300 hover:bg-white/10 transition-all disabled:opacity-30 disabled:hover:bg-white/5"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
