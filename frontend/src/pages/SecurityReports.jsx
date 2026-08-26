import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  RefreshCw, 
  Download, 
  Printer, 
  ShieldAlert, 
  Clock, 
  Terminal,
  Loader2,
  FileCheck2,
  ShieldCheck
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { auditAPI } from '../services/api';
import { useToast } from '../components/ToastNotification';

export default function SecurityReports() {
  const { addToast } = useToast();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [exporting, setExporting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const currentUser = JSON.parse(sessionStorage.getItem('cipherguard_user') || localStorage.getItem('cipherguard_user') || '{}');
  const isAdmin = currentUser.role === 'admin';

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      setErrorMsg('');
      const data = await auditAPI.getSecurityAlerts(filterSeverity, filterStatus);
      setAlerts(data || []);
    } catch (err) {
      console.error(err);
      const errMsg = 'Failed to fetch security alerts. Please verify connection.';
      setErrorMsg(errMsg);
      addToast('error', errMsg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [filterSeverity, filterStatus]);

  const getSeverityBadgeColor = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-500/20 border-rose-500/30 text-rose-300 animate-pulse';
      case 'HIGH':
        return 'bg-orange-500/20 border-orange-500/30 text-orange-400';
      case 'MEDIUM':
        return 'bg-amber-500/10 border-amber-500/20 text-amber-300';
      default:
        return 'bg-white/5 border-gray-800 text-gray-400';
    }
  };

  const filteredAlerts = alerts;

  // Dynamic threat score calculation based on unresolved alerts
  const activeAlerts = alerts.filter(a => a.status === 'active');
  const criticalCount = activeAlerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = activeAlerts.filter(a => a.severity === 'HIGH').length;
  const mediumCount = activeAlerts.filter(a => a.severity === 'MEDIUM').length;
  const threatScore = Math.min(10, (criticalCount * 3.0) + (highCount * 1.5) + (mediumCount * 0.5));

  const handlePrint = () => {
    window.print();
  };

  const handleExportCSV = () => {
    setExporting(true);
    try {
      const headers = ['Alert ID', 'Type', 'Severity', 'Message', 'Timestamp', 'IP Address', 'Status'];
      const rows = filteredAlerts.map(a => [
        a.id,
        a.type,
        a.severity,
        a.message,
        a.timestamp,
        a.ip_address,
        a.status
      ]);

      const csvContent = "data:text/csv;charset=utf-8," 
        + [headers.join(','), ...rows.map(r => r.map(cell => `"${cell}"`).join(','))].join('\n');
      
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement("a");
      link.setAttribute("href", encodedUri);
      link.setAttribute("download", `cipherguard_security_alerts_${new Date().toISOString().slice(0,10)}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      console.error(err);
    } finally {
      setExporting(false);
    }
  };

  if (errorMsg) {
    return (
      <div className="h-[60vh] flex flex-col items-center justify-center gap-4 text-center">
        <div className="p-4 bg-rose-500/10 text-rose-500 border border-rose-500/25 rounded-full shadow-lg shadow-rose-500/5 animate-pulse">
          <ShieldAlert className="w-12 h-12" />
        </div>
        <h3 className="text-xl font-bold text-white">Threat Center Registry Offline</h3>
        <p className="text-xs text-gray-400 max-w-sm">Unable to establish connection to the compliance alerts database. Please check connection parameters.</p>
        <button 
          onClick={fetchAlerts}
          className="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white rounded-xl shadow-lg transition-all"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fadeIn printable-area">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 non-printable">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <AlertTriangle className="w-8 h-8 text-rose-500" /> Security Reports
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            System threat assessment, real-time alert aggregation, and compliance print exports.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handlePrint}
            className="flex items-center gap-1 px-3 py-2 bg-white/5 hover:bg-white/10 border border-gray-800 rounded-xl text-xs font-semibold text-gray-300 transition-all"
          >
            <Printer className="w-3.5 h-3.5" /> Print PDF Report
          </button>
          <button
            onClick={handleExportCSV}
            disabled={exporting || filteredAlerts.length === 0}
            className="flex items-center gap-1 px-3 py-2 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-purple-300 rounded-xl text-xs font-semibold transition-all disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" /> Export CSV
          </button>
          <button
            onClick={fetchAlerts}
            className="p-2 bg-white/5 hover:bg-white/10 border border-gray-800 rounded-xl text-gray-400 hover:text-white transition-all"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Threat Index Assessment Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <GlassCard className="md:col-span-3 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-6" glow={threatScore > 5 ? "rose" : "purple"}>
          <div className="space-y-3">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" /> Compliance Threat Index
            </h3>
            <p className="text-xs text-gray-400 max-w-lg leading-normal">
              Based on the quantity, frequency, and severity of active security alerts (tampered file alarms, auth anomalies, and decryption errors) compiled over the current session.
            </p>
            <div className="flex gap-4 text-[10px] text-gray-500 font-semibold font-mono">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span> {criticalCount} Critical</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-400"></span> {highCount} High</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400"></span> {mediumCount} Medium</span>
            </div>
          </div>

          <div className="text-center sm:border-l border-gray-800/80 sm:pl-8 py-2 w-full sm:w-auto shrink-0 flex flex-col items-center">
            <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold">Threat Score</span>
            <span className={`text-4xl font-extrabold mt-1 block ${
              threatScore >= 6 ? 'text-rose-500 font-mono' :
              threatScore >= 3.5 ? 'text-orange-400 font-mono' :
              'text-emerald-400 font-mono'
            }`}>
              {threatScore.toFixed(1)} / 10
            </span>
            <span className="text-[9px] text-gray-500 uppercase tracking-wider font-mono mt-1 font-bold">
              {threatScore >= 6 ? 'DANGER - ACTION REQ' :
               threatScore >= 3.5 ? 'ELEVATED THREAT' :
               'SECURE STATE'}
            </span>
          </div>
        </GlassCard>

        {/* Audit Status widget */}
        <GlassCard className="flex flex-col justify-center items-center text-center p-4" glow="blue">
          {threatScore > 5 ? (
            <AlertTriangle className="w-10 h-10 text-rose-500 animate-bounce mb-2" />
          ) : (
            <ShieldCheck className="w-10 h-10 text-emerald-400 mb-2" />
          )}
          <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Audit Result</span>
          <span className={`text-sm font-bold mt-1 ${threatScore > 5 ? 'text-rose-400' : 'text-emerald-400'}`}>
            {threatScore > 5 ? 'INTEGRITY AT RISK' : 'COMPLIANCE CLEAR'}
          </span>
        </GlassCard>
      </div>

      {/* Security Alerts Trail Table */}
      <GlassCard className="space-y-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 non-printable">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-rose-400" /> Dynamic Incident Alarm Log
          </h3>
          
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="py-1.5 px-3 rounded-lg bg-white/5 border border-gray-800 text-[11px] text-gray-300 font-semibold cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical only</option>
              <option value="HIGH">High only</option>
              <option value="MEDIUM">Medium only</option>
              <option value="LOW">Low only</option>
            </select>

            <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Status:</span>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="py-1.5 px-3 rounded-lg bg-white/5 border border-gray-800 text-[11px] text-gray-300 font-semibold cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="unresolved">Active / Unresolved</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center gap-3 text-gray-400">
            <Loader2 className="w-10 h-10 text-rose-500 animate-spin" />
            <span className="text-xs uppercase tracking-widest font-bold text-gray-550">Aggregating Threat Register...</span>
          </div>
        ) : filteredAlerts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 font-semibold uppercase tracking-wider">
                  <th className="pb-3">Alarm ID</th>
                  <th className="pb-3">Category Type</th>
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Diagnostic Message</th>
                  <th className="pb-3 font-mono">Timestamp</th>
                  <th className="pb-3">IP Address</th>
                  <th className="pb-3 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/40">
                {filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-white/5 transition-all">
                    <td className="py-4 font-mono text-[10px] text-purple-300">{alert.id}</td>
                    <td className="py-4 font-semibold text-white">{alert.type}</td>
                    <td className="py-4">
                      <span className={`px-2 py-0.5 rounded-full border text-[9px] font-bold ${getSeverityBadgeColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-4 text-gray-300 leading-normal max-w-xs">{alert.message}</td>
                    <td className="py-4 font-mono text-[9px] text-gray-400">
                      <div>Created: {alert.timestamp}</div>
                      {alert.resolved_at && (
                        <div className="text-emerald-400 mt-1 font-semibold">Resolved: {alert.resolved_at}</div>
                      )}
                    </td>
                    <td className="py-4 font-mono text-[10px] text-gray-500">{alert.ip_address}</td>
                    <td className="py-4 text-right flex items-center justify-end gap-2 mt-1">
                      <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                        alert.status === 'active' 
                          ? 'bg-rose-500/10 border border-rose-500/20 text-rose-400' 
                          : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                      }`}>
                        {alert.status}
                      </span>
                      {isAdmin && alert.status === 'active' && (
                        <button
                          onClick={async () => {
                            if (window.confirm(`Mark security incident #${alert.id} as resolved?`)) {
                              try {
                                await auditAPI.resolveSecurityAlert(alert.id);
                                addToast('success', `Incident #${alert.id} resolved successfully.`);
                                fetchAlerts();
                              } catch (err) {
                                addToast('error', "Failed to resolve alert: " + (err.response?.data?.error || err.message));
                              }
                            }
                          }}
                          className="px-2 py-1 bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/40 text-purple-200 rounded-lg text-[9px] font-semibold transition-all focus:ring-2 focus:ring-purple-500 outline-none"
                          aria-label={`Resolve alert ${alert.id}`}
                        >
                          Resolve
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center text-gray-500 space-y-3 flex flex-col items-center justify-center">
            <div className="p-3 bg-white/5 border border-gray-800 text-gray-650 rounded-full">
              <ShieldCheck className="w-8 h-8 text-emerald-400" />
            </div>
            <div className="space-y-0.5">
              <span className="block font-semibold text-gray-400">Zero Active Alerts</span>
              <span className="block text-[10px] text-gray-600">No security alarms or compliance violations matching criteria.</span>
            </div>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
