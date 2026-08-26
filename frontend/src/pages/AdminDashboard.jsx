import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, 
  KeyRound, 
  FileLock2, 
  AlertOctagon, 
  Lock, 
  FileText,
  Clock,
  Loader2,
  Users,
  Share2,
  AlertTriangle,
  ShieldCheck,
  Terminal,
  Activity
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { auditAPI } from '../services/api';
import { useToast } from '../components/ToastNotification';

export default function AdminDashboard() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const currentUser = JSON.parse(sessionStorage.getItem('cipherguard_user') || localStorage.getItem('cipherguard_user') || '{}');

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setErrorMsg('');
      const data = await auditAPI.getAdminDashboard();
      setDashboardData(data);
    } catch (err) {
      console.error(err);
      setErrorMsg('Failed to load system-wide telemetry.');
      addToast('error', 'Failed to retrieve administrative security dashboard metrics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const stats = dashboardData?.stats || {};
  const alertStats = dashboardData?.alert_statistics || {};
  const integrityStats = dashboardData?.integrity_statistics || {};
  const encStats = dashboardData?.encryption_statistics || {};
  const dlpStats = dashboardData?.dlp_statistics || {};
  const shareStats = dashboardData?.share_statistics || {};
  const recentLogs = dashboardData?.recent_logs || [];

  if (loading) {
    return (
      <div className="h-[75vh] flex flex-col items-center justify-center gap-3 text-gray-400">
        <Loader2 className="w-10 h-10 text-purple-500 animate-spin" />
        <span className="text-xs uppercase tracking-widest font-bold font-mono">Accessing Admin Cryptographic Vault...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Admin Privilege Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <Activity className="w-8 h-8 text-purple-400" /> Admin Command Dashboard
          </h2>
          <div className="flex items-center gap-2 mt-2">
            <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              ROLE: ADMINISTRATOR
            </span>
            <span className="text-xs text-gray-500 font-mono">
              Signed in as: {currentUser.email}
            </span>
          </div>
        </div>
        <div>
          <button 
            onClick={fetchDashboardData}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-gray-800 text-xs font-semibold text-gray-300 transition-all"
          >
            <Clock className="w-4 h-4" /> Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Stats Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="blue">
          <div className="p-2.5 bg-blue-500/10 rounded-xl text-blue-400">
            <Users className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Total Users</span>
            <span className="block text-lg font-bold text-white">{stats.total_users ?? 0}</span>
          </div>
        </GlassCard>
        
        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="purple">
          <div className="p-2.5 bg-purple-500/10 rounded-xl text-purple-300">
            <FileText className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Total Files</span>
            <span className="block text-lg font-bold text-white">{stats.secured_files ?? 0}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="blue">
          <div className="p-2.5 bg-blue-500/10 rounded-xl text-blue-400">
            <Lock className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Encrypted Files</span>
            <span className="block text-lg font-bold text-white">{stats.encrypted_files ?? 0}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="purple">
          <div className="p-2.5 bg-purple-500/10 rounded-xl text-purple-400">
            <Share2 className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Active Shares</span>
            <span className="block text-lg font-bold text-white">{stats.active_shares ?? 0}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="rose">
          <div className="p-2.5 bg-rose-500/10 rounded-xl text-rose-450">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Integrity Violations</span>
            <span className="block text-lg font-bold text-rose-400">{stats.tampered_files ?? 0}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="rose">
          <div className="p-2.5 bg-rose-500/10 rounded-xl text-rose-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Security Alerts</span>
            <span className="block text-lg font-bold text-rose-400">{stats.security_alerts ?? 0}</span>
          </div>
        </GlassCard>
      </div>

      {/* Security Threat Score / Info Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <GlassCard className="lg:col-span-2 flex flex-col justify-between" glow="purple">
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-purple-400" /> Administrative Threat Score Assessment
            </h3>
            <p className="text-xs text-gray-400 leading-normal">
              Determined by active system alarms, data breaches, and key rotation schedules. A lower score signifies a hardened environment.
            </p>
          </div>
          <div className="mt-6 flex items-end justify-between">
            <div>
              <span className="block text-[10px] text-gray-500 uppercase tracking-wider font-bold">Threat Index Score</span>
              <span className="text-3xl font-extrabold text-white mt-1 block font-mono">
                {(dashboardData?.threat_score ?? 0.0).toFixed(1)} / 100
              </span>
            </div>
            <div className="text-right">
              <span className="block text-[10px] text-gray-500 uppercase tracking-wider font-bold">System Status</span>
              <span className={`text-xs font-bold font-mono mt-1 block ${
                (dashboardData?.threat_score ?? 0) > 40 ? 'text-rose-400 animate-pulse' : 'text-emerald-400'
              }`}>
                {(dashboardData?.threat_score ?? 0) > 40 ? 'CRITICAL - ATTENTION REQ' : 'SECURE & OPERATIONAL'}
              </span>
            </div>
          </div>
        </GlassCard>

        <GlassCard className="flex flex-col justify-center items-center text-center py-6 px-4" glow="blue">
          <Terminal className="w-10 h-10 text-purple-400 mb-3" />
          <h4 className="text-xs font-bold text-white uppercase tracking-wider">Failed Logins (System)</h4>
          <span className="text-2xl font-extrabold text-white mt-1 block font-mono">
            {stats.failed_login_attempts ?? 0}
          </span>
          <p className="text-[10px] text-gray-500 mt-1 max-w-[200px]">
            Cumulative authentication failures logged across all accounts.
          </p>
        </GlassCard>
      </div>

      {/* Admin Monitoring Grid - Section Vault */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Encryption Audit Panel */}
        <GlassCard className="space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-gray-800 pb-2">
            <KeyRound className="w-4 h-4 text-blue-400" /> Encryption & Ciphers Audit
          </h4>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">AES-256-GCM Keys</span>
              <span className="text-base font-extrabold text-white mt-1 block">{encStats.aes256_keys ?? 0}</span>
            </div>
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">AES-128-GCM Keys</span>
              <span className="text-base font-extrabold text-white mt-1 block">{encStats.aes128_keys ?? 0}</span>
            </div>
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">Encryption Operations</span>
              <span className="text-base font-extrabold text-white mt-1 block">{encStats.successful_encryptions ?? 0}</span>
            </div>
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">Decryption Faults</span>
              <span className="text-base font-extrabold text-rose-455 mt-1 block">{encStats.decryption_failures ?? 0}</span>
            </div>
          </div>
        </GlassCard>

        {/* DLP & Classification Audit Panel */}
        <GlassCard className="space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5 border-b border-gray-800 pb-2">
            <FileLock2 className="w-4 h-4 text-purple-400" /> AI & DLP Classifier Audit
          </h4>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">Secret Classified</span>
              <span className="text-base font-extrabold text-white mt-1 block">{dlpStats.secret_count ?? 0}</span>
            </div>
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">Confidential Classified</span>
              <span className="text-base font-extrabold text-white mt-1 block">{dlpStats.confidential_count ?? 0}</span>
            </div>
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">PII Identifiers</span>
              <span className="text-base font-extrabold text-amber-400 mt-1 block">{dlpStats.pii_flagged ?? 0}</span>
            </div>
            <div className="p-3 bg-white/5 rounded-lg border border-gray-800">
              <span className="block text-[9px] text-gray-500 uppercase font-bold">Credentials Flagged</span>
              <span className="text-base font-extrabold text-rose-455 mt-1 block">{dlpStats.credentials_flagged ?? 0}</span>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Recent System Activity Log */}
      <GlassCard className="space-y-4">
        <h3 className="text-sm font-bold text-white border-b border-gray-800 pb-2">
          Recent Security Audit Log
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 font-semibold uppercase tracking-wider">
                <th className="pb-2">Timestamp</th>
                <th className="pb-2">Action</th>
                <th className="pb-2">User</th>
                <th className="pb-2">IP Address</th>
                <th className="pb-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {recentLogs.map((log, idx) => (
                <tr key={idx} className="hover:bg-white/5 transition-all text-gray-300">
                  <td className="py-2.5 font-mono text-[9px] text-gray-400">{log.time}</td>
                  <td className="py-2.5 font-semibold text-white">{log.action}</td>
                  <td className="py-2.5">{log.user || 'System'}</td>
                  <td className="py-2.5 font-mono text-[10px] text-gray-500">{log.ip}</td>
                  <td className="py-2.5">
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                      log.status === 'success' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                    }`}>
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))}
              {recentLogs.length === 0 && (
                <tr>
                  <td colSpan="5" className="py-6 text-center text-gray-550 font-medium">
                    No recent security events registered.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
}
