import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldCheck, 
  KeyRound, 
  FileLock2, 
  AlertOctagon, 
  ArrowUpRight, 
  Lock, 
  FileText,
  Clock,
  ExternalLink,
  Loader2,
  UploadCloud,
  DownloadCloud,
  Unlock,
  Users,
  Share2,
  AlertTriangle,
  QrCode,
  Copy,
  ShieldAlert
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import GlassCard from '../components/GlassCard';
import { auditAPI, dlpAPI } from '../services/api';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-2xl text-center text-xs text-rose-400">
          <p className="font-semibold">Failed to render visual analytics.</p>
          <button 
            onClick={() => this.setState({ hasError: false })}
            className="mt-2 px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 rounded-xl text-white transition-all text-[10px] font-bold"
          >
            Reset
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);
  const [dashboardError, setDashboardError] = useState('');

  // Module 2 state variables
  const [classifying, setClassifying] = useState(false);
  const [classificationResult, setClassificationResult] = useState(null);
  const [classificationHistory, setClassificationHistory] = useState([]);
  const [classificationError, setClassificationError] = useState('');
  const [classifyDragActive, setClassifyDragActive] = useState(false);

  // Module 3 state variables
  const [showDecryptModal, setShowDecryptModal] = useState(false);
  const [decryptFileId, setDecryptFileId] = useState(null);
  const [decryptFilename, setDecryptFilename] = useState('');
  const [decryptPrivateKey, setDecryptPrivateKey] = useState('');
  const [decryptingFile, setDecryptingFile] = useState(false);
  const [decryptError, setDecryptError] = useState('');

  // Module 5 state variables
  const [alerts, setAlerts] = useState([]);
  const [statsData, setStatsData] = useState(null);

  const fetchHistory = async () => {
    try {
      const history = await dlpAPI.getClassificationHistory();
      setClassificationHistory(Array.isArray(history) ? history : []);
    } catch (err) {
      console.error("Failed to fetch classification history", err);
    }
  };

  useEffect(() => {
    async function loadSummary() {
      try {
        const data = await auditAPI.getDashboard();
        setDashboardData(data);
      } catch (err) {
        console.error("Failed to load dashboard metrics", err);
        setDashboardError("Unable to load dashboard data. Please try again.");
      }
    }
    async function loadStats() {
      try {
        const data = await auditAPI.getStatistics();
        setStatsData(data);
      } catch (err) {
        console.error("Failed to load statistics metrics", err);
      }
    }
    async function loadAlerts() {
      try {
        const data = await auditAPI.getSecurityAlerts();
        setAlerts(Array.isArray(data) ? data.slice(0, 5) : []);
      } catch (err) {
        console.error("Failed to load alerts", err);
      }
    }
    async function init() {
      await Promise.all([loadSummary(), loadStats(), fetchHistory(), loadAlerts()]);
      setLoading(false);
    }
    init();
  }, []);

  const handleClassifyUpload = async (file) => {
    setClassifying(true);
    setClassificationError('');
    setClassificationResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const result = await dlpAPI.classify(formData);
      setClassificationResult(result);
      await fetchHistory();
      // Reload stats to reflect new classification counts
      const [data, stats] = await Promise.all([auditAPI.getDashboard(), auditAPI.getStatistics()]);
      setDashboardData(data);
      setStatsData(stats);
    } catch (err) {
      console.error("Classification failed", err);
      setClassificationError(err.response?.data?.error || "Failed to classify document. Please check file format.");
    } finally {
      setClassifying(false);
    }
  };

  const handleClassifyDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setClassifyDragActive(true);
    } else if (e.type === "dragleave") {
      setClassifyDragActive(false);
    }
  };

  const handleClassifyDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setClassifyDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleClassifyUpload(e.dataTransfer.files[0]);
    }
  };

  const handleClassifyChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleClassifyUpload(e.target.files[0]);
    }
  };

  const handleDownloadEncrypted = async (fileId, filename) => {
    try {
      const token = localStorage.getItem('cipherguard_token') || sessionStorage.getItem('cipherguard_token');
      const response = await fetch(`/api/files/${fileId}/download/encrypted`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!response.ok) throw new Error("Failed to download encrypted file");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.enc`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert("Error downloading encrypted file");
    }
  };

  const handleDownloadDecrypted = async (fileId, filename, classification) => {
    if (classification === 'Secret') {
      setDecryptFileId(fileId);
      setDecryptFilename(filename);
      setDecryptPrivateKey('');
      setDecryptError('');
      setShowDecryptModal(true);
    } else {
      await performDecryptedDownload(fileId, filename, null);
    }
  };

  const performDecryptedDownload = async (fileId, filename, privateKey) => {
    setDecryptingFile(true);
    setDecryptError('');
    try {
      const blob = await cryptoAPI.downloadDecrypted(fileId, privateKey);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setShowDecryptModal(false);
    } catch (err) {
      console.error(err);
      setDecryptError("Decryption failed. Please verify your private KEK signature.");
    } finally {
      setDecryptingFile(false);
    }
  };

  const userString = localStorage.getItem('cipherguard_user') || sessionStorage.getItem('cipherguard_user');
  const user = userString ? JSON.parse(userString) : null;
  const isAdmin = user?.role === 'admin';

  // Shared generic chart options for styling
  const baseChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#9ca3af', boxWidth: 10, font: { family: 'Outfit', size: 10 } }
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleFont: { size: 10, family: 'Outfit' },
        bodyFont: { size: 11, family: 'Outfit' },
        borderColor: '#334155',
        borderWidth: 1
      }
    },
    scales: {
      x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 9 } } },
      y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 9 }, stepSize: 1 } }
    }
  };

  const lineChartOptions = {
    ...baseChartOptions,
    plugins: {
      ...baseChartOptions.plugins,
      legend: {
        position: 'top',
        labels: { color: '#9ca3af', font: { family: 'Outfit', size: 10 } }
      }
    }
  };

  const doughnutChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: { color: '#9ca3af', font: { family: 'Outfit', size: 10 }, boxWidth: 12 }
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleFont: { size: 10, family: 'Outfit' },
        bodyFont: { size: 11, family: 'Outfit' },
        borderColor: '#334155',
        borderWidth: 1
      }
    }
  };

  // DLP Violations Trend Chart
  const lineChartData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [
      {
        fill: true,
        label: 'Risk Scans Run',
        data: [15, 22, 18, 25, 30, 14, 19],
        borderColor: '#a855f7',
        backgroundColor: 'rgba(168, 85, 247, 0.1)',
        tension: 0.35,
      },
      {
        fill: true,
        label: 'DLP Blocks',
        data: [0, 0, 1, 0, 0, 0, 0],
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        tension: 0.35,
      }
    ],
  };

  // 1. File classification: Public / Confidential / Secret
  const distribution = dashboardData?.classification_distribution || { Public: 0, Confidential: 0, Secret: 0 };
  const classificationChartData = {
    labels: ['Public', 'Confidential', 'Secret'],
    datasets: [
      {
        data: [distribution.Public, distribution.Confidential, distribution.Secret],
        backgroundColor: [
          'rgba(59, 130, 246, 0.65)',  // Blue
          'rgba(245, 158, 11, 0.65)',  // Amber
          'rgba(168, 85, 247, 0.65)'   // Purple
        ],
        borderColor: 'rgba(255,255,255,0.05)',
        borderWidth: 1,
      },
    ],
  };

  // 2. Encryption usage: AES-128, AES-256, Hybrid AES + RSA
  const encryptionChartData = {
    labels: statsData?.algorithms_bar?.labels || ['AES-128-GCM', 'AES-256-GCM', 'Hybrid (AES+RSA)'],
    datasets: [
      {
        data: statsData?.algorithms_bar?.data || [0, 0, 0],
        backgroundColor: [
          'rgba(59, 130, 246, 0.65)',
          'rgba(99, 102, 241, 0.65)',
          'rgba(168, 85, 247, 0.65)'
        ],
        borderColor: 'rgba(255,255,255,0.05)',
        borderWidth: 1,
      }
    ]
  };

  // 3. Integrity: Verified / Tampered
  const integrityChartData = {
    labels: statsData?.integrity_doughnut?.labels || ['Verified Intact', 'Tampered/Missing'],
    datasets: [
      {
        data: statsData?.integrity_doughnut?.data || [0, 0],
        backgroundColor: [
          'rgba(16, 185, 129, 0.65)', // Emerald
          'rgba(239, 68, 68, 0.65)'   // Rose
        ],
        borderColor: 'rgba(255,255,255,0.05)',
        borderWidth: 1,
      }
    ]
  };

  // 4. File activity over time
  const fileActivityChartData = {
    labels: statsData?.uploads_line?.labels || [],
    datasets: [
      {
        fill: true,
        label: 'File Uploads',
        data: statsData?.uploads_line?.data || [],
        borderColor: '#a855f7',
        backgroundColor: 'rgba(168, 85, 247, 0.1)',
        tension: 0.35,
      }
    ]
  };

  // 5. Sharing activity over time
  const sharingActivityChartData = {
    labels: statsData?.sharing_line?.labels || [],
    datasets: [
      {
        fill: true,
        label: 'Shares & Accesses',
        data: statsData?.sharing_line?.data || [],
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.1)',
        tension: 0.35,
      }
    ]
  };

  // 6. Failed login attempts
  const failedLoginsChartData = {
    labels: statsData?.failed_logins_line?.labels || [],
    datasets: [
      {
        label: 'Failed Logins',
        data: statsData?.failed_logins_line?.data || [],
        backgroundColor: 'rgba(244, 63, 94, 0.65)',
        borderColor: 'rgba(255,255,255,0.05)',
        borderWidth: 1,
        borderRadius: 6
      }
    ]
  };

  const getLabelColor = (label) => {
    const norm = label?.toLowerCase() || '';
    if (norm === 'secret') return 'bg-purple-500/10 text-purple-400 border-purple-500/25';
    if (norm === 'confidential') return 'bg-amber-500/10 text-amber-400 border-amber-500/25';
    return 'bg-blue-500/10 text-blue-400 border-blue-500/25';
  };

  if (loading) {
    return (
      <div className="h-[60vh] flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-10 h-10 text-purple-500 animate-spin" />
        <span className="text-sm text-gray-400 font-semibold uppercase tracking-wider">Syncing Security Matrix...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fadeIn">
      {dashboardError && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-2xl text-xs text-rose-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{dashboardError}</span>
          </div>
          <button 
            onClick={() => window.location.reload()} 
            className="px-3 py-1 bg-rose-500/20 hover:bg-rose-500/30 rounded-xl text-white font-medium transition-all"
          >
            Retry
          </button>
        </div>
      )}

      {/* Top Banner / Welcome */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white">Security Command Vault</h2>
          <p className="text-gray-400 text-sm mt-1">Real-time status overview, data leakage monitoring, and hybrid cryptosystem status.</p>
        </div>
        <button 
          onClick={() => navigate('/upload')}
          className="flex items-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-sm font-semibold tracking-wide text-white transition-all shadow-lg shadow-purple-500/10 active:scale-95"
        >
          <Lock className="w-4 h-4" /> Secure New File
        </button>
      </div>

      {/* Stats Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="blue">
          <div className="p-2.5 bg-blue-500/10 rounded-xl text-blue-400">
            <Users className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Total Users</span>
            <span className="block text-lg font-bold text-white">{dashboardData?.stats?.total_users ?? '0'}</span>
          </div>
        </GlassCard>
        
        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="purple">
          <div className="p-2.5 bg-purple-500/10 rounded-xl text-purple-300">
            <FileText className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Total Files</span>
            <span className="block text-lg font-bold text-white">{dashboardData?.stats?.secured_files ?? '0'}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="blue">
          <div className="p-2.5 bg-blue-500/10 rounded-xl text-blue-400">
            <Lock className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Encrypted Files</span>
            <span className="block text-lg font-bold text-white">{dashboardData?.stats?.encrypted_files ?? '0'}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="purple">
          <div className="p-2.5 bg-purple-500/10 rounded-xl text-purple-400">
            <Share2 className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Shared Files</span>
            <span className="block text-lg font-bold text-white">{dashboardData?.stats?.shared_files ?? '0'}</span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-start gap-3 py-3 px-4" glow="emerald">
          <div className="p-2.5 bg-emerald-500/10 rounded-xl text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Verified Files</span>
            <span className="block text-lg font-bold text-white">{dashboardData?.stats?.verified_files ?? '0'}</span>
          </div>
        </GlassCard>

        <GlassCard className={`flex items-start gap-3 py-3 px-4 ${dashboardData?.stats?.tampered_files > 0 ? 'border border-rose-500/30' : ''}`} glow={dashboardData?.stats?.tampered_files > 0 ? "rose" : "purple"}>
          <div className={`p-2.5 rounded-xl ${dashboardData?.stats?.tampered_files > 0 ? 'bg-rose-500/15 text-rose-400' : 'bg-white/5 text-gray-400'}`}>
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Tampered Files</span>
            <span className={`block text-lg font-bold ${dashboardData?.stats?.tampered_files > 0 ? 'text-rose-400 font-extrabold animate-pulse' : 'text-white'}`}>
              {dashboardData?.stats?.tampered_files ?? '0'}
            </span>
          </div>
        </GlassCard>

        <GlassCard className={`flex items-start gap-3 py-3 px-4 ${dashboardData?.stats?.security_alerts > 0 ? 'border border-rose-500/30' : ''}`} glow={dashboardData?.stats?.security_alerts > 0 ? "rose" : "purple"}>
          <div className={`p-2.5 rounded-xl ${dashboardData?.stats?.security_alerts > 0 ? 'bg-rose-500/15 text-rose-400' : 'bg-white/5 text-gray-400'}`}>
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div className="space-y-0.5">
            <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Security Alerts</span>
            <span className={`block text-lg font-bold ${dashboardData?.stats?.security_alerts > 0 ? 'text-rose-400' : 'text-white'}`}>
              {dashboardData?.stats?.security_alerts ?? '0'}
            </span>
          </div>
        </GlassCard>
      </div>

      {/* Security Score Panel */}
      <GlassCard className="p-6 space-y-6" glow={dashboardData?.stats?.security_score >= 90 ? "emerald" : dashboardData?.stats?.security_score >= 70 ? "amber" : "rose"}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className={`w-20 h-20 rounded-full border-4 flex flex-col items-center justify-center font-extrabold ${
              dashboardData?.stats?.security_score >= 90 ? 'border-emerald-500 text-emerald-400' :
              dashboardData?.stats?.security_score >= 70 ? 'border-amber-500 text-amber-400' :
              'border-rose-500 text-rose-400'
            }`}>
              <span className="text-2xl">{dashboardData?.stats?.security_score ?? 100}</span>
              <span className="text-[9px] uppercase text-gray-500 tracking-wider">Score</span>
            </div>
            <div>
              <h3 className="text-lg font-extrabold text-white flex items-center gap-2">
                CipherGuard Security Score
              </h3>
              <p className="text-xs text-gray-400 max-w-xl">
                Calculated dynamically based on active unresolved threats, file tampering alerts, encryption coverage, and integrity verification status.
              </p>
            </div>
          </div>
          <div className={`px-4 py-2 rounded-xl border text-xs font-bold tracking-widest ${
            dashboardData?.stats?.security_score >= 90 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
            dashboardData?.stats?.security_score >= 70 ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
            'bg-rose-500/10 text-rose-400 border-rose-500/20'
          }`}>
            SYSTEM RATING: {
              dashboardData?.stats?.security_score >= 90 ? 'OPTIMAL' :
              dashboardData?.stats?.security_score >= 70 ? 'WARNING' :
              'CRITICAL'
            }
          </div>
        </div>

        {/* Contributing Factors */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          {(dashboardData?.stats?.security_factors || []).map((factor, idx) => (
            <div key={idx} className="p-4 bg-white/5 border border-gray-800 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-gray-300">{factor.name}</span>
                <span className={`px-2 py-0.5 rounded-lg text-[9px] font-extrabold tracking-wider ${
                  factor.status === 'Good' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                  factor.status === 'Danger' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' :
                  'bg-amber-500/10 text-amber-400 border-amber-500/20'
                }`}>
                  {factor.status}
                </span>
              </div>
              <p className="text-[10px] text-gray-400 leading-relaxed min-h-[30px]">{factor.description}</p>
              <div className="flex items-center justify-between border-t border-gray-800/50 pt-2 text-[10px]">
                <span className="text-gray-500">Deduction</span>
                <span className={`font-bold ${factor.deduction > 0 ? 'text-rose-400' : 'text-gray-400'}`}>
                  {factor.deduction > 0 ? `-${factor.deduction} pts` : 'None'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </GlassCard>

      {/* Visual Analytics Grid */}
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block animate-pulse"></span> Telemetry & Cryptographic Analytics
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">Real-time charts monitoring document sensitivity distribution, ciphers usage, and platform audit activity.</p>
        </div>

        {/* First Row: Distribution & Categorization Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <ErrorBoundary>
            <GlassCard className="space-y-4" glow="blue">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  File Classification
                </h4>
                <p className="text-[10px] text-gray-400">Distribution of secured vault documents by sensitivity label.</p>
              </div>
              <div className="h-56 flex items-center justify-center">
                <Doughnut data={classificationChartData} options={doughnutChartOptions} />
              </div>
            </GlassCard>
          </ErrorBoundary>

          <ErrorBoundary>
            <GlassCard className="space-y-4" glow="purple">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  Encryption Algorithms
                </h4>
                <p className="text-[10px] text-gray-400">Usage distribution of symmetrical ciphers and RSA key wraps.</p>
              </div>
              <div className="h-56 flex items-center justify-center">
                <Doughnut data={encryptionChartData} options={doughnutChartOptions} />
              </div>
            </GlassCard>
          </ErrorBoundary>

          <ErrorBoundary>
            <GlassCard className="space-y-4" glow="emerald">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  Integrity Verification
                </h4>
                <p className="text-[10px] text-gray-400">Status ratio of verified intact documents vs tampered alerts.</p>
              </div>
              <div className="h-56 flex items-center justify-center">
                <Doughnut data={integrityChartData} options={doughnutChartOptions} />
              </div>
            </GlassCard>
          </ErrorBoundary>
        </div>

        {/* Second Row: Activity Trends over time */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <ErrorBoundary>
            <GlassCard className="space-y-4" glow="purple">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  File Activity over Time
                </h4>
                <p className="text-[10px] text-gray-400">Timeline of document uploads over the past 7 days.</p>
              </div>
              <div className="h-56 flex items-center justify-center">
                <Line data={fileActivityChartData} options={lineChartOptions} />
              </div>
            </GlassCard>
          </ErrorBoundary>

          <ErrorBoundary>
            <GlassCard className="space-y-4" glow="blue">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  Sharing Activity
                </h4>
                <p className="text-[10px] text-gray-400">Daily timeline of sharing links generated and accessed.</p>
              </div>
              <div className="h-56 flex items-center justify-center">
                <Line data={sharingActivityChartData} options={lineChartOptions} />
              </div>
            </GlassCard>
          </ErrorBoundary>

          <ErrorBoundary>
            <GlassCard className="space-y-4" glow="rose">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  Failed Login Attempts
                </h4>
                <p className="text-[10px] text-gray-400">Security event monitoring of failed authentication attempts.</p>
              </div>
              <div className="h-56 flex items-center justify-center">
                <Bar data={failedLoginsChartData} options={lineChartOptions} />
              </div>
            </GlassCard>
          </ErrorBoundary>
        </div>

        {/* Preservation of original DLP trend chart */}
        <ErrorBoundary>
          <GlassCard className="space-y-4">
            <div>
              <h4 className="text-sm font-bold text-white flex items-center gap-2">
                DLP Protection Trend
              </h4>
              <p className="text-[10px] text-gray-400">Scans executed and potential leak intercepts blocked daily.</p>
            </div>
            <div className="h-64 flex items-center justify-center">
              <Line data={lineChartData} options={lineChartOptions} />
            </div>
          </GlassCard>
        </ErrorBoundary>
      </div>

      {/* AI Classifier & DLP Audit Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: AI Sensitivity Classifier Widget */}
        <GlassCard className="space-y-6">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block animate-pulse"></span> AI Sensitivity Classifier
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">Upload a document (PDF, DOCX, or TXT) to predict its classification label using our Naive Bayes ML model.</p>
          </div>

          {classificationError && (
            <div className="p-3.5 bg-rose-500/5 border border-rose-500/10 rounded-xl text-xs text-rose-400 flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 shrink-0" />
              <span>{classificationError}</span>
            </div>
          )}

          {/* Uploader Dropzone */}
          {!classifying && !classificationResult && (
            <div
              className={`border-2 border-dashed rounded-2xl p-6 transition-all text-center flex flex-col items-center justify-center min-h-[160px] ${
                classifyDragActive ? 'border-purple-500 bg-purple-500/5' : 'border-gray-800 hover:border-gray-700'
              }`}
              onDragEnter={handleClassifyDrag}
              onDragOver={handleClassifyDrag}
              onDragLeave={handleClassifyDrag}
              onDrop={handleClassifyDrop}
            >
              <div className="p-3 bg-purple-500/10 text-purple-400 rounded-full mb-3 transition-transform">
                <UploadCloud className="w-6 h-6" />
              </div>
              <p className="text-xs text-gray-300 font-medium">Drag & drop document or <label className="text-purple-400 hover:text-purple-300 cursor-pointer underline">choose file<input type="file" className="hidden" accept=".txt,.pdf,.docx" onChange={handleClassifyChange} /></label></p>
              <p className="text-[10px] text-gray-500 mt-1.5">Supports PDF, DOCX, and TXT (Max 10MB)</p>
            </div>
          )}

          {/* Loader State */}
          {classifying && (
            <div className="flex flex-col items-center justify-center py-8 min-h-[160px] gap-3">
              <Loader2 className="w-8 h-8 text-purple-500 animate-spin" />
              <span className="text-xs text-gray-400 font-semibold uppercase tracking-wider">Extracting content & running NLP predictions...</span>
            </div>
          )}

          {/* Result View */}
          {classificationResult && (
            <div className="p-5 rounded-2xl border border-gray-800 bg-white/5 space-y-4">
              <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                <div className="space-y-0.5">
                  <span className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Scanned Document</span>
                  <span className="block text-xs font-semibold text-white truncate max-w-[220px]" title={classificationResult.filename}>{classificationResult.filename}</span>
                </div>
                <button
                  onClick={() => setClassificationResult(null)}
                  className="text-xs text-gray-400 hover:text-white px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 transition-all"
                >
                  Scan Another
                </button>
              </div>

              <div className="flex items-start gap-4">
                <div className="space-y-1 flex-1">
                  <span className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Classification Outcome</span>
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-bold border uppercase tracking-wider ${getLabelColor(classificationResult.category)}`}>
                      {classificationResult.category}
                    </span>
                    <span className="text-xs text-gray-400 font-medium">
                      Confidence: <span className="text-white font-semibold">
                        {((classificationResult.confidence > 1.0 ? classificationResult.confidence : classificationResult.confidence * 100)).toFixed(1)}%
                      </span>
                    </span>
                  </div>
                  
                  {/* Confidence bar */}
                  <div className="w-full bg-gray-950 rounded-full h-1.5 border border-gray-800 mt-3 overflow-hidden">
                    <div 
                      className={`h-full rounded-full transition-all duration-700 ${
                        classificationResult.category?.toUpperCase() === 'SECRET' ? 'bg-purple-500' :
                        classificationResult.category?.toUpperCase() === 'CONFIDENTIAL' ? 'bg-amber-500' : 'bg-blue-500'
                      }`}
                      style={{ width: `${classificationResult.confidence > 1.0 ? classificationResult.confidence : classificationResult.confidence * 100}%` }}
                    ></div>
                  </div>

                  {/* Detected rule-based indicators */}
                  {classificationResult.detected_indicators && classificationResult.detected_indicators.length > 0 && (
                    <div className="mt-3.5 space-y-1.5 border-t border-gray-800/40 pt-3">
                      <span className="block text-[9px] font-bold text-gray-500 uppercase tracking-wider">Detected Security Indicators</span>
                      <div className="flex flex-wrap gap-1.5">
                        {classificationResult.detected_indicators.map((indicator, index) => (
                          <span key={index} className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[9px] font-semibold uppercase tracking-wider">
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className={`p-3 rounded-xl border text-[11px] leading-relaxed ${
                classificationResult.category?.toUpperCase() === 'SECRET' ? 'bg-purple-500/5 text-purple-300 border-purple-500/10' :
                classificationResult.category?.toUpperCase() === 'CONFIDENTIAL' ? 'bg-amber-500/5 text-amber-300 border-amber-500/10' :
                'bg-blue-500/5 text-blue-300 border-blue-500/10'
              }`}>
                {classificationResult.category?.toUpperCase() === 'SECRET' && (
                  <span><strong>COMPLIANCE ALERT:</strong> Secret credentials, server environment variables, or private key sequences detected. Encrypt file immediately before vault sharing.</span>
                )}
                {classificationResult.category?.toUpperCase() === 'CONFIDENTIAL' && (
                  <span><strong>SECURE NOTE:</strong> RESTRICTED internal department details. Access control and symmetric hybrid encryption recommended.</span>
                )}
                {classificationResult.category?.toUpperCase() === 'PUBLIC' && (
                  <span><strong>AUDIT COMPLIANT:</strong> General public brochure or metadata schema detected. Safe for open distribution.</span>
                )}
              </div>
            </div>
          )}
        </GlassCard>

        {/* Right Column: Classification Prediction History */}
        <GlassCard className="space-y-6 flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-purple-400" /> DLP Classifier Audit Trail
            </h3>
            <p className="text-xs text-gray-400 mt-0.5">Historical records of automated sensitive data classification scans.</p>
          </div>

          <div className="flex-1 overflow-y-auto max-h-[220px] custom-scrollbar border border-gray-850 rounded-xl bg-gray-950/20">
            {classificationHistory && classificationHistory.length > 0 ? (
              <table className="w-full text-left text-xs text-gray-300">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 font-semibold uppercase tracking-wider">
                    <th className="p-3">File Asset</th>
                    <th className="p-3">Category</th>
                    <th className="p-3">Confidence</th>
                    <th className="p-3">Scanned</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/40">
                  {classificationHistory.map((item) => (
                    <tr key={item.id} className="hover:bg-white/5 transition-all">
                      <td className="p-3 font-medium text-white max-w-[150px] truncate" title={item.filename}>{item.filename}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 text-[9px] rounded-full border font-bold uppercase ${getLabelColor(item.category)}`}>
                          {item.category}
                        </span>
                      </td>
                      <td className="p-3 font-mono">{((item.confidence > 1.0 ? item.confidence : item.confidence * 100)).toFixed(1)}%</td>
                      <td className="p-3 text-[10px] text-gray-500 font-mono">{item.date ? (item.date.split(' ')[1] || item.date) : 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="h-full flex items-center justify-center py-10 text-gray-500 text-xs">
                No classification scans recorded yet.
              </div>
            )}
          </div>
        </GlassCard>
      </div>

      {/* Recent Active Share Tracker Widget */}
      {dashboardData?.recent_share && (
        <GlassCard className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 border border-gray-800" glow="purple">
          <div className="md:col-span-2 space-y-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <QrCode className="w-5 h-5 text-purple-400" /> Recent Active Share Link
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">Details of the most recent active sharing policy generated.</p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1 bg-white/5 border border-gray-800 p-3 rounded-2xl">
                <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">File Asset</span>
                <span className="block text-xs font-semibold text-white truncate" title={dashboardData.recent_share.filename}>
                  {dashboardData.recent_share.filename}
                </span>
              </div>

              <div className="space-y-1 bg-white/5 border border-gray-800 p-3 rounded-2xl">
                <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Integrity Status</span>
                {dashboardData.recent_share.integrity_status?.toUpperCase() === 'VERIFIED' || dashboardData.recent_share.integrity_status?.toUpperCase() === 'VERIFIED INTACT' ? (
                  <span className="px-2 py-0.5 rounded-lg text-[9px] font-bold inline-flex items-center gap-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    ✓ Integrity Verified
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-lg text-[9px] font-bold inline-flex items-center gap-1 bg-rose-500/10 text-rose-400 border border-rose-500/20 animate-pulse">
                    ⚠ File Tampered
                  </span>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-wider">
                File SHA-256 Signature
              </label>
              <div className="bg-black/40 border border-gray-800 p-2.5 rounded-xl text-[9px] font-mono text-purple-300 break-all select-all">
                {dashboardData.recent_share.sha256_hash}
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
              <div className="space-y-1">
                <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Secure Sharing Link</span>
                <div className="flex items-center gap-1.5 font-mono text-[9px] text-gray-400 truncate max-w-[280px]">
                  <span>{dashboardData.recent_share.share_link ? `${dashboardData.recent_share.share_link.substring(0, 32)}...` : 'N/A'}</span>
                  {dashboardData.recent_share.share_link && (
                    <button 
                      onClick={() => {
                        navigator.clipboard.writeText(dashboardData.recent_share.share_link);
                        alert("Link copied!");
                      }}
                      className="p-1 hover:bg-white/10 rounded text-gray-500 hover:text-white"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-1 bg-white/5 border border-gray-800 py-2 px-3 rounded-xl text-[10px] text-right">
                <span className="block text-[9px] text-gray-500 uppercase font-bold tracking-wider">Expiry Deadline</span>
                <span className="text-purple-300 font-bold font-mono">{dashboardData.recent_share.expiry_time}</span>
              </div>
            </div>
          </div>

          <div className="md:col-span-1 flex flex-col justify-center items-center gap-3 border-l border-gray-800/80 pl-6">
            <span className="block text-[10px] text-gray-500 font-bold uppercase tracking-wider text-center">QR Code Link Preview</span>
            <div className="bg-white p-3 rounded-2xl w-36 h-36 border border-gray-800 flex items-center justify-center">
              <img src={dashboardData.recent_share.qr_code} alt="Share QR Code" className="w-full h-full" />
            </div>
            <button 
              onClick={() => navigate('/share')}
              className="text-[10px] text-purple-400 hover:text-purple-300 font-semibold"
            >
              Manage shares & history
            </button>
          </div>
        </GlassCard>
      )}

      {/* Recent Vault Activity Grid Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <GlassCard className="space-y-6 h-full">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Recent Vault Activity</h3>
                <p className="text-xs text-gray-400 mt-0.5">Most recent documents updated, encrypted, or audited by the DLP engine.</p>
              </div>
              <button 
                onClick={() => navigate('/logs')}
                className="text-xs text-purple-400 hover:text-purple-300 font-semibold flex items-center gap-1"
              >
                Audit History <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-300">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 text-xs font-semibold uppercase tracking-wider">
                    <th className="pb-3">File Asset Name</th>
                    <th className="pb-3">Security Level</th>
                    <th className="pb-3">Algorithm</th>
                    <th className="pb-3">Key Size</th>
                    <th className="pb-3">Enc Time</th>
                    <th className="pb-3">Vault Size</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {dashboardData?.recent_files && dashboardData.recent_files.length > 0 ? (
                    dashboardData.recent_files.map((file) => (
                      <tr key={file.id} className="group hover:bg-white/5 transition-all">
                        <td className="py-4 font-medium text-white flex items-center gap-2.5">
                          <FileText className="w-4 h-4 text-purple-400" />
                          <span className="truncate max-w-[120px]" title={file.name}>{file.name}</span>
                        </td>
                        <td className="py-4">
                          <span className={`px-2 py-0.5 text-[10px] rounded-full border font-semibold ${getLabelColor(file.class)}`}>
                            {file.class}
                          </span>
                        </td>
                        <td className="py-4 text-xs font-mono text-gray-400">{file.algorithm}</td>
                        <td className="py-4 text-xs font-mono text-gray-500">{file.key_size} bit</td>
                        <td className="py-4 text-xs font-mono text-purple-400/90">{(Number(file.encryption_time_ms) || 0).toFixed(1)} ms</td>
                        <td className="py-4 font-mono text-xs text-gray-300">{file.size}</td>
                        <td className="py-4 text-xs font-semibold text-emerald-400">
                          {file.status}
                        </td>
                        <td className="py-4 text-right">
                          <div className="flex justify-end gap-1.5">
                            <button 
                              onClick={() => handleDownloadEncrypted(file.id, file.name)}
                              className="p-1.5 rounded bg-white/5 hover:bg-purple-600/20 text-gray-400 hover:text-purple-400 transition-all"
                              title="Download Encrypted file (.enc)"
                            >
                              <DownloadCloud className="w-3.5 h-3.5" />
                            </button>
                            <button 
                              onClick={() => handleDownloadDecrypted(file.id, file.name, file.class)}
                              className="p-1.5 rounded bg-white/5 hover:bg-emerald-600/20 text-gray-400 hover:text-emerald-400 transition-all"
                              title="Download Decrypted file"
                            >
                              <Unlock className="w-3.5 h-3.5" />
                            </button>
                            <button 
                              onClick={() => navigate('/file-details', { state: { fileId: file.id } })}
                              className="p-1.5 rounded bg-white/5 hover:bg-blue-600/20 text-gray-400 hover:text-blue-400 transition-all"
                              title="Inspect metadata details"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-gray-500 text-xs">
                        No documents secured in key vault yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </GlassCard>
        </div>

        <div className="lg:col-span-1">
          <GlassCard className="space-y-4 flex flex-col justify-between h-full" glow="rose">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4.5 h-4.5 text-rose-500 animate-pulse" /> Recent Security Alerts
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">Real-time alerts tracking authentication anomalies and policy violations.</p>
            </div>

            <div className="flex-1 overflow-y-auto max-h-[300px] space-y-3 pr-1 border border-gray-850 rounded-xl bg-gray-950/20 p-2.5">
              {alerts && alerts.length > 0 ? (
                alerts.map((alert) => (
                  <div key={alert.id} className="p-3 bg-rose-500/5 hover:bg-rose-500/10 border border-rose-500/10 hover:border-rose-500/20 rounded-xl transition-all space-y-1">
                    <div className="flex justify-between items-center text-[10px]">
                      <span className="font-bold text-rose-400 font-mono">{alert.severity}</span>
                      <span className="text-gray-500 font-mono text-[9px]">{alert.timestamp}</span>
                    </div>
                    <span className="block text-xs font-bold text-white leading-snug">{alert.type}</span>
                    <p className="text-[10px] text-gray-450 leading-relaxed">{alert.message}</p>
                  </div>
                ))
              ) : (
                <div className="h-full flex items-center justify-center py-10 text-gray-500 text-xs">
                  No active security incidents detected.
                </div>
              )}
            </div>
            <button
              onClick={() => navigate('/reports')}
              className="w-full py-2 bg-rose-950/20 hover:bg-rose-950/40 border border-rose-800/30 text-rose-300 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all"
            >
              Analyze threat reports
            </button>
          </GlassCard>
        </div>
      </div>

      {/* Decryption Private Key Modal */}
      {showDecryptModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fadeIn">
          <GlassCard className="max-w-md w-full p-6 space-y-4 border border-gray-800" glow="purple">
            <div className="flex items-center gap-2 pb-2 border-b border-gray-800">
              <Unlock className="w-5 h-5 text-purple-400" />
              <div>
                <h4 className="text-sm font-bold text-white">Private Key Authentication</h4>
                <p className="text-[10px] text-gray-500">{decryptFilename} requires RSA KEK decrypt.</p>
              </div>
            </div>

            {decryptError && (
              <div className="p-3 bg-rose-500/5 border border-rose-500/10 rounded-xl text-[11px] text-rose-400 leading-normal">
                {decryptError}
              </div>
            )}

            <div className="space-y-2">
              <label className="block text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                RSA Private Key (PEM String)
              </label>
              <textarea
                value={decryptPrivateKey}
                onChange={(e) => setDecryptPrivateKey(e.target.value)}
                placeholder="-----BEGIN RSA PRIVATE KEY-----"
                className="w-full h-32 py-2 px-3 rounded-xl glass-input text-[10px] font-mono text-gray-300 placeholder:text-gray-600"
              />
              <span className="block text-[9px] text-gray-500">Leave blank to attempt fallback decryption with system profile key.</span>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowDecryptModal(false)}
                className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-semibold text-gray-400 transition-all"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => performDecryptedDownload(decryptFileId, decryptFilename, decryptPrivateKey)}
                disabled={decryptingFile}
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold text-white transition-all disabled:opacity-50 flex items-center gap-1.5"
              >
                {decryptingFile ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Unlock className="w-3.5 h-3.5" />} Authorize & Download
              </button>
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
}
