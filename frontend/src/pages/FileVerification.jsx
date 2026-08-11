import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  RefreshCw, 
  Clock, 
  Search, 
  FileText,
  AlertTriangle,
  Fingerprint,
  CheckCircle,
  HelpCircle
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { auditAPI, integrityAPI } from '../services/api';

export default function FileVerification() {
  const [files, setFiles] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [checkingId, setCheckingId] = useState(null);
  const [notification, setNotification] = useState(null);

  const fetchFiles = async () => {
    try {
      setLoading(true);
      const data = await auditAPI.getDashboard();
      const formattedFiles = (data.recent_files || []).map(f => ({
        ...f,
        verifiedStatus: 'Pending',
        computedHash: '',
        storedHash: 'Loading...'
      }));
      setFiles(formattedFiles);

      // Verify each file's integrity signature
      formattedFiles.forEach(async (f) => {
        try {
          const res = await integrityAPI.verifyFile(f.id);
          setFiles(prev => prev.map(item => {
            if (item.id === f.id) {
              return {
                ...item,
                storedHash: res.stored_hash,
                computedHash: res.computed_hash,
                verifiedStatus: res.status
              };
            }
            return item;
          }));
        } catch (err) {
          console.error(`Failed to verify file ${f.id} on load`, err);
        }
      });
    } catch (err) {
      console.error(err);
      showNotification('error', 'Failed to retrieve files from cryptographic vault.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const showNotification = (type, text) => {
    setNotification({ type, text });
    setTimeout(() => setNotification(null), 5000);
  };

  const handleVerify = async (fileId) => {
    setCheckingId(fileId);
    setFiles(prev => prev.map(f => f.id === fileId ? { ...f, verifiedStatus: 'Checking' } : f));
    try {
      const res = await integrityAPI.verifyFile(fileId);
      setFiles(prev => prev.map(f => {
        if (f.id === fileId) {
          return {
            ...f,
            storedHash: res.stored_hash,
            computedHash: res.computed_hash,
            verifiedStatus: res.status
          };
        }
        return f;
      }));
      if (res.status === 'Verified') {
        showNotification('success', `Integrity check PASSED for file ${res.filename}.`);
      } else {
        showNotification('tampered', `WARNING: Tampering detected for file ${res.filename}!`);
      }
    } catch (err) {
      console.error(err);
      showNotification('error', 'Integrity verification request failed.');
      setFiles(prev => prev.map(f => f.id === fileId ? { ...f, verifiedStatus: 'Error' } : f));
    } finally {
      setCheckingId(null);
    }
  };

  const handleRegenerateHash = async (fileId) => {
    try {
      const res = await integrityAPI.generateHash(fileId);
      setFiles(prev => prev.map(f => {
        if (f.id === fileId) {
          return {
            ...f,
            storedHash: res.sha256_hash,
            verifiedStatus: 'Pending'
          };
        }
        return f;
      }));
      showNotification('success', 'SHA-256 signature regenerated and saved securely in DB.');
    } catch (err) {
      console.error(err);
      showNotification('error', 'Failed to generate hash signature.');
    }
  };

  const filteredFiles = files.filter(f => 
    f.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            <ShieldCheck className="w-8 h-8 text-purple-400" />
            File Integrity Audit Trail
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            Calculate and match SHA-256 cryptographic signatures of vault assets to detect tampering.
          </p>
        </div>
        <button
          onClick={fetchFiles}
          className="flex items-center gap-1.5 px-4 py-2 bg-white/5 hover:bg-white/10 border border-gray-800 rounded-xl text-xs font-semibold text-gray-300 transition-all active:scale-95"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh Registry
        </button>
      </div>

      {/* Floating Status Notification */}
      {notification && (
        <div className={`p-4 rounded-2xl border text-xs flex items-center gap-2.5 shadow-xl backdrop-blur-md animate-slideIn fixed top-4 right-4 z-55 max-w-sm ${
          notification.type === 'success' 
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
            : notification.type === 'tampered'
            ? 'bg-rose-600/20 border-rose-500/30 text-rose-300 animate-pulse'
            : 'bg-rose-500/10 border-rose-500/20 text-rose-400'
        }`}>
          {notification.type === 'success' ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
          )}
          <span>{notification.text}</span>
        </div>
      )}

      {/* Stats Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <GlassCard className="flex items-center gap-4 py-4" glow="blue">
          <div className="p-3 bg-blue-500/10 rounded-2xl border border-blue-500/20 text-blue-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <span className="block text-[10px] text-gray-400 font-bold uppercase tracking-wider">Integrity Verified</span>
            <span className="text-xl font-bold text-white">
              {files.filter(f => f.verifiedStatus === 'Verified').length} Files
            </span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-center gap-4 py-4" glow="rose">
          <div className="p-3 bg-rose-500/10 rounded-2xl border border-rose-500/20 text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <span className="block text-[10px] text-gray-400 font-bold uppercase tracking-wider">Tampered Detections</span>
            <span className="text-xl font-bold text-rose-400">
              {files.filter(f => f.verifiedStatus === 'Tampered').length} Alarms
            </span>
          </div>
        </GlassCard>

        <GlassCard className="flex items-center gap-4 py-4" glow="purple">
          <div className="p-3 bg-purple-500/10 rounded-2xl border border-purple-500/20 text-purple-400">
            <Fingerprint className="w-6 h-6" />
          </div>
          <div>
            <span className="block text-[10px] text-gray-400 font-bold uppercase tracking-wider">Total Hashed Assets</span>
            <span className="text-xl font-bold text-white">
              {files.length} Hashed
            </span>
          </div>
        </GlassCard>
      </div>

      {/* Main Files Table */}
      <GlassCard className="space-y-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-purple-400" /> Active Vault Checksums
          </h3>
          <div className="relative w-full md:w-64">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
            <input
              type="text"
              placeholder="Search file assets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl glass-input text-xs text-gray-200"
            />
          </div>
        </div>

        {loading ? (
          <div className="py-20 text-center space-y-3">
            <RefreshCw className="w-8 h-8 text-purple-500 animate-spin mx-auto" />
            <p className="text-xs text-gray-500 uppercase tracking-widest">Querying SHA-256 vault index...</p>
          </div>
        ) : filteredFiles.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 text-xs font-semibold uppercase tracking-wider">
                  <th className="pb-3">Asset Name</th>
                  <th className="pb-3">Security Level</th>
                  <th className="pb-3">Stored DB Signature</th>
                  <th className="pb-3">Computed Live Hash</th>
                  <th className="pb-3">Integrity Status</th>
                  <th className="pb-3 text-right">Audit Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredFiles.map((file) => (
                  <tr key={file.id} className="group hover:bg-white/5 transition-all">
                    <td className="py-4 font-medium text-white flex items-center gap-2.5">
                      <FileText className="w-4 h-4 text-purple-400" />
                      <span className="truncate max-w-[130px]" title={file.name}>{file.name}</span>
                    </td>
                    <td className="py-4">
                      <span className={`px-2 py-0.5 text-[9px] rounded-full border font-semibold ${
                        file.class === 'Public' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                        file.class === 'Confidential' ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' :
                        'bg-purple-500/10 border-purple-500/20 text-purple-300'
                      }`}>
                        {file.class}
                      </span>
                    </td>
                    <td className="py-4">
                      <div className="flex items-center gap-1 font-mono text-[9px] text-gray-500">
                        <span className="truncate max-w-[100px]" title={file.storedHash}>
                          {file.storedHash || 'None'}
                        </span>
                      </div>
                    </td>
                    <td className="py-4">
                      <div className="flex items-center gap-1 font-mono text-[9px] text-gray-500">
                        <span className="truncate max-w-[100px]" title={file.computedHash}>
                          {file.computedHash || 'Audit pending'}
                        </span>
                      </div>
                    </td>
                    <td className="py-4">
                      <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold inline-flex items-center gap-1 ${
                        file.verifiedStatus === 'Verified' 
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' 
                          : file.verifiedStatus === 'Tampered'
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/25 animate-pulse'
                          : file.verifiedStatus === 'Checking'
                          ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                          : 'bg-white/5 text-gray-400 border border-gray-800'
                      }`}>
                        {file.verifiedStatus === 'Verified' && <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
                        {file.verifiedStatus === 'Tampered' && <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />}
                        {file.verifiedStatus === 'Checking' && <RefreshCw className="w-3 h-3 animate-spin text-purple-400" />}
                        {file.verifiedStatus}
                      </span>
                    </td>
                    <td className="py-4 text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => handleVerify(file.id)}
                          disabled={checkingId === file.id}
                          className="px-2.5 py-1.5 rounded-lg bg-blue-600/10 hover:bg-blue-600/25 border border-blue-500/30 text-[10px] font-bold text-blue-300 transition-all flex items-center gap-1 disabled:opacity-50"
                          title="Recalculate hash and test verification"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" /> Audit
                        </button>
                        <button
                          onClick={() => handleRegenerateHash(file.id)}
                          className="px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-purple-600/20 border border-gray-800 hover:border-purple-500/30 text-[10px] font-bold text-gray-400 hover:text-purple-300 transition-all flex items-center gap-1"
                          title="Generate new signature in database"
                        >
                          <RefreshCw className="w-3 h-3" /> Re-sign
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center text-gray-500 space-y-1">
            <p className="text-xs">No matching files found in current search query.</p>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
