import React, { useState, useEffect } from 'react';
import { 
  Share2, 
  Clock, 
  QrCode, 
  Copy, 
  CheckCircle, 
  FileText, 
  ShieldAlert, 
  Trash2,
  ExternalLink,
  Eye,
  Loader2
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { shareAPI, auditAPI } from '../services/api';

export default function SecureSharing() {
  const [filesList, setFilesList] = useState([]);
  const [selectedFile, setSelectedFile] = useState('');
  const [duration, setDuration] = useState('24');
  const [sharingHistory, setSharingHistory] = useState([]);

  const [loadingFiles, setLoadingFiles] = useState(true);
  const [sharing, setSharing] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const [showQrModal, setShowQrModal] = useState(false);
  const [activeQrCode, setActiveQrCode] = useState('');
  const [activeShareLink, setActiveShareLink] = useState('');

  const [copiedId, setCopiedId] = useState(null);

  const loadData = async () => {
    try {
      setLoadingFiles(true);
      const dash = await auditAPI.getDashboard();
      setFilesList(dash.recent_files || []);

      const history = await shareAPI.getSharedHistory();
      setSharingHistory(history);
    } catch (err) {
      console.error(err);
      setErrorMsg('Failed to load sharing vault registry.');
    } finally {
      setLoadingFiles(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleShare = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    setSharing(true);
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const data = await shareAPI.shareFile(selectedFile, duration);
      setSuccessMsg(`Secure share link generated successfully!`);
      await loadData();
      
      setActiveQrCode(data.qr_code);
      setActiveShareLink(data.share_link);
      setShowQrModal(true);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.response?.data?.error || 'Failed to authorize sharing policy.');
    } finally {
      setSharing(false);
    }
  };

  const handleRevoke = async (shareId) => {
    try {
      await shareAPI.revokeShare(shareId);
      setSharingHistory(prev => prev.map(s => s.id === shareId ? { ...s, status: 'revoked' } : s));
      setSuccessMsg('Sharing link revoked successfully.');
      setTimeout(() => setSuccessMsg(''), 4000);
    } catch (err) {
      console.error(err);
      setErrorMsg('Failed to revoke sharing authorization.');
    }
  };

  const handleCopyLink = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Title */}
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
          <Share2 className="w-8 h-8 text-purple-400" /> Secure File Sharing
        </h2>
        <p className="text-gray-400 text-sm mt-1">
          Generate temporary, time-limited download links and QR codes for encrypted files with automatic integrity verification.
        </p>
      </div>

      {successMsg && (
        <div className="p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-2xl text-xs text-emerald-400 flex items-center gap-2">
          <CheckCircle className="w-5 h-5 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div className="p-4 bg-rose-500/5 border border-rose-500/10 rounded-2xl text-xs text-rose-400 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Establish Policy Card */}
        <div className="lg:col-span-1">
          <GlassCard className="space-y-6" glow="purple">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Share2 className="w-5 h-5 text-purple-400" /> Share Link Generator
            </h3>

            <form onSubmit={handleShare} className="space-y-6">
              <div className="space-y-2">
                <label className="block text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                  Select Secured Document
                </label>
                {loadingFiles ? (
                  <div className="h-10 rounded-xl bg-white/5 border border-gray-800 flex items-center justify-center">
                    <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />
                  </div>
                ) : (
                  <select 
                    required
                    value={selectedFile}
                    onChange={(e) => setSelectedFile(e.target.value)}
                    className="w-full py-2.5 px-3 rounded-xl glass-input text-xs text-gray-300"
                  >
                    <option value="">-- Choose Vault File --</option>
                    {filesList.map(f => (
                      <option key={f.id} value={f.id}>
                        {f.name}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div className="space-y-2">
                <label className="block text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                  Link Expiration Frame
                </label>
                <select 
                  value={duration}
                  onChange={(e) => setDuration(e.target.value)}
                  className="w-full py-2.5 px-3 rounded-xl glass-input text-xs text-gray-300"
                >
                  <option value="1">1 Hour</option>
                  <option value="24">24 Hours</option>
                  <option value="168">7 Days</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={sharing || !selectedFile}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 disabled:opacity-50 flex items-center justify-center gap-1.5"
              >
                {sharing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Authorizing Policy...</span>
                  </>
                ) : (
                  <>
                    <Share2 className="w-4 h-4" />
                    <span>Authorize Share Link</span>
                  </>
                )}
              </button>
            </form>
          </GlassCard>
        </div>

        {/* Sharing History list */}
        <div className="lg:col-span-2">
          <GlassCard className="space-y-6 h-full">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Clock className="w-5 h-5 text-blue-400" /> Active Share Tokens
            </h3>

            {loadingFiles ? (
              <div className="py-12 text-center text-gray-500">
                <Loader2 className="w-6 h-6 text-blue-500 animate-spin mx-auto" />
              </div>
            ) : sharingHistory.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-500 text-[10px] font-semibold uppercase tracking-wider">
                      <th className="pb-3">File Asset</th>
                      <th className="pb-3">Share Link</th>
                      <th className="pb-3">Expiry Deadline</th>
                      <th className="pb-3">Status</th>
                      <th className="pb-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/40">
                    {sharingHistory.map((share) => {
                      const shareLink = `http://localhost:5173/shared/${share.share_token}`;
                      return (
                        <tr key={share.id} className="group hover:bg-white/5 transition-all text-xs">
                          <td className="py-4 font-semibold text-white flex items-center gap-2 max-w-[120px] truncate" title={share.filename}>
                            <FileText className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                            <span className="truncate">{share.filename}</span>
                          </td>
                          <td className="py-4">
                            <div className="flex items-center gap-1">
                              <span className="font-mono text-[9px] text-gray-500 truncate max-w-[90px]" title={shareLink}>
                                {shareLink.substring(0, 20)}...
                              </span>
                              <button 
                                onClick={() => handleCopyLink(shareLink, share.id)}
                                className="p-1 hover:bg-white/10 rounded transition-all text-gray-500 hover:text-white"
                                title="Copy Share Link"
                              >
                                {copiedId === share.id ? (
                                  <CheckCircle className="w-3 h-3 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                          </td>
                          <td className="py-4 font-mono text-[9px] text-gray-400">
                            {share.expiry_time}
                          </td>
                          <td className="py-4">
                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                              share.status === 'active' 
                                ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400' 
                                : share.status === 'revoked'
                                ? 'bg-rose-500/10 border border-rose-500/20 text-rose-400' 
                                : 'bg-gray-800 border border-gray-700 text-gray-500'
                            }`}>
                              {share.status}
                            </span>
                          </td>
                          <td className="py-4 text-right">
                            <div className="flex justify-end gap-1.5">
                              {share.status === 'active' && (
                                <>
                                  <button
                                    onClick={() => {
                                      setActiveQrCode(share.qr_code);
                                      setActiveShareLink(shareLink);
                                      setShowQrModal(true);
                                    }}
                                    className="p-1.5 rounded bg-white/5 hover:bg-purple-600/25 border border-gray-800 hover:border-purple-500/20 text-gray-400 hover:text-purple-300 transition-all"
                                    title="View QR Code"
                                  >
                                    <QrCode className="w-3.5 h-3.5" />
                                  </button>
                                  <button
                                    onClick={() => handleRevoke(share.id)}
                                    className="p-1.5 rounded bg-white/5 hover:bg-rose-600/25 border border-gray-800 hover:border-rose-500/20 text-gray-400 hover:text-rose-300 transition-all"
                                    title="Revoke Share Link"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                </>
                              )}
                              <a
                                href={shareLink}
                                target="_blank"
                                rel="noreferrer"
                                className="p-1.5 rounded bg-white/5 hover:bg-blue-600/25 border border-gray-800 hover:border-blue-500/20 text-gray-400 hover:text-blue-300 transition-all inline-block"
                                title="Open Sharing Resolver"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </a>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-16 text-center text-gray-500 space-y-1">
                <p className="text-xs">No sharing links generated yet.</p>
              </div>
            )}
          </GlassCard>
        </div>
      </div>

      {/* QR Code Viewer Modal */}
      {showQrModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fadeIn">
          <GlassCard className="max-w-xs w-full p-6 text-center space-y-4 border border-gray-800" glow="purple">
            <h4 className="text-sm font-bold text-white flex items-center justify-center gap-1.5">
              <QrCode className="w-4 h-4 text-purple-400" /> Share QR Code
            </h4>
            <div className="bg-white p-3 rounded-2xl w-48 h-48 mx-auto flex items-center justify-center border border-gray-700">
              <img src={activeQrCode} alt="Share QR Code" className="w-full h-full" />
            </div>
            <p className="text-[10px] text-gray-400 font-mono select-all break-all border border-gray-800 bg-black/30 p-2 rounded-xl">
              {activeShareLink}
            </p>
            <button
              onClick={() => setShowQrModal(false)}
              className="w-full py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-semibold transition-all"
            >
              Done
            </button>
          </GlassCard>
        </div>
      )}
    </div>
  );
}
