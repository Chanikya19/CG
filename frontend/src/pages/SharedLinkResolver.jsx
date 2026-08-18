import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Unlock, 
  DownloadCloud, 
  Clock, 
  Loader2,
  FileText,
  AlertTriangle,
  Lock
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { shareAPI } from '../services/api';

export default function SharedLinkResolver() {
  const { token } = useParams();
  const [loading, setLoading] = useState(true);
  const [shareData, setShareData] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  
  const [privateKey, setPrivateKey] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState('');

  useEffect(() => {
    async function resolveToken() {
      try {
        setLoading(true);
        const data = await shareAPI.resolveShareToken(token);
        setShareData(data);
      } catch (err) {
        console.error(err);
        setErrorMsg(err.response?.data?.error || 'This sharing link is invalid, expired, or has been revoked.');
      } finally {
        setLoading(false);
      }
    }
    resolveToken();
  }, [token]);

  const handleDownload = async (e) => {
    e.preventDefault();
    setDownloading(true);
    setDownloadError('');
    try {
      const blob = await shareAPI.downloadSharedDecrypted(token, privateKey || null);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = shareData.file.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      setDownloadError('Decryption failed. Please verify your RSA private KEK signature.');
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#030712] cyber-grid flex flex-col items-center justify-center gap-4 text-gray-100 p-4">
        <Loader2 className="w-10 h-10 text-purple-500 animate-spin" />
        <span className="text-xs uppercase tracking-widest text-gray-500">Resolving secure sharing token...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#030712] cyber-grid flex flex-col items-center justify-center text-gray-100 p-4">
      {/* Title */}
      <div className="flex items-center gap-2 mb-6">
        <Lock className="w-6 h-6 text-purple-400" />
        <span className="text-xl font-bold tracking-tight text-white font-mono">
          Cipher<span className="text-purple-400">Guard</span> Secure Vault
        </span>
      </div>

      <GlassCard className="max-w-lg w-full p-6 space-y-6 border border-gray-800" glow={errorMsg ? "rose" : shareData?.file.integrity_status === "Tampered" ? "rose" : "purple"}>
        {errorMsg ? (
          /* Expired / Revoked / Invalid state */
          <div className="space-y-4 text-center py-6">
            <div className="w-16 h-16 rounded-full bg-rose-500/10 border border-rose-500/25 flex items-center justify-center mx-auto text-rose-400">
              <Lock className="w-8 h-8" />
            </div>
            <div className="space-y-2">
              <h3 className="text-base font-bold text-white">Access Expired or Revoked</h3>
              <p className="text-xs text-gray-400 leading-normal max-w-sm mx-auto">
                {errorMsg} Contact the file owner to generate a new active sharing authorization token.
              </p>
            </div>
          </div>
        ) : (
          /* Share Details view */
          <div className="space-y-6">
            {/* File Info */}
            <div className="flex items-start gap-4 pb-4 border-b border-gray-800/60">
              <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-2xl text-purple-300">
                <FileText className="w-7 h-7" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-bold text-white truncate max-w-[280px]" title={shareData.file.filename}>
                  {shareData.file.filename}
                </h3>
                <p className="text-[10px] text-gray-500 font-mono">
                  Size: {shareData.file.file_size} | Owner: {shareData.owner}
                </p>
              </div>
            </div>

            {/* Integrity Status Alarm */}
            {shareData.file.integrity_status?.toUpperCase() === "TAMPERED" ? (
              <div className="p-4 bg-rose-600/10 border border-rose-500/30 rounded-2xl space-y-2 text-rose-300">
                <h4 className="text-xs font-bold flex items-center gap-1.5 uppercase tracking-wider">
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" /> Integrity Audit Violation Detected
                </h4>
                <p className="text-[11px] leading-relaxed opacity-90">
                  CRITICAL ALARM: The calculated SHA-256 hash of this document on disk does not match the database signature. This document has been tampered with or modified. Download is blocked to prevent execution of compromised data.
                </p>
              </div>
            ) : (
              <div className="p-3 bg-emerald-500/5 border border-emerald-500/15 rounded-2xl flex items-center gap-2.5 text-emerald-400">
                <ShieldCheck className="w-5 h-5 shrink-0" />
                <div className="text-[10px] leading-tight">
                  <span className="block font-bold">✓ SHA-256 Signature Verified</span>
                  <span className="opacity-75">Document is intact and verified authentic.</span>
                </div>
              </div>
            )}

            {/* Share details metadata */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[10px]">
              <div className="flex justify-between items-center bg-white/5 border border-gray-800 p-3 rounded-2xl">
                <span className="text-gray-400 flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5" /> Expiry Deadline
                </span>
                <span className="font-mono text-purple-300 font-bold">
                  {shareData.expiry_time}
                </span>
              </div>
              <div className="flex justify-between items-center bg-white/5 border border-gray-800 p-3 rounded-2xl">
                <span className="text-gray-400 flex items-center gap-1">
                  <DownloadCloud className="w-3.5 h-3.5" /> Downloads Limit
                </span>
                <span className="font-mono text-blue-300 font-bold">
                  {shareData.file.downloads_count} / {shareData.file.max_downloads !== null && shareData.file.max_downloads !== undefined ? shareData.file.max_downloads : '∞'}
                </span>
              </div>
            </div>

            {/* Download Logic */}
            {shareData.file.integrity_status?.toUpperCase() !== "TAMPERED" && (
              <form onSubmit={handleDownload} className="space-y-4">
                {shareData.file.classification === 'Secret' && (
                  <div className="space-y-2">
                    <label className="block text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                      RSA Private Decryption Key (Required for Secret class)
                    </label>
                    <textarea
                      required
                      value={privateKey}
                      onChange={(e) => setPrivateKey(e.target.value)}
                      placeholder="-----BEGIN RSA PRIVATE KEY-----"
                      className="w-full h-32 py-2 px-3 rounded-xl glass-input text-[10px] font-mono text-gray-300 placeholder:text-gray-600"
                    />
                    <span className="block text-[9px] text-gray-500">
                      This file is classified as Secret and requires your private KEK to unwrap the AES Data Encryption Key.
                    </span>
                  </div>
                )}

                {downloadError && (
                  <div className="p-3 bg-rose-500/5 border border-rose-500/10 rounded-xl text-[11px] text-rose-400 leading-normal">
                    {downloadError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={downloading}
                  className="w-full py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  {downloading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Processing Decryption Ciphers...</span>
                    </>
                  ) : (
                    <>
                      <DownloadCloud className="w-4 h-4" />
                      <span>Download Decrypted Payload</span>
                    </>
                  )}
                </button>
              </form>
            )}

            {shareData.file.integrity_status?.toUpperCase() === "TAMPERED" && (
              <button
                disabled
                className="w-full py-3.5 rounded-xl bg-gray-900 border border-gray-800 text-xs font-semibold text-gray-600 cursor-not-allowed flex items-center justify-center gap-1.5"
              >
                <ShieldAlert className="w-4 h-4 text-gray-700" />
                <span>Download Blocked due to Tampering</span>
              </button>
            )}
          </div>
        )}
      </GlassCard>
    </div>
  );
}
