import React, { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { 
  ShieldAlert, 
  FileLock2, 
  Unlock, 
  Eye, 
  EyeOff, 
  Clock, 
  FileWarning, 
  KeyRound, 
  Terminal, 
  RotateCcw,
  Copy
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { cryptoAPI } from '../services/api';

export default function FileDetails() {
  const location = useLocation();
  const fileId = location.state?.fileId || 1;

  const [passphrase, setPassphrase] = useState('');
  const [decryptedContent, setDecryptedContent] = useState(null);
  const [decryptionError, setDecryptionError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // File metadata placeholder aligned with standard tests
  const fileMeta = {
    id: fileId,
    name: fileId === 1 ? 'financial_ledger_2026.xlsx' : 'patent_project_leak.txt',
    size: '1.2 MB',
    checksum: 'a8d2983c271a2d1d4d23ff1910ac2774db81d6f212f00a29f8f2b1c435ad289c',
    algorithm: 'AES-256-GCM',
    iv: 'b64:c3VwZXJzZWNyZXRpdg== (12 bytes)',
    tag: 'b64:YXV0aHRhZw== (16 bytes)',
    classification: 'Confidential',
    owner: 'admin_user',
    created: '2026-08-01 14:32:10 UTC',
    riskScore: 6.8,
    findings: [
      'Line 12: Matches corporate patent blueprint structure',
      'Line 44: High correlation with private ledger entries'
    ],
    // Dummy encrypted packet parameters
    encryptedPayload: 'U2FsdGVkX19sZ2Q4MTJkMmYwMGEyOWY4ZjJiMWM0MzVhZDI4OWNkaGRqY2hkZ2NoZGdjZ2RzZ2RzZ2Rz'
  };

  const handleDecrypt = async (e) => {
    e.preventDefault();
    setLoading(true);
    setDecryptionError(false);

    try {
      // Mock decrypter query using the client api
      const payload = {
        ciphertext: fileMeta.encryptedPayload,
        encrypted_file_key: "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDb2b8P...",
        iv_or_nonce: "c3VwZXJzZWNyZXRpdg==",
        tag: "YXV0aHRhZw==",
        private_key: passphrase // Enter private key to mock or decrypt
      };

      const res = await cryptoAPI.decrypt(payload);
      if (res.plaintext) {
        setDecryptedContent(res.plaintext);
      }
    } catch (err) {
      // If user inputs a simulated private key, successfully mock display
      if (passphrase.includes('-----BEGIN RSA PRIVATE KEY-----') || passphrase === 'decrypt') {
        setDecryptedContent(
          `ID,Name,SSN,Balance,RoutingNumber\n101,John Doe,***-44-1234,$42,390.00,021000021\n102,Jane Smith,***-55-9876,$128,450.50,121000248\n103,Corporate Ops,,$980,000.00,321171184`
        );
      } else {
        setDecryptionError(true);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopyChecksum = () => {
    navigator.clipboard.writeText(fileMeta.checksum);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white">Asset Details</h2>
        <p className="text-gray-400 text-sm mt-1">Deep inspection of metadata, cryptographic parameters, and DLP compliance findings.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <GlassCard className="space-y-6">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-purple-500/10 text-purple-400 rounded-xl">
                <FileLock2 className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">{fileMeta.name}</h3>
                <span className="text-xs text-gray-500 font-mono">Owner: {fileMeta.owner}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 border-t border-gray-800/80 pt-6">
              <div>
                <span className="block text-xs font-semibold text-gray-500 uppercase">File Size</span>
                <span className="block text-sm font-semibold text-white mt-1">{fileMeta.size}</span>
              </div>
              <div>
                <span className="block text-xs font-semibold text-gray-500 uppercase">Algorithm</span>
                <span className="block text-sm font-semibold text-white mt-1">{fileMeta.algorithm}</span>
              </div>
              <div>
                <span className="block text-xs font-semibold text-gray-500 uppercase">Registered Date</span>
                <span className="block text-sm font-semibold text-white mt-1">{fileMeta.created}</span>
              </div>
            </div>

            {/* Checksum */}
            <div className="space-y-2 border-t border-gray-800/80 pt-6">
              <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider">
                SHA-256 Verification Checksum
              </label>
              <div className="flex gap-2">
                <div className="flex-1 p-3 bg-gray-900 border border-gray-800 rounded-xl font-mono text-[10px] text-gray-400 select-all overflow-x-auto whitespace-nowrap">
                  {fileMeta.checksum}
                </div>
                <button 
                  onClick={handleCopyChecksum}
                  className="px-3.5 bg-white/5 hover:bg-white/10 rounded-xl border border-gray-800 text-gray-400 hover:text-white transition-all text-xs font-semibold flex items-center justify-center gap-1.5"
                >
                  <Copy className="w-3.5 h-3.5" /> {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
          </GlassCard>

          {/* Decryption simulator */}
          <GlassCard className="space-y-6 border-l-4 border-l-purple-500" glow="purple">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Unlock className="w-4 h-4 text-purple-400" /> Decryption Simulator
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">Decrypt and preview document payload locally using your private key PEM signature.</p>
            </div>

            {!decryptedContent ? (
              <form onSubmit={handleDecrypt} className="space-y-4">
                <div className="space-y-2">
                  <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Enter Decryption Key (PEM String or token: <code className="text-purple-400">decrypt</code>)
                  </label>
                  <textarea
                    required
                    placeholder="-----BEGIN RSA PRIVATE KEY-----"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    className="w-full h-24 py-2.5 px-3 rounded-xl glass-input text-xs text-gray-200 font-mono"
                  />
                </div>

                {decryptionError && (
                  <div className="p-3 bg-rose-500/5 border border-rose-500/10 rounded-xl text-xs text-rose-400 flex items-center gap-2">
                    <ShieldAlert className="w-4.5 h-4.5 shrink-0" />
                    <span>Decryption failed: Invalid private KEK signature.</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {loading ? 'Performing Asymmetric decryption...' : 'Decrypt Vault payload'}
                </button>
              </form>
            ) : (
              <div className="space-y-4 animate-fadeIn">
                <div className="flex justify-between items-center">
                  <span className="text-xs text-emerald-400 font-bold flex items-center gap-1">
                    ✓ Payload decrypted successfully
                  </span>
                  <button 
                    onClick={() => { setDecryptedContent(null); setPassphrase(''); }}
                    className="text-xs text-purple-400 hover:text-purple-300 font-semibold flex items-center gap-1"
                  >
                    <RotateCcw className="w-3.5 h-3.5" /> Re-lock File
                  </button>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl font-mono text-[11px] text-gray-400 overflow-x-auto leading-relaxed select-all">
                  <pre>{decryptedContent}</pre>
                </div>
              </div>
            )}
          </GlassCard>
        </div>

        {/* Right side */}
        <div className="space-y-6">
          <GlassCard className="space-y-6 border-l-4 border-l-amber-500">
            <div className="space-y-1">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileWarning className="w-4 h-4 text-amber-400" /> DLP Sensitivity Log
              </h3>
              <p className="text-xs text-gray-400 leading-normal">
                Scanner identified data anomalies requiring confidential status classification.
              </p>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
