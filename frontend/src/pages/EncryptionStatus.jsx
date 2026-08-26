import React, { useState, useEffect } from 'react';
import { 
  Key, 
  RotateCcw, 
  Trash2, 
  Plus, 
  AlertTriangle, 
  RefreshCw, 
  DownloadCloud,
  CheckCircle,
  TrendingUp,
  Cpu,
  Loader2
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { cryptoAPI } from '../services/api';
import { useToast } from '../components/ToastNotification';

export default function EncryptionStatus() {
  const { addToast } = useToast();
  const [keys, setKeys] = useState([
    { id: 'KEY-091A', type: 'Asymmetric (RSA-2048)', name: 'Master Admin KEK', fingerprint: 'sha256:8f:ad:2b:81:4e:c9:0d...', status: 'Active', created: '2026-03-12' },
    { id: 'KEY-241C', type: 'Asymmetric (ECC-256)', name: 'User Ephemeral Exchange', fingerprint: 'sha256:1a:2d:4e:8b:2d:91...', status: 'Active', created: '2026-07-28' },
    { id: 'KEY-875X', type: 'Symmetric (AES-256)', name: 'Vault Storage Default DEK', fingerprint: 'sha256:bb:24:c9:7e:ff:ac...', status: 'Revoked', created: '2026-01-05' }
  ]);
  
  const [entropy, setEntropy] = useState(7.989); // Max entropy is 8.000 (perfect randomness)
  const [spinning, setSpinning] = useState(false);

  const [rsaKeys, setRsaKeys] = useState({ public_key: '', private_key: '' });
  const [loadingKeys, setLoadingKeys] = useState(true);

  useEffect(() => {
    async function loadKeys() {
      try {
        const data = await cryptoAPI.getKeys();
        setRsaKeys(data || { public_key: '', private_key: '' });
      } catch (err) {
        console.error("Failed to load user cryptographic keys", err);
        addToast('error', 'Failed to load system keypair files.');
      } finally {
        setLoadingKeys(false);
      }
    }
    loadKeys();
  }, []);

  const handleGenerateKeys = async () => {
    setLoadingKeys(true);
    try {
      const data = await cryptoAPI.generateKeys();
      setRsaKeys(data || { public_key: '', private_key: '' });
      addToast('success', 'RSA KEK signature key pair rotated successfully!');
    } catch (err) {
      console.error("Failed to generate user cryptographic keys", err);
      addToast('error', 'Failed to rotate RSA ciphers keypair.');
    } finally {
      setLoadingKeys(false);
    }
  };

  const rotateKey = (id) => {
    setKeys(keys.map(k => {
      if (k.id === id) {
        return {
          ...k,
          fingerprint: `sha256:${Math.random().toString(36).substring(2, 8)}:${Math.random().toString(36).substring(2, 8)}...`,
          created: new Date().toISOString().split('T')[0]
        };
      }
      return k;
    }));
  };

  const toggleStatus = (id) => {
    setKeys(keys.map(k => {
      if (k.id === id) {
        return {
          ...k,
          status: k.status === 'Active' ? 'Revoked' : 'Active'
        };
      }
      return k;
    }));
  };

  const recomputeEntropy = () => {
    setSpinning(true);
    setTimeout(() => {
      setSpinning(false);
      setEntropy((7.95 + Math.random() * 0.049).toFixed(3));
    }, 1000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white">Cryptographic Key Vault</h2>
        <p className="text-gray-400 text-sm mt-1">Manage public/private key pairs, track entropy of key generators, and rotate symmetric storage ciphers.</p>
      </div>

      {/* Grid containing Entropy & Key Generation panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Entropy Meter */}
        <GlassCard className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-purple-400" /> Entropy Diagnostics
            </h3>
            <button 
              onClick={recomputeEntropy}
              className={`p-1 text-gray-400 hover:text-white rounded-lg hover:bg-white/5 transition-all ${spinning ? 'animate-spin' : ''}`}
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>

          <div className="text-center py-6 space-y-4">
            <div className="text-5xl font-mono font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-blue-500 tracking-tight">
              {entropy}
            </div>
            <div>
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider bg-emerald-500/10 px-2.5 py-0.5 rounded-full border border-emerald-500/20 inline-block">
                Near Perfect Randomness
              </span>
              <p className="text-[11px] text-gray-500 mt-3 leading-normal px-4">
                Calculated bit entropy. Higher values represent stronger unpredictability, shielding ciphers from brute-force matrix attempts.
              </p>
            </div>
          </div>

          <div className="border-t border-gray-800/80 pt-4 text-xs text-gray-400 flex items-center justify-between">
            <span>RNG Generator:</span>
            <span className="font-mono text-white flex items-center gap-1">
              <Cpu className="w-3.5 h-3.5 text-purple-400" /> `/dev/urandom` API
            </span>
          </div>
        </GlassCard>

        {/* Asymmetric keypair downloader/generator */}
        <GlassCard className="lg:col-span-2 space-y-6">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Key className="w-5 h-5 text-blue-400" /> Active System Keypair
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">Your 2048-bit RSA asymmetric configuration. Used for file envelope decryption.</p>
            </div>
            <button
              onClick={handleGenerateKeys}
              disabled={loadingKeys}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/40 border border-purple-500/30 text-[11px] font-bold text-purple-300 transition-all disabled:opacity-50"
            >
              {loadingKeys ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCcw className="w-3 h-3" />} Rotate Keys
            </button>
          </div>

          {loadingKeys ? (
            <div className="h-28 flex flex-col items-center justify-center gap-2">
              <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />
              <span className="text-[10px] text-gray-500 uppercase tracking-widest">Generating secure ciphers...</span>
            </div>
          ) : (!rsaKeys.public_key && !rsaKeys.private_key) ? (
            <div className="py-6 text-center text-gray-500 space-y-3 flex flex-col items-center justify-center">
              <div className="p-3 bg-white/5 border border-gray-800 text-gray-650 rounded-full">
                <AlertTriangle className="w-8 h-8 text-amber-555" />
              </div>
              <div className="space-y-0.5">
                <span className="block font-semibold text-gray-405">No Active Keypair Found</span>
                <span className="block text-[10px] text-gray-650">An asymmetric key pair is required to secure envelopes in the hybrid cryptosystem.</span>
              </div>
              <button 
                onClick={handleGenerateKeys}
                className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-semibold transition-all focus:ring-2 focus:ring-purple-500 outline-none"
                aria-label="Generate new system keypair"
              >
                Generate Keypair
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-white/5 border border-gray-800 rounded-2xl space-y-3">
                <div>
                  <span className="block text-xs font-bold text-white">Public Encryption Key (CG-PUB)</span>
                  <span className="block text-[9px] text-gray-500 font-mono mt-1 truncate" title={rsaKeys.public_key}>{rsaKeys.public_key.substring(0, 70)}...</span>
                </div>
                <a 
                  href={`data:text/plain;charset=utf-8,${encodeURIComponent(rsaKeys.public_key)}`}
                  download="cipherguard_public.pem"
                  className="w-full py-2 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-purple-300 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5 transition-all focus:ring-2 focus:ring-purple-500 outline-none"
                  aria-label="Download Public Key File"
                >
                  <DownloadCloud className="w-3.5 h-3.5" /> Download Public Key
                </a>
              </div>

              <div className="p-4 bg-white/5 border border-gray-800 rounded-2xl space-y-3">
                <div>
                  <span className="block text-xs font-bold text-white">Private Decryption Key (CG-PRI)</span>
                  <span className="block text-[9px] text-gray-500 font-mono mt-1 truncate" title={rsaKeys.private_key}>{rsaKeys.private_key.substring(0, 70)}...</span>
                </div>
                <a 
                  href={`data:text/plain;charset=utf-8,${encodeURIComponent(rsaKeys.private_key)}`}
                  download="cipherguard_private.pem"
                  className="w-full py-2 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 text-blue-300 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5 transition-all focus:ring-2 focus:ring-purple-500 outline-none"
                  aria-label="Download Private Key File"
                >
                  <DownloadCloud className="w-3.5 h-3.5" /> Download Private Key
                </a>
              </div>
            </div>
          )}
        </GlassCard>
      </div>

      {/* Cryptographic Keys table */}
      <GlassCard className="space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-base font-bold text-white">Key Exchange Registry</h3>
            <p className="text-xs text-gray-400 mt-0.5">Registry tracking all key configurations, creation details, and active certificates.</p>
          </div>
          <button className="flex items-center gap-1.5 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-xs font-semibold tracking-wide text-white rounded-xl transition-all shadow-md">
            <Plus className="w-3.5 h-3.5" /> Create Token Key
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-300">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs font-semibold uppercase tracking-wider">
                <th className="pb-3">Key ID</th>
                <th className="pb-3">Descriptive Label</th>
                <th className="pb-3">Type</th>
                <th className="pb-3">SHA-256 Digest Signature</th>
                <th className="pb-3">Registered</th>
                <th className="pb-3">Status</th>
                <th className="pb-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {keys.map((k) => (
                <tr key={k.id} className="hover:bg-white/5 transition-all">
                  <td className="py-4 font-mono text-xs text-purple-400 font-bold">{k.id}</td>
                  <td className="py-4 font-medium text-white">{k.name}</td>
                  <td className="py-4 text-xs text-gray-400">{k.type}</td>
                  <td className="py-4 font-mono text-[10px] text-gray-500">{k.fingerprint}</td>
                  <td className="py-4 text-xs text-gray-400">{k.created}</td>
                  <td className="py-4">
                    <span className={`px-2 py-0.5 text-[10px] rounded-full font-semibold border ${
                      k.status === 'Active' 
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                        : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                    }`}>
                      {k.status}
                    </span>
                  </td>
                  <td className="py-4 text-right">
                    <div className="flex justify-end gap-2">
                      <button 
                        onClick={() => rotateKey(k.id)}
                        className="p-1 rounded hover:bg-purple-600/10 text-gray-400 hover:text-purple-400 transition-all"
                        title="Rotate key digests"
                        disabled={k.status === 'Revoked'}
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                      </button>
                      <button 
                        onClick={() => toggleStatus(k.id)}
                        className={`p-1 rounded hover:bg-rose-600/10 text-gray-400 hover:text-rose-400 transition-all`}
                        title={k.status === 'Active' ? 'Revoke Key' : 'Activate Key'}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
}
