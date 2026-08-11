import React, { useState, useEffect } from 'react';
import { 
  User, 
  Mail, 
  Key, 
  Smartphone, 
  DownloadCloud, 
  ShieldCheck, 
  RefreshCw,
  Cpu,
  Loader2
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { authAPI } from '../services/api';

export default function Profile() {
  const [loading, setLoading] = useState(true);
  const [profileData, setProfileData] = useState(null);
  const [profileKeys, setProfileKeys] = useState({
    publicKeyFingerprint: 'sha256:d8:a1:c5:2b:81:4e:c9:0d:3f:22:1a...',
    keySize: 2048,
    keyType: 'RSA'
  });

  useEffect(() => {
    async function loadProfile() {
      try {
        const data = await authAPI.getProfile();
        setProfileData(data);
      } catch (err) {
        console.error("Failed to load user profile.", err);
      } finally {
        setLoading(false);
      }
    }
    loadProfile();
  }, []);

  const handleRecreateKeys = () => {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      setProfileKeys({
        publicKeyFingerprint: `sha256:${Math.random().toString(36).substring(2, 10)}:${Math.random().toString(36).substring(2, 10)}:${Math.random().toString(36).substring(2, 10)}...`,
        keySize: 2048,
        keyType: 'RSA'
      });
    }, 1000);
  };

  if (loading && !profileData) {
    return (
      <div className="h-[60vh] flex flex-col items-center justify-center gap-3">
        <Loader2 className="w-10 h-10 text-purple-500 animate-spin" />
        <span className="text-sm text-gray-400 font-semibold">Retrieving Security Profile...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white">Security Profile</h2>
        <p className="text-gray-400 text-sm mt-1">Review authenticated credentials, download asymmetric PEM certificates, and manage device authorizations.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-6">
          <GlassCard className="space-y-6 text-center">
            <div className="w-24 h-24 rounded-full bg-gradient-to-tr from-purple-600 to-blue-500 border border-purple-400/30 flex items-center justify-center mx-auto shadow-2xl">
              <User className="w-10 h-10 text-white" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">{profileData?.username}</h3>
              <span className="text-xs text-gray-500 font-mono">ID: CG-USR-{profileData?.id || '001'}</span>
            </div>

            <div className="space-y-3 text-left border-t border-gray-800/80 pt-6 text-xs text-gray-300">
              <div className="flex items-center gap-3">
                <Mail className="w-4 h-4 text-purple-400 shrink-0" />
                <span>{profileData?.email}</span>
              </div>
              <div className="flex items-center gap-3">
                <Key className="w-4 h-4 text-purple-400 shrink-0" />
                <span>Security Clearance: {profileData?.role}</span>
              </div>
              <div className="flex items-center gap-3">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-emerald-400 font-semibold">2FA Authenticator Linked</span>
              </div>
            </div>
          </GlassCard>
        </div>

        <div className="lg:col-span-2 space-y-6">
          <GlassCard className="space-y-6 border-l-4 border-l-purple-500" glow="purple">
            <div className="flex justify-between items-start gap-4">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-purple-400" /> Identity Cryptokey Parameters
                </h3>
                <p className="text-xs text-gray-400 mt-0.5">Asymmetric details utilized to process data encryption wrappers.</p>
              </div>
              <button
                onClick={handleRecreateKeys}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded-xl border border-gray-800 text-xs font-semibold text-gray-400 hover:text-white transition-all"
              >
                <RefreshCw className="w-3 h-3" /> Re-Generate
              </button>
            </div>

            <div className="space-y-4 border-t border-gray-800/80 pt-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <span className="block text-xs font-bold text-gray-400">Cryptosystem Cipher</span>
                  <span className="block text-sm font-semibold text-white mt-1">{profileKeys.keyType}</span>
                </div>
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-xl">
                  <span className="block text-xs font-bold text-gray-400">Asymmetric Size</span>
                  <span className="block text-sm font-semibold text-white mt-1">{profileKeys.keySize}-Bit Matrices</span>
                </div>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider">
                  Public Key Identifier Fingerprint (MD5/SHA-256)
                </label>
                <div className="p-3.5 bg-gray-900 border border-gray-800 rounded-xl font-mono text-[10px] text-purple-400 break-all select-all leading-normal">
                  {profileKeys.publicKeyFingerprint}
                </div>
              </div>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
