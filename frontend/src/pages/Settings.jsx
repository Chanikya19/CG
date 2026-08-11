import React, { useState } from 'react';
import { 
  Settings as SettingsIcon, 
  ShieldAlert, 
  Lock, 
  ToggleLeft, 
  ToggleRight, 
  Sliders, 
  CheckCircle,
  Eye,
  Key
} from 'lucide-react';
import GlassCard from '../components/GlassCard';

export default function Settings() {
  const [mfaEnabled, setMfaEnabled] = useState(true);
  const [dlpLevel, setDlpLevel] = useState(80); // 80% scan threshold
  const [defaultAlgo, setDefaultAlgo] = useState('AES-256-GCM');
  const [showSaved, setShowSaved] = useState(false);

  const saveSettings = (e) => {
    e.preventDefault();
    setShowSaved(true);
    setTimeout(() => setShowSaved(false), 2000);
  };

  const getDlpLabel = (val) => {
    if (val < 40) return 'Low Risk Protection (Basic Scans)';
    if (val < 75) return 'Medium Risk Standard (Monitors common PII / IP)';
    return 'Aggressive Level (Flags any potential key/hash/token sequence)';
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white">System Settings</h2>
        <p className="text-gray-400 text-sm mt-1">Configure global cryptosystem defaults, DLP sensitivities, and operator authentication protocols.</p>
      </div>

      <form onSubmit={saveSettings} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Form: Settings parameters */}
        <div className="lg:col-span-2 space-y-6">
          <GlassCard className="space-y-6">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Sliders className="w-5 h-5 text-purple-400" /> Data Leak Prevention (DLP) Policies
            </h3>

            {/* DLP scan slider */}
            <div className="space-y-3 border-b border-gray-800/80 pb-6">
              <div className="flex justify-between items-center text-xs font-semibold text-gray-400">
                <label className="uppercase tracking-wider">Rule Severity Threshold</label>
                <span className="text-purple-400 font-mono">{dlpLevel}% Sensitivity</span>
              </div>
              <input
                type="range"
                min="10"
                max="100"
                value={dlpLevel}
                onChange={(e) => setDlpLevel(Number(e.target.value))}
                className="w-full h-1 bg-gray-900 rounded-lg appearance-none cursor-pointer accent-purple-500"
              />
              <div className="flex justify-between items-center text-[10px] text-gray-500 font-mono">
                <span>10% (Permissive)</span>
                <span>100% (Strict Block)</span>
              </div>
              <div className="p-3 bg-purple-500/5 border border-purple-500/10 rounded-xl text-xs text-purple-300">
                <strong>Active Mode:</strong> {getDlpLabel(dlpLevel)}
              </div>
            </div>

            {/* RegEx parameters */}
            <div className="space-y-4">
              <span className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Matching Rules Configuration
              </span>
              
              <div className="space-y-3 text-xs">
                <label className="flex items-center justify-between p-3.5 bg-white/5 border border-gray-800 rounded-xl cursor-pointer">
                  <div>
                    <span className="font-bold text-white block">Personally Identifiable Information (PII)</span>
                    <span className="text-gray-500 text-[10px] block mt-0.5">Scans for pattern matches of SSN, Credit Cards, Driver licenses.</span>
                  </div>
                  <input type="checkbox" defaultChecked className="rounded bg-gray-900 border-gray-800 text-purple-600 focus:ring-purple-500/30" />
                </label>

                <label className="flex items-center justify-between p-3.5 bg-white/5 border border-gray-800 rounded-xl cursor-pointer">
                  <div>
                    <span className="font-bold text-white block">Credential / Key Leaks</span>
                    <span className="text-gray-500 text-[10px] block mt-0.5">Identifies private cryptographic files, password hashes, or API secrets.</span>
                  </div>
                  <input type="checkbox" defaultChecked className="rounded bg-gray-900 border-gray-800 text-purple-600 focus:ring-purple-500/30" />
                </label>

                <label className="flex items-center justify-between p-3.5 bg-white/5 border border-gray-800 rounded-xl cursor-pointer">
                  <div>
                    <span className="font-bold text-white block">Intellectual Property Indicators</span>
                    <span className="text-gray-500 text-[10px] block mt-0.5">Matches trademark codes, patent proposals, or source code directories.</span>
                  </div>
                  <input type="checkbox" defaultChecked className="rounded bg-gray-900 border-gray-800 text-purple-600 focus:ring-purple-500/30" />
                </label>
              </div>
            </div>
          </GlassCard>

          {/* Cryptographic Defaults */}
          <GlassCard className="space-y-6">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-blue-400" /> Default Cryptographic Settings
            </h3>

            <div className="space-y-4">
              <div className="space-y-2">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Default Symmetric Cipher
                </label>
                <select 
                  value={defaultAlgo}
                  onChange={(e) => setDefaultAlgo(e.target.value)}
                  className="w-full py-2.5 px-3 rounded-xl glass-input text-xs text-gray-300"
                >
                  <option value="AES-256-GCM">AES-256-GCM (Authenticated Envelope)</option>
                  <option value="ChaCha20-Poly1305">ChaCha20-Poly1305 (Fast Stream)</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Key Derivation Iterations (PBKDF2 Hashing)
                </label>
                <select className="w-full py-2.5 px-3 rounded-xl glass-input text-xs text-gray-300">
                  <option value="100k">100,000 Iterations (Recommended)</option>
                  <option value="200k">200,000 Iterations (High Security)</option>
                  <option value="50k">50,000 Iterations (Legacy Speed)</option>
                </select>
              </div>
            </div>
          </GlassCard>
        </div>

        {/* Right Side: Security Actions */}
        <div className="space-y-6">
          <GlassCard className="space-y-6">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-purple-400" /> Session & MFA Settings
            </h3>

            {/* Toggle 2FA */}
            <div className="flex items-center justify-between p-3.5 bg-white/5 border border-gray-800 rounded-xl">
              <div>
                <span className="text-xs font-bold text-white block">Multi-Factor Authenticator</span>
                <span className="text-gray-500 text-[10px] block mt-0.5">Enforces 6-digit dynamic codes upon login.</span>
              </div>
              <button 
                type="button"
                onClick={() => setMfaEnabled(!mfaEnabled)}
                className="text-purple-400 hover:text-purple-300 transition-all shrink-0"
              >
                {mfaEnabled ? <ToggleRight className="w-8 h-8" /> : <ToggleLeft className="w-8 h-8 text-gray-600" />}
              </button>
            </div>

            {/* Session Expiry */}
            <div className="space-y-2">
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Session Token Invalidation (Idle Time)
              </label>
              <select className="w-full py-2 px-3 rounded-xl glass-input text-xs text-gray-300">
                <option value="15">15 Minutes</option>
                <option value="30">30 Minutes (Standard)</option>
                <option value="60">1 Hour</option>
              </select>
            </div>
          </GlassCard>

          {/* Action buttons */}
          <div className="space-y-3">
            <button
              type="submit"
              className="w-full py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 flex items-center justify-center gap-2"
            >
              Apply Global Policies
            </button>

            {showSaved && (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl text-xs font-semibold text-center animate-fadeIn">
                ✓ Global policy values updated successfully
              </div>
            )}
          </div>
        </div>
      </form>
    </div>
  );
}
