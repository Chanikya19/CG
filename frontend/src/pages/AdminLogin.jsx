import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Key, Eye, EyeOff, ShieldAlert, Mail } from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { authAPI } from '../services/api';

export default function AdminLogin() {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    
    // Client-side validations
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid administrative email address.');
      setLoading(false);
      return;
    }

    if (password.length < 1) {
      setError('Access key passphrase is required.');
      setLoading(false);
      return;
    }

    try {
      const data = await authAPI.adminLogin(email, password, rememberMe);
      if (data.token) {
        setSuccess('Administrator authentication successful. Loading Command Vault...');
        setTimeout(() => {
          navigate('/admin/dashboard');
        }, 1200);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication credentials rejected. Access denied.');
    } finally {
      if (!success) {
        setLoading(false);
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative bg-[#020617] cyber-grid px-4">
      {/* Background radial effects */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full bg-purple-600/10 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 rounded-full bg-blue-600/10 blur-[120px] pointer-events-none"></div>

      <div className="w-full max-w-md">
        {/* Header Branding */}
        <div className="flex flex-col items-center mb-8">
          <div className="p-3.5 bg-gradient-to-tr from-purple-600 to-red-500 rounded-2xl border border-purple-400/20 shadow-2xl mb-4 animate-pulse">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white">
            Cipher<span className="text-red-400">Admin</span>
          </h1>
          <p className="text-gray-500 text-xs mt-1 uppercase font-mono tracking-widest">
            DLP Secure Command Gateway
          </p>
        </div>

        {/* Auth Panel */}
        <GlassCard className="p-8 shadow-2xl border-white/5" glow="red">
          {error && (
            <div className="mb-5 p-3.5 bg-rose-500/5 border border-rose-500/10 rounded-xl text-xs text-rose-400 flex items-center gap-2">
              <ShieldAlert className="w-4.5 h-4.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="mb-5 p-3.5 bg-emerald-500/5 border border-emerald-500/10 rounded-xl text-xs text-emerald-400 flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block animate-ping shrink-0"></span>
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Admin Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                <input
                  type="email"
                  required
                  placeholder="admin@cipherguard.io"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-xl glass-input text-sm text-gray-200"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Access Key (Password)
              </label>
              <div className="relative">
                <Key className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-11 py-3 rounded-xl glass-input text-sm text-gray-200"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-2 cursor-pointer text-gray-400 hover:text-white select-none">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded border-gray-800 bg-gray-900 text-red-600 focus:ring-red-500/30"
                />
                <span>Remember Credentials</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 rounded-xl bg-gradient-to-r from-red-600 to-purple-600 hover:from-red-500 hover:to-purple-500 text-sm font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 disabled:opacity-50"
            >
              {loading ? 'Decrypting Credentials...' : 'Authenticate Admin'}
            </button>
          </form>
        </GlassCard>
      </div>
    </div>
  );
}
