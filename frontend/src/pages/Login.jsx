import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Key, Eye, EyeOff, ShieldAlert, Mail } from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { authAPI } from '../services/api';

export default function Login() {
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
      setError('Please enter a valid secure communication email address.');
      setLoading(false);
      return;
    }

    if (password.length < 1) {
      setError('Access key passphrase is required.');
      setLoading(false);
      return;
    }

    try {
      const data = await authAPI.login(email, password, rememberMe);
      if (data.token) {
        setSuccess('Authentication successful. Establishing secure link...');
        setTimeout(() => {
          navigate('/dashboard');
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
          <div className="p-3.5 bg-gradient-to-tr from-purple-600 to-blue-500 rounded-2xl border border-purple-400/20 shadow-2xl mb-4">
            <Shield className="w-8 h-8 text-white animate-pulse" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white">
            Cipher<span className="text-purple-400">Guard</span>
          </h1>
          <p className="text-gray-500 text-xs mt-1 uppercase font-mono tracking-widest">
            Intelligent Hybrid Encryption
          </p>
        </div>

        {/* Auth Panel */}
        <GlassCard className="p-8 shadow-2xl border-white/5" glow="purple">
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
                Secure Email Address
              </label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                <input
                  type="email"
                  required
                  placeholder="operator@cipherguard.io"
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
                  className="rounded border-gray-800 bg-gray-900 text-purple-600 focus:ring-purple-500/30"
                />
                <span>Remember Credentials</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-sm font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 disabled:opacity-50"
            >
              {loading ? 'Decrypting Credentials...' : 'Authenticate Operator'}
            </button>
          </form>
        </GlassCard>

        {/* Footer info links */}
        <p className="text-center text-xs text-gray-500 mt-8">
          Need database access?{' '}
          <Link to="/register" className="text-purple-400 font-semibold hover:underline">
            Register Security Profile
          </Link>
        </p>
      </div>
    </div>
  );
}
