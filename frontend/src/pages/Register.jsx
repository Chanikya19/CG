import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Key, Eye, EyeOff, User, Mail, Database, DownloadCloud, ShieldAlert } from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { authAPI } from '../services/api';

export default function Register() {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [registered, setRegistered] = useState(false);
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [keysResponse, setKeysResponse] = useState(null);

  // Password strength checks
  const [checks, setChecks] = useState({
    length: false,
    upper: false,
    lower: false,
    number: false,
    special: false
  });

  useEffect(() => {
    setChecks({
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password)
    });
  }, [password]);

  const isPasswordValid = Object.values(checks).every(Boolean);

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Extra validations
    if (fullName.trim().length < 2) {
      setError('Full name must be at least 2 characters long.');
      setLoading(false);
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid secure communication email.');
      setLoading(false);
      return;
    }

    if (!isPasswordValid) {
      setError('Passphrase does not meet all secure cryptographic requirements.');
      setLoading(false);
      return;
    }

    try {
      const data = await authAPI.register(fullName, email, password);
      setKeysResponse({
        publicKey: data.public_key,
        privateKey: data.private_key
      });
      setRegistered(true);
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed. System rejected profile parameters.');
    } finally {
      setLoading(false);
    }
  };

  const handleRedirect = () => {
    navigate('/login');
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative bg-[#020617] cyber-grid px-4">
      {/* Background radial effects */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full bg-purple-600/10 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 rounded-full bg-blue-600/10 blur-[120px] pointer-events-none"></div>

      <div className="w-full max-w-md my-8">
        {/* Header Branding */}
        <div className="flex flex-col items-center mb-6">
          <div className="p-3.5 bg-gradient-to-tr from-purple-600 to-blue-500 rounded-2xl border border-purple-400/20 shadow-2xl mb-3">
            <Shield className="w-8 h-8 text-white" />
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
            <div className="mb-4 p-3 bg-rose-500/5 border border-rose-500/10 rounded-xl text-xs text-rose-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!registered ? (
            <form onSubmit={handleRegister} className="space-y-5">
              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                  Full Name
                </label>
                <div className="relative">
                  <User className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                  <input
                    type="text"
                    required
                    placeholder="e.g. Harsha Vardhan"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl glass-input text-sm text-gray-200"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                  Secure Communication Email
                </label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                  <input
                    type="email"
                    required
                    placeholder="admin@cipherguard.io"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl glass-input text-sm text-gray-200"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                  Master Passphrase (Password)
                </label>
                <div className="relative">
                  <Key className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500 w-4 h-4" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-10 pr-11 py-2.5 rounded-xl glass-input text-sm text-gray-200"
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

              {/* Real-time Password Strength Check */}
              {password && (
                <div className="p-3 bg-slate-900/50 border border-white/5 rounded-xl text-xs space-y-1.5">
                  <span className="font-semibold text-gray-400 block mb-1">Passphrase Integrity Requirements:</span>
                  <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[11px]">
                    <span className={checks.length ? 'text-emerald-400' : 'text-gray-500'}>
                      {checks.length ? '✓' : '•'} Min 8 Characters
                    </span>
                    <span className={checks.upper ? 'text-emerald-400' : 'text-gray-500'}>
                      {checks.upper ? '✓' : '•'} Uppercase Letter (A-Z)
                    </span>
                    <span className={checks.lower ? 'text-emerald-400' : 'text-gray-500'}>
                      {checks.lower ? '✓' : '•'} Lowercase Letter (a-z)
                    </span>
                    <span className={checks.number ? 'text-emerald-400' : 'text-gray-500'}>
                      {checks.number ? '✓' : '•'} Numerical Digit (0-9)
                    </span>
                    <span className={checks.special ? 'text-emerald-400' : 'text-gray-500'}>
                      {checks.special ? '✓' : '•'} Special Symbol (!@#$)
                    </span>
                  </div>
                </div>
              )}

              {/* Hybrid Cryptosystem setup notification */}
              <div className="p-3 bg-purple-500/5 rounded-xl border border-purple-500/10 space-y-1 text-xs">
                <span className="font-bold text-purple-300 block flex items-center gap-1">
                  <Database className="w-3.5 h-3.5" /> Asymmetric Keypair Integration
                </span>
                <span className="text-gray-400 leading-normal">
                  Our system will auto-generate your asymmetric 2048-bit RSA keys upon registration for secure file sharing.
                </span>
              </div>

              <button
                type="submit"
                disabled={loading || (password.length > 0 && !isPasswordValid)}
                className="w-full py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-sm font-semibold tracking-wider text-white transition-all shadow-lg active:scale-95 disabled:opacity-30"
              >
                {loading ? 'Compiling Encryption Matrices...' : 'Generate Profile'}
              </button>
            </form>
          ) : (
            <div className="space-y-6 text-center">
              <div className="w-12 h-12 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
                ✓
              </div>
              <div className="space-y-2">
                <h3 className="text-base font-bold text-white">Cryptosystem Registered</h3>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Your security profile was generated successfully. Your asymmetric private/public keys are ready. Download them for secure vault integration.
                </p>
              </div>

              <div className="flex gap-2">
                <a 
                  href={`data:text/plain;charset=utf-8,${encodeURIComponent(keysResponse?.publicKey)}`}
                  download="cipherguard_public.pem"
                  className="flex-1 py-2 px-3 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/25 rounded-xl text-xs font-semibold text-purple-300 flex items-center justify-center gap-1.5"
                >
                  <DownloadCloud className="w-3.5 h-3.5" /> Public Pem
                </a>
                <a 
                  href={`data:text/plain;charset=utf-8,${encodeURIComponent(keysResponse?.privateKey)}`}
                  download="cipherguard_private.pem"
                  className="flex-1 py-2 px-3 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/25 rounded-xl text-xs font-semibold text-blue-300 flex items-center justify-center gap-1.5"
                >
                  <DownloadCloud className="w-3.5 h-3.5" /> Private Pem
                </a>
              </div>

              <button
                onClick={handleRedirect}
                className="w-full py-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-xs font-semibold tracking-wider text-white transition-all shadow-lg"
              >
                Proceed to Login
              </button>
            </div>
          )}
        </GlassCard>

        {/* Footer info links */}
        <p className="text-center text-xs text-gray-500 mt-6">
          Already registered?{' '}
          <Link to="/login" className="text-purple-400 font-semibold hover:underline">
            Initiate Session
          </Link>
        </p>
      </div>
    </div>
  );
}
