import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  UploadCloud, 
  Key, 
  Share2, 
  FileText, 
  User, 
  Settings as SettingsIcon, 
  LogOut, 
  Activity,
  Bell,
  Search,
  Globe,
  ShieldCheck,
  BarChart3,
  AlertTriangle,
  Menu,
  X
} from 'lucide-react';
import { authAPI } from '../services/api';

export default function DashboardLayout({ children }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  
  const userString = localStorage.getItem('cipherguard_user') || sessionStorage.getItem('cipherguard_user');
  const user = userString ? JSON.parse(userString) : null;
  const displayName = user?.full_name || 'Security Operator';
  const displayInitials = displayName.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() || 'CG';
  
  const allMenuItems = [
    { name: 'Admin Dashboard', path: '/admin/dashboard', icon: Activity, adminOnly: true },
    { name: 'Dashboard', path: '/dashboard', icon: Activity, userOnly: true },
    { name: 'Upload File', path: '/upload', icon: UploadCloud, userOnly: true },
    { name: 'File Integrity', path: '/verify', icon: ShieldCheck, userOnly: true },
    { name: 'Encryption Status', path: '/encryption-status', icon: Key, userOnly: true },
    { name: 'Secure Sharing', path: '/share', icon: Share2, userOnly: true },
    { name: 'Analytics', path: '/analytics', icon: BarChart3, userOnly: true },
    { name: 'Security Reports', path: '/reports', icon: AlertTriangle, adminOnly: true },
    { name: 'Activity Logs', path: '/logs', icon: FileText },
    { name: 'Profile', path: '/profile', icon: User },
    { name: 'Settings', path: '/settings', icon: SettingsIcon },
  ];

  const menuItems = allMenuItems.filter(item => {
    if (item.adminOnly && user?.role !== 'admin') return false;
    if (item.userOnly && user?.role === 'admin') return false;
    return true;
  });

  const handleLogout = () => {
    const isAdmin = user?.role === 'admin';
    authAPI.logout();
    if (isAdmin) {
      navigate('/admin/login');
    } else {
      navigate('/login');
    }
  };

  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);
  const closeSidebar = () => setIsSidebarOpen(false);

  return (
    <div className="min-h-screen flex text-gray-100 bg-[#030712] cyber-grid">
      {/* Backdrop overlay on mobile */}
      {isSidebarOpen && (
        <div 
          onClick={closeSidebar}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-20 lg:hidden transition-opacity duration-300"
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside 
        className={`w-64 glass-panel border-r border-gray-800 flex flex-col justify-between p-4 fixed lg:sticky top-0 h-screen z-30 transition-transform duration-300 ${
          isSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
        aria-label="Sidebar navigation"
        aria-hidden={!isSidebarOpen}
      >
        <div>
          {/* Logo */}
          <div className="flex items-center justify-between px-3 py-4 mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-tr from-purple-600 to-blue-500 rounded-xl shadow-lg border border-purple-400/20">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <span className="text-xl font-bold tracking-tight text-white">Cipher<span className="text-purple-400">Guard</span></span>
                <span className="block text-[10px] text-gray-500 font-mono tracking-widest uppercase">Intelligent DLP</span>
              </div>
            </div>
            {/* Close button on mobile */}
            <button 
              onClick={closeSidebar}
              className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all lg:hidden"
              aria-label="Close sidebar menu"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Menu Items */}
          <nav className="space-y-1" role="navigation">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path || (item.path === '/dashboard' && location.pathname.startsWith('/file-details'));
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  onClick={closeSidebar}
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group relative ${
                    isActive 
                      ? 'bg-gradient-to-r from-purple-600/20 to-blue-600/10 border-l-4 border-purple-500 text-white font-medium' 
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <Icon className={`w-5 h-5 transition-transform duration-200 group-hover:scale-110 ${isActive ? 'text-purple-400' : 'text-gray-400'}`} />
                  <span className="text-sm">{item.name}</span>
                  {isActive && (
                    <span className="absolute right-3 w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse"></span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* User profile footer info / Logout */}
        <div className="border-t border-gray-800/80 pt-4">
          <div className="flex items-center justify-between mb-3 px-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-purple-500/20 flex items-center justify-center border border-purple-500/30">
                <span className="text-xs font-semibold text-purple-300">{displayInitials}</span>
              </div>
              <div className="max-w-[120px] overflow-hidden">
                <span className="block text-xs font-semibold text-white truncate" title={displayName}>{displayName}</span>
                <span className="block text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block animate-ping"></span> SECURED
                </span>
              </div>
            </div>
          </div>
          <button 
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-gray-400 hover:text-rose-400 hover:bg-rose-500/5 transition-all text-sm font-medium"
            aria-label="Log out of session"
          >
            <LogOut className="w-4 h-4" />
            <span>Terminate Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-h-screen w-full overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 glass-panel border-b border-gray-800 flex items-center justify-between px-4 sm:px-8 sticky top-0 z-10">
          <div className="flex items-center gap-3">
            {/* Hamburger trigger on mobile */}
            <button 
              onClick={toggleSidebar}
              className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all lg:hidden"
              aria-label="Toggle navigation menu"
              aria-expanded={isSidebarOpen}
            >
              <Menu className="w-5 h-5" />
            </button>
            <span className="text-sm text-gray-400 font-medium hidden sm:inline">Network Health:</span>
            <span className="px-2 py-0.5 text-xs rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5">
              <Globe className="w-3 h-3 inline animate-pulse" /> <span className="hidden xs:inline">Threat Level</span> Low
            </span>
          </div>

          <div className="flex items-center gap-4 sm:gap-6">
            {/* Search */}
            <div className="relative hidden md:block">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input 
                type="text" 
                placeholder="Search audit trail or file vault..." 
                className="pl-9 pr-4 py-1.5 text-xs w-48 lg:w-60 rounded-lg glass-input text-gray-300 focus:w-64 lg:focus:w-80 transition-all"
                aria-label="Search"
              />
            </div>

            {/* Notification triggers */}
            <button 
              className="relative p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all"
              aria-label="Open notifications"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-purple-500 ring-2 ring-gray-950"></span>
            </button>

            <div className="h-6 w-px bg-gray-800"></div>

            {/* Status indicators */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400 hidden xs:inline">Keys Secured:</span>
              <span className="text-xs font-mono font-bold text-purple-400">14 Active</span>
            </div>
          </div>
        </header>

        {/* View Port Content */}
        <main className="flex-1 p-4 sm:p-8 overflow-y-auto max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
