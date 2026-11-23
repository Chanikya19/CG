import React, { useState, useEffect, useRef } from 'react';
import { Bell, ShieldAlert, Check, RefreshCw } from 'lucide-react';
import { notificationsAPI } from '../services/api';

export default function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const containerRef = useRef(null);

  // Get current user role
  const userStr = localStorage.getItem('cipherguard_user') || sessionStorage.getItem('cipherguard_user');
  const user = userStr ? JSON.parse(userStr) : null;
  const isAdmin = user && user.role === 'admin';

  const fetchNotificationData = async () => {
    try {
      setLoading(true);
      if (isAdmin) {
        // Admins fetch global admin alerts
        const data = await notificationsAPI.getAdminAlerts();
        setNotifications(data);
        const countData = await notificationsAPI.getAdminUnreadCount();
        setUnreadCount(countData.unread_count);
      } else {
        // Users fetch personal notifications
        const data = await notificationsAPI.getNotifications();
        setNotifications(data.notifications || []);
        setUnreadCount(data.unread_count || 0);
      }
    } catch (err) {
      console.error("Failed to load notifications:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotificationData();

    // Poll for notifications every 30 seconds
    const interval = setInterval(() => {
      fetchNotificationData();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  // Handle clicking outside to close
  useEffect(() => {
    function handleClickOutside(event) {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleToggle = () => {
    setIsOpen(!isOpen);
    if (!isOpen) {
      fetchNotificationData();
    }
  };

  const handleMarkAsRead = async (id, e) => {
    e.stopPropagation();
    try {
      if (isAdmin) {
        await notificationsAPI.markAdminRead(id);
      } else {
        await notificationsAPI.markRead(id);
      }
      // Update state local view
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, is_read: true } : n))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch (err) {
      console.error("Failed to mark read:", err);
    }
  };

  const handleResolveAlert = async (id, e) => {
    e.stopPropagation();
    try {
      await notificationsAPI.resolveAdminAlert(id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, status: 'resolved', is_read: true } : n))
      );
      // Recalculate unread count
      const countData = await notificationsAPI.getAdminUnreadCount();
      setUnreadCount(countData.unread_count);
    } catch (err) {
      console.error("Failed to resolve alert:", err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      if (!isAdmin) {
        await notificationsAPI.markAllRead();
        setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
        setUnreadCount(0);
      }
    } catch (err) {
      console.error("Failed to mark all read:", err);
    }
  };

  const getSeverityBadge = (severity) => {
    let classes = "";
    switch (severity) {
      case "CRITICAL":
        classes = "bg-rose-950/40 text-rose-400 border-rose-500/30";
        break;
      case "HIGH":
        classes = "bg-orange-950/40 text-orange-400 border-orange-500/30";
        break;
      case "MEDIUM":
        classes = "bg-amber-950/40 text-amber-400 border-amber-500/30";
        break;
      case "LOW":
        classes = "bg-blue-950/40 text-blue-400 border-blue-500/30";
        break;
      case "INFO":
      default:
        classes = "bg-emerald-950/40 text-emerald-400 border-emerald-500/30";
        break;
    }
    return (
      <span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${classes}`}>
        {severity}
      </span>
    );
  };

  return (
    <div className="relative" ref={containerRef} id="notification-center-widget">
      {/* Trigger Bell Button */}
      <button
        onClick={handleToggle}
        className="relative p-2 rounded-xl text-gray-400 hover:text-white hover:bg-white/5 border border-white/5 transition-all duration-200"
        aria-label="Toggle notifications"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute top-0 right-0 transform translate-x-1 -translate-y-1 bg-red-500 text-white font-bold text-[10px] px-1.5 py-0.5 rounded-full ring-2 ring-slate-950">
            {unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Menu Container */}
      {isOpen && (
        <div className="absolute right-0 mt-3 w-80 max-h-[480px] flex flex-col bg-slate-900/95 backdrop-blur-lg border border-slate-700/50 rounded-2xl shadow-2xl z-50 overflow-hidden animate-fadeIn">
          {/* Header Panel */}
          <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-semibold text-gray-100">
                {isAdmin ? "Admin Security Center" : "Notifications"}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={fetchNotificationData}
                className="p-1 text-gray-500 hover:text-white hover:bg-slate-800 rounded"
                title="Refresh alerts"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
              {!isAdmin && unreadCount > 0 && (
                <button
                  onClick={handleMarkAllRead}
                  className="text-xs text-emerald-400 hover:text-emerald-300 font-medium"
                >
                  Mark all read
                </button>
              )}
            </div>
          </div>

          {/* Alert Cards Container */}
          <div className="flex-1 overflow-y-auto max-h-[360px] divide-y divide-slate-800/50">
            {loading && notifications.length === 0 ? (
              <div className="p-8 text-center text-xs text-gray-500">
                Loading notifications...
              </div>
            ) : notifications.length === 0 ? (
              <div className="p-8 text-center text-xs text-gray-500">
                No recent security notifications.
              </div>
            ) : (
              notifications.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-4 text-left transition-all ${
                    !alert.is_read ? 'bg-white/[0.02]' : 'opacity-65'
                  }`}
                >
                  {/* Card Title Header */}
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <span className="text-xs font-bold text-gray-200 leading-tight">
                      {alert.title || alert.alert_type}
                    </span>
                    <div className="flex items-center gap-1 shrink-0">
                      {getSeverityBadge(alert.severity)}
                    </div>
                  </div>

                  {/* Message body */}
                  <p className="text-xs font-semibold text-gray-400 leading-relaxed mb-2.5 break-words">
                    {alert.message}
                  </p>

                  {/* Metadata and control buttons */}
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] text-gray-500 font-medium">
                      {alert.created_at}
                    </span>

                    <div className="flex items-center gap-2">
                      {/* Mark read button (if unread) */}
                      {!alert.is_read && (
                        <button
                          onClick={(e) => handleMarkAsRead(alert.id, e)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-gray-400 hover:text-white transition-all"
                          title="Mark as read"
                        >
                          <Check className="w-3.5 h-3.5" />
                        </button>
                      )}

                      {/* Admin Incident Resolution action */}
                      {isAdmin && alert.status !== 'resolved' && (
                        <button
                          onClick={(e) => handleResolveAlert(alert.id, e)}
                          className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/40 hover:bg-emerald-950/80 text-emerald-400 border border-emerald-500/30 hover:border-emerald-500/50 transition-all font-semibold"
                        >
                          Resolve
                        </button>
                      )}
                      
                      {isAdmin && alert.status === 'resolved' && (
                        <span className="text-[10px] text-emerald-500 font-bold bg-emerald-950/20 px-1.5 py-0.5 rounded">
                          Resolved
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
