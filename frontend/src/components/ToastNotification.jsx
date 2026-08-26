import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, X } from 'lucide-react';

const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((type, message, duration = 5000) => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, type, message }]);

    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, duration);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      {/* Toast container */}
      <div 
        className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none"
        role="log"
        aria-live="polite"
      >
        {toasts.map((toast) => {
          let bgClass = '';
          let borderClass = '';
          let textClass = '';
          let Icon = CheckCircle2;

          if (toast.type === 'success') {
            bgClass = 'bg-emerald-950/80 backdrop-blur-md';
            borderClass = 'border-emerald-500/30';
            textClass = 'text-emerald-400';
            Icon = CheckCircle2;
          } else if (toast.type === 'error') {
            bgClass = 'bg-rose-950/80 backdrop-blur-md';
            borderClass = 'border-rose-500/30';
            textClass = 'text-rose-400';
            Icon = XCircle;
          } else if (toast.type === 'warning') {
            bgClass = 'bg-amber-950/80 backdrop-blur-md';
            borderClass = 'border-amber-500/30';
            textClass = 'text-amber-400';
            Icon = AlertTriangle;
          }

          return (
            <div
              key={toast.id}
              className={`p-4 rounded-xl border ${bgClass} ${borderClass} shadow-xl flex items-start gap-3 pointer-events-auto transition-all duration-300 transform translate-y-0 animate-slideIn`}
              role="alert"
            >
              <Icon className={`w-5 h-5 shrink-0 ${textClass}`} />
              <div className="flex-1 text-xs font-semibold text-gray-105 leading-normal">
                {toast.message}
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="p-0.5 rounded-lg text-gray-500 hover:text-white hover:bg-white/5 transition-all shrink-0"
                aria-label="Close notification"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
