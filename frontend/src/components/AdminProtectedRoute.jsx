import React from 'react';
import { Navigate } from 'react-router-dom';

/**
 * Route wrapper that redirects unauthenticated users or non-admin users.
 * Checks for security session token and admin role.
 */
export default function AdminProtectedRoute({ children }) {
  const token = localStorage.getItem('cipherguard_token') || sessionStorage.getItem('cipherguard_token');
  const userString = localStorage.getItem('cipherguard_user') || sessionStorage.getItem('cipherguard_user');
  const user = userString ? JSON.parse(userString) : null;

  if (!token) {
    return <Navigate to="/admin/login" replace />;
  }

  if (!user || user.role !== 'admin') {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}
