import React from 'react';
import { Navigate } from 'react-router-dom';

/**
 * Route wrapper that redirects unauthenticated requests back to the Login gateway.
 * Checks for security session token in local or session persistent scope.
 */
export default function ProtectedRoute({ children }) {
  const token = localStorage.getItem('cipherguard_token') || sessionStorage.getItem('cipherguard_token');
  
  if (!token) {
    // Redirect operator to authenticating checkpoint
    return <Navigate to="/login" replace />;
  }
  
  return children;
}
