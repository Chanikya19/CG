import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ToastProvider } from './components/ToastNotification';

// Layout
import DashboardLayout from './layout/DashboardLayout';

// Components
import ProtectedRoute from './components/ProtectedRoute';

// Pages
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import UploadFile from './pages/UploadFile';
import FileDetails from './pages/FileDetails';
import EncryptionStatus from './pages/EncryptionStatus';
import SecureSharing from './pages/SecureSharing';
import ActivityLogs from './pages/ActivityLogs';
import Profile from './pages/Profile';
import FileVerification from './pages/FileVerification';
import SharedLinkResolver from './pages/SharedLinkResolver';
import Analytics from './pages/Analytics';
import SecurityReports from './pages/SecurityReports';
import Settings from './pages/Settings';

export default function App() {
  return (
    <ToastProvider>
      <Router>
        <Routes>

        {/* Auth Routes (Unauthenticated Layout) */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Dashboard Routes (Wrapped in DashboardLayout and ProtectedRoute) */}
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <DashboardLayout>
              <Dashboard />
            </DashboardLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/upload" element={
          <ProtectedRoute>
            <DashboardLayout>
              <UploadFile />
            </DashboardLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/file-details" element={
          <ProtectedRoute>
            <DashboardLayout>
              <FileDetails />
            </DashboardLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/encryption-status" element={
          <ProtectedRoute>
            <DashboardLayout>
              <EncryptionStatus />
            </DashboardLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/verify" element={
          <ProtectedRoute>
            <DashboardLayout>
              <FileVerification />
            </DashboardLayout>
          </ProtectedRoute>
        } />

        <Route path="/share" element={
          <ProtectedRoute>
            <DashboardLayout>
              <SecureSharing />
            </DashboardLayout>
          </ProtectedRoute>
        } />

        <Route path="/shared/:token" element={<SharedLinkResolver />} />
        
        <Route path="/logs" element={
          <ProtectedRoute>
            <DashboardLayout>
              <ActivityLogs />
            </DashboardLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/analytics" element={
          <ProtectedRoute>
            <DashboardLayout>
              <Analytics />
            </DashboardLayout>
          </ProtectedRoute>
        } />

        <Route path="/reports" element={
          <ProtectedRoute>
            <DashboardLayout>
              <SecurityReports />
            </DashboardLayout>
          </ProtectedRoute>
        } />

        <Route path="/profile" element={
          <ProtectedRoute>
            <DashboardLayout>
              <Profile />
            </DashboardLayout>
          </ProtectedRoute>
        } />
        
        <Route path="/settings" element={
          <ProtectedRoute>
            <DashboardLayout>
              <Settings />
            </DashboardLayout>
          </ProtectedRoute>
        } />

        {/* Fallbacks */}
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
      </Router>
    </ToastProvider>
  );
}
