import axios from 'axios';

// Create Axios client linked to Vite dev proxy prefix
const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor: Automatically append JWT authorization tokens to requests
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('cipherguard_token') || sessionStorage.getItem('cipherguard_token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response Interceptor: Redirect to login on token expiries (401 errors)
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('cipherguard_token');
      localStorage.removeItem('cipherguard_user');
      sessionStorage.removeItem('cipherguard_token');
      sessionStorage.removeItem('cipherguard_user');
      if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// API Endpoints Mapping
export const authAPI = {
  login: async (email, password, rememberMe = false) => {
    const res = await apiClient.post('/login', { email, password });
    if (res.data.token) {
      const storage = rememberMe ? localStorage : sessionStorage;
      storage.setItem('cipherguard_token', res.data.token);
      storage.setItem('cipherguard_user', JSON.stringify(res.data.user));
    }
    return res.data;
  },
  register: async (fullName, email, password) => {
    const res = await apiClient.post('/register', { full_name: fullName, email, password });
    if (res.data.token) {
      sessionStorage.setItem('cipherguard_token', res.data.token);
      sessionStorage.setItem('cipherguard_user', JSON.stringify(res.data.user));
    }
    return res.data;
  },
  getProfile: async () => {
    const res = await apiClient.get('/profile');
    return res.data;
  },
  logout: () => {
    localStorage.removeItem('cipherguard_token');
    localStorage.removeItem('cipherguard_user');
    sessionStorage.removeItem('cipherguard_token');
    sessionStorage.removeItem('cipherguard_user');
  }
};

export const dlpAPI = {
  classify: async (payload) => {
    if (payload instanceof FormData) {
      const res = await apiClient.post('/classify', payload, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return res.data;
    }
    const res = await apiClient.post('/classify', { text: payload });
    return res.data;
  },
  getClassificationHistory: async () => {
    const res = await apiClient.get('/classify/history');
    return res.data;
  },
  upload: async (formData) => {
    const res = await apiClient.post('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return res.data;
  }
};

export const cryptoAPI = {
  encrypt: async (plaintext, publicKey, keySize = 256) => {
    const res = await apiClient.post('/encrypt', { plaintext, public_key: publicKey, key_size: keySize });
    return res.data;
  },
  decrypt: async (payload) => {
    const res = await apiClient.post('/decrypt', payload);
    return res.data;
  },
  getKeys: async () => {
    const res = await apiClient.get('/keys/current');
    return res.data;
  },
  generateKeys: async () => {
    const res = await apiClient.get('/keys/generate');
    return res.data;
  },
  downloadEncryptedUrl: (fileId) => {
    return `/api/files/${fileId}/download/encrypted`;
  },
  downloadDecrypted: async (fileId, privateKey = null) => {
    const res = await apiClient.post(`/files/${fileId}/download/decrypted`, { private_key: privateKey }, {
      responseType: 'blob'
    });
    return res.data;
  }
};

export const integrityAPI = {
  generateHash: async (fileId) => {
    const res = await apiClient.post('/generate-hash', { file_id: fileId });
    return res.data;
  },
  verifyFile: async (fileId) => {
    const res = await apiClient.post('/verify-file', { file_id: fileId });
    return res.data;
  }
};

export const shareAPI = {
  shareFile: async (fileId, expiryHours, maxDownloads = null) => {
    const res = await apiClient.post('/share-file', { 
      file_id: fileId, 
      expiry_hours: Number(expiryHours),
      max_downloads: maxDownloads 
    });
    return res.data;
  },
  getSharedHistory: async () => {
    const res = await apiClient.get('/share/history');
    return res.data;
  },
  revokeShare: async (shareId) => {
    const res = await apiClient.delete(`/share/${shareId}`);
    return res.data;
  },
  resolveShareToken: async (token) => {
    const res = await apiClient.get(`/shared/${token}`);
    return res.data;
  },
  downloadSharedDecrypted: async (token, privateKey = null) => {
    const res = await apiClient.post(`/shared/${token}/download`, { private_key: privateKey }, {
      responseType: 'blob'
    });
    return res.data;
  }
};

export const auditAPI = {
  getDashboard: async () => {
    const res = await apiClient.get('/dashboard');
    return res.data;
  },
  getLogs: async (search = '', module = 'ALL', status = 'ALL') => {
    const res = await apiClient.get(`/logs?search=${encodeURIComponent(search)}&module=${module}&status=${status}`);
    return res.data;
  },
  getSecurityAlerts: async () => {
    const res = await apiClient.get('/security-alerts');
    return res.data;
  },
  getStatistics: async () => {
    const res = await apiClient.get('/statistics');
    return res.data;
  }
};

export default apiClient;
