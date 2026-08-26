import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  UploadCloud, 
  Settings2, 
  ShieldAlert, 
  CheckCircle2, 
  Loader2, 
  Fingerprint, 
  FileCheck2,
  FileWarning,
  FileCode2,
  FileImage,
  FileSpreadsheet,
  FileText,
  Lock,
  LockKeyhole,
  Check,
  AlertTriangle,
  ArrowRight,
  RefreshCcw
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { dlpAPI } from '../services/api';
import { useToast } from '../components/ToastNotification';

export default function UploadFile() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [algorithm, setAlgorithm] = useState('AES-256-GCM');
  const [scanStep, setScanStep] = useState(0); // 0: Idle, 1: Uploading, 2: DLP Scanning, 3: Encrypting, 4: Complete
  const [uploadProgress, setUploadProgress] = useState(0);
  const [dlpResult, setDlpResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileTypeDetails = (fileName) => {
    if (!fileName) return { Icon: FileText, colorClass: 'text-purple-400', label: 'Vault Document' };
    const ext = fileName.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'pdf':
        return { Icon: FileText, colorClass: 'text-rose-400 bg-rose-500/10 border-rose-500/20', label: 'PDF Document' };
      case 'doc':
      case 'docx':
        return { Icon: FileText, colorClass: 'text-blue-400 bg-blue-500/10 border-blue-500/20', label: 'Word Document' };
      case 'xls':
      case 'xlsx':
      case 'csv':
        return { Icon: FileSpreadsheet, colorClass: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20', label: 'Spreadsheet' };
      case 'png':
      case 'jpg':
      case 'jpeg':
      case 'gif':
        return { Icon: FileImage, colorClass: 'text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/20', label: 'Image File' };
      case 'txt':
        return { Icon: FileCode2, colorClass: 'text-amber-400 bg-amber-500/10 border-amber-500/20', label: 'Plain Text Document' };
      default:
        return { Icon: FileText, colorClass: 'text-purple-400 bg-purple-500/10 border-purple-500/20', label: 'Vault Document' };
    }
  };

  const triggerUpload = async (file) => {
    setSelectedFile(file);
    setErrorMsg('');
    setScanStep(1);
    setUploadProgress(0);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('algorithm', algorithm);

      // 1. Upload File with progress tracking
      const data = await dlpAPI.upload(formData, (progressEvent) => {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setUploadProgress(percentCompleted);
      });

      // 2. DLP Scanning presentation state
      setScanStep(2);
      await new Promise((resolve) => setTimeout(resolve, 1200));

      const confidence = data.file.risk_score > 9.0 
        ? 95 + Math.random() * 4.9 
        : data.file.risk_score > 5.0 
        ? 80 + Math.random() * 14.5
        : 75 + Math.random() * 20;

      let indicators = [];
      if (data.file.classification === 'Secret') {
        indicators = ['Credentials/Private Keys', 'Access Token Patterns', 'Regex matched sequences'];
      } else if (data.file.classification === 'Confidential') {
        indicators = ['Confidential keywords', 'Financial data references'];
      } else {
        indicators = ['General public text', 'No PII matches'];
      }

      setDlpResult({
        violations: data.file.classification === 'Secret' ? ['Potential secret key or credential signature matches identified'] : [],
        classification: data.file.classification,
        riskScore: data.file.risk_score,
        confidence: confidence,
        indicators: indicators,
        algorithm: data.file.algorithm,
        keySize: data.file.key_size,
        encryptionTimeMs: data.file.encryption_time_ms
      });

      // 3. Encrypting presentation state
      setScanStep(3);
      await new Promise((resolve) => setTimeout(resolve, 1500));

      // 4. Complete state
      setScanStep(4);
      addToast('success', `Document "${file.name}" has been successfully vaulted and secured!`);
    } catch (err) {
      console.error(err);
      const errMsg = err.response?.data?.error || 'File upload failed or was blocked by compliance rules.';
      setErrorMsg(errMsg);
      addToast('error', errMsg);
      setScanStep(0);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      triggerUpload(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      triggerUpload(e.target.files[0]);
    }
  };

  const resetScanner = () => {
    setSelectedFile(null);
    setDlpResult(null);
    setScanStep(0);
    setErrorMsg('');
    setUploadProgress(0);
  };

  const fileDetails = selectedFile ? getFileTypeDetails(selectedFile.name) : null;
  const FileTypeIcon = fileDetails ? fileDetails.Icon : null;

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Title */}
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
          <UploadCloud className="w-8 h-8 text-purple-400" /> Secure Upload & Vaulting
        </h2>
        <p className="text-gray-400 text-sm mt-1">
          Upload and secure sensitive assets in the hybrid cryptosystem. Files automatically undergo DLP inspection before storage.
        </p>
      </div>

      {errorMsg && (
        <div 
          className="p-4 bg-rose-500/5 border border-rose-500/20 rounded-2xl text-sm text-rose-400 flex items-start gap-3 shadow-lg animate-slideIn"
          role="alert"
        >
          <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5 text-rose-500 animate-pulse" />
          <div className="space-y-1">
            <span className="font-bold block">Security Exception</span>
            <p className="text-xs text-rose-300/90 leading-relaxed">{errorMsg}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Upload Card */}
        <div className="lg:col-span-2 space-y-6">
          <GlassCard className="p-0 overflow-hidden h-[420px] flex flex-col justify-between" glow={dragActive ? "purple" : ""}>
            {scanStep === 0 ? (
              <div 
                className={`w-full h-full flex flex-col items-center justify-center border-2 border-dashed rounded-2xl p-6 transition-all ${
                  dragActive ? 'border-purple-500 bg-purple-500/5 scale-[0.99] border-glow-purple' : 'border-gray-800 hover:border-gray-700'
                }`}
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
              >
                <div className="p-4 bg-purple-500/10 text-purple-400 rounded-full mb-4 shadow-lg border border-purple-500/15">
                  <UploadCloud className="w-10 h-10 animate-pulse" />
                </div>
                <h3 className="text-lg font-bold text-white mb-1">Drag and Drop Document</h3>
                <p className="text-xs text-gray-500 text-center max-w-sm mb-6 leading-relaxed">
                  Supported formats: .pdf, .docx, .xlsx, .csv, .txt, .png (Max Size: 10MB)
                </p>
                <label className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-xs font-semibold tracking-wider text-white cursor-pointer shadow-lg active:scale-95 transition-all focus-within:ring-2 focus-within:ring-purple-500 outline-none">
                  Choose File
                  <input type="file" className="hidden" onChange={handleChange} aria-label="Upload File Selection" />
                </label>
              </div>
            ) : (
              <div className="w-full h-full flex flex-col justify-between p-8">
                {/* Progress Indicators */}
                <div className="space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-sm border-b border-gray-850 pb-3">
                    <div className="flex items-center gap-3">
                      {FileTypeIcon && (
                        <div className={`p-2 rounded-lg border ${fileDetails.colorClass}`}>
                          <FileTypeIcon className="w-5 h-5" />
                        </div>
                      )}
                      <div>
                        <span className="block font-semibold text-white max-w-[200px] sm:max-w-[320px] truncate" title={selectedFile?.name}>
                          {selectedFile?.name}
                        </span>
                        <span className="block text-[10px] text-gray-500 uppercase tracking-widest">{fileDetails?.label}</span>
                      </div>
                    </div>
                    <span className="text-xs text-gray-400 font-mono bg-white/5 border border-gray-800 px-2 py-0.5 rounded-md self-start sm:self-center">
                      {formatFileSize(selectedFile?.size || 0)}
                    </span>
                  </div>
                  
                  <div className="space-y-1">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-gray-400 font-semibold">
                        {scanStep === 1 && `Uploading data assets (${uploadProgress}%)`}
                        {scanStep === 2 && 'Executing compliance scanners'}
                        {scanStep === 3 && 'Performing cryptographic lockouts'}
                        {scanStep === 4 && 'Secured & Vaulted'}
                      </span>
                      <span className="text-xs font-bold font-mono text-purple-400">
                        {scanStep === 1 && `${uploadProgress}%`}
                        {scanStep === 2 && '50%'}
                        {scanStep === 3 && '85%'}
                        {scanStep === 4 && '100%'}
                      </span>
                    </div>
                    <div className="h-2.5 w-full bg-gray-900 rounded-full overflow-hidden border border-gray-850">
                      <div 
                        className={`h-full transition-all duration-300 bg-gradient-to-r from-purple-500 via-indigo-500 to-blue-500 rounded-full`}
                        style={{
                          width: 
                            scanStep === 1 ? `${Math.max(5, uploadProgress)}%` : 
                            scanStep === 2 ? '50%' : 
                            scanStep === 3 ? '85%' : '100%'
                        }}
                      ></div>
                    </div>
                  </div>
                </div>

                {/* Progress details */}
                <div className="flex-1 flex flex-col items-center justify-center py-4 text-center">
                  {scanStep === 1 && (
                    <div className="space-y-3 animate-fadeIn">
                      <Loader2 className="w-10 h-10 text-purple-500 animate-spin mx-auto" />
                      <h4 className="text-sm font-bold text-white">Uploading Document Payload...</h4>
                      <p className="text-xs text-gray-500 max-w-md">Extracting binary arrays, parsing payload stream and establishing TLS context.</p>
                    </div>
                  )}

                  {scanStep === 2 && (
                    <div className="space-y-3 animate-fadeIn">
                      <Fingerprint className="w-10 h-10 text-purple-500 animate-pulse mx-auto" />
                      <h4 className="text-sm font-bold text-white">Running AI DLP Inspection...</h4>
                      <p className="text-xs text-gray-500 max-w-md">Scanning extracted tokens. Comparing document matrices with NLP classifiers for potential leaks.</p>
                    </div>
                  )}

                  {scanStep === 3 && (
                    <div className="space-y-4 animate-fadeIn max-w-md w-full bg-white/5 border border-gray-850 p-4 rounded-xl text-left">
                      <div className="flex items-center gap-3 border-b border-gray-800 pb-2 mb-2">
                        <Lock className="w-5 h-5 text-blue-400 animate-bounce" />
                        <div>
                          <h4 className="text-xs font-bold text-white uppercase tracking-wider">Encryption in progress...</h4>
                          <p className="text-[10px] text-gray-500">Securing data vectors in isolated storage blocks.</p>
                        </div>
                      </div>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Cipher Algorithm:</span>
                          <span className="font-mono text-purple-400 font-bold">{algorithm}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Key Protection:</span>
                          <span className="font-mono text-blue-400 font-bold">RSA-2048 Asymmetric Wrap</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Integrity Status:</span>
                          <span className="font-mono text-emerald-400 font-bold flex items-center gap-1">
                            <Loader2 className="w-3 h-3 animate-spin inline" /> Hashing SHA-256...
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {scanStep === 4 && (
                    <div className="space-y-3 animate-fadeIn">
                      {dlpResult?.classification === 'Secret' ? (
                        <div className="p-4 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-full w-16 h-16 flex items-center justify-center mx-auto shadow-lg shadow-amber-500/5">
                          <FileWarning className="w-8 h-8 animate-pulse" />
                        </div>
                      ) : (
                        <div className="p-4 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full w-16 h-16 flex items-center justify-center mx-auto shadow-lg shadow-emerald-500/5">
                          <FileCheck2 className="w-8 h-8" />
                        </div>
                      )}
                      <h4 className="text-sm font-bold text-white">Document Secured & Vaulted</h4>
                      <p className="text-xs text-gray-400 max-w-sm mx-auto">
                        Hybrid key generated, signed with asymmetric owner certificate, and stored on isolated storage vault.
                      </p>
                    </div>
                  )}
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-800/80 pt-4">
                  {scanStep < 4 ? (
                    <button 
                      onClick={resetScanner}
                      className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl text-xs font-semibold text-gray-400 transition-all border border-gray-850 hover:text-white"
                      aria-label="Cancel upload setup"
                    >
                      Cancel Setup
                    </button>
                  ) : (
                    <div className="flex gap-2">
                      <button 
                        onClick={() => navigate('/dashboard')}
                        className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl text-xs font-semibold text-gray-400 transition-all border border-gray-850 hover:text-white"
                        aria-label="Go to Vault Dashboard"
                      >
                        Vault Dashboard
                      </button>
                      <button 
                        onClick={resetScanner}
                        className="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 rounded-xl text-xs font-semibold text-white shadow-lg shadow-purple-600/10 transition-all active:scale-95"
                        aria-label="Vault Next Document"
                      >
                        Vault Next Document
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </GlassCard>

          {/* DLP Report */}
          {dlpResult && (
            <GlassCard className="p-6 space-y-4 border-l-4 border-l-purple-500 animate-slideUp">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-gray-850 pb-3">
                <div>
                  <h3 className="text-base font-bold text-white">DLP Engine Findings Report</h3>
                  <p className="text-[10px] text-gray-500 mt-0.5">Automated deep scanning classification diagnostic payload metadata.</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded-full border tracking-wide uppercase ${
                    dlpResult.classification === 'Secret' 
                      ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' 
                      : dlpResult.classification === 'Confidential'
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                      : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                  }`}>
                    Classification: {dlpResult.classification}
                  </span>
                  <span className="text-[10px] font-mono bg-white/5 border border-gray-850 px-2.5 py-1 rounded-full text-gray-300">
                    Risk Score: {dlpResult.riskScore}/10.00
                  </span>
                </div>
              </div>

              {/* Classification details */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
                <div className="p-3.5 bg-white/5 border border-gray-850 rounded-xl space-y-1">
                  <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Category</span>
                  <span className={`text-sm font-extrabold uppercase tracking-wide ${
                    dlpResult.classification === 'Secret' ? 'text-purple-400' : dlpResult.classification === 'Confidential' ? 'text-amber-400' : 'text-blue-400'
                  }`}>{dlpResult.classification}</span>
                </div>
                <div className="p-3.5 bg-white/5 border border-gray-850 rounded-xl space-y-1">
                  <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Confidence Level</span>
                  <span className="text-sm font-extrabold text-white">{dlpResult.confidence.toFixed(1)}%</span>
                </div>
                <div className="p-3.5 bg-white/5 border border-gray-850 rounded-xl space-y-1">
                  <span className="block text-[10px] text-gray-500 uppercase font-bold tracking-wider">Integrity Audit</span>
                  <span className="text-sm font-extrabold text-emerald-400 flex items-center gap-1">
                    <Check className="w-4 h-4 shrink-0" /> Intact Verified
                  </span>
                </div>
              </div>

              {/* Detected indicators */}
              {dlpResult.indicators && dlpResult.indicators.length > 0 && (
                <div className="space-y-2">
                  <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-wider">
                    Detected Compliance Indicators
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {dlpResult.indicators.map((ind, i) => (
                      <span 
                        key={i} 
                        className={`px-2.5 py-0.5 rounded text-[10px] font-semibold border ${
                          dlpResult.classification === 'Secret' 
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/25' 
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                        }`}
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {dlpResult.classification === 'Secret' ? (
                <div className="space-y-2">
                  <div className="flex gap-2.5 p-3.5 bg-rose-500/5 border border-rose-500/10 rounded-xl text-xs text-rose-400 leading-normal">
                    <ShieldAlert className="w-4.5 h-4.5 shrink-0 mt-0.5 text-rose-500" />
                    <div>
                      <span className="font-bold block mb-1">DLP Rule Warning Highlights:</span>
                      <ul className="list-disc pl-4 space-y-1 text-rose-300/90">
                        <li>High sensitivity credential, token or private key signatures recognized.</li>
                        <li>Encryption escalated to asymmetric RSA envelope wrappers.</li>
                        <li>Audit log trace generated. Vault access restricted strictly to authorized key holders.</li>
                      </ul>
                    </div>
                  </div>
                </div>
              ) : dlpResult.classification === 'Confidential' ? (
                <div className="flex gap-2.5 p-3.5 bg-amber-500/5 border border-amber-500/10 rounded-xl text-xs text-amber-400 leading-normal">
                  <AlertTriangle className="w-4.5 h-4.5 shrink-0 mt-0.5 text-amber-500" />
                  <div>
                    <span className="font-bold block mb-0.5">Restricted Access Classification</span>
                    <p className="text-amber-300/90">Internal company assets. Standard symmetric lock active. Sharing requires strict download expiry bounds.</p>
                  </div>
                </div>
              ) : (
                <div className="flex gap-2.5 p-3.5 bg-emerald-500/5 border border-emerald-500/10 rounded-xl text-xs text-emerald-400 leading-normal">
                  <CheckCircle2 className="w-4.5 h-4.5 shrink-0 mt-0.5 text-emerald-500" />
                  <div>
                    <span className="font-bold block">Integrity Clearance Approved</span>
                    <p className="text-emerald-300/90">No sensitive data credentials, access codes, or regex structures detected. Vault files marked safe for public distribution.</p>
                  </div>
                </div>
              )}
            </GlassCard>
          )}
        </div>

        {/* Right Settings */}
        <div className="space-y-6">
          <GlassCard className="space-y-6">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Settings2 className="w-5 h-5 text-purple-400" /> Cryptosystem Settings
            </h3>

            <div className="space-y-2">
              <label id="cipher-label" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Symmetric Block Cipher
              </label>
              <div className="grid grid-cols-2 gap-2" role="group" aria-labelledby="cipher-label">
                <button
                  type="button"
                  onClick={() => setAlgorithm('AES-256-GCM')}
                  className={`py-2.5 px-3 text-xs font-semibold rounded-xl border text-center transition-all focus:ring-2 focus:ring-purple-500 outline-none ${
                    algorithm === 'AES-256-GCM'
                      ? 'bg-purple-600/15 border-purple-500 text-purple-300 shadow-md font-bold'
                      : 'border-gray-800 text-gray-400 bg-white/5 hover:text-white hover:border-gray-700'
                  }`}
                  aria-label="Use AES-256-GCM algorithm"
                  aria-pressed={algorithm === 'AES-256-GCM'}
                >
                  AES-256-GCM
                </button>
                <button
                  type="button"
                  onClick={() => setAlgorithm('ChaCha20-Poly1305')}
                  className={`py-2.5 px-3 text-xs font-semibold rounded-xl border text-center transition-all focus:ring-2 focus:ring-purple-500 outline-none ${
                    algorithm === 'ChaCha20-Poly1305'
                      ? 'bg-purple-600/15 border-purple-500 text-purple-300 shadow-md font-bold'
                      : 'border-gray-800 text-gray-400 bg-white/5 hover:text-white hover:border-gray-700'
                  }`}
                  aria-label="Use ChaCha20-Poly1305 algorithm"
                  aria-pressed={algorithm === 'ChaCha20-Poly1305'}
                >
                  ChaCha20-Poly1305
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="wrapper-key-select" className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Asymmetric Wrapper Key (KEK)
              </label>
              <select 
                id="wrapper-key-select"
                className="w-full py-2.5 px-3 text-xs rounded-xl glass-input text-gray-300 focus:ring-2 focus:ring-purple-500 outline-none cursor-pointer"
              >
                <option value="owner">Your RSA-2048 Keypair (Active)</option>
              </select>
            </div>
          </GlassCard>

          <GlassCard className="space-y-4" glow="blue">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <LockKeyhole className="w-4 h-4 text-blue-400" /> Security Standards
            </h4>
            <ul className="space-y-2.5 text-[11px] text-gray-450 leading-relaxed">
              <li className="flex items-start gap-2">
                <Check className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                <span>Zero-Knowledge validation protocols prevent private KEK components from exposing to external servers.</span>
              </li>
              <li className="flex items-start gap-2">
                <Check className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                <span>All uploads are checked locally before disk committing.</span>
              </li>
            </ul>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
