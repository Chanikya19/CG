import React, { useState } from 'react';
import { 
  UploadCloud, 
  Settings2, 
  ShieldAlert, 
  CheckCircle2, 
  Loader2, 
  Fingerprint, 
  FileCheck2,
  FileWarning
} from 'lucide-react';
import GlassCard from '../components/GlassCard';
import { dlpAPI } from '../services/api';

export default function UploadFile() {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [algorithm, setAlgorithm] = useState('AES-256-GCM');
  const [scanStep, setScanStep] = useState(0); // 0: Idle, 1: Reading, 2: DLP Scanning, 3: Encrypting, 4: Complete
  const [dlpResult, setDlpResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');

  const triggerUpload = async (file) => {
    setSelectedFile(file);
    setErrorMsg('');
    setScanStep(1);

    // Simulated progress mapping
    setTimeout(() => {
      setScanStep(2);
    }, 800);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('algorithm', algorithm);

      // Perform real file upload and DLP backend verification
      const data = await dlpAPI.upload(formData);
      
      setDlpResult({
        violations: data.file.classification === 'Secret' ? ['Potential secret key or credential signature matches identified'] : [],
        classification: data.file.classification,
        riskScore: data.file.risk_score
      });
      
      setScanStep(3);
      setTimeout(() => {
        setScanStep(4);
      }, 1000);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.response?.data?.error || 'File upload failed or was blocked by compliance rules.');
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
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-3xl font-extrabold tracking-tight text-white">Secure Upload & Vaulting</h2>
        <p className="text-gray-400 text-sm mt-1">Upload assets to the hybrid cryptosystem. Files automatically undergo DLP inspection before storage.</p>
      </div>

      {errorMsg && (
        <div className="p-4 bg-rose-500/5 border border-rose-500/10 rounded-2xl text-sm text-rose-400 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Upload Card */}
        <div className="lg:col-span-2 space-y-6">
          <GlassCard className="p-0 overflow-hidden h-96">
            {scanStep === 0 ? (
              <div 
                className={`w-full h-full flex flex-col items-center justify-center border-2 border-dashed rounded-2xl p-6 transition-all ${
                  dragActive ? 'border-purple-500 bg-purple-500/5' : 'border-gray-800 hover:border-gray-700'
                }`}
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
              >
                <div className="p-4 bg-purple-500/10 text-purple-400 rounded-full mb-4">
                  <UploadCloud className="w-10 h-10" />
                </div>
                <h3 className="text-lg font-bold text-white mb-1">Drag and Drop Document</h3>
                <p className="text-xs text-gray-500 text-center max-w-sm mb-6 leading-relaxed">
                  Support formats: .pdf, .docx, .xlsx, .csv, .txt, .png (Max Size: 100MB)
                </p>
                <label className="px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-xs font-semibold tracking-wider text-white cursor-pointer shadow-lg active:scale-95 transition-all">
                  Choose File
                  <input type="file" className="hidden" onChange={handleChange} />
                </label>
              </div>
            ) : (
              <div className="w-full h-full flex flex-col justify-between p-8">
                {/* Progress Indicators */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Processing: <span className="font-semibold text-white">{selectedFile?.name}</span></span>
                    <span className="text-xs text-gray-500 font-mono">{(selectedFile?.size / 1024).toFixed(1)} KB</span>
                  </div>
                  
                  <div className="h-2 w-full bg-gray-900 rounded-full overflow-hidden border border-gray-800">
                    <div 
                      className={`h-full transition-all duration-500 bg-gradient-to-r from-purple-500 to-blue-500 ${
                        scanStep === 1 ? 'w-1/4' : scanStep === 2 ? 'w-1/2' : scanStep === 3 ? 'w-3/4' : 'w-full'
                      }`}
                    ></div>
                  </div>
                </div>

                {/* Progress details */}
                <div className="flex-1 flex flex-col items-center justify-center py-6 text-center">
                  {scanStep === 1 && (
                    <div className="space-y-3">
                      <Loader2 className="w-10 h-10 text-purple-500 animate-spin mx-auto" />
                      <h4 className="text-sm font-bold text-white">Reading Document Payload...</h4>
                      <p className="text-xs text-gray-500">Extracting string data and mapping metadata arrays.</p>
                    </div>
                  )}

                  {scanStep === 2 && (
                    <div className="space-y-3">
                      <Fingerprint className="w-10 h-10 text-purple-500 animate-pulse mx-auto" />
                      <h4 className="text-sm font-bold text-white">Running AI DLP Inspection...</h4>
                      <p className="text-xs text-gray-500">Checking model matrices for social security numbers, private key sequences, and tokens.</p>
                    </div>
                  )}

                  {scanStep === 3 && (
                    <div className="space-y-3">
                      <Loader2 className="w-10 h-10 text-blue-500 animate-spin mx-auto" />
                      <h4 className="text-sm font-bold text-white">Executing Hybrid Cryptosystem...</h4>
                      <p className="text-xs text-gray-500">Generating random DEK, executing {algorithm} block cipher, and packaging headers.</p>
                    </div>
                  )}

                  {scanStep === 4 && (
                    <div className="space-y-3">
                      {dlpResult?.violations.length > 0 ? (
                        <FileWarning className="w-12 h-12 text-amber-500 mx-auto" />
                      ) : (
                        <FileCheck2 className="w-12 h-12 text-emerald-400 mx-auto" />
                      )}
                      <h4 className="text-sm font-bold text-white">Document Secured & Vaulted</h4>
                      <p className="text-xs text-gray-500">Vault key signed with user asymmetric public key.</p>
                    </div>
                  )}
                </div>

                <div className="flex justify-end gap-3 border-t border-gray-800/80 pt-4">
                  {scanStep < 4 ? (
                    <button 
                      onClick={resetScanner}
                      className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl text-xs font-semibold text-gray-400"
                    >
                      Cancel Setup
                    </button>
                  ) : (
                    <button 
                      onClick={resetScanner}
                      className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 rounded-xl text-xs font-semibold text-white shadow-lg shadow-purple-600/10"
                    >
                      Vault Next Document
                    </button>
                  )}
                </div>
              </div>
            )}
          </GlassCard>

          {/* DLP Report */}
          {dlpResult && (
            <GlassCard className="p-6 space-y-4 border-l-4 border-l-purple-500 animate-slideUp">
              <div className="flex justify-between items-center">
                <h3 className="text-base font-bold text-white">DLP Engine Findings Report</h3>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-full border ${
                  dlpResult.classification === 'Secret' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                }`}>
                  Classification: {dlpResult.classification} (Risk: {dlpResult.riskScore}/10.00)
                </span>
              </div>

              {dlpResult.classification === 'Secret' ? (
                <div className="space-y-2">
                  <div className="flex gap-2.5 p-3.5 bg-rose-500/5 border border-rose-500/10 rounded-xl text-xs text-rose-400">
                    <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold block mb-1">DLP Rule Violation Warnings:</span>
                      <ul className="list-disc pl-4 space-y-1">
                        <li>High sensitivity credential or token patterns recognized.</li>
                        <li>Encryption escalated to RSA envelope wrappers.</li>
                      </ul>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex gap-2.5 p-3.5 bg-emerald-500/5 border border-emerald-500/10 rounded-xl text-xs text-emerald-400">
                  <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold block">Integrity Clearance Approved</span>
                    <span>No credential, token, or PII string structures found. Document classified as: {dlpResult.classification}.</span>
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
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Symmetric Block Cipher
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setAlgorithm('AES-256-GCM')}
                  className={`py-2 px-3 text-xs font-semibold rounded-xl border text-center transition-all ${
                    algorithm === 'AES-256-GCM'
                      ? 'bg-purple-600/15 border-purple-500 text-purple-300 shadow-md'
                      : 'border-gray-800 text-gray-400 bg-white/5 hover:text-white'
                  }`}
                >
                  AES-256-GCM
                </button>
                <button
                  onClick={() => setAlgorithm('ChaCha20-Poly1305')}
                  className={`py-2 px-3 text-xs font-semibold rounded-xl border text-center transition-all ${
                    algorithm === 'ChaCha20-Poly1305'
                      ? 'bg-purple-600/15 border-purple-500 text-purple-300 shadow-md'
                      : 'border-gray-800 text-gray-400 bg-white/5 hover:text-white'
                  }`}
                >
                  ChaCha20-Poly1305
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Asymmetric Wrapper Key (KEK)
              </label>
              <select className="w-full py-2 px-3 text-xs rounded-xl glass-input text-gray-300">
                <option value="owner">Your RSA-2048 Keypair (Active)</option>
              </select>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
