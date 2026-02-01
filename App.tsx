
import React, { useState, useEffect, useCallback } from 'react';
import { Role, PKIState, LogEntry, Certificate, KeyPair, MedicalReport } from './types';
import { generateId, simulateKeyGeneration, createCertificate, computeHash, signData, verifySignature, encryptData, decryptData, exportIdentityBundle, importIdentityBundle, encryptWithPassword, decryptWithPassword, registerImportedKeyPair, isCertificateValid } from './services/cryptoService';
import Sidebar from './components/Sidebar';
import LogViewer from './components/LogViewer';

const App: React.FC = () => {
  // PKI State
  const [state, setState] = useState<PKIState>({
    currentUserRole: Role.DOCTOR,
    caCertificate: null,
    certificates: [],
    keyPairs: {},
    logs: [],
    reports: []
  });

  const [activeTab, setActiveTab] = useState('dashboard');
  const [reportText, setReportText] = useState("");
  const [selectedRecipient, setSelectedRecipient] = useState<string>("");
  const [currentUserName, setCurrentUserName] = useState<string>('Dr. Alice');
  const [newIdentityName, setNewIdentityName] = useState<string>('');
  const [newIdentityRole, setNewIdentityRole] = useState<Role>(Role.DOCTOR);

  const arrayBufferToBase64 = (buffer: ArrayBuffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  };

  const base64ToArrayBuffer = (b64: string) => {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };

  // Helper to add logs
  const addLog = useCallback((type: LogEntry['type'], message: string, details?: string) => {
    setState(prev => ({
      ...prev,
      logs: [...prev.logs, {
        id: generateId(),
        timestamp: Date.now(),
        type,
        message,
        details
      }]
    }));
  }, []);

  // Initialize CA on mount
  useEffect(() => {
    const initCA = async () => {
      addLog('INFO', 'Initializing PKI Environment...');
      const caKeys = await simulateKeyGeneration('Root-CA-Admin');
      const caCert = createCertificate('Internal Root CA', Role.CA, caKeys.publicKey, null);
      
      setState(prev => ({
        ...prev,
        caCertificate: caCert,
        keyPairs: { ...prev.keyPairs, 'Internal Root CA': caKeys },
        certificates: [...prev.certificates, caCert]
      }));
      
      addLog('SUCCESS', 'Root CA Initialized. Trust Anchor established.');
    };

    initCA();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the selected user name in sync with the active role and enrolled certificates
  useEffect(() => {
    const candidates = state.certificates.filter(c => c.role === state.currentUserRole && !c.isRevoked);
    if (candidates.length > 0) {
      // prefer the most recently issued certificate for the role
      const preferred = candidates[candidates.length - 1].subject;
      setCurrentUserName(prev => (prev && candidates.some(c => c.subject === prev)) ? prev : preferred);
    } else {
      setCurrentUserName(state.currentUserRole === Role.DOCTOR ? 'Dr. Alice' : state.currentUserRole === Role.PATIENT ? 'Mr. Bob' : 'Administrator');
    }
  }, [state.currentUserRole, state.certificates]);

  const handleGenerateIdentity = async (name: string, role: Role) => {
    addLog('CRYPTO', `Generating ${role} Key Pair (RSA 2048)...`);
    const keys = await simulateKeyGeneration(name);
    
    addLog('INFO', `Requesting Certificate for ${name} from Internal CA...`);
    if (!state.caCertificate) return;
    
    const cert = createCertificate(name, role, keys.publicKey, state.caCertificate);
    
    setState(prev => ({
      ...prev,
      keyPairs: { ...prev.keyPairs, [name]: keys },
      certificates: [...prev.certificates, cert]
    }));

    // If the newly created identity matches the currently selected role, switch to it
    if (role === state.currentUserRole) {
      setCurrentUserName(name);
    }

    addLog('SUCCESS', `Identity verified. Certificate issued for ${name}.`, `Serial: ${cert.serialNumber}`);
  };

  // Export identity (certificate + private key) as encrypted bundle
  const handleExportIdentity = async (cert: Certificate) => {
    const keys = state.keyPairs[cert.subject];
    if (!keys) { addLog('ERROR', 'No keys found for identity'); return; }
    const pwd = window.prompt(`Enter password to protect exported identity for ${cert.subject}`) || '';
    if (!pwd) return;
    try {
      const bundle = await exportIdentityBundle(cert, keys.privateKey, pwd);
      const blob = new Blob([bundle], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${cert.subject.replace(/\s+/g,'_')}_identity.json`;
      a.click();
      URL.revokeObjectURL(url);
      addLog('SUCCESS', `Exported identity for ${cert.subject}`);
    } catch (e) {
      addLog('ERROR', `Export failed: ${(e as Error).message}`);
    }
  };

  const handleImportIdentityFile = async (file: File | null) => {
    if (!file) return;
    const text = await file.text();
    const pwd = window.prompt('Enter password for imported identity') || '';
    if (!pwd) return;
    try {
      const parsed = await importIdentityBundle(text, pwd);
      // register keys into crypto service
      const ok = await registerImportedKeyPair(parsed.privateKeyStr, parsed.cert.publicKey);
      if (!ok) throw new Error('Failed to import key material');
      // add to app state
      setState(prev => ({
        ...prev,
        keyPairs: { ...prev.keyPairs, [parsed.cert.subject]: { publicKey: parsed.cert.publicKey, privateKey: parsed.privateKeyStr, algorithm: 'RSA-2048', createdAt: Date.now() } },
        certificates: [...prev.certificates, parsed.cert]
      }));
      addLog('SUCCESS', `Imported identity ${parsed.cert.subject}`);
    } catch (e) {
      addLog('ERROR', `Import failed: ${(e as Error).message}`);
    }
  };

  // Vault persistence
  const handleSaveVault = async () => {
    const pwd = window.prompt('Enter password to encrypt your vault') || '';
    if (!pwd) return;
    const payload = JSON.stringify({ certificates: state.certificates, keyPairs: state.keyPairs });
    try {
      const encrypted = await encryptWithPassword(payload, pwd);
      localStorage.setItem('pki_vault', encrypted);
      addLog('SUCCESS', 'Vault saved to localStorage');
    } catch (e) {
      addLog('ERROR', `Vault save failed: ${(e as Error).message}`);
    }
  };

  const handleLoadVault = async () => {
    const stored = localStorage.getItem('pki_vault');
    if (!stored) { addLog('ERROR', 'No vault found in localStorage'); return; }
    const pwd = window.prompt('Enter vault password') || '';
    if (!pwd) return;
    try {
      const decrypted = await decryptWithPassword(stored, pwd);
      const parsed = JSON.parse(decrypted) as { certificates: Certificate[]; keyPairs: Record<string, KeyPair> };
      // register keys
      for (const [name, kp] of Object.entries(parsed.keyPairs)) {
        await registerImportedKeyPair(kp.privateKey, kp.publicKey);
      }
      setState(prev => ({ ...prev, certificates: parsed.certificates, keyPairs: parsed.keyPairs }));
      addLog('SUCCESS', 'Vault loaded');
    } catch (e) {
      addLog('ERROR', `Vault load failed: ${(e as Error).message}`);
    }
  };

  // File operations: sign/encrypt/decrypt files
  const readFileAsText = (file: File) => new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });

  const downloadBlob = (data: string | Blob, filename: string, mime = 'application/octet-stream') => {
    const blob = typeof data === 'string' ? new Blob([data], { type: mime }) : data;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSignFile = async (file: File) => {
    if (!file) return;
    const doctorName = currentUserName;
    const keys = state.keyPairs[doctorName];
    if (!keys) { addLog('ERROR', 'No keys for signing'); return; }
    try {
      const arrBuf = await (await file.arrayBuffer());
      const b64 = arrayBufferToBase64(arrBuf);
      const sig = await signData(b64, keys.privateKey);
      downloadBlob(sig, `${file.name}.sig`, 'application/octet-stream');
      addLog('SUCCESS', `Signed file ${file.name}`);
    } catch (e) {
      addLog('ERROR', `Sign file failed: ${(e as Error).message}`);
    }
  };

  const handleEncryptFile = async (file: File, recipientName: string) => {
    if (!file || !recipientName) return;
    const cert = state.certificates.find(c => c.subject === recipientName);
    if (!cert) { addLog('ERROR', 'Recipient certificate not found'); return; }
    try {
      const arrBuf = await (await file.arrayBuffer());
      const b64 = arrayBufferToBase64(arrBuf);
      const enc = await encryptData(b64, cert.publicKey);
      downloadBlob(enc, `${file.name}.enc`, 'application/json');
      addLog('SUCCESS', `Encrypted file ${file.name} for ${recipientName}`);
    } catch (e) {
      addLog('ERROR', `Encrypt file failed: ${(e as Error).message}`);
    }
  };

  const handleDecryptFile = async (file: File) => {
    if (!file) return;
    if (state.currentUserRole !== Role.PATIENT) { addLog('ERROR', 'Only patients can decrypt files'); return; }
    const owner = currentUserName;
    const keys = state.keyPairs[owner];
    if (!keys) { addLog('ERROR', 'No private key available for decryption'); return; }
    try {
      const text = await file.text();
      const plain = await decryptData(text, keys.privateKey);
      if (plain === 'DECRYPTION_FAILED') throw new Error('Decryption failed');
      // decode base64 back to binary
      const arrBuf = base64ToArrayBuffer(plain);
      downloadBlob(new Blob([arrBuf]), `${file.name.replace(/\.enc$/, '')}.dec`, 'application/octet-stream');
      addLog('SUCCESS', `Decrypted file ${file.name}`);
    } catch (e) {
      addLog('ERROR', `Decrypt file failed: ${(e as Error).message}`);
    }
  };

  const handleSendReport = async () => {
    if (!reportText || !selectedRecipient) return;
    const doctorName = currentUserName;
    const patientName = selectedRecipient;

    // Ensure doctor has keys and a non-revoked certificate
    const doctorKeys = state.keyPairs[doctorName];
    const doctorCert = state.certificates.find(c => c.subject === doctorName);
    const patientCert = state.certificates.find(c => c.subject === patientName);

    if (!doctorKeys || !doctorCert || !patientCert) {
      addLog('ERROR', 'Cannot process report: Missing cryptographic materials.');
      return;
    }

    if (doctorCert.isRevoked) {
      addLog('ERROR', `Signing blocked: ${doctorName}'s certificate has been revoked.`);
      return;
    }

    addLog('INFO', `Starting secure report processing for ${patientName}...`);

    // 1. Digital Signature (Integrity & Non-repudiation)
    let signature = 'SIGNING_FAILED';
    try {
      signature = await signData(reportText, doctorKeys.privateKey);
      addLog('CRYPTO', `Report digitally signed by ${doctorName}.`, `Sig: ${signature.substring(0, 40)}...`);
    } catch (e) {
      addLog('ERROR', `Signing error: ${(e as Error).message}`);
      return;
    }

    // 2. Encryption (Confidentiality) - hybrid AES-GCM + RSA-OAEP
    let encrypted = '';
    try {
      encrypted = await encryptData(reportText, patientCert.publicKey);
      addLog('CRYPTO', `Report encrypted using ${patientName}'s RSA Public Key.`);
    } catch (e) {
      addLog('ERROR', `Encryption error: ${(e as Error).message}`);
      return;
    }

    const newReport: MedicalReport = {
      id: generateId(),
      doctorName,
      patientName,
      content: "ENCRYPTED_DATA", // The real content is hidden
      encryptedContent: encrypted,
      signature: signature,
      timestamp: Date.now()
    };

    setState(prev => ({ ...prev, reports: [...prev.reports, newReport] }));
    setReportText("");
    addLog('SUCCESS', `Medical report securely dispatched to ${patientName}.`);
  };

  const handleRevoke = (serial: string) => {
    setState(prev => ({
      ...prev,
      certificates: prev.certificates.map(c => c.serialNumber === serial ? { ...c, isRevoked: true } : c)
    }));
    addLog('WARNING', `Certificate revoked by Administrator.`, `Serial: ${serial}`);
  };

  // Views
  const renderDashboard = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2">Trust Anchors</h3>
          <p className="text-2xl font-bold">{state.caCertificate ? '1 Root CA' : '0'}</p>
        </div>
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2">Valid Entities</h3>
          <p className="text-2xl font-bold text-green-400">{state.certificates.filter(c => !c.isRevoked).length}</p>
        </div>
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h3 className="text-slate-400 text-xs font-bold uppercase tracking-widest mb-2">Active Reports</h3>
          <p className="text-2xl font-bold text-blue-400">{state.reports.length}</p>
        </div>
      </div>

      <div className="bg-slate-800/50 p-8 rounded-xl border border-dashed border-slate-700 text-center">
        <div className="max-w-xl mx-auto space-y-4">
          <div className="w-16 h-16 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
            <span className="text-3xl">🛡️</span>
          </div>
          <h2 className="text-xl font-bold">Secure Client PKI Demonstration</h2>
          <p className="text-slate-400 text-sm">
            This tool demonstrates the core pillars of cybersecurity in medical data exchange:
          </p>
          <div className="grid grid-cols-2 gap-4 text-left mt-6">
            <div className="bg-slate-900 p-3 rounded border border-slate-800">
              <span className="font-bold text-blue-400">Confidentiality:</span>
              <p className="text-xs text-slate-500">Reports are encrypted with the patient's public key.</p>
            </div>
            <div className="bg-slate-900 p-3 rounded border border-slate-800">
              <span className="font-bold text-blue-400">Integrity:</span>
              <p className="text-xs text-slate-500">SHA-256 hashes detect any unauthorized tampering.</p>
            </div>
            <div className="bg-slate-900 p-3 rounded border border-slate-800">
              <span className="font-bold text-blue-400">Authentication:</span>
              <p className="text-xs text-slate-500">CA-signed certificates verify the identities of users.</p>
            </div>
            <div className="bg-slate-900 p-3 rounded border border-slate-800">
              <span className="font-bold text-blue-400">Non-repudiation:</span>
              <p className="text-xs text-slate-500">Doctors cannot deny signing reports once signature is verified.</p>
            </div>
          </div>
        </div>

            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-bold mb-3">File Operations</h3>
              <div className="space-y-3">
                <div>
                  <input type="file" id="fileOpInput" className="w-full bg-slate-900 p-2 rounded" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button onClick={() => {
                      const el = document.getElementById('fileOpInput') as HTMLInputElement | null;
                      const file = el?.files?.[0] || null;
                      if (!file) { addLog('ERROR', 'No file selected'); return; }
                      handleSignFile(file);
                    }}
                    className="bg-indigo-600 py-2 rounded">Sign File</button>
                  <button onClick={() => {
                      const el = document.getElementById('fileOpInput') as HTMLInputElement | null;
                      const file = el?.files?.[0] || null;
                      if (!file) { addLog('ERROR', 'No file selected'); return; }
                      if (!selectedRecipient) { addLog('ERROR', 'Select recipient to encrypt for'); return; }
                      handleEncryptFile(file, selectedRecipient);
                    }}
                    className="bg-blue-600 py-2 rounded">Encrypt File</button>
                </div>
                <div>
                  <button onClick={() => {
                    const el = document.getElementById('fileOpInput') as HTMLInputElement | null;
                    const file = el?.files?.[0] || null;
                    if (!file) { addLog('ERROR', 'No file selected'); return; }
                    handleDecryptFile(file);
                  }}
                  className="w-full bg-emerald-600 py-2 rounded">Decrypt File (Patient)</button>
                </div>
              </div>
            </div>
      </div>
    </div>
  );

  const renderIdentity = () => (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="space-y-4">
        <h2 className="text-lg font-bold">Identity Enrollment</h2>
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 space-y-4">
          <p className="text-sm text-slate-400">Create new cryptographic identities for the scenario.</p>
          <div className="flex gap-2">
            <input type="file" accept="application/json" onChange={(e) => handleImportIdentityFile(e.target.files ? e.target.files[0] : null)} className="bg-slate-900 p-2 rounded" />
            <button onClick={handleSaveVault} className="bg-yellow-600 px-3 rounded">Save Vault</button>
            <button onClick={handleLoadVault} className="bg-emerald-600 px-3 rounded">Load Vault</button>
          </div>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              <input
                type="text"
                placeholder="Enter full name (e.g., Dr. Smith)"
                value={newIdentityName}
                onChange={(e) => setNewIdentityName(e.target.value)}
                className="col-span-2 bg-slate-900 border border-slate-700 rounded p-2 text-sm"
              />
              <select
                value={newIdentityRole}
                onChange={(e) => setNewIdentityRole(e.target.value as Role)}
                className="bg-slate-900 border border-slate-700 rounded p-2 text-sm"
              >
                <option value={Role.DOCTOR}>Doctor</option>
                <option value={Role.PATIENT}>Patient</option>
              </select>
              <button
                onClick={() => {
                  const nameInput = newIdentityName.trim();
                  const roleInput = newIdentityRole;
                  if (!nameInput) {
                    addLog('ERROR', 'Please enter a name to register.');
                    return;
                  }
                  if (state.certificates.some(c => c.subject === nameInput)) {
                    addLog('ERROR', `Identity already exists: ${nameInput}`);
                    return;
                  }
                  handleGenerateIdentity(nameInput, roleInput);
                  setNewIdentityName('');
                }}
                className="col-span-1 bg-emerald-600 hover:bg-emerald-500 py-2 rounded-lg font-bold"
              >
                Register
              </button>
              <button
                onClick={() => setNewIdentityName('')}
                className="col-span-1 bg-slate-700 hover:bg-slate-600 py-2 rounded-lg font-bold"
              >
                Clear
              </button>
            </div>
            <div className="text-[11px] text-slate-400">Or use the quick enroll buttons below.</div>
            <div className="space-y-2">
              <button 
                onClick={() => handleGenerateIdentity("Dr. Alice", Role.DOCTOR)}
                disabled={state.certificates.some(c => c.subject === "Dr. Alice")}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 py-3 rounded-lg font-bold transition-colors flex items-center justify-center gap-2"
              >
                <span>👨‍⚕️</span> Enroll Dr. Alice
              </button>
              <button 
                onClick={() => handleGenerateIdentity("Mr. Bob", Role.PATIENT)}
                disabled={state.certificates.some(c => c.subject === "Mr. Bob")}
                className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 py-3 rounded-lg font-bold transition-colors flex items-center justify-center gap-2"
              >
                <span>👤</span> Enroll Mr. Bob (Patient)
              </button>
            </div>
          </div>
        </div>

        <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
          <h3 className="text-sm font-bold uppercase text-slate-500 mb-4">Your Private Key Vault</h3>
          {Object.entries(state.keyPairs).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(state.keyPairs).map(([name, keys]: [string, any]) => (
                <div key={name} className="p-3 bg-slate-900 rounded border border-slate-800">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-bold text-slate-300">{name}'s Vault</span>
                    <span className="text-[10px] text-green-500 font-mono">ENCRYPTED AT REST</span>
                  </div>
                  <div className="font-mono text-[10px] text-slate-500 break-all bg-black p-2 rounded truncate">
                    {keys.privateKey}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-600 italic">No keys stored in local vault.</div>
          )}
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-bold">Public Certificates</h2>
        <div className="space-y-4 overflow-y-auto max-h-[600px] pr-2">
          {state.certificates.map((cert) => (
            <div key={cert.serialNumber} className={`bg-slate-800 rounded-xl border p-4 relative ${cert.isRevoked ? 'border-red-900 opacity-60' : 'border-slate-700'}`}>
              {cert.isRevoked && (
                <div className="absolute top-2 right-2 bg-red-600 text-white text-[10px] px-2 py-0.5 rounded font-bold uppercase">Revoked</div>
              )}
              <div className="flex justify-between items-start mb-3">
                <div>
                  <h4 className="font-bold text-blue-400">{cert.subject}</h4>
                  <p className="text-[10px] text-slate-500">Serial: {cert.serialNumber}</p>
                </div>
                <div className="text-right flex items-start gap-2">
                  <button onClick={() => handleExportIdentity(cert)} className="text-[10px] bg-slate-700 px-2 py-1 rounded">Export</button>
                  <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                    cert.role === Role.DOCTOR ? 'bg-blue-900 text-blue-300' :
                    cert.role === Role.PATIENT ? 'bg-indigo-900 text-indigo-300' :
                    'bg-slate-900 text-slate-300'
                  }`}>
                    {cert.role}
                  </span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between text-[10px]">
                  <span className="text-slate-500">Issuer:</span>
                  <span className="text-slate-300">{cert.issuer}</span>
                </div>
                <div className="flex justify-between text-[10px]">
                  <span className="text-slate-500">Algorithm:</span>
                  <span className="text-slate-300">RSA-2048 / SHA-256</span>
                </div>
                <div className="flex justify-between text-[10px]">
                  <span className="text-slate-500">Expiry:</span>
                  <span className="text-slate-300">{new Date(cert.validTo).toLocaleDateString()}</span>
                </div>
                <div className="mt-2 p-2 bg-slate-900 rounded font-mono text-[9px] text-slate-500 truncate border border-slate-800">
                  {cert.publicKey}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderSecureExchange = () => {
    const isDoctor = state.currentUserRole === Role.DOCTOR;
    const isPatient = state.currentUserRole === Role.PATIENT;
    const doctorCert = state.certificates.find(c => c.subject === currentUserName);

    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 h-full">
        <div className="space-y-6">
          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6 shadow-xl">
            <h2 className="text-lg font-bold mb-4 flex items-center gap-2">
              <span>✍️</span> Compose Secure Report
            </h2>
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-slate-500 uppercase block mb-1">Select Patient (Recipient)</label>
                <select 
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-sm"
                  value={selectedRecipient}
                  onChange={(e) => setSelectedRecipient(e.target.value)}
                >
                  <option value="">-- Choose Recipient --</option>
                  {state.certificates.filter(c => c.role === Role.PATIENT && !c.isRevoked).map(c => (
                    <option key={c.subject} value={c.subject}>{c.subject}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-bold text-slate-500 uppercase block mb-1">Medical Observations</label>
                <textarea 
                  value={reportText}
                  onChange={(e) => setReportText(e.target.value)}
                  placeholder="Enter medical findings..."
                  className="w-full h-32 bg-slate-900 border border-slate-700 rounded p-3 text-sm focus:ring-1 focus:ring-blue-500 focus:outline-none"
                />
              </div>
              <button 
                onClick={handleSendReport}
                disabled={!isDoctor || !selectedRecipient || !reportText || doctorCert?.isRevoked}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 py-3 rounded-lg font-bold transition-all shadow-lg active:scale-[0.98]"
              >
                Sign & Encrypt Report
              </button>
              {doctorCert?.isRevoked && (
                <p className="text-[10px] text-yellow-300 text-center italic mt-2">Signing disabled: Doctor's certificate has been revoked.</p>
              )}
              {!isDoctor && <p className="text-[10px] text-red-400 text-center italic">Access Denied: Only doctors can issue reports.</p>}
            </div>
          </div>

          <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold text-slate-400 uppercase">Process Overview</h3>
            <div className="space-y-3">
              <div className="flex gap-3 items-start">
                <div className="bg-blue-900/40 text-blue-400 w-6 h-6 rounded flex items-center justify-center flex-shrink-0 text-xs font-bold">1</div>
                <div>
                  <p className="text-xs font-bold">Hashing</p>
                  <p className="text-[10px] text-slate-500">Create fixed-length digest of the report data using SHA-256.</p>
                </div>
              </div>
              <div className="flex gap-3 items-start">
                <div className="bg-blue-900/40 text-blue-400 w-6 h-6 rounded flex items-center justify-center flex-shrink-0 text-xs font-bold">2</div>
                <div>
                  <p className="text-xs font-bold">Digital Signature</p>
                  <p className="text-[10px] text-slate-500">Doctor signs the hash with their RSA Private Key (Non-repudiation).</p>
                </div>
              </div>
              <div className="flex gap-3 items-start">
                <div className="bg-blue-900/40 text-blue-400 w-6 h-6 rounded flex items-center justify-center flex-shrink-0 text-xs font-bold">3</div>
                <div>
                  <p className="text-xs font-bold">Asymmetric Encryption</p>
                  <p className="text-[10px] text-slate-500">Encrypt report with Patient's RSA Public Key (Confidentiality).</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <h2 className="text-lg font-bold">Inbox / Secure Reports</h2>
          <div className="space-y-4">
            {state.reports.length === 0 && <div className="text-center py-12 text-slate-600 italic">No reports found in the network...</div>}
            {state.reports.map((report) => (
              <ReportCard key={report.id} report={report} state={state} addLog={addLog} />
            ))}
          </div>
        </div>
      </div>
    );
  };

  const renderCA = () => (
    <div className="space-y-6">
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
        <h2 className="text-lg font-bold mb-4">Certificate Revocation List (CRL) Management</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-900 text-slate-500 uppercase text-[10px] font-bold">
              <tr>
                <th className="p-3">Subject</th>
                <th className="p-3">Serial Number</th>
                <th className="p-3">Role</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {state.certificates.map(cert => (
                <tr key={cert.serialNumber} className="hover:bg-slate-700/30 transition-colors">
                  <td className="p-3 font-medium">{cert.subject}</td>
                  <td className="p-3 font-mono text-[10px]">{cert.serialNumber}</td>
                  <td className="p-3">{cert.role}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${cert.isRevoked ? 'bg-red-900/40 text-red-400' : 'bg-green-900/40 text-green-400'}`}>
                      {cert.isRevoked ? 'REVOKED' : 'ACTIVE'}
                    </span>
                  </td>
                  <td className="p-3 text-right">
                    <button 
                      onClick={() => handleRevoke(cert.serialNumber)}
                      disabled={cert.isRevoked || cert.role === Role.CA}
                      className="text-[10px] bg-red-600/20 text-red-500 border border-red-500/50 px-2 py-1 rounded hover:bg-red-600 hover:text-white disabled:opacity-30 transition-all"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800">
          <h3 className="font-bold mb-2">Trust Policy</h3>
          <p className="text-xs text-slate-400">
            The Internal CA is the root of trust. All entities must present a certificate signed by this authority to participate in report exchange.
            If a certificate is revoked, signatures from that entity will no longer be considered valid by the client tool.
          </p>
        </div>
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-bold mb-1">Root Certificate</h3>
            <p className="text-[10px] text-slate-500">SHA-256 Fingerprint: 0xFD...23</p>
          </div>
          <button className="bg-slate-700 hover:bg-slate-600 text-xs px-3 py-1.5 rounded transition-colors">Export .CER</button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden text-slate-200">
      <Sidebar 
        currentTab={activeTab} 
        setTab={setActiveTab} 
        userRole={state.currentUserRole}
        setUserRole={(role) => setState(prev => ({ ...prev, currentUserRole: role }))}
      />
      
      <main className="flex-1 overflow-hidden flex flex-col">
        <header className="h-16 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between px-8">
          <div className="flex items-center gap-3">
            <span className="text-sm font-bold uppercase text-slate-500">{activeTab.replace('-', ' ')}</span>
            <span className="h-4 w-px bg-slate-700"></span>
            <div className="text-xs text-slate-400 flex items-center gap-2">
              <span className="opacity-50">Identity:</span>
              <select
                value={currentUserName}
                onChange={(e) => setCurrentUserName(e.target.value)}
                className="bg-transparent text-blue-400 font-bold text-sm border-none p-0 m-0"
              >
                {state.certificates.filter(c => c.role === state.currentUserRole && !c.isRevoked).map(c => (
                  <option key={c.subject} value={c.subject}>{c.subject}</option>
                ))}
                {state.certificates.filter(c => c.role === state.currentUserRole && !c.isRevoked).length === 0 && (
                  <option value={state.currentUserRole === Role.DOCTOR ? 'Dr. Alice' : state.currentUserRole === Role.PATIENT ? 'Mr. Bob' : 'Administrator'}>
                    {state.currentUserRole === Role.DOCTOR ? 'Dr. Alice' : state.currentUserRole === Role.PATIENT ? 'Mr. Bob' : 'Administrator'}
                  </option>
                )}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex -space-x-2">
              {state.certificates.map(c => (
                <div key={c.subject} title={c.subject} className="w-6 h-6 rounded-full bg-slate-700 border border-slate-900 flex items-center justify-center text-[10px] font-bold cursor-help">
                  {c.subject[0]}
                </div>
              ))}
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8">
          <div className="max-w-6xl mx-auto h-full">
            {activeTab === 'dashboard' && renderDashboard()}
            {activeTab === 'identity' && renderIdentity()}
            {activeTab === 'ca' && renderCA()}
            {activeTab === 'secure-exchange' && renderSecureExchange()}
            {activeTab === 'logs' && <div className="h-[600px]"><LogViewer logs={state.logs} /></div>}
          </div>
        </div>
      </main>

      {/* Floating Log Feed for non-log tab */}
      {activeTab !== 'logs' && (
        <div className="w-80 border-l border-slate-800 hidden xl:block">
          <LogViewer logs={state.logs} />
        </div>
      )}
    </div>
  );
};

// Sub-component for Report Card to handle local interactive state (decryption/verification)
const ReportCard: React.FC<{ report: MedicalReport, state: PKIState, addLog: (t: LogEntry['type'], m: string, d?: string) => void }> = ({ report, state, addLog }) => {
  const [isDecrypted, setIsDecrypted] = useState(false);
  const [decryptedContent, setDecryptedContent] = useState<string>("");
  const [verifyStatus, setVerifyStatus] = useState<'IDLE' | 'SUCCESS' | 'FAILED'>('IDLE');

  const handleDecrypt = () => {
    // Check if current user is a patient
    if (state.currentUserRole !== Role.PATIENT) {
      addLog('ERROR', `Access Denied: Only patients can decrypt reports.`);
      return;
    }

    // Get the private key for the patient this report was sent to
    const patientKeys = state.keyPairs[report.patientName];
    if (!patientKeys) {
      addLog('ERROR', `Access Denied: Private key not found for ${report.patientName}.`);
      return;
    }

    if (report.encryptedContent) {
      (async () => {
        try {
          const result = await decryptData(report.encryptedContent!, patientKeys.privateKey);
          setDecryptedContent(result);
          setIsDecrypted(true);
          addLog('SUCCESS', `Report decrypted successfully by ${report.patientName}.`);
        } catch (e) {
          addLog('ERROR', `Decryption failed: ${(e as Error).message}`);
        }
      })();
    }
  };

  const handleVerify = () => {
    if (!isDecrypted || !report.signature) return;

    const doctorCert = state.certificates.find(c => c.subject === report.doctorName);
    if (!doctorCert) {
      addLog('ERROR', `Verification Failed: Signer's certificate not found.`);
      setVerifyStatus('FAILED');
      return;
    }

    if (doctorCert.isRevoked) {
      addLog('ERROR', `Security Warning: Signer's certificate has been revoked by the CA!`);
      setVerifyStatus('FAILED');
      return;
    }

    (async () => {
      try {
        const isValid = await verifySignature(decryptedContent, report.signature!, doctorCert.publicKey);
        if (isValid) {
          setVerifyStatus('SUCCESS');
          addLog('SUCCESS', `Digital Signature Verified. Integrity and Authentication confirmed.`);
        } else {
          setVerifyStatus('FAILED');
          addLog('ERROR', `CRITICAL: Signature mismatch! Report tampering detected.`);
        }
      } catch (e) {
        setVerifyStatus('FAILED');
        addLog('ERROR', `Verification error: ${(e as Error).message}`);
      }
    })();
  };

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden shadow-lg animate-in slide-in-from-bottom-2 duration-500">
      <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-900/40">
        <div>
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">From</span>
          <span className="text-sm font-bold text-blue-400">{report.doctorName}</span>
        </div>
        <div className="text-right">
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">To</span>
          <span className="text-sm font-bold text-indigo-400">{report.patientName}</span>
        </div>
      </div>
      
      <div className="p-6 space-y-4">
        <div className="bg-black/40 rounded border border-slate-700 p-4 font-mono text-xs">
          {isDecrypted ? (
            <div className="text-slate-200">{decryptedContent}</div>
          ) : (
            <div className="text-slate-600 break-all leading-tight italic">
              {report.encryptedContent?.substring(0, 100)}... (CIPHERTEXT)
            </div>
          )}
        </div>

        <div className="flex gap-2">
          {!isDecrypted ? (
            <>
              <button 
                onClick={handleDecrypt}
                disabled={state.currentUserRole !== Role.PATIENT}
                className="flex-1 bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 disabled:cursor-not-allowed py-2 rounded text-xs font-bold transition-all"
              >
                🔓 Decrypt with Private Key
              </button>
              {state.currentUserRole !== Role.PATIENT && (
                <div className="flex-1 bg-yellow-900/20 border border-yellow-600/50 rounded p-2 flex items-center gap-2">
                  <span className="text-xs text-yellow-400">⚠️ Switch to Patient role in sidebar to decrypt</span>
                </div>
              )}
            </>
          ) : (
            <button 
              onClick={handleVerify}
              disabled={verifyStatus === 'SUCCESS'}
              className={`flex-1 py-2 rounded text-xs font-bold transition-all border ${
                verifyStatus === 'SUCCESS' ? 'bg-green-900/20 border-green-500 text-green-500' :
                verifyStatus === 'FAILED' ? 'bg-red-900/20 border-red-500 text-red-500' :
                'bg-blue-600 hover:bg-blue-500 border-blue-600'
              }`}
            >
              {verifyStatus === 'SUCCESS' ? '✓ Signature Valid' : 
               verifyStatus === 'FAILED' ? '✗ Verification Failed' : '🛡️ Verify Digital Signature'}
            </button>
          )}
        </div>

        {verifyStatus === 'SUCCESS' && (
          <div className="bg-green-900/20 border border-green-500/30 p-2 rounded flex items-center gap-2">
            <span className="text-lg">✅</span>
            <div className="text-[10px]">
              <p className="font-bold text-green-400 uppercase">Trusted Content</p>
              <p className="text-green-500/80">Identity confirmed via PKI. Data has not been tampered with.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
