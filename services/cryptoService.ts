
import { Certificate, KeyPair, Role } from '../types';

// Use globalThis.crypto (available in modern browsers and Node.js 16+)
// In Vitest with 'node' environment, globalThis.crypto is available
const crypto = globalThis.crypto as unknown as Crypto;

// Module-level maps to keep CryptoKey objects tied to exported key strings
const privateKeyStore: Record<string, { enc?: CryptoKey; sign?: CryptoKey }> = {};
const publicKeyStore: Record<string, { enc?: CryptoKey; sign?: CryptoKey }> = {};

export const generateId = () => Math.random().toString(36).substring(2, 15);

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

export const simulateKeyGeneration = async (subject: string): Promise<KeyPair> => {
  // Generate RSA-OAEP key pair for encryption
  const encKeyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  // Generate RSA-PSS key pair for signing
  const signKeyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  // Export keys to base64
  const encPub = arrayBufferToBase64(await crypto.subtle.exportKey('spki', encKeyPair.publicKey));
  const encPriv = arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', encKeyPair.privateKey));
  const signPub = arrayBufferToBase64(await crypto.subtle.exportKey('spki', signKeyPair.publicKey));
  const signPriv = arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', signKeyPair.privateKey));

  // Compose public/private payloads as JSON strings so older code can store a single string
  const publicKeyStr = JSON.stringify({ enc: encPub, sign: signPub });
  const privateKeyStr = JSON.stringify({ enc: encPriv, sign: signPriv });

  // Store CryptoKey objects in module maps indexed by the exported private/public strings
  privateKeyStore[privateKeyStr] = { enc: encKeyPair.privateKey, sign: signKeyPair.privateKey };
  publicKeyStore[publicKeyStr] = { enc: encKeyPair.publicKey, sign: signKeyPair.publicKey };

  return {
    publicKey: publicKeyStr,
    privateKey: privateKeyStr,
    algorithm: 'RSA-2048',
    createdAt: Date.now()
  };
};

export const createCertificate = (
  subject: string,
  role: Role,
  publicKey: string,
  issuerCert: Certificate | null
): Certificate => {
  const serial = generateId().toUpperCase();
  const now = Date.now();

  // Signature placeholder: in production, this would be the CA signing the certificate structure
  const mockSignature = arrayBufferToBase64(new TextEncoder().encode(`SIG-${serial}-${issuerCert?.subject || 'ROOT'}`));

  return {
    serialNumber: serial,
    subject,
    issuer: issuerCert ? issuerCert.subject : 'Root CA Internal',
    role,
    publicKey,
    validFrom: now,
    validTo: now + (365 * 24 * 60 * 60 * 1000), // 1 year
    isRevoked: false,
    signature: mockSignature
  };
};

export const computeHash = async (data: string): Promise<string> => {
  const enc = new TextEncoder().encode(data);
  const hashBuf = await crypto.subtle.digest('SHA-256', enc);
  return 'sha256-' + arrayBufferToBase64(hashBuf);
};

export const signData = async (data: string, privateKeyStr: string): Promise<string> => {
  const store = privateKeyStore[privateKeyStr];
  if (!store || !store.sign) throw new Error('Signing key not found');

  const enc = new TextEncoder().encode(data);
  const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, store.sign, enc);
  return arrayBufferToBase64(signature);
};

export const verifySignature = async (data: string, signatureB64: string, publicKeyStr: string): Promise<boolean> => {
  const pub = publicKeyStore[publicKeyStr];
  if (!pub || !pub.sign) throw new Error('Public signing key not found');

  const enc = new TextEncoder().encode(data);
  const sigBuf = base64ToArrayBuffer(signatureB64);
  return await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub.sign, sigBuf, enc);
};

export const encryptData = async (data: string, publicKeyStr: string): Promise<string> => {
  const pub = publicKeyStore[publicKeyStr];
  if (!pub || !pub.enc) throw new Error('Recipient public encryption key not found');

  // 1. Generate a one-time AES-GCM key
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // 2. Encrypt the payload with AES-GCM
  const encoded = new TextEncoder().encode(data);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);

  // 3. Export the raw AES key and encrypt (wrap) it using recipient's RSA-OAEP public key
  const rawAes = await crypto.subtle.exportKey('raw', aesKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub.enc, rawAes);

  return JSON.stringify({ wrappedKey: arrayBufferToBase64(wrappedKey), iv: arrayBufferToBase64(iv.buffer), ciphertext: arrayBufferToBase64(ciphertext) });
};

export const decryptData = async (encryptedDataStr: string, privateKeyStr: string): Promise<string> => {
  const store = privateKeyStore[privateKeyStr];
  if (!store || !store.enc) throw new Error('Recipient private encryption key not found');

  try {
    const obj = JSON.parse(encryptedDataStr);
    const wrappedKey = base64ToArrayBuffer(obj.wrappedKey);
    const iv = new Uint8Array(base64ToArrayBuffer(obj.iv));
    const ciphertext = base64ToArrayBuffer(obj.ciphertext);

    // Unwrap (decrypt) the AES key using RSA-OAEP private key
    const rawAes = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, store.enc, wrappedKey);
    const aesKey = await crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);

    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
    return new TextDecoder().decode(plainBuf);
  } catch (e) {
    return 'DECRYPTION_FAILED';
  }
};

// Password-based encryption helpers (PBKDF2 + AES-GCM)
export const encryptWithPassword = async (plaintext: string, password: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const derived = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, pwKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, derived, new TextEncoder().encode(plaintext));
  return JSON.stringify({ salt: arrayBufferToBase64(salt.buffer), iv: arrayBufferToBase64(iv.buffer), ciphertext: arrayBufferToBase64(ciphertext) });
};

export const decryptWithPassword = async (payloadStr: string, password: string) => {
  const obj = JSON.parse(payloadStr);
  const salt = base64ToArrayBuffer(obj.salt);
  const iv = new Uint8Array(base64ToArrayBuffer(obj.iv));
  const ciphertext = base64ToArrayBuffer(obj.ciphertext);
  const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const derived = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 100000, hash: 'SHA-256' }, pwKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, derived, ciphertext);
  return new TextDecoder().decode(plainBuf);
};

// Export identity (certificate + private key bundle) encrypted with password
export const exportIdentityBundle = async (cert: Certificate, privateKeyStr: string, password: string) => {
  const payload = JSON.stringify({ cert, privateKeyStr });
  return await encryptWithPassword(payload, password);
};

// Import identity bundle: decrypt and return parsed object
export const importIdentityBundle = async (bundleStr: string, password: string) => {
  const plaintext = await decryptWithPassword(bundleStr, password);
  return JSON.parse(plaintext) as { cert: Certificate; privateKeyStr: string };
};

// Simple certificate validity check (expiry + revocation)
export const isCertificateValid = (cert: Certificate) => {
  const now = Date.now();
  if (cert.isRevoked) return false;
  if (now < cert.validFrom || now > cert.validTo) return false;
  return true;
};

// Register imported raw key strings (private/public JSON payloads) into module maps
export const registerImportedKeyPair = async (privateKeyStr: string, publicKeyStr: string) => {
  try {
    const priv = JSON.parse(privateKeyStr) as { enc: string; sign: string };
    const pub = JSON.parse(publicKeyStr) as { enc: string; sign: string };

    // import public keys
    const encPubKey = await crypto.subtle.importKey('spki', base64ToArrayBuffer(pub.enc), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    const signPubKey = await crypto.subtle.importKey('spki', base64ToArrayBuffer(pub.sign), { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify']);

    // import private keys
    const encPrivKey = await crypto.subtle.importKey('pkcs8', base64ToArrayBuffer(priv.enc), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
    const signPrivKey = await crypto.subtle.importKey('pkcs8', base64ToArrayBuffer(priv.sign), { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);

    // store in maps
    publicKeyStore[publicKeyStr] = { enc: encPubKey, sign: signPubKey };
    privateKeyStore[privateKeyStr] = { enc: encPrivKey, sign: signPrivKey };
    return true;
  } catch (e) {
    return false;
  }
};
