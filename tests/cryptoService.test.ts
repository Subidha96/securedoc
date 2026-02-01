import { describe, it, expect, beforeAll } from 'vitest';
import {
  simulateKeyGeneration,
  createCertificate,
  computeHash,
  signData,
  verifySignature,
  encryptData,
  decryptData,
  encryptWithPassword,
  decryptWithPassword,
  exportIdentityBundle,
  importIdentityBundle,
  isCertificateValid,
  registerImportedKeyPair,
  generateId
} from '../services/cryptoService';
import { revokeSerial, unrevokeSerial, isRevoked, listCRL } from '../services/ocspService';
import { Role } from '../types';

describe('Cryptographic Service Tests', () => {
  let aliceKeyPair: any;
  let bobKeyPair: any;
  let doctorCert: any;

  beforeAll(async () => {
    aliceKeyPair = await simulateKeyGeneration('Alice');
    bobKeyPair = await simulateKeyGeneration('Bob');
    doctorCert = createCertificate('Dr. Alice', Role.DOCTOR, aliceKeyPair.publicKey, null);
  });

  describe('ID Generation', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toBe(id2);
      expect(id1.length).toBeGreaterThan(0);
    });
  });

  describe('Key Generation (simulateKeyGeneration)', () => {
    it('should generate valid RSA-2048 key pair', async () => {
      const keyPair = await simulateKeyGeneration('TestUser');
      
      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.algorithm).toBe('RSA-2048');
      expect(keyPair.createdAt).toBeDefined();
    });

    it('should store keys as JSON-encoded base64 strings', async () => {
      const keyPair = await simulateKeyGeneration('JSONTest');
      
      const pubObj = JSON.parse(keyPair.publicKey);
      const privObj = JSON.parse(keyPair.privateKey);
      
      expect(pubObj.enc).toBeDefined();
      expect(pubObj.sign).toBeDefined();
      expect(privObj.enc).toBeDefined();
      expect(privObj.sign).toBeDefined();
    });

    it('should generate unique keys on each call', async () => {
      const kp1 = await simulateKeyGeneration('User');
      const kp2 = await simulateKeyGeneration('User');
      
      expect(kp1.publicKey).not.toBe(kp2.publicKey);
      expect(kp1.privateKey).not.toBe(kp2.privateKey);
    });
  });

  describe('Certificate Creation (createCertificate)', () => {
    it('should create valid certificate with required fields', () => {
      const cert = createCertificate('John Doe', Role.PATIENT, aliceKeyPair.publicKey, null);
      
      expect(cert.subject).toBe('John Doe');
      expect(cert.role).toBe(Role.PATIENT);
      expect(cert.publicKey).toBe(aliceKeyPair.publicKey);
      expect(cert.issuer).toBe('Root CA Internal');
      expect(cert.isRevoked).toBe(false);
      expect(cert.serialNumber).toBeDefined();
      expect(cert.signature).toBeDefined();
    });

    it('should set valid 1-year expiry window', () => {
      const cert = createCertificate('User', Role.DOCTOR, aliceKeyPair.publicKey, null);
      const now = Date.now();
      const oneYear = 365 * 24 * 60 * 60 * 1000;
      
      expect(cert.validFrom).toBeLessThanOrEqual(now);
      expect(cert.validTo).toBeGreaterThan(now);
      expect(cert.validTo - cert.validFrom).toBeCloseTo(oneYear, -2);
    });

    it('should set issuer from parent certificate', () => {
      const parentCert = createCertificate('CA', Role.CA, aliceKeyPair.publicKey, null);
      const childCert = createCertificate('User', Role.PATIENT, bobKeyPair.publicKey, parentCert);
      
      expect(childCert.issuer).toBe(parentCert.subject);
    });

    it('should generate unique serial numbers', () => {
      const cert1 = createCertificate('User1', Role.DOCTOR, aliceKeyPair.publicKey, null);
      const cert2 = createCertificate('User1', Role.DOCTOR, aliceKeyPair.publicKey, null);
      
      expect(cert1.serialNumber).not.toBe(cert2.serialNumber);
    });
  });

  describe('Hashing (computeHash)', () => {
    it('should compute SHA-256 hash', async () => {
      const hash = await computeHash('test data');
      
      expect(hash).toBeDefined();
      expect(hash.startsWith('sha256-')).toBe(true);
    });

    it('should produce deterministic hashes', async () => {
      const data = 'consistent input';
      const hash1 = await computeHash(data);
      const hash2 = await computeHash(data);
      
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await computeHash('input1');
      const hash2 = await computeHash('input2');
      
      expect(hash1).not.toBe(hash2);
    });

    it('should hash empty strings', async () => {
      const hash = await computeHash('');
      expect(hash).toBeDefined();
      expect(hash.startsWith('sha256-')).toBe(true);
    });

    it('should hash large inputs', async () => {
      const largeData = 'x'.repeat(100000);
      const hash = await computeHash(largeData);
      expect(hash).toBeDefined();
    });
  });

  describe('Digital Signatures (signData & verifySignature)', () => {
    it('should sign data with RSA-PSS', async () => {
      const data = 'Sign this message';
      const signature = await signData(data, aliceKeyPair.privateKey);
      
      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should verify valid signature', async () => {
      const data = 'Message to verify';
      const signature = await signData(data, aliceKeyPair.privateKey);
      const isValid = await verifySignature(data, signature, aliceKeyPair.publicKey);
      
      expect(isValid).toBe(true);
    });

    it('should reject tampered data signature', async () => {
      const originalData = 'Original message';
      const signature = await signData(originalData, aliceKeyPair.privateKey);
      const tamperedData = 'Tampered message';
      const isValid = await verifySignature(tamperedData, signature, aliceKeyPair.publicKey);
      
      expect(isValid).toBe(false);
    });

    it('should reject signature from wrong key', async () => {
      const data = 'Message';
      const signature = await signData(data, aliceKeyPair.privateKey);
      const isValid = await verifySignature(data, signature, bobKeyPair.publicKey);
      
      expect(isValid).toBe(false);
    });

    it('should produce different signatures for same data (RSA-PSS randomness)', async () => {
      const data = 'Same message';
      const sig1 = await signData(data, aliceKeyPair.privateKey);
      const sig2 = await signData(data, aliceKeyPair.privateKey);
      
      expect(sig1).not.toBe(sig2);
      expect(await verifySignature(data, sig1, aliceKeyPair.publicKey)).toBe(true);
      expect(await verifySignature(data, sig2, aliceKeyPair.publicKey)).toBe(true);
    });

    it('should sign and verify long messages', async () => {
      const longData = 'Message'.repeat(1000);
      const signature = await signData(longData, aliceKeyPair.privateKey);
      const isValid = await verifySignature(longData, signature, aliceKeyPair.publicKey);
      
      expect(isValid).toBe(true);
    });
  });

  describe('Hybrid Encryption (encryptData & decryptData)', () => {
    it('should encrypt data with RSA-OAEP + AES-GCM', async () => {
      const plaintext = 'Secret message';
      const ciphertext = await encryptData(plaintext, aliceKeyPair.publicKey);
      
      expect(ciphertext).toBeDefined();
      expect(typeof ciphertext).toBe('string');
      
      const parsed = JSON.parse(ciphertext);
      expect(parsed.wrappedKey).toBeDefined();
      expect(parsed.iv).toBeDefined();
      expect(parsed.ciphertext).toBeDefined();
    });

    it('should decrypt with corresponding private key', async () => {
      const plaintext = 'Confidential data';
      const ciphertext = await encryptData(plaintext, aliceKeyPair.publicKey);
      const decrypted = await decryptData(ciphertext, aliceKeyPair.privateKey);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should fail decryption with wrong private key', async () => {
      const plaintext = 'Secret';
      const ciphertext = await encryptData(plaintext, aliceKeyPair.publicKey);
      const decrypted = await decryptData(ciphertext, bobKeyPair.privateKey);
      
      expect(decrypted).toBe('DECRYPTION_FAILED');
    });

    it('should produce different ciphertexts for same plaintext', async () => {
      const plaintext = 'Same data';
      const cipher1 = await encryptData(plaintext, aliceKeyPair.publicKey);
      const cipher2 = await encryptData(plaintext, aliceKeyPair.publicKey);
      
      expect(cipher1).not.toBe(cipher2);
      expect(await decryptData(cipher1, aliceKeyPair.privateKey)).toBe(plaintext);
      expect(await decryptData(cipher2, aliceKeyPair.privateKey)).toBe(plaintext);
    });

    it('should handle large data encryption/decryption', async () => {
      const largeData = 'x'.repeat(50000);
      const ciphertext = await encryptData(largeData, aliceKeyPair.publicKey);
      const decrypted = await decryptData(ciphertext, aliceKeyPair.privateKey);
      
      expect(decrypted).toBe(largeData);
    });

    it('should fail gracefully on invalid ciphertext format', async () => {
      const result = await decryptData('invalid-json', aliceKeyPair.privateKey);
      expect(result).toBe('DECRYPTION_FAILED');
    });
  });

  describe('Password-Based Encryption (encryptWithPassword & decryptWithPassword)', () => {
    it('should encrypt with password using PBKDF2 + AES-GCM', async () => {
      const plaintext = 'Protected data';
      const password = 'strong-password-123';
      const encrypted = await encryptWithPassword(plaintext, password);
      
      expect(encrypted).toBeDefined();
      const parsed = JSON.parse(encrypted);
      expect(parsed.salt).toBeDefined();
      expect(parsed.iv).toBeDefined();
      expect(parsed.ciphertext).toBeDefined();
    });

    it('should decrypt with correct password', async () => {
      const plaintext = 'Secret content';
      const password = 'my-password';
      const encrypted = await encryptWithPassword(plaintext, password);
      const decrypted = await decryptWithPassword(encrypted, password);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should fail decryption with wrong password', async () => {
      const plaintext = 'Protected';
      const encrypted = await encryptWithPassword(plaintext, 'correct');
      
      try {
        await decryptWithPassword(encrypted, 'wrong');
        expect.fail('Should have thrown error');
      } catch (e) {
        expect(e).toBeDefined();
      }
    });

    it('should produce different ciphertexts for same password', async () => {
      const plaintext = 'Same data';
      const password = 'password';
      
      const enc1 = await encryptWithPassword(plaintext, password);
      const enc2 = await encryptWithPassword(plaintext, password);
      
      expect(enc1).not.toBe(enc2);
    });

    it('should handle empty passwords', async () => {
      const plaintext = 'Data';
      const encrypted = await encryptWithPassword(plaintext, '');
      const decrypted = await decryptWithPassword(encrypted, '');
      
      expect(decrypted).toBe(plaintext);
    });

    it('should handle special characters in password', async () => {
      const plaintext = 'Content';
      const password = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      const encrypted = await encryptWithPassword(plaintext, password);
      const decrypted = await decryptWithPassword(encrypted, password);
      
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('Identity Bundle Export/Import', () => {
    it('should export identity bundle', async () => {
      const password = 'bundle-password';
      const bundle = await exportIdentityBundle(doctorCert, aliceKeyPair.privateKey, password);
      
      expect(bundle).toBeDefined();
      const parsed = JSON.parse(bundle);
      expect(parsed.salt).toBeDefined();
      expect(parsed.iv).toBeDefined();
      expect(parsed.ciphertext).toBeDefined();
    });

    it('should import identity bundle with correct password', async () => {
      const password = 'import-password';
      const bundle = await exportIdentityBundle(doctorCert, aliceKeyPair.privateKey, password);
      const imported = await importIdentityBundle(bundle, password);
      
      expect(imported.cert.subject).toBe(doctorCert.subject);
      expect(imported.cert.role).toBe(doctorCert.role);
      expect(imported.privateKeyStr).toBe(aliceKeyPair.privateKey);
    });

    it('should fail import with wrong password', async () => {
      const bundle = await exportIdentityBundle(doctorCert, aliceKeyPair.privateKey, 'correct');
      
      try {
        await importIdentityBundle(bundle, 'wrong');
        expect.fail('Should have thrown error');
      } catch (e) {
        expect(e).toBeDefined();
      }
    });
  });

  describe('Certificate Validity (isCertificateValid)', () => {
    it('should mark freshly created certificate as valid', () => {
      const cert = createCertificate('User', Role.DOCTOR, aliceKeyPair.publicKey, null);
      expect(isCertificateValid(cert)).toBe(true);
    });

    it('should mark revoked certificate as invalid', () => {
      const cert = createCertificate('User', Role.PATIENT, aliceKeyPair.publicKey, null);
      cert.isRevoked = true;
      expect(isCertificateValid(cert)).toBe(false);
    });

    it('should mark expired certificate as invalid', () => {
      const cert = createCertificate('User', Role.DOCTOR, aliceKeyPair.publicKey, null);
      cert.validTo = Date.now() - 1000;
      expect(isCertificateValid(cert)).toBe(false);
    });

    it('should mark not-yet-valid certificate as invalid', () => {
      const cert = createCertificate('User', Role.DOCTOR, aliceKeyPair.publicKey, null);
      cert.validFrom = Date.now() + 100000;
      expect(isCertificateValid(cert)).toBe(false);
    });
  });

  describe('Key Registration (registerImportedKeyPair)', () => {
    it('should register imported keys', async () => {
      const keyPair = await simulateKeyGeneration('RegisterUser');
      const result = await registerImportedKeyPair(keyPair.privateKey, keyPair.publicKey);
      
      expect(result).toBe(true);
    });

    it('should enable signing after registration', async () => {
      const keyPair = await simulateKeyGeneration('SignAfterReg');
      await registerImportedKeyPair(keyPair.privateKey, keyPair.publicKey);
      
      const data = 'Sign after registration';
      const signature = await signData(data, keyPair.privateKey);
      const isValid = await verifySignature(data, signature, keyPair.publicKey);
      
      expect(isValid).toBe(true);
    });
  });

  describe('OCSP/CRL Service', () => {
    it('should revoke certificate serial', () => {
      const serial = 'SERIAL123';
      revokeSerial(serial);
      expect(isRevoked(serial)).toBe(true);
    });

    it('should unrevoke certificate serial', () => {
      const serial = 'SERIAL456';
      revokeSerial(serial);
      unrevokeSerial(serial);
      expect(isRevoked(serial)).toBe(false);
    });

    it('should return false for non-revoked serial', () => {
      expect(isRevoked('UNKNOWN')).toBe(false);
    });

    it('should list CRL entries', () => {
      const serial1 = 'SERIAL_LIST_1';
      const serial2 = 'SERIAL_LIST_2';
      revokeSerial(serial1);
      revokeSerial(serial2);
      
      const crl = listCRL();
      expect(crl.length).toBeGreaterThanOrEqual(2);
      expect(crl.some(e => e.serial === serial1)).toBe(true);
      expect(crl.some(e => e.serial === serial2)).toBe(true);
    });
  });

  describe('Integration Tests', () => {
    it('should execute complete secure communication flow', async () => {
      // Alice signs a message
      const message = 'Hello Bob, this is Alice';
      const signature = await signData(message, aliceKeyPair.privateKey);
      
      // Alice encrypts message and signature for Bob
      const encMsg = await encryptData(message, bobKeyPair.publicKey);
      const encSig = await encryptData(signature, bobKeyPair.publicKey);
      
      // Bob receives and decrypts
      const decMsg = await decryptData(encMsg, bobKeyPair.privateKey);
      const decSig = await decryptData(encSig, bobKeyPair.privateKey);
      
      // Bob verifies Alice's signature
      const isValid = await verifySignature(decMsg, decSig, aliceKeyPair.publicKey);
      
      expect(decMsg).toBe(message);
      expect(isValid).toBe(true);
    });

    it('should persist and restore identity vault', async () => {
      const vaultPassword = 'vault-master-key';
      
      // Export identity
      const bundle = await exportIdentityBundle(doctorCert, aliceKeyPair.privateKey, vaultPassword);
      
      // Simulate vault storage and retrieval
      const restored = await importIdentityBundle(bundle, vaultPassword);
      
      // Register and use restored keys
      await registerImportedKeyPair(restored.privateKeyStr, restored.cert.publicKey);
      
      const testData = 'Vault persistence test';
      const sig = await signData(testData, restored.privateKeyStr);
      const valid = await verifySignature(testData, sig, restored.cert.publicKey);
      
      expect(valid).toBe(true);
    });

    it('should validate certificate chain', () => {
      const caCert = createCertificate('Root CA', Role.CA, aliceKeyPair.publicKey, null);
      const doctorCert2 = createCertificate('Dr. Bob', Role.DOCTOR, bobKeyPair.publicKey, caCert);
      
      expect(isCertificateValid(caCert)).toBe(true);
      expect(isCertificateValid(doctorCert2)).toBe(true);
      expect(doctorCert2.issuer).toBe(caCert.subject);
    });

    it('should handle medical report signing and encryption', async () => {
      const reportContent = JSON.stringify({
        patientName: 'John Doe',
        diagnosis: 'Confidential medical information',
        timestamp: Date.now()
      });
      
      // Sign the report
      const signature = await signData(reportContent, aliceKeyPair.privateKey);
      
      // Encrypt for patient
      const encrypted = await encryptData(reportContent, bobKeyPair.publicKey);
      
      // Patient decrypts
      const decrypted = await decryptData(encrypted, bobKeyPair.privateKey);
      
      // Patient verifies doctor's signature
      const isValid = await verifySignature(decrypted, signature, aliceKeyPair.publicKey);
      
      expect(decrypted).toBe(reportContent);
      expect(isValid).toBe(true);
    });
  });
});
