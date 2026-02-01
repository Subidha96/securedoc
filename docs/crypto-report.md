# Cryptography & Security Report — secure-client-pki-tool

Generated: 2026-02-01

## Purpose
This file documents the cryptographic features, functions, data flows, parameters, and security considerations found in this workspace. It is intended as a reference for developers and auditors working on the project.

## Key files referenced
- [services/cryptoService.ts](services/cryptoService.ts)
- [services/ocspService.ts](services/ocspService.ts)
- [App.tsx](App.tsx)
- [package.json](package.json)

## High-level summary
- Asymmetric algorithms: RSA (2048-bit) used for encryption (RSA-OAEP) and signing (RSA-PSS).
- Symmetric algorithm: AES-GCM (256-bit) used for bulk encryption (hybrid scheme).
- Password-based key derivation: PBKDF2 with SHA-256 and 100,000 iterations.
- Hybrid encryption: AES-GCM payload encrypted with one-time AES key; AES key wrapped with RSA-OAEP.
- Signing: RSA-PSS with SHA-256, `saltLength: 32` (used in `signData`/`verifySignature`).
- Key export format: base64-encoded SPKI (public) and PKCS#8 (private) blobs wrapped in JSON strings.
- Identity export: password-protected JSON bundle (PBKDF2 + AES-GCM) implemented; PKCS#12 support planned (node-forge added to dependencies).

## Concrete functions and what they do

- `simulateKeyGeneration(subject)` — services/cryptoService.ts
  - Generates two RSA-2048 key pairs using Web Crypto:
    - RSA-OAEP (encryption/decryption) for confidentiality.
    - RSA-PSS (sign/verify) for signatures.
  - Exports public keys as SPKI and private keys as PKCS#8, base64-encodes them and returns a `KeyPair` object containing `publicKey` and `privateKey` JSON-strings.
  - Stores the runtime `CryptoKey` objects in module-level maps `privateKeyStore` and `publicKeyStore` keyed by the exported base64 JSON string.

- `registerImportedKeyPair(privateKeyStr, publicKeyStr)` — services/cryptoService.ts
  - Imports base64 SPKI/PKCS#8 blobs into `CryptoKey` objects and registers them in the module maps.
  - Enables the UI to import previously exported identity bundles and use the keys immediately.

- `signData(data, privateKeyStr)` — services/cryptoService.ts
  - Signs UTF-8 `data` using RSA-PSS (SHA-256) and returns base64 signature.
  - Uses the `CryptoKey` in `privateKeyStore[privateKeyStr].sign`.

- `verifySignature(data, signatureB64, publicKeyStr)` — services/cryptoService.ts
  - Verifies a base64 signature against `data` using the `CryptoKey` in `publicKeyStore[publicKeyStr].sign` (RSA-PSS, SHA-256).

- `encryptData(data, publicKeyStr)` — services/cryptoService.ts
  - Implements hybrid encryption:
    1. Generates a one-time AES-GCM-256 key and a 12-byte IV.
    2. Encrypts `data` with AES-GCM.
    3. Exports AES key raw bytes and encrypts (wraps) them with recipient's RSA-OAEP public key.
    4. Returns a JSON string with base64 `wrappedKey`, `iv`, and `ciphertext`.

- `decryptData(encryptedDataStr, privateKeyStr)` — services/cryptoService.ts
  - Parses the JSON payload, decrypts the wrapped AES key with RSA-OAEP private key, imports AES key, then decrypts ciphertext with AES-GCM and returns UTF-8 plaintext (or 'DECRYPTION_FAILED' on error).

- `encryptWithPassword(plaintext, password)` / `decryptWithPassword(payloadStr, password)` — services/cryptoService.ts
  - PBKDF2 (SHA-256, 100,000 iterations) derives an AES-GCM key from `password` and a 16-byte random salt.
  - AES-GCM (12-byte IV) encrypts the plaintext; result is JSON with base64 `salt`, `iv`, and `ciphertext`.
  - Used by `exportIdentityBundle` / `importIdentityBundle` and the vault persistence flows in `App.tsx`.

- `exportIdentityBundle(cert, privateKeyStr, password)` / `importIdentityBundle(bundleStr, password)` — services/cryptoService.ts
  - Wrap and unwrap a JSON object `{ cert, privateKeyStr }` with password-based encryption described above.

- `createCertificate(subject, role, publicKey, issuerCert)` — services/cryptoService.ts
  - Produces a lightweight JS certificate object with properties: `serialNumber`, `subject`, `issuer`, `role`, `publicKey`, `validFrom`, `validTo`, `isRevoked`, `signature`.
  - `signature` is a placeholder mock (not a real X.509 signature) and should be replaced when moving to real certificates.

- `isCertificateValid(cert)` — services/cryptoService.ts
  - Performs expiry and `isRevoked` checks (no CRL/OCSP network checks by default; an in-memory simulator exists separately).

- `services/ocspService.ts` (new)
  - In-memory CRL/OCSP helper functions: `revokeSerial(serial)`, `unrevokeSerial(serial)`, `isRevoked(serial)`, `listCRL()`.
  - Currently not deeply integrated into all verification flows; `isCertificateValid` uses only `isRevoked` flag on the cert object itself.

## Data formats & key material handling
- Public keys: exported as SPKI (base64), stored within a JSON string: `JSON.stringify({ enc: '<spki>', sign: '<spki>' })`.
- Private keys: exported as PKCS#8 (base64), stored within a JSON string: `JSON.stringify({ enc: '<pkcs8>', sign: '<pkcs8>' })`.
- Runtime representation: module `privateKeyStore` and `publicKeyStore` map the exported string to usable `CryptoKey` objects.
- Exported identity bundle: encrypted JSON (not PKCS#12), containing certificate and the exported private key string; protected by PBKDF2-derived AES-GCM.

## Security parameters (explicit)
- RSA keys: 2048-bit modulus (generated by Web Crypto).
- RSA-PSS: SHA-256 hash, saltLength = 32 (as used in signing/verification calls).
- RSA-OAEP: SHA-256 hash (used for wrapping AES keys).
- AES-GCM: 256-bit key, IV length 12 bytes (generated with `crypto.getRandomValues`).
- PBKDF2: SHA-256, iterations = 100000, salt length = 16 bytes.

## Current limitations & risks
- Private key extractability: The implementation exports private keys as PKCS#8 base64 and stores them in memory and in encrypted bundles. This means private keys are exportable by design — acceptable for a demo but risky for production.
- Module-level key maps: `privateKeyStore` and `publicKeyStore` keep `CryptoKey` references keyed by exported strings. If the exported strings are leaked, they reveal a mapping to runtime keys.
- Certificate model: certificates are JS objects with a mock `signature` field, not real X.509 structures. This limits interoperability and realistic chain validation.
- Revocation: an in-memory CRL/OCSP helper exists but there is no full OCSP flow or remote revocation checking. `isCertificateValid` uses only certificate fields.
- PKCS#12: not implemented yet; `node-forge` is present in dependencies but no code currently builds or imports true `.p12` blobs.
- PBKDF2 iterations: 100,000 is moderate; for higher resistance to brute force consider Argon2 or higher iteration counts depending on the threat model and platform performance.

## Recommendations & next steps
1. PKCS#12 support
   - Implement true PKCS#12 export/import using `node-forge` or platform tooling so users can import identities into OS/third-party apps. Place code in a new `services/pkcs12Service.ts` and add UI in `App.tsx` for `.p12` export/import.
2. Non-extractable keys for runtime
   - For higher security, generate keys as non-exportable (set `extractable: false`) and avoid exporting private key PKCS#8 unless explicitly requested by the user. Maintain a secure backup/export flow requiring password confirmation.
3. Stronger password-based protection
   - Consider Argon2 (via a WASM library) or increasing PBKDF2 iterations for vault/bundle protection.
4. Real X.509 certificates & chains
   - Replace the JS certificate object with real X.509 structures for interoperability and implement chain validation with proper issuer certificates.
5. OCSP/CRL integration
   - Wire `services/ocspService.ts` into verification flows so `verifySignature` and `isCertificateValid` consult the simulator (and plan an optional networked OCSP endpoint for integration testing).
6. Secure storage options
   - For production, consider platform secure storage (Keychain on macOS, Windows Credential Manager, etc.) or hardware-backed keys.
7. Tests
   - Add unit and integration tests (vitest is already listed in `package.json`) covering key generation, sign/verify, encrypt/decrypt, export/import, and revocation flows.

## Where to look in the code
- `services/cryptoService.ts` — core crypto operations (key generation, sign/verify, encrypt/decrypt, password-wrapped export/import).
- `services/ocspService.ts` — in-memory revocation helpers.
- `App.tsx` — UI flows that call the crypto service: registration, identity export/import, vault save/load, file sign/encrypt/decrypt, and revocation actions.

## Quick operational notes for devs
- To run the app locally: install dependencies and start Vite dev server (see `package.json` scripts).
- To test encryption/signing manually: create two identities, use `handleSignFile`, `handleEncryptFile`, and `handleDecryptFile` UI actions in the app to validate operations.

---
If you want, I can now implement true PKCS#12 export/import (`services/pkcs12Service.ts`) and add example UI buttons and a small test suite using `vitest`. Confirm and I will proceed.
