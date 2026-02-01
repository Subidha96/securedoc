# Secure Client PKI Tool

A lightweight, educational GUI-based PKI (Public Key Infrastructure) security tool demonstrating digital certificates, RSA encryption, digital signatures, and secure medical report exchange for healthcare data protection.

## Features

✅ **PKI System Architecture** - Certificate Authority, key pairs, trust anchors  
✅ **Digital Signatures** - SHA-256 hashing and RSA signature generation/verification  
✅ **Asymmetric Encryption** - RSA encryption/decryption for confidentiality  
✅ **Certificate Lifecycle Management** - Issue, revoke, and validate certificates  
✅ **Role-Based Access Control** - Doctor, Patient, and CA Administrator roles  
✅ **Secure Report Exchange** - Encrypted and signed medical report transmission  
✅ **Real-time Security Logs** - Track all cryptographic operations  

## Prerequisites

- Node.js (v18 or higher)
- npm or yarn

## Installation & Running

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

3. Open your browser to `http://localhost:3000`

## Build for Production

```bash
npm run build
npm run preview
```

## Docker Setup

### Build Docker Image Locally

```bash
docker build -t securedoc:latest .
```

### Run with Docker

```bash
docker run -p 3000:3000 securedoc:latest
```

Open your browser to `http://localhost:3000`

### Using Pre-built Docker Image

Pull and run the latest pre-built image from GitHub Container Registry:

```bash
docker pull ghcr.io/subidha96/securedoc:latest
docker run -p 3000:3000 ghcr.io/subidha96/securedoc:latest
```

### Release Versions

Tagged release images are available:

```bash
docker pull ghcr.io/subidha96/securedoc:v1.0.0
docker run -p 3000:3000 ghcr.io/subidha96/securedoc:v1.0.0
```



- **Root CA Initialization**: System initializes with an Internal Root CA on startup
- **Identity Enrollment**: Users can enroll as doctors or patients with cryptographic key pairs
- **Certificate Issuance**: Root CA signs certificates for enrolled entities
- **Secure Exchange**: Doctors compose, sign, and encrypt reports for patients
- **Verification**: Patients decrypt and verify the authenticity of received reports

## Security Features Demonstrated

- **Confidentiality**: RSA-2048 encryption
- **Integrity**: SHA-256 hashing
- **Authentication**: CA-signed digital certificates
- **Non-repudiation**: Digital signatures with private keys

## Educational Use

This tool is designed for educational purposes to understand PKI concepts. The cryptographic operations use simulated implementations for demonstration clarity. For production use, integrate with real Web Crypto APIs and proper key management systems.
