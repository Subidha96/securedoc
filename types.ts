
export enum Role {
  DOCTOR = 'DOCTOR',
  PATIENT = 'PATIENT',
  CA = 'CERTIFICATE_AUTHORITY'
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
  algorithm: string;
  createdAt: number;
}

export interface Certificate {
  serialNumber: string;
  subject: string;
  issuer: string;
  role: Role;
  publicKey: string;
  validFrom: number;
  validTo: number;
  isRevoked: boolean;
  signature: string; // Signature of the CA
}

export interface MedicalReport {
  id: string;
  doctorName: string;
  patientName: string;
  content: string;
  timestamp: number;
  signature?: string;
  encryptedContent?: string;
}

export interface LogEntry {
  id: string;
  timestamp: number;
  type: 'INFO' | 'SUCCESS' | 'WARNING' | 'ERROR' | 'CRYPTO';
  message: string;
  details?: string;
}

export interface PKIState {
  currentUserRole: Role;
  caCertificate: Certificate | null;
  certificates: Certificate[];
  keyPairs: Record<string, KeyPair>; // Keyed by subject name
  logs: LogEntry[];
  reports: MedicalReport[];
}
