// Simple in-memory OCSP/CRL simulator
type RevokedEntry = { serial: string; revokedAt: number };

const CRL: RevokedEntry[] = [];

export const revokeSerial = (serial: string) => {
  if (!CRL.some(e => e.serial === serial)) CRL.push({ serial, revokedAt: Date.now() });
};

export const unrevokeSerial = (serial: string) => {
  const idx = CRL.findIndex(e => e.serial === serial);
  if (idx >= 0) CRL.splice(idx, 1);
};

export const isRevoked = (serial: string) => CRL.some(e => e.serial === serial);

export const listCRL = () => CRL.slice();

export default { revokeSerial, unrevokeSerial, isRevoked, listCRL };
