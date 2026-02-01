// Polyfill globalThis.crypto in Node.js environments (for Vitest)
// This only runs in test environments and doesn't affect the Vite browser build
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as any;
}
