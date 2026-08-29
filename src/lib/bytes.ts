/** Byte/hex/text helpers shared by the pages (pure TypeScript, no wasm). */

export const isHex = (s: string): boolean => /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0;

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (!isHex(clean)) throw new Error('Invalid hex string');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export const textToHex = (s: string): string => bytesToHex(new TextEncoder().encode(s));

export function hexToText(hex: string): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(hexToBytes(hex));
}

export function hexToBase64(hex: string): string {
  return btoa(String.fromCharCode(...hexToBytes(hex)));
}

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

/** Number of differing bits between two equal-length hex strings. */
export function hammingDistanceHex(a: string, b: string): number {
  const x = hexToBytes(a), y = hexToBytes(b);
  let d = 0;
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    let v = x[i] ^ y[i];
    while (v) { d += v & 1; v >>= 1; }
  }
  return d;
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return '∞';
  if (seconds < 1e-3) return '< 1 ms';
  if (seconds < 1) return `${(seconds * 1e3).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} h`;
  const years = seconds / 31557600;
  if (years < 1) return `${(seconds / 86400).toFixed(1)} days`;
  if (years < 1e3) return `${years.toFixed(1)} years`;
  if (years < 1e6) return `${(years / 1e3).toFixed(1)} thousand years`;
  if (years < 1e9) return `${(years / 1e6).toFixed(1)} million years`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)} billion years`;
  return `${years.toExponential(2)} years`;
}

export function formatMs(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}
