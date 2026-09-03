/** Attack-cost arithmetic for §13 (pure TypeScript, no wasm). */

export interface AttackTarget {
  name: string;
  /** Effective classical security in bits: the attack costs ~2^bits operations. */
  bits: number;
  /** What the attacker actually runs — not always brute force. */
  attack: string;
  /** Outlook against a large fault-tolerant quantum computer. */
  quantum: string;
  note?: string;
}

// Asymmetric strengths are the NIST SP 800-57 equivalences: "RSA-2048 ≈ 112
// bits" means the number field sieve costs about as much as 2^112 symmetric
// operations, so one guesses/s scale can compare them all.
export const TARGETS: AttackTarget[] = [
  { name: 'DES', bits: 56, attack: 'brute force', quantum: 'Grover: 2²⁸ — instant', note: 'publicly brute-forced in 1998: EFF’s $250k Deep Crack, 56 hours' },
  { name: '3DES', bits: 112, attack: 'meet-in-the-middle', quantum: 'Grover: 2⁵⁶ effective', note: 'retired by NIST in 2023' },
  { name: 'AES-128', bits: 128, attack: 'brute force', quantum: 'Grover: 2⁶⁴ effective' },
  { name: 'AES-256', bits: 256, attack: 'brute force', quantum: 'Grover: 2¹²⁸ — still safe' },
  { name: 'RSA-1024', bits: 80, attack: 'GNFS factoring', quantum: 'Shor: broken outright', note: 'disallowed since 2013; RSA-768 was factored in 2009' },
  { name: 'RSA-2048', bits: 112, attack: 'GNFS factoring', quantum: 'Shor: broken outright' },
  { name: 'RSA-3072', bits: 128, attack: 'GNFS factoring', quantum: 'Shor: broken outright' },
  { name: 'X25519 / P-256', bits: 128, attack: 'Pollard’s rho on the curve', quantum: 'Shor: broken outright' },
];

export interface Adversary {
  id: string;
  name: string;
  rate: number;
  note: string;
}

export const ADVERSARIES: Adversary[] = [
  { id: 'device', name: 'This device', rate: 1e7, note: 'measured by the benchmark above' },
  { id: 'rig', name: 'GPU rig', rate: 1e10, note: '10¹⁰ guesses/s — eight top GPUs, the offline-cracking figure from §7' },
  { id: 'state', name: 'Nation state', rate: 1e16, note: '10¹⁶ guesses/s — a million GPU rigs running as one machine' },
  { id: 'bitcoin', name: 'All of Bitcoin', rate: 1e21, note: '10²¹ ops/s — every mining ASIC on earth repurposed (they cannot be; this is an upper bound on humanity’s brute force)' },
];

export const SECONDS_PER_YEAR = 31_557_600;
export const AGE_OF_UNIVERSE_SECONDS = 4.35e17; // ≈ 13.8 billion years

/** Expected time to hit the key: half the space at the given rate. */
export function expectedBreakSeconds(bits: number, ratePerSecond: number): number {
  return 2 ** (bits - 1) / ratePerSecond;
}

/** "3.2 × 10¹⁵" — exponents rendered as superscripts, no 'e' notation. */
export function formatBig(x: number): string {
  if (!Number.isFinite(x)) return '∞';
  if (x < 1000) return x >= 10 ? String(Math.round(x)) : x.toPrecision(2);
  const sup = '⁰¹²³⁴⁵⁶⁷⁸⁹';
  const e = Math.floor(Math.log10(x));
  const mant = (x / 10 ** e).toPrecision(2);
  const exp = String(e).split('').map((d) => sup[Number(d)]).join('');
  return `${mant} × 10${exp}`;
}

/** The break time expressed in ages of the universe (may be far below 1). */
export function universeAges(seconds: number): number {
  return seconds / AGE_OF_UNIVERSE_SECONDS;
}
