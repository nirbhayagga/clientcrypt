'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { formatDuration, formatMs, randomHex, hexToBytes } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, Select, Output, Stat, Status, ErrorText, Button, Callout } from '@/components/ui';

const RATES: { label: string; rate: number; note: string }[] = [
  { label: 'Online, rate-limited', rate: 100, note: '100 guesses/s — a login form with throttling' },
  { label: 'Online, unthrottled', rate: 1e4, note: '10⁴ guesses/s — API without lockout' },
  { label: 'Offline, Argon2id / bcrypt', rate: 1e5, note: '10⁵ guesses/s — leaked database with a slow hash' },
  { label: 'Offline, SHA-256 on GPUs', rate: 1e11, note: '10¹¹ guesses/s — leaked database with a fast hash' },
];

const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? 'th' : ['th', 'st', 'nd', 'rd'][n % 10] ?? 'th'}`;

export default function PasswordsPage() {
  const state = useWasm();
  const ready = state === 'ready';
  const P = wasm.PasswordSecurity;

  const [pw, setPw] = useState('Tr0ub4dor&3');
  const entropy = ready ? P.calculate_entropy(pw) : 0;
  const pool = ready ? P.alphabet_size(pw) : undefined;
  const rank = ready ? P.common_password_rank(pw) : 0;
  const length = Array.from(pw).length;
  const tone: 'danger' | 'warn' | 'ok' | 'accent' = rank ? 'danger' : entropy < 40 ? 'danger' : entropy < 60 ? 'warn' : entropy < 80 ? 'ok' : 'accent';

  // KDF cost
  const [iterations, setIterations] = useState(600_000);
  const [mKib, setMKib] = useState(19 * 1024);
  const [tCost, setTCost] = useState(2);
  const [logN, setLogN] = useState(14);
  const [salt] = useState(() => randomHex(16));
  const [kdf, setKdf] = useState<{ pbkdf2: string; pbkdf2Ms: number; scrypt: string; scryptMs: number; argon: string; argonMs: number; shaUs: number } | null>(null);
  const [kdfBusy, setKdfBusy] = useState(false);
  const [kdfError, setKdfError] = useState<string | null>(null);

  const runKdf = () => {
    setKdfBusy(true); setKdfError(null);
    setTimeout(() => {
      const r = attempt(() => {
        const s = hexToBytes(salt);
        const t0 = performance.now();
        P.benchmark_sha256(10_000);
        const shaUs = ((performance.now() - t0) / 10_000) * 1000;
        const t1 = performance.now();
        const pbkdf2 = P.pbkdf2_sha256(pw, s, iterations, 32);
        const pbkdf2Ms = performance.now() - t1;
        const t2 = performance.now();
        const scrypt = P.scrypt(pw, s, logN, 8, 1);
        const scryptMs = performance.now() - t2;
        const t3 = performance.now();
        const argon = P.argon2id(pw, s, mKib, tCost, 1);
        const argonMs = performance.now() - t3;
        return { pbkdf2, pbkdf2Ms, scrypt, scryptMs, argon, argonMs, shaUs };
      });
      if (r.ok) setKdf(r.value); else setKdfError(r.error);
      setKdfBusy(false);
    }, 30);
  };

  return (
    <Page kicker="§7 · Password security" title="Password strength and key derivation"
      lede="A password's strength is the number of guesses an attacker needs, not its appearance. Two things decide that number: how the password was chosen, and how expensive the defender made each guess.">
      <Status state={state} />

      <Panel title="Guessing-resistance model">
        <Field label="Password" hint={`${length} characters`}>
          {(id) => <TextInput id={id} mono value={pw} onChange={(e) => setPw(e.target.value)} disabled={!ready} style={{ fontSize: '1.1rem', borderColor: `var(--${tone})` }} />}
        </Field>
        <div className="grid" style={{ marginTop: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
          <Stat label="Alphabet" value={pool ?? 0} sub="symbols in the classes used" />
          <Stat label="Entropy bound" value={`${entropy.toFixed(1)} bits`} sub={`${length} × log₂(${pool ?? 0})`} tone={tone} />
          <Stat label="Key space" value={entropy ? `2^${entropy.toFixed(0)}` : '—'} sub={entropy ? `≈ 10^${(entropy * Math.log10(2)).toFixed(0)} guesses` : ''} />
          <Stat label="Top-1000 list" value={rank ? `#${rank}` : 'not listed'} tone={rank ? 'danger' : 'ok'} sub={rank ? 'guessed instantly' : 'xato-net corpus'} />
        </div>
        {rank > 0 && <div style={{ marginTop: '1rem' }}><Callout tone="danger">This exact string is the {ordinal(rank)} most common password in a 10-million-password leak corpus. Its effective entropy is about {Math.log2(rank).toFixed(0)} bits regardless of the estimate above.</Callout></div>}
        <hr className="divider" />
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Attacker</th><th>Rate</th><th>Expected time (classical)</th><th>Grover search (quantum)</th></tr></thead>
            <tbody>
              {RATES.map((r) => (
                <tr key={r.label}>
                  <td>{r.label}<div className="faint small">{r.note}</div></td>
                  <td className="mono">10^{Math.log10(r.rate)}/s</td>
                  <td className="mono">{ready ? formatDuration(P.crack_time(entropy, r.rate, false)) : '—'}</td>
                  <td className="mono">{ready ? formatDuration(P.crack_time(entropy, r.rate, true)) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Note title="What the model assumes">
          The bound L·log₂(N) treats the password as uniformly random over its alphabet. Real passwords are not: dictionary words,
          keyboard walks, leetspeak and appended years are all tried first, so “Tr0ub4dor&amp;3” is far weaker than its bits suggest.
          The Grover column halves the exponent — it is the theoretical limit for a quantum computer that could evaluate the hash in
          superposition, and is not a near-term threat to passwords.
        </Note>
      </Panel>

      <Panel title="Key derivation cost" refs={['RFC 8018', 'RFC 7914', 'RFC 9106', 'OWASP']}
        action={<Button variant="primary" onClick={runKdf} disabled={!ready || kdfBusy}>{kdfBusy ? 'Deriving…' : 'Derive keys and time them'}</Button>}>
        <p className="muted small">
          A password hash should be slow for the attacker and tolerable for the defender. PBKDF2 iterates HMAC; scrypt and Argon2id
          additionally fill memory, so GPU and ASIC attackers lose their parallelism advantage. Defaults are the OWASP 2023 minimums; the salt is random per page load.
        </p>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
          <Field label="PBKDF2-HMAC-SHA256 iterations">{(id) => (
            <Select id={id} value={iterations} onChange={(e) => setIterations(Number(e.target.value))} disabled={kdfBusy}>
              {[1000, 10_000, 100_000, 600_000, 1_300_000].map((n) => <option key={n} value={n}>{n.toLocaleString()}</option>)}
            </Select>
          )}</Field>
          <Field label="Argon2id memory">{(id) => (
            <Select id={id} value={mKib} onChange={(e) => setMKib(Number(e.target.value))} disabled={kdfBusy}>
              {[1024, 8 * 1024, 19 * 1024, 64 * 1024].map((n) => <option key={n} value={n}>{n / 1024} MiB</option>)}
            </Select>
          )}</Field>
          <Field label="Argon2id passes (t)">{(id) => (
            <Select id={id} value={tCost} onChange={(e) => setTCost(Number(e.target.value))} disabled={kdfBusy}>
              {[1, 2, 3, 4].map((n) => <option key={n} value={n}>{n}</option>)}
            </Select>
          )}</Field>
          <Field label="scrypt cost N = 2^n" hint={`${(128 * 8 * 2 ** logN) / 1024 / 1024} MiB`}>{(id) => (
            <Select id={id} value={logN} onChange={(e) => setLogN(Number(e.target.value))} disabled={kdfBusy}>
              {[10, 12, 14, 15, 16].map((n) => <option key={n} value={n}>2^{n}</option>)}
            </Select>
          )}</Field>
        </div>
        <ErrorText error={kdfError} />
        {kdf && (
          <>
            <hr className="divider" />
            <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
              <Stat label="One SHA-256" value={`${kdf.shaUs.toFixed(2)} µs`} sub={`≈ ${(1e6 / kdf.shaUs).toExponential(1)} guesses/s on this device`} />
              <Stat label={`PBKDF2 · ${iterations.toLocaleString()} it.`} value={formatMs(kdf.pbkdf2Ms)} sub={`≈ ${(1000 / kdf.pbkdf2Ms).toFixed(1)} guesses/s`} tone="warn" />
              <Stat label={`scrypt · N = 2^${logN}, r = 8`} value={formatMs(kdf.scryptMs)} sub={`≈ ${(1000 / kdf.scryptMs).toFixed(1)} guesses/s`} tone="info" />
              <Stat label={`Argon2id · ${mKib / 1024} MiB × ${tCost}`} value={formatMs(kdf.argonMs)} sub={`≈ ${(1000 / kdf.argonMs).toFixed(1)} guesses/s`} tone="accent" />
            </div>
            <div className="stack" style={{ marginTop: '1rem' }}>
              <Output label="salt (16 bytes)" value={salt} copy={false} />
              <Output label="PBKDF2-HMAC-SHA256 derived key" value={kdf.pbkdf2} />
              <Output label="scrypt derived key" value={kdf.scrypt} />
              <Output label="Argon2id tag" value={kdf.argon} />
            </div>
            <p className="muted small" style={{ marginTop: '0.75rem' }}>
              The same password costs {(kdf.pbkdf2Ms * 1000 / kdf.shaUs).toFixed(0)}× more to check with PBKDF2, {(kdf.scryptMs * 1000 / kdf.shaUs).toFixed(0)}× with scrypt
              and {(kdf.argonMs * 1000 / kdf.shaUs).toFixed(0)}× with Argon2id than with a bare hash — and the attacker pays the same factor per guess.
              PBKDF2 buys time with iterations alone, so a GPU with thousands of cores parallelises it almost perfectly; scrypt and Argon2id also
              demand memory per guess, which is what actually blunts custom hardware.
            </p>
          </>
        )}
      </Panel>
    </Page>
  );
}
