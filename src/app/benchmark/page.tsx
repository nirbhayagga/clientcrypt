'use client';

import { useState } from 'react';
import { useWasm, wasm } from '@/lib/wasm';
import { bytesToHex, formatMs, formatDuration } from '@/lib/bytes';
import { chainSha256, sha256 } from '@/lib/sha256';
import { TARGETS, ADVERSARIES, expectedBreakSeconds, universeAges, formatBig } from '@/lib/attack';
import { Page, Panel, Note, Range, Segmented, Stat, Status, Button, Callout, Output } from '@/components/ui';

type Result = { ms: number; digest: string };
type Runner = 'wasm' | 'js' | 'webcrypto';

const RUNNERS: { id: Runner; name: string; how: string }[] = [
  { id: 'wasm', name: 'Rust → WebAssembly', how: 'RustCrypto sha2 crate, compiled with opt-level s and LTO' },
  { id: 'js', name: 'JavaScript', how: 'Hand-written SHA-256 on typed arrays, JIT-compiled by V8/SpiderMonkey' },
  { id: 'webcrypto', name: 'WebCrypto (native)', how: 'crypto.subtle.digest — the browser\'s own C/assembly implementation, async per call' },
];

export default function BenchmarkPage() {
  const state = useWasm();
  const ready = state === 'ready';
  const [iterations, setIterations] = useState(200_000);
  const [results, setResults] = useState<Partial<Record<Runner, Result>>>({});
  const [running, setRunning] = useState<Runner | null>(null);
  const jsSelfCheck = bytesToHex(sha256(new TextEncoder().encode('abc'))) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

  const run = async (which: Runner) => {
    setRunning(which);
    await new Promise((r) => setTimeout(r, 30));
    let digest = '', ms = 0;
    if (which === 'wasm') {
      const t0 = performance.now();
      digest = wasm.PasswordSecurity.benchmark_sha256(iterations);
      ms = performance.now() - t0;
    } else if (which === 'js') {
      const t0 = performance.now();
      digest = bytesToHex(chainSha256(iterations));
      ms = performance.now() - t0;
    } else {
      let data: ArrayBuffer = new Uint8Array(32).buffer;
      const t0 = performance.now();
      for (let i = 0; i < iterations; i++) data = await crypto.subtle.digest('SHA-256', data);
      ms = performance.now() - t0;
      digest = bytesToHex(new Uint8Array(data));
    }
    setResults((r) => ({ ...r, [which]: { ms, digest } }));
    setRunning(null);
  };

  const digests = new Set(Object.values(results).map((r) => r.digest));
  const fastest = Math.min(...Object.values(results).map((r) => r.ms));

  return (
    <Page kicker="§13 · Benchmark" title="WebAssembly versus JavaScript"
      lede="The same workload in three runtimes: a chain of SHA-256 computations where each input is the previous digest, so the work cannot be parallelised or skipped. All three must arrive at the same final digest.">
      <Status state={state} />

      <Panel title="Workload" action={<Button variant="primary" disabled={!ready || running !== null} onClick={async () => { for (const r of RUNNERS) await run(r.id); }}>Run all</Button>}>
        <Range label="Chained SHA-256 iterations" min={10_000} max={2_000_000} step={10_000} value={iterations} onChange={(v) => { setIterations(v); setResults({}); }} format={(v) => v.toLocaleString()} disabled={running !== null} />
        <p className="muted small" style={{ marginTop: '0.5rem' }}>
          Each iteration hashes 32 bytes: one 64-byte SHA-256 block after padding. {(iterations * 64 / 1e6).toFixed(1)} MB of compression-function input per run.
          {jsSelfCheck ? ' The JavaScript implementation reproduces the FIPS 180-4 “abc” vector.' : ' Warning: the JavaScript implementation failed its self-check.'}
        </p>
      </Panel>

      <div className="grid-3">
        {RUNNERS.map((r) => {
          const res = results[r.id];
          return (
            <Panel key={r.id} title={r.name}>
              <p className="muted small" style={{ minHeight: '3.4em' }}>{r.how}</p>
              <Button block disabled={!ready || running !== null} onClick={() => run(r.id)}>{running === r.id ? 'Running…' : 'Run'}</Button>
              <div style={{ marginTop: '1rem' }}>
                <Stat label="Time" value={res ? formatMs(res.ms) : '—'} sub={res ? `${((res.ms * 1e6) / iterations).toFixed(0)} ns per hash · ${(iterations / (res.ms / 1000) / 1e6).toFixed(2)} M hashes/s` : ''} tone={res && res.ms === fastest ? 'accent' : undefined} />
              </div>
            </Panel>
          );
        })}
      </div>

      {Object.keys(results).length > 0 && (
        <Panel title="Results">
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Runtime</th><th>Time</th><th>Relative</th><th>Final digest</th></tr></thead>
              <tbody>
                {RUNNERS.filter((r) => results[r.id]).map((r) => {
                  const res = results[r.id]!;
                  return <tr key={r.id}><td>{r.name}</td><td className="mono">{formatMs(res.ms)}</td><td className="mono">{(res.ms / fastest).toFixed(2)}×</td><td className="mono">{res.digest}</td></tr>;
                })}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: '1rem' }}>
            {digests.size === 1
              ? <Callout tone="ok">All runs agree on the final digest — they performed identical work.</Callout>
              : <Callout tone="danger">Digests differ between runtimes; the comparison is not valid.</Callout>}
          </div>
          {results.wasm && results.js && (
            <div style={{ marginTop: '1rem' }}>
              <Output copy={false} value={(() => {
                const ratio = (x: number, y: number) => `${(Math.max(x, y) / Math.min(x, y)).toFixed(2)}× ${x < y ? 'faster' : 'slower'}`;
                let s = `WebAssembly is ${ratio(results.wasm!.ms, results.js!.ms)} than JavaScript on this device for this workload`;
                if (results.webcrypto) s += `; native WebCrypto is ${ratio(results.webcrypto.ms, results.wasm!.ms)} than WebAssembly (including one Promise per call)`;
                return `${s}.`;
              })()} />
            </div>
          )}
        </Panel>
      )}

      <BreakPanel measuredRate={results.wasm ? iterations / (results.wasm.ms / 1000) : null} />

      <Note title="Reading the numbers">
        WebAssembly wins on predictable integer arithmetic because it skips type speculation and deoptimisation, but a good JIT is not far behind on
        this kind of code. WebCrypto pays an asynchronous round trip per digest, which dominates at this message size; on large messages it is the fastest by far.
        For cryptography the deciding argument for WebAssembly is not speed but control: constant-time code, audited implementations, and primitives
        (AES-ECB, Argon2, X25519 as a raw function) that WebCrypto does not expose.
      </Note>
    </Page>
  );
}

/* Attack cost ----------------------------------------------------------------- */

function BreakPanel({ measuredRate }: { measuredRate: number | null }) {
  const [advId, setAdvId] = useState('rig');
  const adv = ADVERSARIES.find((a) => a.id === advId)!;
  const rate = advId === 'device' && measuredRate ? measuredRate : adv.rate;

  return (
    <Panel title="The attacker’s benchmark: how long to break it" refs={['NIST SP 800-57']}>
      <p className="muted small">
        {'The benchmark above measures the defender; this table runs the same arithmetic for the attacker. A key search '}
        {'expects to test half the key space, so the time is 2ᵇ⁻¹ ÷ rate. RSA and elliptic curves are listed at their '}
        <em>equivalent</em>{' strengths from NIST SP 800-57: “RSA-2048 ≈ 112 bits” means the number field sieve costs roughly '}
        {'as much as a 2¹¹² symmetric search — the attack is cleverer, and that cleverness is already priced in.'}
      </p>
      <Segmented label="Adversary" value={advId} onChange={setAdvId}
        options={ADVERSARIES.map((a) => ({ value: a.id, label: a.name }))} />
      <p className="muted small" style={{ marginTop: '0.5rem' }}>
        {advId === 'device'
          ? (measuredRate
            ? `${formatBig(measuredRate)} guesses/s — your measured single-thread SHA-256 rate from the benchmark above, used as a stand-in for key tests.`
            : 'Assuming 10⁷ guesses/s for now — run the WebAssembly benchmark above and this row switches to your device’s measured rate.')
          : adv.note}
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Target</th><th>Strength</th><th>The attack</th><th>Expected time</th><th>Ages of the universe</th><th>Quantum outlook</th></tr></thead>
          <tbody>
            {TARGETS.map((t) => {
              const s = expectedBreakSeconds(t.bits, rate);
              const ages = universeAges(s);
              return (
                <tr key={t.name}>
                  <td>{t.name}{t.note ? <div className="muted small">{t.note}</div> : null}</td>
                  <td className="mono">{`2^${t.bits}`}</td>
                  <td>{t.attack}</td>
                  <td className="mono">{formatDuration(s)}</td>
                  <td className="mono">{ages >= 0.01 ? formatBig(ages) : '—'}</td>
                  <td>{t.quantum}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div style={{ marginTop: '1rem' }}>
        <Callout tone="info">
          {'The interesting line is AES-128 against all of Bitcoin: about five billion years — roughly the Sun’s remaining '}
          {'lifetime, using every mining ASIC on the planet for nothing else. Uncomfortably finite as cosmic numbers go, '}
          {'which is why new designs default to 256-bit keys: AES-256 costs 2¹²⁸ times more, and no growth curve rescues that.'}
        </Callout>
      </div>
      <Note title="What “broken” means in practice">
        Nobody brute-forces well-chosen keys; every real break in this site’s attack sections (§10) is a shortcut — a padding
        oracle, a reused nonce, an unauthenticated handshake. The table is the reason those shortcuts are the whole game:
        against the mathematics itself, the economics are hopeless. The one genuine schedule-changer is a fault-tolerant
        quantum computer, which is why post-quantum key exchange is being deployed years before one exists — browsers
        already ship hybrid ML-KEM in TLS, and WireGuard&apos;s optional pre-shared key (§9) hedges the same risk. Traffic
        recorded today can be decrypted then.
      </Note>
    </Panel>
  );
}
