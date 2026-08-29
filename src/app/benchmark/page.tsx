'use client';

import { useState } from 'react';
import { useWasm, wasm } from '@/lib/wasm';
import { bytesToHex, formatMs } from '@/lib/bytes';
import { chainSha256, sha256 } from '@/lib/sha256';
import { Page, Panel, Note, Range, Stat, Status, Button, Callout, Output } from '@/components/ui';

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
    <Page kicker="§8 · Benchmark" title="WebAssembly versus JavaScript"
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

      <Note title="Reading the numbers">
        WebAssembly wins on predictable integer arithmetic because it skips type speculation and deoptimisation, but a good JIT is not far behind on
        this kind of code. WebCrypto pays an asynchronous round trip per digest, which dominates at this message size; on large messages it is the fastest by far.
        For cryptography the deciding argument for WebAssembly is not speed but control: constant-time code, audited implementations, and primitives
        (AES-ECB, Argon2, X25519 as a raw function) that WebCrypto does not expose.
      </Note>
    </Page>
  );
}
