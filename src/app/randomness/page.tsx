'use client';

import { useEffect, useRef, useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { bytesToHex } from '@/lib/bytes';
import { Page, Panel, Note, Field, Select, Segmented, Output, Stat, Status, ErrorText, Button } from '@/components/ui';

interface Analysis {
  bytes: number; bits: number; ones_fraction: number; monobit_p: number; runs_p: number;
  runs_observed: number; shannon_bits_per_byte: number; chi_squared: number;
  longest_run_of_ones: number; distinct_bytes: number;
}
interface Extraction {
  input_bytes: number; output_bytes: number; retained_fraction: number;
  extracted_hex: string; conditioned_hex: string; before: Analysis; after: Analysis;
}

/* Generators the page can compare ------------------------------------------- */

const GENERATORS = {
  randu: { label: 'RANDU (IBM, 1960s)', a: 65539n, c: 0n, m: 1n << 31n, note: 'The textbook cautionary tale: every triple satisfies x₂ = 6x₁ − 9x₀, so all output lies on 15 planes.' },
  minstd: { label: 'MINSTD (Lehmer)', a: 16807n, c: 0n, m: 2147483647n, note: 'Respectable for simulation, still fully predictable from one output.' },
  toy: { label: 'Small-modulus LCG', a: 137n, c: 187n, m: 256n, note: 'A modulus of 256 cannot produce more than 256 values before repeating.' },
} as const;
type GenKey = keyof typeof GENERATORS;

/** crypto.getRandomValues refuses more than 65,536 bytes in one call, so a
 *  large sample has to be filled in chunks. */
function randomUnits(n: number): number[] {
  const buf = new Uint32Array(n);
  for (let off = 0; off < n; off += 16384) {
    crypto.getRandomValues(buf.subarray(off, Math.min(off + 16384, n)));
  }
  return Array.from(buf, (v) => v / 2 ** 32);
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) {
    crypto.getRandomValues(b.subarray(off, Math.min(off + 65536, n)));
  }
  return b;
}

/** Plots the output as points. In `pairs` mode the coordinates are
 *  consecutive outputs (x_n, x_n+1). In `triples` mode they are (x_n, x_n+1,
 *  x_n+2) projected so that RANDU's planes are seen edge-on: the horizontal
 *  axis is the plane normal (9, -6, 1), along which the lattice is discrete. */
function project(points: number[], mode: 'pairs' | 'triples'): [number, number][] {
  const out: [number, number][] = [];
  if (mode === 'pairs') {
    for (let i = 0; i + 1 < points.length; i += 2) out.push([points[i], points[i + 1]]);
    return out;
  }
  // Orthonormal basis: n along the RANDU plane normal, u perpendicular to it.
  const n = [9, -6, 1], u = [6, 9, 0];
  const nl = Math.hypot(...n), ul = Math.hypot(...u);
  for (let i = 0; i + 2 < points.length; i += 3) {
    const p = [points[i], points[i + 1], points[i + 2]];
    const x = (p[0] * n[0] + p[1] * n[1] + p[2] * n[2]) / nl;
    const y = (p[0] * u[0] + p[1] * u[1] + p[2] * u[2]) / ul;
    out.push([(x + 0.56) / 1.49, y / 1.39]);
  }
  return out;
}

function LatticePlot({ points, label, mode }: { points: number[]; label: string; mode: 'pairs' | 'triples' }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const S = c.width;
    ctx.fillStyle = '#090b0e';
    ctx.fillRect(0, 0, S, S);
    ctx.fillStyle = '#d9a441';
    for (const [x, y] of project(points, mode)) {
      if (x >= 0 && x <= 1 && y >= 0 && y <= 1) ctx.fillRect(x * (S - 2), (1 - y) * (S - 2), 1.5, 1.5);
    }
  }, [points, mode]);
  return (
    <div className="canvas-box">
      <canvas ref={ref} width={256} height={256} aria-label={`Scatter plot of consecutive output ${mode} from ${label}`} />
      <div className="cap">{label}</div>
    </div>
  );
}

function LatticePanel({ ready }: { ready: boolean }) {
  const [gen, setGen] = useState<GenKey>('randu');
  const [mode, setMode] = useState<'pairs' | 'triples'>('triples');
  const [count, setCount] = useState(6000);
  const g = GENERATORS[gen];
  const n = count * 3;

  const lcg = ready ? attempt(() => Array.from(wasm.Randomness.lcg(1n, g.a, g.c, g.m, n))) : null;
  const csprng = ready ? randomUnits(n) : [];
  const mathRandom = Array.from({ length: n }, () => Math.random());

  return (
    <Panel title="Seeing the difference" refs={['spectral test']}
      action={<Segmented label="Dimensions" value={mode} onChange={setMode} disabled={!ready}
        options={[{ value: 'pairs', label: '2D pairs' }, { value: 'triples', label: '3D triples' }]} />}>
      <p className="muted small">
        {mode === 'pairs'
          ? 'Consecutive outputs plotted as (x, y). At this scale all three look like noise — which is the point: two dimensions are not enough to see the defect.'
          : 'Consecutive triples plotted as points in the unit cube, viewed along the direction (9, −6, 1). RANDU\u2019s output collapses into a handful of parallel planes seen edge-on, because every triple satisfies x\u2082 = 6x\u2081 \u2212 9x\u2080. The other two fill the space.'}
      </p>
      <div className="grid-2">
        <Field label="Weak generator">{(id) => (
          <Select id={id} value={gen} onChange={(e) => setGen(e.target.value as GenKey)} disabled={!ready}>
            {Object.entries(GENERATORS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </Select>
        )}</Field>
        <Field label="Points">{(id) => (
          <Select id={id} value={count} onChange={(e) => setCount(Number(e.target.value))} disabled={!ready}>
            {[2000, 6000, 15000].map((v) => <option key={v} value={v}>{v.toLocaleString()}</option>)}
          </Select>
        )}</Field>
      </div>
      <hr className="divider" />
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
        <LatticePlot points={lcg?.ok ? lcg.value : []} label={g.label} mode={mode} />
        <LatticePlot points={mathRandom} label="Math.random()" mode={mode} />
        <LatticePlot points={csprng} label="crypto.getRandomValues()" mode={mode} />
      </div>
      <p className="muted small" style={{ marginTop: '0.75rem' }}>{g.note}</p>
      <Note title="Why this took until 1968 to notice">
        RANDU passed every test anyone ran on it, because those tests looked at one value or two at a time. The structure only
        appears in three dimensions — switch the toggle above and the same data that looked like noise falls onto stripes. A
        generation of Monte Carlo simulation results were quietly wrong. The general lesson survives: statistical testing finds
        the defects you thought to look for.
      </Note>
      <Note title="What the other two plots do and do not prove">
        <code>Math.random()</code> fills the cube — modern engines use xorshift128+, which has no such lattice. It is still
        catastrophic for keys: the state is small, seeded predictably, and recoverable from a handful of outputs. Looking
        random and being unpredictable are different properties, and only the second one is security.
      </Note>
    </Panel>
  );
}

/* Statistical tests ---------------------------------------------------------- */

type SourceKey = 'csprng' | 'math' | 'lcg' | 'counter' | 'collected';

function TestPanel({ ready, collected }: { ready: boolean; collected: Uint8Array | null }) {
  const [source, setSource] = useState<SourceKey>('csprng');
  const [size, setSize] = useState(4096);

  const sample = (): Uint8Array => {
    if (source === 'csprng') return randomBytes(size);
    if (source === 'math') return Uint8Array.from({ length: size }, () => Math.floor(Math.random() * 256));
    if (source === 'counter') return Uint8Array.from({ length: size }, (_, i) => i & 0xff);
    if (source === 'collected') return collected ?? new Uint8Array();
    return wasm.Randomness.lcg_bytes(1n, 65539n, 0n, 1n << 31n, size);
  };

  const res = ready ? attempt(() => {
    const s = sample();
    if (!s.length) throw new Error('Collect some entropy first, in the panel below');
    return { a: wasm.Randomness.analyse(s) as Analysis, hex: bytesToHex(s.slice(0, 16)) };
  }) : null;
  const a = res?.ok ? res.value.a : null;
  const verdict = (p: number): 'danger' | 'ok' => (p < 0.01 ? 'danger' : 'ok');

  return (
    <Panel title="Statistical tests" refs={['NIST SP 800-22']}>
      <p className="muted small">
        Two of the NIST battery. <strong>Monobit</strong> asks whether ones and zeros balance; <strong>runs</strong> asks
        whether the bit flips at the rate independent coins would. Each returns a p-value, and below 0.01 the sequence is
        rejected at the 1% level. Try the counter: 0, 1, 2, 3… is the most predictable sequence there is, and it scores a
        perfect 1.0000 on both — its bits are exactly balanced and it flips exactly as often as chance would.
      </p>
      <div className="grid-2">
        <Field label="Source">{(id) => (
          <Select id={id} value={source} onChange={(e) => setSource(e.target.value as SourceKey)} disabled={!ready}>
            <option value="csprng">crypto.getRandomValues() — the CSPRNG</option>
            <option value="math">Math.random() — not cryptographic</option>
            <option value="lcg">RANDU — a broken LCG</option>
            <option value="counter">A plain counter 0,1,2,…</option>
            <option value="collected">Entropy you collected below</option>
          </Select>
        )}</Field>
        <Field label="Sample size">{(id) => (
          <Select id={id} value={size} onChange={(e) => setSize(Number(e.target.value))} disabled={!ready || source === 'collected'}>
            {[1024, 4096, 16384].map((n) => <option key={n} value={n}>{n.toLocaleString()} bytes</option>)}
          </Select>
        )}</Field>
      </div>
      <ErrorText error={res && !res.ok ? res.error : null} />
      {a && (
        <>
          <hr className="divider" />
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
            <Stat label="Monobit p" value={a.monobit_p.toFixed(4)} tone={verdict(a.monobit_p)} sub={a.monobit_p < 0.01 ? 'rejected' : 'not rejected'} />
            <Stat label="Runs p" value={a.runs_p.toFixed(4)} tone={verdict(a.runs_p)} sub={a.runs_p < 0.01 ? 'rejected' : 'not rejected'} />
            <Stat label="Ones" value={`${(a.ones_fraction * 100).toFixed(2)}%`} sub="ideal 50%" />
            <Stat label="Entropy" value={`${a.shannon_bits_per_byte.toFixed(3)}`} sub="bits per byte, max 8" />
            <Stat label="Distinct bytes" value={`${a.distinct_bytes} / 256`} />
          </div>
          <div style={{ marginTop: '1rem' }}>
            <Output label={`First 16 bytes of the ${a.bytes.toLocaleString()}-byte sample`} value={res!.ok ? res!.value.hex : ''} copy={false} />
          </div>
        </>
      )}
      <Note title="Passing is necessary, not sufficient">
        The counter above is the whole argument: a sequence anyone can predict perfectly scores as well as the CSPRNG. These
        tests detect generators that are visibly broken — bias, or the wrong rate of oscillation — and nothing else. They
        cannot detect a generator that is merely <em>knowable</em>, which is the only property that matters. That is why the
        answer is never &quot;my numbers looked random&quot; but &quot;the state came from the operating system and is too large to guess&quot;.
      </Note>
    </Panel>
  );
}

/* Physical entropy collection ------------------------------------------------ */

function CollectPanel({ ready, collected, setCollected }: { ready: boolean; collected: Uint8Array | null; setCollected: (b: Uint8Array) => void }) {
  const [mode, setMode] = useState<'pointer' | 'jitter'>('pointer');
  const [samples, setSamples] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  const TARGET = 512;

  const onMove = (e: React.PointerEvent) => {
    if (mode !== 'pointer' || samples.length >= TARGET) return;
    // The low bits of coordinates and of the sub-millisecond timestamp are the
    // unpredictable part; the trajectory itself is not.
    const t = performance.now();
    const v = ((e.clientX & 0xff) ^ ((e.clientY & 0xff) << 1) ^ (Math.floor(t * 1000) & 0xff)) & 0xff;
    setSamples((s) => (s.length >= TARGET ? s : [...s, v]));
  };

  const runJitter = () => {
    setBusy(true);
    setTimeout(() => {
      // CPU timing jitter: the nanosecond-scale variation in how long an
      // identical loop takes, caused by scheduling, caches and frequency
      // scaling. This is the principle behind Linux's jitter entropy source.
      const out: number[] = [];
      for (let i = 0; i < TARGET; i++) {
        const t0 = performance.now();
        let acc = 0;
        for (let j = 0; j < 2000; j++) acc += Math.sqrt(j) | 0;
        const dt = performance.now() - t0;
        out.push((Math.floor(dt * 1e6) ^ (acc & 0xff)) & 0xff);
      }
      setSamples(out);
      setBusy(false);
    }, 30);
  };

  const raw = new Uint8Array(samples);
  const ext = ready && raw.length >= 32 ? attempt(() => wasm.Randomness.extract(raw) as Extraction) : null;
  const e = ext?.ok ? ext.value : null;

  return (
    <Panel title="Collecting real entropy" refs={['von Neumann extractor']}
      action={<Segmented label="Entropy source" value={mode} onChange={(v) => { setMode(v); setSamples([]); }} disabled={!ready}
        options={[{ value: 'pointer', label: 'Pointer motion' }, { value: 'jitter', label: 'CPU jitter' }]} />}>
      <p className="muted small">
        Both sources here are physical rather than computed: where you move a pointer and when, and how long an identical loop
        takes on a machine that is also doing other things. Neither is reproducible by an attacker who reruns your code — which
        is exactly what a pseudorandom generator cannot promise.
      </p>

      {mode === 'pointer' ? (
        <div onPointerMove={onMove} style={{
          height: '9rem', border: '1px dashed var(--border-strong)', borderRadius: 'var(--radius)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'crosshair',
          background: 'var(--bg-inset)', touchAction: 'none', marginBottom: '1rem',
        }}>
          <span className="muted small">
            {samples.length >= TARGET ? 'Collected.' : `Move the pointer here — ${samples.length} / ${TARGET} samples`}
          </span>
        </div>
      ) : (
        <div className="row" style={{ marginBottom: '1rem' }}>
          <Button variant="primary" onClick={runJitter} disabled={!ready || busy}>{busy ? 'Timing…' : `Measure ${TARGET} loop timings`}</Button>
          <span className="status">{samples.length} samples</span>
        </div>
      )}

      {samples.length > 0 && (
        <div className="bars" style={{ height: 60 }} aria-label="Collected sample values">
          {Array.from({ length: 64 }, (_, i) => {
            const slice = samples.filter((_, j) => j % 64 === i);
            const avg = slice.length ? slice.reduce((x, y) => x + y, 0) / slice.length : 0;
            return <div key={i} className="bar"><div className="bar-fill" style={{ height: `${(avg / 255) * 100}%` }} /></div>;
          })}
        </div>
      )}

      {e && (
        <>
          <hr className="divider" />
          <div className="grid-3">
            <Stat label="Raw bias" value={`${(e.before.ones_fraction * 100).toFixed(1)}%`} tone={Math.abs(e.before.ones_fraction - 0.5) > 0.05 ? 'warn' : 'ok'} sub="ones before extraction" />
            <Stat label="After extraction" value={`${(e.after.ones_fraction * 100).toFixed(1)}%`} tone="ok" sub="ones after von Neumann" />
            <Stat label="Retained" value={`${(e.retained_fraction * 100).toFixed(0)}%`} sub={`${e.input_bytes} → ${e.output_bytes} bytes`} />
          </div>
          <div className="stack" style={{ marginTop: '1rem' }}>
            <Output label="Debiased bits (von Neumann)" value={e.extracted_hex} scroll />
            <Output label="Conditioned to a 256-bit key (SHA-256 of the raw samples)" value={e.conditioned_hex} tone="accent" />
          </div>
          <div style={{ marginTop: '1rem' }}>
            <Button onClick={() => setCollected(raw)} disabled={raw.length < 32}>Send this sample to the tests above</Button>
            {collected && <span className="status" style={{ marginLeft: '0.6rem' }}>{collected.length} bytes available as a test source</span>}
          </div>
        </>
      )}

      <Note title="Why extraction and conditioning are separate steps">
        Raw physical noise is biased and correlated — a pointer moves smoothly, and loop timings cluster. The von Neumann
        extractor removes bias without assuming how much entropy is present, at the cost of most of the input. Hashing then
        spreads whatever entropy remains across all 256 output bits. Neither step <em>creates</em> entropy: if you collected
        20 bits of real unpredictability, the SHA-256 output is a 256-bit string with 20 bits of entropy in it.
      </Note>
    </Panel>
  );
}

/* Page ----------------------------------------------------------------------- */

export default function RandomnessPage() {
  const state = useWasm();
  const ready = state === 'ready';
  const [collected, setCollected] = useState<Uint8Array | null>(null);

  return (
    <Page kicker="§5 · Randomness" title="Pseudorandom, random, and unpredictable"
      lede="Every key, IV, nonce and salt on this site is only as good as the numbers behind it. A generator can look flawless under every statistical test and still be trivially predictable — which is why the interesting question is not whether output looks random, but whether an attacker can reproduce it.">
      <Status state={state} />
      <LatticePanel ready={ready} />
      <TestPanel ready={ready} collected={collected} />
      <CollectPanel ready={ready} collected={collected} setCollected={setCollected} />

      <Panel title="What to actually use">
        <p className="muted small">
          Nothing on this page is a recommendation to build your own generator. The correct answer in a browser is
          <code>crypto.getRandomValues()</code>, and in Rust the operating system source behind <code>getrandom</code> — which is
          what every key elsewhere on this site uses. Those are pseudorandom generators too, but they are <em>seeded</em> from
          hardware entropy the operating system has collected, and their state is large enough and secret enough that observing
          output tells you nothing about what comes next.
        </p>
        <div className="table-wrap" style={{ marginTop: '1rem' }}>
          <table className="table">
            <thead><tr><th>Failure</th><th>What went wrong</th></tr></thead>
            <tbody>
              <tr><td style={{ whiteSpace: 'nowrap' }}>Debian OpenSSL, 2008</td><td className="muted small">A patch removed the entropy seeding, leaving the process ID as the only variable input. Every key generated for two years came from a set of 32,768 possibilities.</td></tr>
              <tr><td style={{ whiteSpace: 'nowrap' }}>Sony PlayStation 3, 2010</td><td className="muted small">The ECDSA signing nonce was a constant instead of random. Two signatures are enough to solve for the private key, and the console&apos;s code-signing key was recovered.</td></tr>
              <tr><td style={{ whiteSpace: 'nowrap' }}>Android SecureRandom, 2013</td><td className="muted small">Improper initialisation meant some Bitcoin wallets reused nonces, and the coins were taken by anyone who noticed.</td></tr>
              <tr><td style={{ whiteSpace: 'nowrap' }}>Dual_EC_DRBG, 2007–2013</td><td className="muted small">A standardised generator whose constants admitted a possible backdoor: whoever chose them could predict output from a small sample. Withdrawn from the NIST standard.</td></tr>
            </tbody>
          </table>
        </div>
        <p className="muted small" style={{ marginTop: '0.75rem' }}>
          None of these were caught by statistical testing, because none of them produced output that looked wrong. They were
          failures of unpredictability, not of distribution.
        </p>
      </Panel>
    </Page>
  );
}
