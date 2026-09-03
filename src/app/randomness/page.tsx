'use client';

import { useEffect, useRef, useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { bytesToHex, hexToBytes, randomHex, hammingDistanceHex } from '@/lib/bytes';
import { Page, Panel, Note, Callout, Field, TextInput, Select, Segmented, Output, Stat, Status, ErrorText, Button, Tag } from '@/components/ui';

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

/* Stretching a seed: the CSPRNG itself --------------------------------------- */

function CsprngPanel({ ready, setCollected }: { ready: boolean; setCollected: (b: Uint8Array) => void }) {
  const [seed, setSeed] = useState('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const [len, setLen] = useState(64);

  const res = ready ? attempt(() => {
    const a = wasm.Randomness.csprng_stream(seed, 0n, len);
    const b = wasm.Randomness.csprng_stream(seed, 0n, len);
    // Flip the lowest bit of the first seed byte.
    const flipped = (parseInt(seed.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0') + seed.slice(2);
    const c = wasm.Randomness.csprng_stream(flipped, 0n, len);
    const sample = wasm.Randomness.csprng_stream(seed, 0n, 8192);
    const stats = wasm.Randomness.analyse(hexToBytes(sample)) as Analysis;
    return { a, b, c, stats, sample };
  }) : null;
  const r = res?.ok ? res.value : null;
  const diffBits = r ? hammingDistanceHex(r.a, r.c) : 0;

  return (
    <Panel title="Stretching a seed: what a CSPRNG actually is" refs={['ChaCha20 keystream']}
      action={<Button size="sm" onClick={() => setSeed(randomHex(32))} disabled={!ready}>New random seed</Button>}>
      <p className="muted small">
        The panels above collect and test entropy, and the answer below says &quot;use the operating system&quot; — this panel is
        the step in between. An OS gathers a few hundred bits of real entropy <em>once</em>, then stretches them with a keyed
        stream cipher into every random byte it will ever hand out. Here that generator is ChaCha20 keyed by your 32-byte
        seed: fully deterministic, yet indistinguishable from random to anyone who lacks the seed.
      </p>
      <div className="grid-2">
        <Field label="Seed (32 bytes, hex)" hint="the only secret; everything below follows from it">{(id) => (
          <TextInput id={id} mono value={seed} onChange={(e) => setSeed(e.target.value.toLowerCase())} disabled={!ready} />
        )}</Field>
        <Field label="Output length">{(id) => (
          <Select id={id} value={len} onChange={(e) => setLen(Number(e.target.value))} disabled={!ready}>
            {[32, 64, 128].map((n) => <option key={n} value={n}>{n} bytes</option>)}
          </Select>
        )}</Field>
      </div>
      <ErrorText error={res && !res.ok ? res.error : null} />
      {r && (
        <>
          <div className="stack">
            <Output label={<>Stream from this seed {r.a === r.b && <Tag tone="ok">same seed → identical every time</Tag>}</>} value={r.a} scroll />
            <Output label={<>Stream after flipping one seed bit <Tag tone="danger">{`${((diffBits / (len * 8)) * 100).toFixed(1)}% of bits differ`}</Tag></>} value={r.c} scroll />
          </div>
          <div className="grid-3" style={{ marginTop: '0.75rem' }}>
            <Stat label="Monobit p (8 KB sample)" value={r.stats.monobit_p.toFixed(4)} tone={r.stats.monobit_p < 0.01 ? 'danger' : 'ok'} sub="passes the battery above" />
            <Stat label="Entropy of output" value={r.stats.shannon_bits_per_byte.toFixed(3)} sub="bits per byte — yet true entropy is only the seed's" />
            <Stat label="Stream limit" value="2⁶⁴ blocks" sub="per seed and nonce; then rekey" />
          </div>
          <div style={{ marginTop: '0.75rem' }}>
            <Button onClick={() => setCollected(hexToBytes(r.sample))} disabled={!ready}>Send 8 KB of this stream to the tests above</Button>
          </div>
        </>
      )}
      <Note title="Deterministic and unpredictable are compatible">
        The stream passes every statistical test yet contains no entropy beyond the 256 seed bits — run the panel twice and
        it repeats exactly. That is not a defect; it is the design. Security rests entirely on the seed being secret and
        random, which is why the failures in the table below are all <em>seeding</em> failures. This construction (a stream
        cipher as generator) is what Linux&apos;s <code>/dev/urandom</code>, <code>getrandom()</code> and the browser&apos;s{' '}
        <code>crypto.getRandomValues()</code> do after boot.
      </Note>
    </Panel>
  );
}

/* Using randomness without skewing it ---------------------------------------- */

const PERMS = ['ABC', 'ACB', 'BAC', 'BCA', 'CAB', 'CBA'];

function SamplingPanel({ ready }: { ready: boolean }) {
  const [n, setN] = useState(100);
  const [tick, setTick] = useState(0);

  // Modulo bias: map 100k random bytes into 0..n-1 both ways.
  const draws = 100_000;
  const biased = new Array<number>(n).fill(0);
  const fair = new Array<number>(n).fill(0);
  if (ready) {
    void tick;
    const bytes = randomBytes(draws);
    const limit = 256 - (256 % n);
    for (const b of bytes) {
      biased[b % n]++;
      if (b < limit) fair[b % n]++; // rejection sampling: discard the ragged tail
    }
  }
  const overRepresented = 256 % n === 0 ? 0 : 256 % n;
  const biasRatio = overRepresented ? Math.ceil(256 / n) / Math.floor(256 / n) : 1;

  // Fisher–Yates, correct vs naive, over the 6 permutations of ABC.
  const trials = 30_000;
  const naive = new Array<number>(6).fill(0);
  const correct = new Array<number>(6).fill(0);
  if (ready) {
    const rand = (k: number) => Math.floor((crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32) * k);
    for (let t = 0; t < trials; t++) {
      const a = ['A', 'B', 'C'];
      // Naive: swap every position with a random position anywhere.
      for (let i = 0; i < 3; i++) { const j = rand(3); [a[i], a[j]] = [a[j], a[i]]; }
      naive[PERMS.indexOf(a.join(''))]++;
      const b = ['A', 'B', 'C'];
      // Fisher–Yates: swap position i only with a position ≥ i.
      for (let i = 0; i < 2; i++) { const j = i + rand(3 - i); [b[i], b[j]] = [b[j], b[i]]; }
      correct[PERMS.indexOf(b.join(''))]++;
    }
  }

  const maxFreq = Math.max(...biased, ...fair, 1);
  return (
    <Panel title="Using randomness without skewing it" refs={['rejection sampling', 'Fisher–Yates']}
      action={<Button size="sm" onClick={() => setTick((t) => t + 1)} disabled={!ready}>Redraw</Button>}>
      <p className="muted small">
        A perfect random source is still ruined by careless use. <code>random_byte % {n}</code> looks harmless, but 256 does
        not divide evenly into {n}: the first {overRepresented || 'no'} values get one extra byte each and appear{' '}
        {overRepresented ? `${((biasRatio - 1) * 100).toFixed(0)}% more often` : 'no more often'} than the rest. The fix is
        rejection sampling — throw away the ragged tail of the byte range and draw again.
      </p>
      <Field label="Range to sample (0 to n−1)">{(id) => (
        <Select id={id} value={n} onChange={(e) => setN(Number(e.target.value))} disabled={!ready}>
          <option value={100}>n = 100 — % biases half the values upward by 50%</option>
          <option value={52}>n = 52 — a card deck; 48 values land 25% hot</option>
          <option value={6}>n = 6 — a die; the bias is only 2.4%, but it is there</option>
        </Select>
      )}</Field>
      <div className="grid-2">
        {([['random_byte % n', biased, 'danger'], ['rejection sampling', fair, 'ok']] as const).map(([label, counts, tone]) => (
          <div key={label}>
            <div className="label" style={{ marginBottom: '0.4rem' }}><span>{label}</span></div>
            <div className="bars" style={{ height: 72, gap: 1 }} aria-label={`Histogram of ${label}`}>
              {counts.map((c, i) => (
                <div key={i} className="bar"><div className="bar-fill" style={{ height: `${(c / maxFreq) * 100}%`, background: tone === 'danger' && overRepresented && i < overRepresented ? 'var(--danger)' : undefined }} /></div>
              ))}
            </div>
          </div>
        ))}
      </div>
      <hr className="divider" />
      <p className="muted small">
        The same mistake in shuffle form: swapping every card with a random position <em>anywhere</em> gives 3³ = 27 equally
        likely execution paths spread over 6 permutations — and 27 is not divisible by 6, so some orderings must come up more
        often. Fisher–Yates swaps position <em>i</em> only with positions from <em>i</em> onward: 3·2·1 = 6 paths, one per
        permutation. A real casino-platform version of this bug let players predict online card orders.
      </p>
      <div className="grid-2">
        {([['naive shuffle', naive], ['Fisher–Yates', correct]] as const).map(([label, counts]) => (
          <div key={label}>
            <div className="label" style={{ marginBottom: '0.4rem' }}><span>{label} — {trials.toLocaleString()} shuffles of ABC</span></div>
            <div className="bars" style={{ height: 72 }} aria-label={`Permutation frequencies for ${label}`}>
              {counts.map((c, i) => {
                const dev = Math.abs(c - trials / 6) / (trials / 6);
                return (
                  <div key={PERMS[i]} className="bar">
                    <div className="bar-value">{((c / trials) * 100).toFixed(1)}%</div>
                    <div className="bar-fill" style={{ height: `${(c / (trials / 3)) * 100}%`, background: dev > 0.05 ? 'var(--danger)' : undefined }} />
                    <div className="bar-label">{PERMS[i]}</div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <Note title="Where this bites in cryptography">
        Anywhere a random value is folded into a smaller range: picking a key from a wordlist, generating a numeric code,
        choosing a DH exponent below the group order. The diceware generator in §7 and every <code>gen_range</code> in this
        site&apos;s crate use rejection sampling for exactly this reason. The bias is small per draw but systematic, and
        systematic is what cryptanalysis eats.
      </Note>
    </Panel>
  );
}

/* Birthday collisions --------------------------------------------------------- */

function BirthdayPanel({ ready }: { ready: boolean }) {
  const [bits, setBits] = useState(24);
  const [result, setResult] = useState<{ bits: number; mean: number; min: number; max: number; trials: number } | null>(null);
  const [busy, setBusy] = useState(false);

  const run = () => {
    setBusy(true);
    setTimeout(() => {
      const trials = bits >= 32 ? 40 : 150;
      const counts: number[] = [];
      const buf = new Uint32Array(1024);
      for (let t = 0; t < trials; t++) {
        const seen = new Set<number>();
        let draws = 0;
        outer: for (;;) {
          crypto.getRandomValues(buf);
          for (const v of buf) {
            const x = bits >= 32 ? v : v >>> (32 - bits);
            draws++;
            if (seen.has(x)) break outer;
            seen.add(x);
          }
        }
        counts.push(draws);
      }
      const mean = counts.reduce((a, b) => a + b, 0) / trials;
      setResult({ bits, mean, min: Math.min(...counts), max: Math.max(...counts), trials });
      setBusy(false);
    }, 30);
  };

  const theory = 1.2533 * Math.sqrt(2 ** bits);
  return (
    <Panel title="The birthday bound" refs={['birthday paradox']}>
      <p className="muted small">
        How many random {bits}-bit values can you draw before two collide? Intuition says something near the size of the
        space, 2<sup>{bits}</sup> = {(2 ** bits).toLocaleString()}. The real answer is near its <em>square root</em>:
        about 1.25·2<sup>{bits}/2</sup> ≈ {Math.round(theory).toLocaleString()} draws, because what matters is the number of
        <em> pairs</em>, which grows quadratically.
      </p>
      <div className="row">
        <Field label="Value size">{(id) => (
          <Select id={id} value={bits} onChange={(e) => setBits(Number(e.target.value))} disabled={!ready}>
            {[16, 20, 24, 28, 32].map((b) => <option key={b} value={b}>{b} bits — space of {(2 ** b).toLocaleString()}</option>)}
          </Select>
        )}</Field>
        <Button variant="primary" onClick={run} disabled={!ready || busy} style={{ alignSelf: 'end' }}>
          {busy ? 'Drawing…' : 'Draw until values collide'}
        </Button>
      </div>
      {result && (
        <div className="grid-3" style={{ marginTop: '0.75rem' }}>
          <Stat label={`Mean draws to a collision (${result.trials} runs)`} value={Math.round(result.mean).toLocaleString()} tone="accent" sub={`range ${result.min.toLocaleString()} – ${result.max.toLocaleString()}`} />
          <Stat label="Theory: 1.25 · √space" value={Math.round(1.2533 * Math.sqrt(2 ** result.bits)).toLocaleString()} sub={`for ${result.bits}-bit values`} />
          <Stat label="Fraction of the space used" value={`${((result.mean / 2 ** result.bits) * 100).toFixed(3)}%`} sub="collision long before the space fills" />
        </div>
      )}
      <Note title="Why key and nonce sizes are what they are">
        This square root is subtracted from every security level. A 128-bit hash does not take 2¹²⁸ attempts to collide — it
        takes 2⁶⁴, which is feasible; that is why SHA-256 exists and MD5&apos;s 128 bits were never enough. A 64-bit random nonce
        under one key risks repeating after 2³² messages — the keystream-reuse disaster of §2 — so GCM uses counters, and
        ChaCha&apos;s XChaCha variant widens the nonce to 192 bits precisely so random nonces become safe. When you see a size
        that looks twice as large as necessary, the birthday bound is usually why.
      </Note>
    </Panel>
  );
}

/* Monte Carlo ----------------------------------------------------------------- */

function PiPlot({ pts, label, estimate }: { pts: [number, number][]; label: string; estimate: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const S = c.width;
    ctx.fillStyle = '#090b0e';
    ctx.fillRect(0, 0, S, S);
    ctx.strokeStyle = '#3a4150';
    ctx.beginPath();
    ctx.arc(0, S, S - 1, -Math.PI / 2, 0);
    ctx.stroke();
    for (const [x, y] of pts) {
      ctx.fillStyle = x * x + y * y <= 1 ? '#d9a441' : '#5b6472';
      ctx.fillRect(x * (S - 2), (1 - y) * (S - 2), 1.5, 1.5);
    }
  }, [pts]);
  const err = Math.abs(estimate - Math.PI);
  return (
    <div className="canvas-box">
      <canvas ref={ref} width={220} height={220} aria-label={`Monte Carlo estimate of pi using ${label}`} />
      <div className="cap">{label} — π ≈ {estimate.toFixed(4)} <span style={err > 0.01 ? { color: 'var(--danger)' } : undefined}>(off by {err.toFixed(4)})</span></div>
    </div>
  );
}

function MonteCarloPanel({ ready }: { ready: boolean }) {
  const [count, setCount] = useState(10_000);
  const [tick, setTick] = useState(0);

  const toPairs = (units: number[]): [number, number][] => {
    const out: [number, number][] = [];
    for (let i = 0; i + 1 < units.length; i += 2) out.push([units[i], units[i + 1]]);
    return out;
  };
  const estimate = (pts: [number, number][]) => (4 * pts.filter(([x, y]) => x * x + y * y <= 1).length) / Math.max(pts.length, 1);

  void tick;
  const csprng = ready ? toPairs(randomUnits(count * 2)) : [];
  const lcgRes = ready ? attempt(() => toPairs(Array.from(wasm.Randomness.lcg(1n, 137n, 187n, 256n, count * 2)))) : null;
  const lcg = lcgRes?.ok ? lcgRes.value : [];

  return (
    <Panel title="Randomness doing work: Monte Carlo" refs={['Monte Carlo method']}
      action={<Button size="sm" onClick={() => setTick((t) => t + 1)} disabled={!ready}>Redraw</Button>}>
      <p className="muted small">
        Scatter random points in a unit square and the fraction landing inside the quarter circle estimates π/4 — no
        geometry needed, just fair coordinates. This is the method behind pricing models, particle transport and every
        &quot;simulate it a million times&quot; answer, and it inherits the quality of its generator: the small-modulus LCG can only
        ever produce 256 distinct coordinate pairs, so its estimate stops improving no matter how many points you ask for.
      </p>
      <Field label="Points">{(id) => (
        <Select id={id} value={count} onChange={(e) => setCount(Number(e.target.value))} disabled={!ready}>
          {[2_000, 10_000, 50_000].map((v) => <option key={v} value={v}>{v.toLocaleString()}</option>)}
        </Select>
      )}</Field>
      <div className="grid-2" style={{ marginTop: '0.5rem' }}>
        <PiPlot pts={csprng} label="crypto.getRandomValues()" estimate={estimate(csprng)} />
        <PiPlot pts={lcg} label="LCG, modulus 256" estimate={estimate(lcg)} />
      </div>
      <Note title="RANDU's legacy, quantified">
        The lattice panel at the top of this page showed RANDU&apos;s planes as a curiosity of geometry; this panel is why it
        mattered. Physics and statistics papers of the 1960s–70s ran exactly this kind of simulation on RANDU, and their
        integrals converged to subtly wrong values. Cryptographic generators are overkill for simulation — good non-crypto
        generators like PCG or xoshiro are faster — but the failure mode of a bad one is silent, systematic error.
      </Note>
    </Panel>
  );
}

/* Commit–reveal --------------------------------------------------------------- */

function CommitRevealPanel({ ready }: { ready: boolean }) {
  const [aliceBit, setAliceBit] = useState<'0' | '1'>('0');
  const [bobBit, setBobBit] = useState<'0' | '1'>('1');
  const [nonce, setNonce] = useState('e3b0c44298fc1c149afbf4c8996fb924');
  const [cheat, setCheat] = useState(false);

  const res = ready ? attempt(() => {
    const commit = (bit: string, n: string) => wasm.Hasher.digest('sha256', hexToBytes(`0${bit}${n}`));
    const commitment = commit(aliceBit, nonce);
    // If Alice cheats, she reveals the opposite bit after seeing Bob's.
    const revealedBit = cheat ? (aliceBit === '0' ? '1' : '0') : aliceBit;
    const recomputed = commit(revealedBit, nonce);
    return { commitment, revealedBit, recomputed, valid: recomputed === commitment };
  }) : null;
  const r = res?.ok ? res.value : null;
  const coin = r ? (Number(r.revealedBit) ^ Number(bobBit)) : 0;

  return (
    <Panel title="Agreeing on randomness: a commit–reveal coin flip" refs={['commitment scheme']}
      action={<Button size="sm" onClick={() => setNonce(randomHex(16))} disabled={!ready}>New nonce</Button>}>
      <p className="muted small">
        Alice and Bob want a fair coin flip over a network, trusting nothing but hashes. Alice picks a bit and{' '}
        <strong>commits</strong> to it by publishing SHA-256(bit ‖ nonce) — binding (she cannot find another preimage) yet
        hiding (the random nonce stops Bob testing both bits). Bob then announces his bit in the clear. Alice{' '}
        <strong>reveals</strong>, anyone recomputes her hash, and the coin is the XOR: heads if the bits differ. Neither
        player can bias a coin the other half-controls.
      </p>
      <div className="grid-3">
        <Field label="Alice's secret bit">{() => (
          <Segmented label="Alice's bit" value={aliceBit} onChange={setAliceBit} disabled={!ready}
            options={[{ value: '0', label: '0' }, { value: '1', label: '1' }]} />
        )}</Field>
        <Field label="Bob's bit (public, sent after the commitment)">{() => (
          <Segmented label="Bob's bit" value={bobBit} onChange={setBobBit} disabled={!ready}
            options={[{ value: '0', label: '0' }, { value: '1', label: '1' }]} />
        )}</Field>
        <Field label="Alice's behaviour">{() => (
          <Segmented label="Alice's behaviour" value={cheat ? 'cheat' : 'honest'} onChange={(v) => setCheat(v === 'cheat')} disabled={!ready}
            options={[{ value: 'honest', label: 'Honest' }, { value: 'cheat', label: 'Cheat' }]} />
        )}</Field>
      </div>
      <ErrorText error={res && !res.ok ? res.error : null} />
      {r && (
        <>
          <div className="stack">
            <Output label="1 — Alice publishes her commitment" value={r.commitment} />
            <Output label={`2 — Bob announces his bit: ${bobBit}`} value={`Bob cannot use the commitment: without the nonce it hides Alice's bit completely.`} copy={false} />
            <Output label={`3 — Alice reveals bit ${r.revealedBit} and her nonce; everyone recomputes`} value={r.recomputed} tone={r.valid ? 'ok' : 'danger'} />
          </div>
          <div style={{ marginTop: '0.75rem' }}>
            {r.valid
              ? <Callout tone="ok">Commitment verifies. The coin is {r.revealedBit} ⊕ {bobBit} = <strong>{coin} — {coin ? 'heads' : 'tails'}</strong>. Alice locked her choice in before seeing Bob&apos;s, so neither side could steer it.</Callout>
              : <Callout tone="danger">Caught. Alice tried to reveal the opposite bit after seeing Bob&apos;s, but SHA-256(new bit ‖ nonce) does not match what she published. To cheat she would need a second preimage of her own commitment.</Callout>}
          </div>
        </>
      )}
      <Note title="The same trick at protocol scale">
        Replace the coin with anything neither party may control alone: sealed-bid auctions, leader election, and the
        randomness beacons that lotteries and proof-of-stake chains publish are all commit–reveal at heart. It also
        previews §11: a commitment is the first move of the Schnorr zero-knowledge proof, where &quot;reveal&quot; is replaced by an
        algebraic answer that convinces without disclosing.
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
      <CsprngPanel ready={ready} setCollected={setCollected} />
      <DistinguishPanel ready={ready} />
      <SamplingPanel ready={ready} />
      <BirthdayPanel ready={ready} />
      <MonteCarloPanel ready={ready} />
      <CommitRevealPanel ready={ready} />
      <FairRollPanel ready={ready} />

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

/* The distinguishing game ------------------------------------------------------ */

type Opponent = 'chacha' | 'lcg';

// Full-period byte LCG (Hull–Dobell: c odd, a ≡ 1 mod 4): never repeats a byte
// within 256 draws — the tell a careful player can learn to spot.
function lcgBytes(seed: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed & 0xff;
  for (let i = 0; i < n; i++) {
    x = (137 * x + 187) & 0xff;
    out[i] = x;
  }
  return out;
}

function DistinguishPanel({ ready }: { ready: boolean }) {
  const [opponent, setOpponent] = useState<Opponent>('chacha');
  const [round, setRound] = useState<{ a: string; b: string; prngIs: 0 | 1 } | null>(null);
  const [verdict, setVerdict] = useState<{ correct: boolean; prngIs: 0 | 1 } | null>(null);
  const [score, setScore] = useState({ chacha: { wins: 0, rounds: 0 }, lcg: { wins: 0, rounds: 0 } });

  const deal = () => {
    const truly = new Uint8Array(32);
    crypto.getRandomValues(truly);
    const prng = opponent === 'chacha'
      ? hexToBytes(wasm.Randomness.csprng_stream(randomHex(32), 0n, 32))
      : lcgBytes(crypto.getRandomValues(new Uint8Array(1))[0], 32);
    const prngIs = (crypto.getRandomValues(new Uint8Array(1))[0] & 1) as 0 | 1;
    setRound({ a: bytesToHex(prngIs === 0 ? prng : truly), b: bytesToHex(prngIs === 1 ? prng : truly), prngIs });
    setVerdict(null);
  };

  const guess = (which: 0 | 1) => {
    if (!round) return;
    const correct = which === round.prngIs;
    setVerdict({ correct, prngIs: round.prngIs });
    setScore((s) => ({ ...s, [opponent]: { wins: s[opponent].wins + (correct ? 1 : 0), rounds: s[opponent].rounds + 1 } }));
  };

  const distinct = (hex: string) => new Set(hexToBytes(hex)).size;
  const sc = score[opponent];

  return (
    <Panel title="The distinguishing game" refs={['IND definition']}
      action={<Button variant="primary" onClick={deal} disabled={!ready}>Deal a round</Button>}>
      <p className="muted small">
        {'“Computationally secure” has a precise game behind it: one line below came from '}<code>crypto.getRandomValues()</code>
        {', the other from a deterministic generator. If no efficient player can guess which is which better than 50%, the '}
        {'generator is a secure PRG — that indistinguishability is the actual definition, and everything in §2 and §8 rests on '}
        {'it. Against ChaCha20 you cannot win. Against the toy LCG you can: its full period never repeats a byte in 32 draws, '}
        {'while true randomness repeats one about 87% of the time — pick the line with all bytes distinct and you will be '}
        {'right roughly 9 rounds in 10.'}
      </p>
      <Segmented label="Opponent" value={opponent} onChange={(v) => { setOpponent(v); setRound(null); setVerdict(null); }} disabled={!ready}
        options={[{ value: 'chacha', label: 'ChaCha20 CSPRNG' }, { value: 'lcg', label: 'LCG (full period)' }]} />
      {round && (
        <>
          <div className="stack" style={{ marginTop: '0.75rem' }}>
            <Output label={`Line A — ${distinct(round.a)}/32 distinct bytes`} value={round.a} copy={false} ariaLabel="Distinguishing line A" />
            <Output label={`Line B — ${distinct(round.b)}/32 distinct bytes`} value={round.b} copy={false} ariaLabel="Distinguishing line B" />
          </div>
          <div className="row" style={{ marginTop: '0.75rem', gap: '0.5rem' }}>
            <Button onClick={() => guess(0)} disabled={!ready || verdict !== null}>A is the generator</Button>
            <Button onClick={() => guess(1)} disabled={!ready || verdict !== null}>B is the generator</Button>
          </div>
        </>
      )}
      {verdict && (
        <div style={{ marginTop: '0.75rem' }}>
          <Callout tone={verdict.correct ? 'ok' : 'danger'}>
            {verdict.correct ? 'Correct — ' : 'Wrong — '}
            {`line ${verdict.prngIs === 0 ? 'A' : 'B'} was the ${opponent === 'chacha' ? 'ChaCha20 stream' : 'LCG'}, line ${verdict.prngIs === 0 ? 'B' : 'A'} came from the OS.`}
          </Callout>
        </div>
      )}
      {sc.rounds > 0 && (
        <div style={{ marginTop: '0.75rem' }}>
          <Stat label={`Your score vs ${opponent === 'chacha' ? 'ChaCha20' : 'the LCG'}`} value={`${sc.wins} of ${sc.rounds} round${sc.rounds === 1 ? '' : 's'}`}
            sub={`${((100 * sc.wins) / sc.rounds).toFixed(0)}% — ${opponent === 'chacha' ? 'expect 50% no matter your strategy' : 'the distinct-bytes tell beats 90%'}`} />
        </div>
      )}
    </Panel>
  );
}

/* A provably fair roll --------------------------------------------------------- */

// Uniform integer in [1, n] by rejection sampling (§ modulo bias, applied).
function fairRoll(bytes: Uint8Array, n: number): { value: number; used: number } | null {
  const limit = 256 - (256 % n);
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] < limit) return { value: (bytes[i] % n) + 1, used: i + 1 };
  }
  return null;
}

function FairRollPanel({ ready }: { ready: boolean }) {
  const [sides, setSides] = useState(52);
  const [clientSeed, setClientSeed] = useState('my lucky words');
  const [game, setGame] = useState<{ serverSeed: string; commit: string; nonce: number; rolls: number[] } | null>(null);
  const [revealed, setRevealed] = useState(false);

  const newGame = () => {
    const serverSeed = randomHex(32);
    const commit = wasm.Hasher.digest('sha256', hexToBytes(serverSeed));
    setGame({ serverSeed, commit, nonce: 0, rolls: [] });
    setRevealed(false);
  };

  const roll = () => {
    if (!game || revealed) return;
    const msg = new TextEncoder().encode(`${clientSeed}:${game.nonce}`);
    const digest = wasm.Hasher.hmac('sha256', hexToBytes(game.serverSeed), msg);
    const r = fairRoll(hexToBytes(digest), sides);
    if (!r) return;
    setGame({ ...game, nonce: game.nonce + 1, rolls: [...game.rolls, r.value] });
  };

  // Verification recomputes every roll from the revealed seed — pure function
  // of public values, so the player can audit the whole session.
  const audit = game && revealed ? attempt(() => {
    if (wasm.Hasher.digest('sha256', hexToBytes(game.serverSeed)) !== game.commit) return false;
    return game.rolls.every((v, i) => {
      const d = wasm.Hasher.hmac('sha256', hexToBytes(game.serverSeed), new TextEncoder().encode(`${clientSeed}:${i}`));
      return fairRoll(hexToBytes(d), sides)?.value === v;
    });
  }) : null;

  return (
    <Panel title="A provably fair roll" refs={['commit–reveal, applied']}
      action={<Button variant="primary" onClick={newGame} disabled={!ready}>New game</Button>}>
      <p className="muted small">
        {'The commit–reveal coin flip above, grown into the scheme gambling sites actually ship as “provably fair”. The house '}
        {'picks a hidden server seed and publishes only its hash — the commitment, shown before you play. Each roll is '}
        {'HMAC(server seed, your seed + a counter), reduced to the range by rejection sampling (no modulo bias). The house '}
        {'cannot change the seed after your bets without breaking the hash; you contributed entropy, so it could not pick a '}
        {'seed that beats you; and after the reveal you recompute every roll yourself.'}
      </p>
      <div className="grid-2">
        <Field label="Range" hint="a die, a deck, a wheel">{(id) => (
          <Select id={id} value={sides} onChange={(e) => setSides(Number(e.target.value))} disabled={!ready}>
            <option value={6}>1–6 — a die</option>
            <option value={37}>1–37 — a roulette wheel</option>
            <option value={52}>1–52 — a card deck</option>
            <option value={100}>1–100 — percent roll</option>
          </Select>
        )}</Field>
        <Field label="Your client seed" hint="your contribution to every roll">{(id) => (
          <TextInput id={id} mono value={clientSeed} onChange={(e) => setClientSeed(e.target.value)} disabled={!ready || (game !== null && game.rolls.length > 0)} />
        )}</Field>
      </div>
      {game && (
        <>
          <div className="stack" style={{ marginTop: '0.5rem' }}>
            <Output label="House commitment = SHA-256(server seed), published before play" value={game.commit} ariaLabel="House commitment" />
            {revealed && <Output label="Server seed, revealed after play" value={game.serverSeed} tone="accent" />}
          </div>
          <div className="row" style={{ marginTop: '0.75rem', gap: '0.5rem' }}>
            <Button onClick={roll} disabled={!ready || revealed}>Roll</Button>
            <Button onClick={() => setRevealed(true)} disabled={!ready || revealed || game.rolls.length === 0}>End game &amp; reveal seed</Button>
          </div>
          {game.rolls.length > 0 && (
            <div style={{ marginTop: '0.75rem' }}>
              <Output label={`Rolls (nonce 0…${game.rolls.length - 1})`} value={game.rolls.join(', ')} copy={false} ariaLabel="Fair rolls" />
            </div>
          )}
          {revealed && audit && (
            <div style={{ marginTop: '0.75rem' }}>
              <Callout tone={audit.ok && audit.value ? 'ok' : 'danger'}>
                {audit.ok && audit.value
                  ? 'Audit passed: the revealed seed matches the commitment, and every roll recomputes from seed + your words + nonce. The house had no room to cheat.'
                  : 'Audit FAILED — the house cheated or the transcript is corrupt.'}
              </Callout>
            </div>
          )}
        </>
      )}
      <Note title="True randomness and the house">
        {'Where does the “true” randomness come from? '}<code>crypto.getRandomValues()</code>{' is the OS pool — interrupt '}
        {'timings, hardware jitter, on-die noise — stretched by exactly the CSPRNG construction shown above, and that is the '}
        {'right tool for shuffles, wheels and keys alike (with rejection sampling for ranges — §modulo bias). What a casino '}
        {'needs on top is not better randomness but '}<em>accountability</em>{': the player must be able to verify the house, '}
        {'and that is a cryptography problem, solved here with a hash commitment. Real sites publish the next server-seed '}
        {'hash while the current one is in play, chaining every session to the last.'}
      </Note>
    </Panel>
  );
}
