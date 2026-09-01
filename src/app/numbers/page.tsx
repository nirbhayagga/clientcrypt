'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Field, TextInput, Select, Output, Stat, Status, ErrorText, Callout, Tag } from '@/components/ui';

interface ModExpStep { bit_index: number; bit: number; after_square: string; after_multiply: string; multiplied: boolean }
interface ModExpTrace {
  base: string; exponent: string; modulus: string; exponent_bits: string;
  steps: ModExpStep[]; result: string; multiplications: number; naive_multiplications: string;
}
interface EuclidStep { a: string; b: string; quotient: string; remainder: string; s: string; t: string }
interface EuclidTrace {
  a: string; b: string; gcd: string; x: string; y: string;
  steps: EuclidStep[]; identity: string; coprime: boolean; inverse: string | null;
}
interface RsaWalkthrough {
  p: string; q: string; n: string; phi: string; lambda: string; e: string; d: string; key_bits: number;
  message: string; ciphertext: string; decrypted: string; roundtrip_ok: boolean;
  encrypt_trace: ModExpTrace; decrypt_trace: ModExpTrace; inverse_proof: string;
}
interface DhWalkthrough {
  p: string; g: string; a: string; b: string; public_a: string; public_b: string;
  secret_from_alice: string; secret_from_bob: string; agree: boolean;
  eavesdropper_sees: string[]; brute_force_work: string;
}

const num = (s: string, fallback = 0) => {
  const n = Number(s.replace(/[^0-9]/g, ''));
  return Number.isFinite(n) && n >= 0 ? n : fallback;
};

/* Modular exponentiation ---------------------------------------------------- */

function ModExpPanel({ ready }: { ready: boolean }) {
  const [base, setBase] = useState('4');
  const [exp, setExp] = useState('13');
  const [mod, setMod] = useState('497');
  const t = ready ? attempt(() => wasm.Numbers.mod_exp_trace(BigInt(num(base)), BigInt(num(exp)), BigInt(num(mod) || 1)) as ModExpTrace) : null;
  const trace = t?.ok ? t.value : null;

  return (
    <Panel title="Modular exponentiation: square and multiply"
      action={trace && <Tag tone="accent">{trace.multiplications} multiplications vs {trace.naive_multiplications}</Tag>}>
      <p className="muted small">
        Every public-key operation on this site is one modular exponentiation. Computing bᵉ mod m by multiplying b by itself
        e−1 times is hopeless when e has hundreds of digits. Instead, read the exponent in binary from the left: square the
        accumulator at every bit, and multiply by the base when the bit is 1. That turns e multiplications into about log₂(e).
      </p>
      <div className="grid-3">
        <Field label="Base b">{(id) => <TextInput id={id} mono value={base} onChange={(e) => setBase(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Exponent e">{(id) => <TextInput id={id} mono value={exp} onChange={(e) => setExp(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Modulus m">{(id) => <TextInput id={id} mono value={mod} onChange={(e) => setMod(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={t && !t.ok ? t.error : null} />
      {trace && (
        <>
          <hr className="divider" />
          <p className="mono small" style={{ marginBottom: '0.75rem' }}>
            e = {trace.exponent} = 0b<span style={{ color: 'var(--accent)' }}>{trace.exponent_bits}</span> · reading left to right
          </p>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Bit</th><th>Value</th><th>After squaring</th><th>× base?</th><th>Accumulator</th></tr></thead>
              <tbody>
                {trace.steps.map((s) => (
                  <tr key={s.bit_index}>
                    <td className="mono">{s.bit_index}</td>
                    <td className="mono" style={{ color: s.bit ? 'var(--accent)' : undefined }}>{s.bit}</td>
                    <td className="mono">{s.after_square}</td>
                    <td className="mono">{s.multiplied ? `× ${trace.base}` : '—'}</td>
                    <td className="mono">{s.after_multiply}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="grid-3" style={{ marginTop: '1rem' }}>
            <Stat label="Result" value={`${trace.base}^${trace.exponent} mod ${trace.modulus}`} sub="" />
            <Stat label="=" value={trace.result} tone="accent" />
            <Stat label="Multiplications" value={`${trace.multiplications}`} sub={`naive method: ${trace.naive_multiplications}`} tone="ok" />
          </div>
        </>
      )}
      <Note title="Why this is the whole game">
        Exponentiation is easy; going backwards is not. Given g, p and gˣ mod p, no efficient classical algorithm recovers x —
        that is the discrete logarithm problem, and it is what Diffie–Hellman rests on. RSA rests on the sibling assumption that
        factoring n = p·q is hard. Both are believed hard, not proven hard.
      </Note>
    </Panel>
  );
}

/* Extended Euclid ----------------------------------------------------------- */

function EuclidPanel({ ready }: { ready: boolean }) {
  const [a, setA] = useState('17');
  const [b, setB] = useState('3120');
  const t = ready ? attempt(() => wasm.Numbers.extended_gcd(BigInt(num(a)), BigInt(num(b))) as EuclidTrace) : null;
  const trace = t?.ok ? t.value : null;

  return (
    <Panel title="Extended Euclidean algorithm" action={trace && <Tag tone={trace.coprime ? 'ok' : undefined}>gcd = {trace.gcd}</Tag>}>
      <p className="muted small">
        The ordinary Euclidean algorithm finds gcd(a, b) by repeated remainders. The extended version also tracks how each
        remainder was built from the originals, ending with integers x and y such that a·x + b·y = gcd(a, b). When the gcd is 1
        that x <em>is</em> a⁻¹ mod b — which is exactly how RSA turns the public exponent e into the private exponent d.
      </p>
      <div className="grid-2">
        <Field label="a">{(id) => <TextInput id={id} mono value={a} onChange={(e) => setA(e.target.value)} disabled={!ready} />}</Field>
        <Field label="b (the modulus, for an inverse)">{(id) => <TextInput id={id} mono value={b} onChange={(e) => setB(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={t && !t.ok ? t.error : null} />
      {trace && (
        <>
          <hr className="divider" />
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Step</th><th>a</th><th>b</th><th>q = ⌊a/b⌋</th><th>r = a − q·b</th></tr></thead>
              <tbody>
                {trace.steps.map((s, i) => (
                  <tr key={i}>
                    <td className="mono">{i}</td>
                    <td className="mono">{s.a}</td>
                    <td className="mono">{s.b}</td>
                    <td className="mono">{s.quotient}</td>
                    <td className="mono">{s.remainder}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: '1rem' }} className="stack">
            <Output label="Bézout identity" value={trace.identity} copy={false} />
            {trace.coprime && trace.inverse
              ? <Callout tone="ok">a and b are coprime, so a⁻¹ mod b = {trace.inverse}. Check: {trace.a} × {trace.inverse} ≡ 1 (mod {trace.b}).</Callout>
              : <Callout tone="warn">gcd({trace.a}, {trace.b}) = {trace.gcd} ≠ 1, so {trace.a} has no inverse modulo {trace.b}. This is why RSA insists gcd(e, φ(n)) = 1.</Callout>}
          </div>
        </>
      )}
    </Panel>
  );
}

/* RSA by hand --------------------------------------------------------------- */

function RsaPanel({ ready }: { ready: boolean }) {
  const [p, setP] = useState('61');
  const [q, setQ] = useState('53');
  const [e, setE] = useState('17');
  const [m, setM] = useState('65');
  const primes = ready ? Array.from(wasm.Numbers.primes_below(200)) : [];
  const t = ready ? attempt(() => wasm.Numbers.rsa_walkthrough(BigInt(num(p)), BigInt(num(q)), BigInt(num(e)), BigInt(num(m))) as RsaWalkthrough) : null;
  const r = t?.ok ? t.value : null;

  return (
    <Panel title="RSA key generation, worked by hand" refs={['toy sizes — not secure']}
      action={r && <Tag>{r.key_bits}-bit modulus</Tag>}>
      <p className="muted small">
        The same five steps a 2048-bit key goes through, with primes small enough to check on paper. Pick two primes, multiply
        them, compute the group order, choose a public exponent coprime to it, and invert that exponent. The security rests on
        one asymmetry: n is public, but recovering p and q from it is hard — at these sizes, of course, it is trivial.
      </p>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
        <Field label="Prime p">{(id) => (
          <Select id={id} value={p} onChange={(ev) => setP(ev.target.value)} disabled={!ready}>
            {primes.map((v) => <option key={v} value={v}>{v}</option>)}
          </Select>
        )}</Field>
        <Field label="Prime q">{(id) => (
          <Select id={id} value={q} onChange={(ev) => setQ(ev.target.value)} disabled={!ready}>
            {primes.map((v) => <option key={v} value={v}>{v}</option>)}
          </Select>
        )}</Field>
        <Field label="Public exponent e">{(id) => <TextInput id={id} mono value={e} onChange={(ev) => setE(ev.target.value)} disabled={!ready} />}</Field>
        <Field label="Message m" hint={r ? `must be < ${r.n}` : 'a number'}>{(id) => <TextInput id={id} mono value={m} onChange={(ev) => setM(ev.target.value)} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={t && !t.ok ? t.error : null} />
      {r && (
        <>
          <hr className="divider" />
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Step</th><th>Quantity</th><th>Value</th></tr></thead>
              <tbody>
                <tr><td>1. Choose primes</td><td className="mono">p, q</td><td className="mono">{r.p}, {r.q}</td></tr>
                <tr><td>2. Modulus</td><td className="mono">n = p · q</td><td className="mono">{r.p} × {r.q} = {r.n}</td></tr>
                <tr><td>3. Group order</td><td className="mono">φ(n) = (p−1)(q−1)</td><td className="mono">{r.phi}</td></tr>
                <tr><td></td><td className="mono">λ(n) = lcm(p−1, q−1)</td><td className="mono">{r.lambda}</td></tr>
                <tr><td>4. Public exponent</td><td className="mono">e, coprime with φ(n)</td><td className="mono">{r.e}</td></tr>
                <tr><td>5. Private exponent</td><td className="mono">d = e⁻¹ mod λ(n)</td><td className="mono">{r.d}</td></tr>
                <tr><td></td><td className="mono">check</td><td className="mono">{r.inverse_proof}</td></tr>
              </tbody>
            </table>
          </div>
          <div className="grid-3" style={{ marginTop: '1rem' }}>
            <Stat label="Public key" value={`(${r.n}, ${r.e})`} sub="anyone may hold this" />
            <Stat label="Private key" value={`(${r.n}, ${r.d})`} tone="danger" sub="recoverable from p and q" />
            <Stat label="Round trip" value={r.roundtrip_ok ? 'm = (mᵉ)ᵈ' : 'failed'} tone={r.roundtrip_ok ? 'ok' : 'danger'} sub={`${r.message} → ${r.ciphertext} → ${r.decrypted}`} />
          </div>
          <div className="grid-2" style={{ marginTop: '1rem' }}>
            <Output label={`Encrypt: ${r.message}^${r.e} mod ${r.n}`} value={`${r.ciphertext}  (${r.encrypt_trace.multiplications} multiplications)`} copy={false} />
            <Output label={`Decrypt: ${r.ciphertext}^${r.d} mod ${r.n}`} value={`${r.decrypted}  (${r.decrypt_trace.multiplications} multiplications)`} copy={false} />
          </div>
        </>
      )}
      <Note title="What is missing compared with §6">
        Everything that makes RSA safe in practice: primes hundreds of digits long, OAEP padding so identical messages do not
        produce identical ciphertexts, and a message that is a symmetric key rather than data. Textbook RSA as shown here is
        deterministic and malleable — encrypt the same number twice and you get the same ciphertext.
      </Note>
    </Panel>
  );
}

/* Diffie–Hellman by hand ----------------------------------------------------- */

function DhPanel({ ready }: { ready: boolean }) {
  const [p, setP] = useState('23');
  const [g, setG] = useState('5');
  const [a, setA] = useState('6');
  const [b, setB] = useState('15');
  const t = ready ? attempt(() => wasm.Numbers.dh_walkthrough(BigInt(num(p)), BigInt(num(g)), BigInt(num(a)), BigInt(num(b))) as DhWalkthrough) : null;
  const d = t?.ok ? t.value : null;

  return (
    <Panel title="Diffie–Hellman, worked by hand" refs={['toy sizes — not secure']}>
      <p className="muted small">
        Two parties agree on a shared secret while every message between them is public. Each picks a private exponent, sends
        g raised to it, and raises what they receive to their own exponent. Both land on g^(ab) mod p because exponentiation
        commutes; an eavesdropper who saw everything still faces a discrete logarithm.
      </p>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
        <Field label="Prime p">{(id) => <TextInput id={id} mono value={p} onChange={(e) => setP(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Generator g">{(id) => <TextInput id={id} mono value={g} onChange={(e) => setG(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Alice's secret a">{(id) => <TextInput id={id} mono value={a} onChange={(e) => setA(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Bob's secret b">{(id) => <TextInput id={id} mono value={b} onChange={(e) => setB(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={t && !t.ok ? t.error : null} />
      {d && (
        <>
          <hr className="divider" />
          <div className="grid-2">
            <div className="stack">
              <h3 style={{ fontSize: '1rem' }}>Alice</h3>
              <Output label={`sends A = ${d.g}^${d.a} mod ${d.p}`} value={d.public_a} copy={false} />
              <Output label={`computes B^a mod p = ${d.public_b}^${d.a} mod ${d.p}`} value={d.secret_from_alice} tone="accent" copy={false} />
            </div>
            <div className="stack">
              <h3 style={{ fontSize: '1rem' }}>Bob</h3>
              <Output label={`sends B = ${d.g}^${d.b} mod ${d.p}`} value={d.public_b} copy={false} />
              <Output label={`computes A^b mod p = ${d.public_a}^${d.b} mod ${d.p}`} value={d.secret_from_bob} tone="accent" copy={false} />
            </div>
          </div>
          <div style={{ marginTop: '1rem' }}>
            {d.agree
              ? <Callout tone="ok">Both sides hold {d.secret_from_alice}. Neither ever transmitted it.</Callout>
              : <Callout tone="danger">The secrets differ — check that g generates a large subgroup mod p.</Callout>}
          </div>
          <div style={{ marginTop: '1rem' }}>
            <div className="label"><span>Everything an eavesdropper sees</span></div>
            <div className="row" style={{ marginTop: '0.35rem' }}>
              {d.eavesdropper_sees.map((v) => <Tag key={v}>{v}</Tag>)}
            </div>
            <p className="faint small" style={{ marginTop: '0.5rem' }}>
              To recover the secret they must solve g^x ≡ A (mod p) for x — {d.brute_force_work}, which at p = {d.p} takes no time at all.
              At the 2048-bit primes of §6 the same search is out of reach.
            </p>
          </div>
        </>
      )}
    </Panel>
  );
}

/* Page ----------------------------------------------------------------------- */

export default function NumbersPage() {
  const state = useWasm();
  const ready = state === 'ready';
  return (
    <Page kicker="§4 · Number theory" title="The arithmetic under public-key cryptography"
      lede="Public-key cryptography is modular arithmetic with numbers too large to print. The operations are the ones below, at sizes small enough to follow every step by hand; §6 runs the same operations at sizes that are actually secure.">
      <Status state={state} />
      <ModExpPanel ready={ready} />
      <EuclidPanel ready={ready} />
      <RsaPanel ready={ready} />
      <DhPanel ready={ready} />
      <Note title="Where the data-structures view lives">
        The sieve of Eratosthenes, integer factorisation as a search problem, and the rest of the algorithmic number theory
        are visualised in{' '}
        <a href="https://stepwise.nirbhay.dev" target="_blank" rel="noreferrer">Stepwise</a>. This page is the cryptographic
        reading of the same mathematics: not how fast you can find primes, but what secrecy you can build once you have them.
      </Note>
    </Page>
  );
}
