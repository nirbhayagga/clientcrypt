'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Field, TextInput, Output, Stat, Status, ErrorText, Button, Callout } from '@/components/ui';

interface PaddingOracle {
  key: string; iv: string; ciphertext: string; recovered_hex: string; recovered_text: string;
  matched: boolean; oracle_calls: number; blocks_attacked: number;
}
interface DhMitm {
  p: string; g: string; alice_private: string; bob_private: string; mallory_a: string; mallory_b: string;
  alice_sends: string; bob_sends: string; mallory_to_bob: string; mallory_to_alice: string;
  alice_secret: string; bob_secret: string; mallory_secret_with_alice: string; mallory_secret_with_bob: string;
  alice_deceived: boolean; bob_deceived: boolean; alice_bob_share_a_key: boolean;
}

/* Padding oracle ------------------------------------------------------------ */

function PaddingOraclePanel({ ready }: { ready: boolean }) {
  const [text, setText] = useState('transfer approved');
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<PaddingOracle | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = () => {
    setBusy(true); setError(null); setRes(null);
    setTimeout(() => {
      const r = attempt(() => wasm.Attacks.padding_oracle(text) as PaddingOracle);
      if (r.ok) setRes(r.value); else setError(r.error);
      setBusy(false);
    }, 30);
  };

  return (
    <Panel title="CBC padding-oracle attack" refs={['Vaudenay 2002']}
      action={<Button variant="primary" onClick={run} disabled={!ready || busy}>{busy ? 'Attacking…' : 'Run the attack'}</Button>}>
      <p className="muted small">
        The message below is encrypted with AES-CBC under a key the attacker never sees. The only thing the &quot;server&quot; leaks
        is one bit per query — whether the padding decrypted cleanly — which it gives away through a distinct error, a status
        code, or even a timing difference. That single bit is enough to recover the entire plaintext, one byte at a time.
      </p>
      <Field label="Secret message (≤ 64 bytes)">{(id) => <TextInput id={id} value={text} onChange={(e) => setText(e.target.value)} disabled={!ready || busy} />}</Field>
      <ErrorText error={error} />
      {res && (
        <>
          <hr className="divider" />
          <div className="stack">
            <Output label={`Ciphertext the attacker sees (IV ${res.iv.slice(0, 12)}… + ${res.blocks_attacked} block${res.blocks_attacked === 1 ? '' : 's'})`} value={res.ciphertext} scroll copy={false} />
            <Output label="Recovered plaintext — using only the padding oracle, never the key" value={res.recovered_text} tone="danger" />
          </div>
          <div className="grid-3" style={{ marginTop: '1rem' }}>
            <Stat label="Outcome" value={res.matched ? 'plaintext recovered' : 'failed'} tone={res.matched ? 'danger' : 'ok'} />
            <Stat label="Oracle queries" value={res.oracle_calls.toLocaleString()} sub={`≈ ${Math.round(res.oracle_calls / (res.blocks_attacked * 16))} per byte, vs 2¹²⁸ to brute force`} />
            <Stat label="Key used by the attack" value="none" tone="accent" sub={`the key ${res.key.slice(0, 12)}… stayed secret`} />
          </div>
          {res.matched && <div style={{ marginTop: '1rem' }}><Callout tone="danger">The attacker reconstructed &ldquo;{res.recovered_text}&rdquo; from a boolean oracle alone. The key was never involved.</Callout></div>}
        </>
      )}
      <Note title="How one bit becomes plaintext">
        In CBC, plaintext = D_K(ciphertext block) XOR the previous block, and the attacker controls that previous block. By
        editing it and asking &ldquo;did the padding parse?&rdquo;, they force the last decrypted byte to 0x01, which reveals one byte of
        D_K; XOR with the real previous block gives the plaintext byte. Then they target 0x02 0x02, and so on. This broke SSL 3.0
        (POODLE), TLS (Lucky Thirteen) and ASP.NET. The fix is authenticated encryption — §2&apos;s GCM and ChaCha20-Poly1305
        reject a tampered ciphertext before it is ever decrypted, so there is no oracle to query.
      </Note>
    </Panel>
  );
}

/* Diffie–Hellman MITM -------------------------------------------------------- */

function DhMitmPanel({ ready }: { ready: boolean }) {
  const [p, setP] = useState('2147483647');
  const [g, setG] = useState('7');
  const [a, setA] = useState('123456');
  const [b, setB] = useState('654321');
  const [m1, setM1] = useState('1111');
  const [m2, setM2] = useState('2222');

  const res = ready ? attempt(() => wasm.Attacks.dh_mitm(p, g, a, b, m1, m2) as DhMitm) : null;
  const d = res?.ok ? res.value : null;

  const short = (s: string) => (s.length > 18 ? `${s.slice(0, 18)}…` : s);

  return (
    <Panel title="Man-in-the-middle on unauthenticated Diffie–Hellman" refs={['active attacker']}>
      <p className="muted small">
        §6 showed Alice and Bob agreeing on a shared secret over an open channel. What it did not show is that the agreement
        proves nothing about <em>who</em> is on the other end. If Mallory can intercept and replace messages, she completes a
        separate key exchange with each of them, and both believe they are talking to the other. Nothing in the arithmetic
        goes wrong — that is exactly why it is dangerous.
      </p>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
        <Field label="Prime p">{(id) => <TextInput id={id} mono value={p} onChange={(e) => setP(e.target.value.trim())} disabled={!ready} />}</Field>
        <Field label="Generator g">{(id) => <TextInput id={id} mono value={g} onChange={(e) => setG(e.target.value.trim())} disabled={!ready} />}</Field>
        <div />
        <Field label="Alice's secret a">{(id) => <TextInput id={id} mono value={a} onChange={(e) => setA(e.target.value.trim())} disabled={!ready} />}</Field>
        <Field label="Bob's secret b">{(id) => <TextInput id={id} mono value={b} onChange={(e) => setB(e.target.value.trim())} disabled={!ready} />}</Field>
        <div />
        <Field label="Mallory's m₁ (to Bob)">{(id) => <TextInput id={id} mono value={m1} onChange={(e) => setM1(e.target.value.trim())} disabled={!ready} />}</Field>
        <Field label="Mallory's m₂ (to Alice)">{(id) => <TextInput id={id} mono value={m2} onChange={(e) => setM2(e.target.value.trim())} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={res && !res.ok ? res.error : null} />
      {d && (
        <>
          <hr className="divider" />
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Channel</th><th>Alice believes</th><th>Mallory does</th><th>Bob believes</th></tr></thead>
              <tbody>
                <tr>
                  <td>public value out</td>
                  <td className="mono">A = {short(d.alice_sends)}</td>
                  <td className="mono" style={{ color: 'var(--danger)' }}>swaps in {short(d.mallory_to_alice)} / {short(d.mallory_to_bob)}</td>
                  <td className="mono">B = {short(d.bob_sends)}</td>
                </tr>
                <tr>
                  <td>derived secret</td>
                  <td className="mono" style={{ color: 'var(--accent)' }}>{short(d.alice_secret)}</td>
                  <td className="mono" style={{ color: 'var(--danger)' }}>holds both</td>
                  <td className="mono" style={{ color: 'var(--accent)' }}>{short(d.bob_secret)}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="grid-3" style={{ marginTop: '1rem' }}>
            <Stat label="Alice ↔ Mallory" value={d.alice_deceived ? 'shared key' : '—'} tone="danger" sub="Alice thinks this is Bob" />
            <Stat label="Bob ↔ Mallory" value={d.bob_deceived ? 'shared key' : '—'} tone="danger" sub="Bob thinks this is Alice" />
            <Stat label="Alice ↔ Bob" value={d.alice_bob_share_a_key ? 'shared key' : 'no shared key'} tone={d.alice_bob_share_a_key ? 'ok' : 'accent'} sub="they never actually agree" />
          </div>
          <div style={{ marginTop: '1rem' }}>
            <Callout tone="danger">
              Mallory holds Alice&apos;s key ({short(d.mallory_secret_with_alice)}) and Bob&apos;s key ({short(d.mallory_secret_with_bob)}).
              She decrypts everything Alice sends, reads it, and re-encrypts it for Bob — invisibly, in both directions.
            </Callout>
          </div>
        </>
      )}
      <Note title="What authentication adds">
        The gap is that a raw public value carries no identity. TLS (§8) closes it by having the server <em>sign</em> its key
        share with a certificate key that a certificate authority has vouched for; Alice rejects Mallory&apos;s substitute because
        it is not signed by the name she expected. WireGuard (§9) closes it differently, by requiring each peer&apos;s static public
        key to be known in advance. Diffie–Hellman gives you secrecy against a passive eavesdropper for free; resistance to an
        active one has to be bought with authentication.
      </Note>
    </Panel>
  );
}

/* Page ----------------------------------------------------------------------- */

export default function AttacksPage() {
  const state = useWasm();
  const ready = state === 'ready';
  return (
    <Page kicker="§10 · Attacks" title="Two attacks, and the defences that answer them"
      lede="The rest of the site builds primitives; this section breaks two of them. Both attacks run to completion in your browser, and both exist to make one point — the countermeasure elsewhere on the site is not decoration.">
      <Status state={state} />
      <PaddingOraclePanel ready={ready} />
      <DhMitmPanel ready={ready} />
      <Note title="Why show attacks at all">
        A demonstration you can run is harder to forget than a warning you have to trust. Both of these were live in deployed
        systems for years — the padding oracle in TLS, the missing authentication in countless hand-rolled key exchanges — and
        both were fixed by exactly the constructions this site spends its other sections on. Seeing the break is the argument
        for the fix.
      </Note>
    </Page>
  );
}
