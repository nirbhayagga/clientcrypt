'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Callout, Field, TextInput, Output, Stat, Status, ErrorText, Button } from '@/components/ui';

interface SchnorrRound {
  p: string; g: string; secret_x: string; public_y: string; r: string;
  commitment_t: string; challenge_c: string; response_s: string;
  check_left: string; check_right: string; verified: boolean; note: string;
}
interface SchnorrSignature {
  public_y: string; message: string; commitment_t: string; challenge_c: string;
  response_s: string; verified: boolean; tampered_verifies: boolean;
}

// 2^31 − 1, a Mersenne prime small enough that every value on screen is legible.
const P = '2147483647';
const G = '7';

function InteractivePanel({ ready }: { ready: boolean }) {
  const [x, setX] = useState('1234567');
  const [round, setRound] = useState<SchnorrRound | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rounds, setRounds] = useState(0);

  const publicY = ready ? attempt(() => {
    const r = wasm.Zkp.schnorr_prove_with_r(P, G, x, '0', '1') as SchnorrRound;
    return r.public_y;
  }) : null;

  const challenge = () => {
    const c = String(crypto.getRandomValues(new Uint32Array(1))[0]);
    const r = attempt(() => wasm.Zkp.schnorr_prove(P, G, x, c) as SchnorrRound);
    if (r.ok) { setRound(r.value); setRounds((n) => n + 1); setError(null); }
    else { setRound(null); setError(r.error); }
  };

  return (
    <Panel title="The interactive proof" refs={['Schnorr 1991']}
      action={<Button variant="primary" onClick={challenge} disabled={!ready}>Issue a random challenge</Button>}>
      <p className="muted small">
        Peggy knows a secret exponent x. Everyone knows y = g<sup>x</sup> mod p — recovering x from y is the discrete-log
        problem of §4, easy at this toy size and infeasible at 2048 bits. Peggy convinces Victor she knows x in three moves:
        she <strong>commits</strong> to a fresh random r as t = g<sup>r</sup>; Victor returns a random{' '}
        <strong>challenge</strong> c; she <strong>responds</strong> with s = r + c·x. Victor accepts if
        g<sup>s</sup> = t·y<sup>c</sup> — an equation Peggy can only satisfy for a c she did not choose by actually using x.
      </p>
      <div className="grid-2">
        <Field label="Peggy's secret x" hint="never sent; try changing it">{(id) => (
          <TextInput id={id} mono value={x} onChange={(e) => { setX(e.target.value); setRound(null); setRounds(0); }} disabled={!ready} />
        )}</Field>
        <Field label={<>Public key y = g<sup>x</sup> mod p</>} hint={`p = ${P} (2³¹ − 1), g = ${G}`}>{(id) => (
          <TextInput id={id} mono readOnly value={publicY?.ok ? publicY.value : ''} aria-label="Public value y" />
        )}</Field>
      </div>
      <ErrorText error={error ?? (publicY && !publicY.ok ? publicY.error : null)} />
      {round && (
        <>
          <hr className="divider" />
          <div className="stack">
            <Output label={<>1 — Peggy commits: t = g<sup>r</sup> (her fresh secret r stays hidden)</>} value={round.commitment_t} copy={false} />
            <Output label="2 — Victor challenges with a random c" value={round.challenge_c} copy={false} />
            <Output label="3 — Peggy responds: s = r + c·x mod (p−1)" value={round.response_s} copy={false} />
          </div>
          <div className="grid-3" style={{ marginTop: '0.75rem' }}>
            <Stat label="Victor computes gˢ" value={round.check_left} sub="from public values only" />
            <Stat label="Victor computes t·yᶜ" value={round.check_right} sub="from public values only" />
            <Stat label="Verdict" value={round.verified ? 'accepted' : 'rejected'} tone={round.verified ? 'ok' : 'danger'} sub={`${rounds} round${rounds === 1 ? '' : 's'} so far`} />
          </div>
          <div style={{ marginTop: '0.75rem' }}>
            <Callout tone="info">
              What did Victor learn about x? Nothing: s = r + c·x with a fresh uniform r is itself uniform, so the transcript
              (t, c, s) could be produced by anyone <em>choosing c first</em> — pick s at random and set t = g<sup>s</sup>·y<sup>−c</sup>.
              Simulatable means zero-knowledge. What convinces Victor is the order of moves: c arrived <em>after</em> t was fixed.
            </Callout>
          </div>
        </>
      )}
      <Note title="Soundness: why answering at all proves knowledge">
        If Peggy could answer two different challenges c₁ ≠ c₂ for the same commitment t, the two responses would satisfy
        s₁ − s₂ = (c₁ − c₂)·x — a linear equation anyone could solve for x. So the ability to answer an unpredictable
        challenge <em>is</em> possession of x; a cheater who fixed her answer in advance survives one round with probability
        1/c-space, and each extra round multiplies her odds down. The crate&apos;s test suite performs this extraction.
      </Note>
    </Panel>
  );
}

function FiatShamirPanel({ ready }: { ready: boolean }) {
  const [msg, setMsg] = useState('transfer 100 to Bob');
  const [sig, setSig] = useState<SchnorrSignature | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sign = () => {
    const r = attempt(() => wasm.Zkp.schnorr_sign(P, G, '1234567', msg) as SchnorrSignature);
    if (r.ok) { setSig(r.value); setError(null); } else { setSig(null); setError(r.error); }
  };

  return (
    <Panel title="Fiat–Shamir: the proof becomes a signature" refs={['Fiat–Shamir 1986']}
      action={<Button variant="primary" onClick={sign} disabled={!ready}>Sign the message</Button>}>
      <p className="muted small">
        The interactive protocol needs Victor online only to supply an unpredictable c. Replace him with a hash:
        c = SHA-256(g, y, t, <em>message</em>). The prover still cannot choose c before t — the hash sees t — so soundness
        survives, and the transcript (t, s) becomes something new: a <strong>signature</strong> on the message, verifiable by
        anyone, bound to the signer&apos;s y. This is not an analogy — Ed25519 in §6 is exactly this construction on an elliptic
        curve, and most zk-SNARK systems use the same transform to become non-interactive.
      </p>
      <Field label="Message">{(id) => (
        <TextInput id={id} mono value={msg} onChange={(e) => setMsg(e.target.value)} disabled={!ready} />
      )}</Field>
      <ErrorText error={error} />
      {sig && (
        <>
          <div className="stack">
            <Output label="Commitment t" value={sig.commitment_t} copy={false} />
            <Output label="Challenge c = SHA-256(g ‖ y ‖ t ‖ message)" value={sig.challenge_c} copy={false} scroll />
            <Output label="Response s — the signature is (t, s)" value={sig.response_s} copy={false} />
          </div>
          <div className="grid-2" style={{ marginTop: '0.75rem' }}>
            <Stat label="Signature verifies" value={sig.verified ? 'yes' : 'no'} tone={sig.verified ? 'ok' : 'danger'} sub="recompute c from the message, check gˢ = t·yᶜ" />
            <Stat label="Same signature on a tampered message" value={sig.tampered_verifies ? 'accepted' : 'rejected'} tone={sig.tampered_verifies ? 'danger' : 'ok'} sub="the hash pins c to these exact bytes" />
          </div>
        </>
      )}
      <Note title="Where zero-knowledge goes from here">
        Schnorr proves one statement — &quot;I know x for this y&quot;. Modern systems prove arbitrary ones: &quot;this transaction
        balances&quot;, &quot;I am over 18&quot;, &quot;this program produced that output&quot; — without revealing the inputs, by expressing the
        statement as a circuit and proving it satisfied. The three-move shape (commit, challenge, respond) and the
        Fiat–Shamir hash survive all the way up; what changes is the mathematics that keeps the proof small. The commit–reveal
        coin flip in §5 is the same idea one rung down the ladder.
      </Note>
    </Panel>
  );
}

export default function ZkpPage() {
  const state = useWasm();
  const ready = state === 'ready';

  return (
    <Page kicker="§11 · Zero-knowledge" title="Proving without revealing"
      lede="A zero-knowledge proof convinces a sceptical verifier that a statement is true while teaching them nothing else — not even information they could use to convince someone else. The Schnorr protocol below is the simplest honest example, and the ancestor of both modern signatures and zk-SNARKs.">
      <Status state={state} />
      <InteractivePanel ready={ready} />
      <FiatShamirPanel ready={ready} />
    </Page>
  );
}
