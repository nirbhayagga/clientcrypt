'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Callout, Field, TextInput, Select, Output, Stat, Status, ErrorText, Button } from '@/components/ui';

interface Share { x: number; y: number }
interface ShamirSplit { secret: number; threshold: number; coefficients: number[]; polynomial: string; shares: Share[] }
interface LagrangeTerm { x: number; y: number; weight: number; contribution: number }
interface ShamirRecon { secret: number; polynomial: string; terms: LagrangeTerm[] }

const P = '2147483647';

export default function SharingPage() {
  const state = useWasm();
  const ready = state === 'ready';

  const [secret, setSecret] = useState('31337');
  const [k, setK] = useState(3);
  const [n, setN] = useState(5);
  const [split, setSplit] = useState<ShamirSplit | null>(null);
  const [splitError, setSplitError] = useState<string | null>(null);
  const [picked, setPicked] = useState<number[]>([]);
  const [claim, setClaim] = useState('999999999');

  const deal = () => {
    const r = attempt(() => wasm.Sharing.split(Number(secret.trim() || 'NaN'), k, n) as ShamirSplit);
    if (r.ok) { setSplit(r.value); setPicked([]); setSplitError(null); } else { setSplit(null); setSplitError(r.error); }
  };

  const toggle = (x: number) => {
    setPicked((prev) => prev.includes(x) ? prev.filter((v) => v !== x) : [...prev, x].sort((a, b) => a - b));
  };

  const chosen = split ? split.shares.filter((s) => picked.includes(s.x)) : [];
  const recon = ready && chosen.length >= 2
    ? attempt(() => wasm.Sharing.reconstruct(new Uint32Array(chosen.flatMap((s) => [s.x, s.y]))) as ShamirRecon)
    : null;
  const forged = ready && split && chosen.length === split.threshold - 1
    ? attempt(() => wasm.Sharing.forge(new Uint32Array(chosen.flatMap((s) => [s.x, s.y])), Number(claim.trim() || 'NaN')) as ShamirRecon)
    : null;

  return (
    <Page kicker="§12 · Secret sharing" title="Splitting a secret"
      lede="Shamir's threshold scheme turns one secret into n shares such that any k of them recover it exactly — and any k−1 of them are consistent with every possible secret, so a coalition below the threshold learns literally nothing. It is how root keys, recovery codes and HSM backups are actually held.">
      <Status state={state} />

      <Panel title="Deal the shares" refs={['Shamir 1979']}
        action={<Button variant="primary" onClick={deal} disabled={!ready}>Split the secret</Button>}>
        <p className="muted small">
          {'Pick a random polynomial of degree k−1 whose constant term is the secret, working mod the prime p = '}{P}
          {' (the same 2³¹ − 1 as §11). Share i is simply the point (i, f(i)). Since k points determine a degree-(k−1) '}
          {'polynomial uniquely — and k−1 points do not — the threshold falls exactly where the algebra says it must.'}
        </p>
        <div className="grid-3">
          <Field label="Secret" hint={`an integer below p`}>{(id) => (
            <TextInput id={id} mono value={secret} onChange={(e) => setSecret(e.target.value)} disabled={!ready} />
          )}</Field>
          <Field label="Threshold k" hint="shares needed to recover">{(id) => (
            <Select id={id} value={k} onChange={(e) => { setK(Number(e.target.value)); setSplit(null); }} disabled={!ready}>
              {[2, 3, 4, 5].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          )}</Field>
          <Field label="Shares n" hint="shares dealt in total">{(id) => (
            <Select id={id} value={n} onChange={(e) => { setN(Number(e.target.value)); setSplit(null); }} disabled={!ready}>
              {[3, 4, 5, 6, 7, 8].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          )}</Field>
        </div>
        <ErrorText error={splitError} />
        {split && (
          <>
            <div className="stack" style={{ marginTop: '0.5rem' }}>
              <Output label="The dealing polynomial — the dealer destroys this after handing out shares" value={split.polynomial} copy={false} scroll ariaLabel="Dealing polynomial" />
            </div>
            <div className="table-wrap" style={{ marginTop: '0.75rem' }}>
              <table className="table">
                <thead><tr><th>Share</th><th>Point (x, y = f(x))</th><th>Held by</th></tr></thead>
                <tbody>
                  {split.shares.map((s, i) => (
                    <tr key={s.x}>
                      <td className="mono">#{s.x}</td>
                      <td className="mono">({s.x}, {s.y})</td>
                      <td className="muted">{['Alice', 'Bob', 'Carol', 'Dan', 'Erin', 'Frank', 'Grace', 'Heidi', 'Ivan', 'Judy'][i]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>

      {split && (
        <Panel title={`Reconstruct — any ${split.threshold} of ${split.shares.length}`}>
          <p className="muted small">
            {'Select shares to bring to the table. With k, Lagrange interpolation rebuilds f and reads the secret at f(0); '}
            {'each share contributes y·ℓ(0) for its basis weight, and the contributions simply sum. With fewer than k, watch '}
            {'the panel below instead.'}
          </p>
          <div className="row" style={{ gap: '0.5rem', flexWrap: 'wrap' }}>
            {split.shares.map((s) => (
              <Button key={s.x} size="sm" variant={picked.includes(s.x) ? 'primary' : undefined} onClick={() => toggle(s.x)} disabled={!ready}>
                {picked.includes(s.x) ? '✓ ' : ''}Share #{s.x}
              </Button>
            ))}
          </div>
          {recon && (recon.ok ? (
            <>
              <div className="table-wrap" style={{ marginTop: '0.75rem' }}>
                <table className="table">
                  <thead><tr><th>Share</th><th>Weight ℓᵢ(0)</th><th>Contribution y·ℓᵢ(0) mod p</th></tr></thead>
                  <tbody>
                    {recon.value.terms.map((t) => (
                      <tr key={t.x}><td className="mono">#{t.x}</td><td className="mono">{t.weight}</td><td className="mono">{t.contribution}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="grid-2" style={{ marginTop: '0.75rem' }}>
                <Stat label="Recovered f(0)" value={recon.value.secret} tone={recon.value.secret === split.secret ? 'ok' : 'danger'}
                  sub={recon.value.secret === split.secret ? 'the secret, recovered exactly' : 'not the secret — too few shares pin a different polynomial'} />
                <Stat label="Shares at the table" value={`${chosen.length} of ${split.threshold} needed`}
                  tone={chosen.length >= split.threshold ? 'ok' : 'warn'} sub={chosen.length >= split.threshold ? 'threshold met' : 'below threshold'} />
              </div>
            </>
          ) : <ErrorText error={recon.error} />)}
          {chosen.length === 1 && <p className="muted small" style={{ marginTop: '0.75rem' }}>Pick at least two shares to interpolate anything at all.</p>}
        </Panel>
      )}

      {split && (
        <Panel title={`What ${split.threshold - 1} shares know: nothing`}>
          <p className="muted small">
            {'The privacy claim is not “hard to invert” but information-theoretic, like the one-time pad in §1 — and here is '}
            {'the constructive proof. Select exactly k−1 = '}{String(split.threshold - 1)}{' shares above, claim ANY secret '}
            {'below, and a valid dealing polynomial appears that passes through those very shares and your claim. Holding '}
            {'k−1 shares, every secret in the field remains exactly as plausible as every other.'}
          </p>
          <Field label="Claimed secret" hint="any integer below p">{(id) => (
            <TextInput id={id} mono value={claim} onChange={(e) => setClaim(e.target.value)} disabled={!ready} />
          )}</Field>
          {chosen.length !== split.threshold - 1 && (
            <p className="muted small" style={{ marginTop: '0.5rem' }}>{`Select exactly ${split.threshold - 1} share${split.threshold === 2 ? '' : 's'} in the panel above to run the forgery.`}</p>
          )}
          {forged && (forged.ok ? (
            <>
              <div style={{ marginTop: '0.5rem' }}>
                <Output label="A polynomial consistent with the held shares AND the claimed secret" value={forged.value.polynomial} copy={false} scroll ariaLabel="Forged polynomial" />
              </div>
              <div style={{ marginTop: '0.75rem' }}>
                <Callout tone="info">
                  {'This polynomial has your claimed secret at f(0) and agrees with every share the coalition holds — so '}
                  {'nothing they hold can rule the claim out. Only a k-th share collapses the possibilities to one. Compare '}
                  {'the one-time pad forgery in §1 and the Schnorr simulator in §11: three costumes, one argument.'}
                </Callout>
              </div>
            </>
          ) : <ErrorText error={forged.error} />)}
          <Note title="Where thresholds run the world">
            The DNSSEC root key ceremony needs a quorum of geographically scattered credential holders; HSMs back up their
            master keys as smartcard quorums (3-of-5 is common); cryptocurrency multisig and MPC wallets split signing power
            the same way; and distributed systems share signing keys so no single compromised node can speak for the
            cluster. The mathematics on this page is, almost unchanged, what ships.
          </Note>
        </Panel>
      )}
    </Page>
  );
}
