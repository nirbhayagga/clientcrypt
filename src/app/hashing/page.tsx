'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt, errorMessage } from '@/lib/wasm';
import { hexToBytes, hammingDistanceHex } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Output, Stat, Status, ErrorText, Button, Callout, Tag } from '@/components/ui';

type Fmt = 'text' | 'hex';

const ALGS: { id: string; name: string; bits: number; std: string; status: 'broken' | 'ok'; note: string }[] = [
  { id: 'md5', name: 'MD5', bits: 128, std: 'RFC 1321', status: 'broken', note: 'Collisions in seconds (Wang et al., 2004). Not a cryptographic hash any more.' },
  { id: 'sha1', name: 'SHA-1', bits: 160, std: 'FIPS 180-4', status: 'broken', note: 'First public collision: SHAttered (2017); chosen-prefix collisions since 2020.' },
  { id: 'sha256', name: 'SHA-256', bits: 256, std: 'FIPS 180-4', status: 'ok', note: 'Merkle–Damgård construction; 128-bit collision resistance.' },
  { id: 'sha512', name: 'SHA-512', bits: 512, std: 'FIPS 180-4', status: 'ok', note: '64-bit words; faster than SHA-256 on 64-bit CPUs, slower in wasm32.' },
  { id: 'sha3-256', name: 'SHA3-256', bits: 256, std: 'FIPS 202', status: 'ok', note: 'Keccak sponge; structurally different from SHA-2 and immune to length extension.' },
];

const toBytes = (s: string, fmt: Fmt) => (fmt === 'hex' ? hexToBytes(s) : new TextEncoder().encode(s));

function flipBit(bytes: Uint8Array, bit: number): Uint8Array {
  const out = new Uint8Array(bytes);
  if (out.length) out[Math.floor(bit / 8) % out.length] ^= 1 << (bit % 8);
  return out;
}

function HexDiff({ a, b }: { a: string; b: string }) {
  return (
    <div className="hexdiff">
      {a.split('').map((ch, i) => (ch === b[i] ? ch : <span key={i} className="d">{ch}</span>))}
    </div>
  );
}

export default function HashingPage() {
  const state = useWasm();
  const ready = state === 'ready';
  const H = wasm.Hasher;

  const [fmt, setFmt] = useState<Fmt>('text');
  const [msg, setMsg] = useState('The quick brown fox jumps over the lazy dog');
  const bytes = attempt(() => toBytes(msg, fmt));
  const digests = ready && bytes.ok ? ALGS.map((a) => ({ ...a, hex: H.digest(a.id, bytes.value) })) : [];

  // Avalanche
  const [avAlg, setAvAlg] = useState('sha256');
  const [bit, setBit] = useState(0);
  const flipped = bytes.ok ? flipBit(bytes.value, bit) : null;
  const avA = ready && bytes.ok ? H.digest(avAlg, bytes.value) : '';
  const avB = ready && flipped ? H.digest(avAlg, flipped) : '';
  const avBits = avA && avB ? hammingDistanceHex(avA, avB) : 0;

  // HMAC
  const [macAlg, setMacAlg] = useState('sha256');
  const [macKey, setMacKey] = useState('Jefe');
  const [macMsg, setMacMsg] = useState('what do ya want for nothing?');
  const mac = ready ? attempt(() => H.hmac(macAlg, new TextEncoder().encode(macKey), new TextEncoder().encode(macMsg))) : null;

  // HIBP k-anonymity
  const [pw, setPw] = useState('password123');
  const [hibp, setHibp] = useState<{ kind: 'ok' | 'danger' | 'warn'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const pwSha1 = ready ? H.digest('sha1', new TextEncoder().encode(pw)).toUpperCase() : '';
  const prefix = pwSha1.slice(0, 5), suffix = pwSha1.slice(5);

  const checkHibp = async () => {
    setBusy(true);
    try {
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const hit = text.split('\n').map((l) => l.trim().split(':')).find(([s]) => s === suffix);
      const count = hit ? Number(hit[1]) : 0;
      setHibp(count > 0
        ? { kind: 'danger', text: `Found: this password appears ${count.toLocaleString()} times in known breaches.` }
        : { kind: 'ok', text: `Not found among the ${text.split('\n').length.toLocaleString()} hashes returned for prefix ${prefix} (padded response).` });
    } catch (e) {
      setHibp({ kind: 'warn', text: `Lookup failed: ${errorMessage(e)}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page kicker="§3 · Hash functions & MACs" title="Hash functions and message authentication"
      lede="A cryptographic hash maps arbitrary input to a fixed-size digest and must be preimage-, second-preimage- and collision-resistant. Keyed with HMAC it becomes an authenticator; on its own it authenticates nothing.">
      <Status state={state} />

      <Panel title="Message digests" refs={['FIPS 180-4', 'FIPS 202', 'RFC 1321']}
        action={<Segmented label="Input format" value={fmt} onChange={setFmt} disabled={!ready} options={[{ value: 'text', label: 'Text' }, { value: 'hex', label: 'Hex' }]} />}>
        <Field label="Message" hint={bytes.ok ? `${bytes.value.length} bytes` : 'invalid hex'}>
          {(id) => <TextArea id={id} mono={fmt === 'hex'} rows={3} value={msg} onChange={(e) => setMsg(e.target.value)} invalid={!bytes.ok} disabled={!ready} />}
        </Field>
        <ErrorText error={bytes.ok ? null : bytes.error} />
        <hr className="divider" />
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Algorithm</th><th>Digest</th><th>Size</th><th>Status</th></tr></thead>
            <tbody>
              {digests.map((d) => (
                <tr key={d.id}>
                  <td style={{ minWidth: '16ch' }}><strong>{d.name}</strong><div className="faint small">{d.std}</div></td>
                  <td className="mono">{d.hex}<div className="faint small" style={{ fontFamily: 'var(--font-sans)', marginTop: '0.25rem' }}>{d.note}</div></td>
                  <td className="mono">{d.bits}</td>
                  <td><Tag tone={d.status === 'ok' ? 'ok' : 'danger'}>{d.status}</Tag></td>
                </tr>
              ))}
              {!digests.length && <tr><td colSpan={4} className="faint">—</td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Avalanche effect" refs={['strict avalanche criterion']}>
        <p className="muted small">
          Flipping a single input bit should change every output bit with probability ½. The second message below is the
          first with one bit inverted; differing hex digits are highlighted.
        </p>
        <div className="grid-2">
          <Field label="Algorithm">{(id) => (
            <Select id={id} value={avAlg} onChange={(e) => setAvAlg(e.target.value)} disabled={!ready}>
              {ALGS.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </Select>
          )}</Field>
          <Field label="Bit to flip" hint={bytes.ok && bytes.value.length ? `byte ${Math.floor(bit / 8) % bytes.value.length}, bit ${bit % 8}` : ''}>
            {(id) => <TextInput id={id} type="number" min={0} max={bytes.ok ? bytes.value.length * 8 - 1 : 0} value={bit} onChange={(e) => setBit(Math.max(0, Number(e.target.value) || 0))} disabled={!ready} />}
          </Field>
        </div>
        <hr className="divider" />
        <div className="label"><span>H(m)</span></div>
        <div className="hexdiff">{avA || '—'}</div>
        <div className="label" style={{ marginTop: '0.5rem' }}><span>H(m with one bit flipped)</span></div>
        {avB ? <HexDiff a={avB} b={avA} /> : <div className="hexdiff">—</div>}
        <div className="grid-3" style={{ marginTop: '1rem' }}>
          <Stat label="Bits changed" value={avA ? `${avBits} / ${avA.length * 4}` : '—'} tone="accent" />
          <Stat label="Fraction" value={avA ? `${((avBits / (avA.length * 4)) * 100).toFixed(1)}%` : '—'} sub="ideal ≈ 50%" />
          <Stat label="Input bits changed" value={1} />
        </div>
      </Panel>

      <div className="grid-2">
        <Panel title="HMAC" refs={['RFC 2104', 'FIPS 198-1']}>
          <div className="stack">
            <Field label="Hash">{(id) => (
              <Select id={id} value={macAlg} onChange={(e) => setMacAlg(e.target.value)} disabled={!ready}>
                {ALGS.map((a) => <option key={a.id} value={a.id}>HMAC-{a.name}</option>)}
              </Select>
            )}</Field>
            <Field label="Key">{(id) => <TextInput id={id} mono value={macKey} onChange={(e) => setMacKey(e.target.value)} disabled={!ready} />}</Field>
            <Field label="Message">{(id) => <TextInput id={id} value={macMsg} onChange={(e) => setMacMsg(e.target.value)} disabled={!ready} />}</Field>
            <Output label="Tag" value={mac?.ok ? mac.value : ''} tone="accent" ariaLabel="HMAC tag" />
            <ErrorText error={mac && !mac.ok ? mac.error : null} />
          </div>
          <Note title="Construction">
            HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m)). The naive H(K ‖ m) is insecure for Merkle–Damgård hashes (MD5, SHA-1, SHA-2):
            knowing H(K ‖ m) and |K| lets anyone compute H(K ‖ m ‖ pad ‖ m′) — a length-extension attack. The defaults reproduce RFC 4231 test case 2.
          </Note>
        </Panel>

        <Panel title="k-anonymity password lookup" refs={['Have I Been Pwned']}>
          <div className="stack">
            <Field label="Password">{(id) => <TextInput id={id} mono value={pw} onChange={(e) => { setPw(e.target.value); setHibp(null); }} disabled={!ready} />}</Field>
            <div className="label"><span>SHA-1</span><span className="hint">prefix sent · suffix kept local</span></div>
            <div className="hexdiff" aria-label="SHA-1 of the password"><span className="d">{prefix}</span>{suffix}</div>
            <div className="row">
              <Button variant="primary" onClick={checkHibp} disabled={!ready || busy}>{busy ? 'Querying…' : `Query range ${prefix || '…'}`}</Button>
              <span className="status">GET api.pwnedpasswords.com/range/{prefix || '…'}</span>
            </div>
            {hibp && <Callout tone={hibp.kind}>{hibp.text}</Callout>}
          </div>
          <Note title="Protocol">
            Only the first 5 hex digits (20 bits) of the SHA-1 digest leave the browser. The server returns every suffix sharing that prefix
            (≈ 800–1,000 of them, padded to hide the count) and the match is made locally, so the service cannot learn which password was checked.
            This is the one network request the application can make.
          </Note>
        </Panel>
      </div>

      <Note title="Not the same “hashing”">
        This section is about <em>cryptographic</em> hash functions, where the design goals are preimage and collision resistance. The other
        meaning — hash <em>tables</em>, with chaining, open addressing and rehashing — is a data-structures topic with entirely different goals
        (speed and load factor, not adversarial resistance), and a good hash table function such as FNV or MurmurHash would be a catastrophic
        digest. Those are visualised step by step in{' '}
        <a href="https://stepwise.nirbhay.dev" target="_blank" rel="noreferrer">Stepwise</a>, a companion site for algorithms and data structures.
      </Note>
    </Page>
  );
}
