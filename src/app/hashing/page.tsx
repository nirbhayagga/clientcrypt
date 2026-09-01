'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt, errorMessage } from '@/lib/wasm';
import { hexToBytes, hammingDistanceHex } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Range, Output, Stat, Status, ErrorText, Button, Callout, Tag } from '@/components/ui';

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

interface Round { index: number; w: string; k: string; t1: string; t2: string; state: string[] }
interface Sha256Trace {
  message_len: number; padded_len: number; block_count: number; block_index: number;
  block_hex: string; padding_hex: string; schedule: string[]; rounds: Round[];
  state_in: string[]; state_out: string[]; digest: string;
}
interface LengthExtension {
  original_digest: string; recovered_state: string[]; glue_padding_hex: string;
  forged_message_hex: string; forged_digest: string; genuine_digest: string; attack_succeeded: boolean;
}

const LETTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

/** SHA-256's compression function, one block and one round at a time. */
function Sha256InternalsPanel({ ready }: { ready: boolean }) {
  const [msg, setMsg] = useState('abc');
  const [block, setBlock] = useState(0);
  const [round, setRound] = useState(0);
  const t = ready ? attempt(() => wasm.HashInternals.sha256_trace(new TextEncoder().encode(msg), block) as Sha256Trace) : null;
  const trace = t?.ok ? t.value : null;
  const r = trace?.rounds[Math.min(round, 63)];
  const prev = round > 0 ? trace?.rounds[round - 1] : null;
  const before = prev ? prev.state : trace?.state_in;

  return (
    <Panel title="Inside SHA-256" refs={['FIPS 180-4 §6.2']}
      action={trace && <Tag>{trace.block_count} block{trace.block_count === 1 ? '' : 's'} · {trace.padded_len} bytes padded</Tag>}>
      <p className="muted small">
        SHA-256 pads the message to a multiple of 64 bytes, then folds each block into a 256-bit state through 64 rounds. Each
        round mixes in one word of the message schedule and one of the constants K, which are the fractional parts of the cube
        roots of the first 64 primes — chosen so nobody can claim a hidden structure.
      </p>
      <div className="grid-2">
        <Field label="Message" hint={trace ? `${trace.message_len} bytes` : ''}>
          {(id) => <TextInput id={id} mono value={msg} onChange={(e) => { setMsg(e.target.value); setBlock(0); }} disabled={!ready} />}
        </Field>
        <Field label="Block" hint={trace ? `0 – ${trace.block_count - 1}` : ''}>
          {(id) => (
            <Select id={id} value={block} onChange={(e) => setBlock(Number(e.target.value))} disabled={!ready || !trace}>
              {Array.from({ length: trace?.block_count ?? 1 }, (_, i) => <option key={i} value={i}>block {i}</option>)}
            </Select>
          )}
        </Field>
      </div>
      <ErrorText error={t && !t.ok ? t.error : null} />
      {trace && (
        <>
          <hr className="divider" />
          <div className="label"><span>Padded block (64 bytes)</span><span className="hint">message · padding</span></div>
          <div className="hexdiff" style={{ marginTop: '0.35rem' }}>
            {trace.block_hex.slice(0, Math.max(0, (trace.message_len - trace.block_index * 64) * 2))}
            <span className="d">{trace.block_hex.slice(Math.max(0, (trace.message_len - trace.block_index * 64) * 2))}</span>
          </div>
          <p className="faint small" style={{ marginTop: '0.4rem' }}>
            Padding is a single 0x80 byte, zeros, then the message length in bits as a 64-bit big-endian integer — so two
            different messages can never share a padded form.
          </p>

          <hr className="divider" />
          <div className="label"><span>Message schedule W[0…63]</span><span className="hint">first 16 words are the block; the rest are derived</span></div>
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(5.5rem, 1fr))', gap: '0.25rem', marginTop: '0.5rem' }}>
            {trace.schedule.map((w, i) => (
              <div key={i} className="mono" style={{
                fontSize: '0.68rem', padding: '0.15rem 0.3rem', borderRadius: '3px',
                background: i === round ? 'var(--accent-dim)' : 'var(--bg-inset)',
                border: `1px solid ${i === round ? 'var(--accent-border)' : 'var(--border)'}`,
                color: i < 16 ? 'var(--fg)' : 'var(--fg-muted)',
              }}>{w}</div>
            ))}
          </div>

          <hr className="divider" />
          <Range label={`Round ${round} of 63`} min={0} max={63} value={round} onChange={setRound} disabled={!ready} format={(v) => `W[${v}] = ${trace.schedule[v]}`} />
          {r && before && (
            <div className="table-wrap" style={{ marginTop: '0.75rem' }}>
              <table className="table">
                <thead><tr><th>Word</th>{LETTERS.map((l) => <th key={l}>{l}</th>)}</tr></thead>
                <tbody>
                  <tr><td className="muted">before</td>{before.map((v, i) => <td key={i} className="mono">{v}</td>)}</tr>
                  <tr><td className="muted">after</td>{r.state.map((v, i) => (
                    <td key={i} className="mono" style={before[i] !== v ? { color: 'var(--accent)' } : undefined}>{v}</td>
                  ))}</tr>
                </tbody>
              </table>
            </div>
          )}
          {r && (
            <p className="muted small" style={{ marginTop: '0.75rem' }}>
              T₁ = h + Σ₁(e) + Ch(e,f,g) + K[{round}] + W[{round}] = <span className="mono">{r.t1}</span> ·
              T₂ = Σ₀(a) + Maj(a,b,c) = <span className="mono">{r.t2}</span>.
              Every register shifts one place down; only <em>a</em> and <em>e</em> get new values. After 64 rounds the result is
              added to the incoming state — that addition is what makes the round function irreversible.
            </p>
          )}
          <div className="grid-2" style={{ marginTop: '1rem' }}>
            <Output label="State entering this block" value={trace.state_in.join(' ')} copy={false} />
            <Output label="State leaving this block" value={trace.state_out.join(' ')} tone={trace.block_index === trace.block_count - 1 ? 'accent' : undefined}
              copy={false} />
          </div>
          {trace.block_index === trace.block_count - 1 && (
            <p className="faint small" style={{ marginTop: '0.5rem' }}>
              This is the last block, so the output state concatenated <span className="mono">{trace.digest}</span> is the digest.
            </p>
          )}
        </>
      )}
    </Panel>
  );
}

/** The length extension attack on H(secret ‖ message). */
function LengthExtensionPanel({ ready }: { ready: boolean }) {
  const [secret, setSecret] = useState('super-secret-key');
  const [message, setMessage] = useState('user=alice&role=user');
  const [suffix, setSuffix] = useState('&role=admin');
  const [guess, setGuess] = useState(16);
  const known = ready ? attempt(() => wasm.HashInternals.naive_keyed_hash(new TextEncoder().encode(secret), new TextEncoder().encode(message))) : null;
  const att = ready && known?.ok ? attempt(() => wasm.HashInternals.length_extension(
    known.value, guess, new TextEncoder().encode(message), new TextEncoder().encode(suffix), new TextEncoder().encode(secret),
  ) as LengthExtension) : null;
  const a = att?.ok ? att.value : null;

  return (
    <Panel title="Length extension: why H(key ‖ message) is not a MAC" refs={['Merkle–Damgård']}>
      <p className="muted small">
        {'A SHA-256 digest is not a summary of the message — it '}<em>is</em>
        {' the algorithm’s internal state when it ran out of input. Anyone holding a digest can load that state back in and keep hashing. So given only H(secret ‖ message) and the length of the secret, an attacker can append data and produce a valid digest for the extended message, without ever learning the secret.'}
      </p>
      <div className="grid-3">
        <Field label="Secret (server only)">{(id) => <TextInput id={id} mono value={secret} onChange={(e) => { setSecret(e.target.value); setGuess(e.target.value.length); }} disabled={!ready} />}</Field>
        <Field label="Message (public)">{(id) => <TextInput id={id} mono value={message} onChange={(e) => setMessage(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Appended by attacker">{(id) => <TextInput id={id} mono value={suffix} onChange={(e) => setSuffix(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <div style={{ marginTop: '0.75rem' }}>
        <Range label="Attacker's guess at the secret length" min={0} max={64} value={guess} onChange={setGuess} disabled={!ready}
          format={(v) => `${v} bytes${v === secret.length ? ' — correct' : ''}`} />
      </div>
      <ErrorText error={att && !att.ok ? att.error : null} />
      {a && (
        <>
          <hr className="divider" />
          <div className="stack">
            <Output label="What the attacker starts with: H(secret ‖ message)" value={a.original_digest} copy={false} />
            <Output label="The same 32 bytes read back as SHA-256's eight state words" value={a.recovered_state.join(' ')} copy={false} />
            <Output label="Glue padding the attacker must insert (the original message's padding)" value={a.glue_padding_hex} copy={false} scroll />
            <Output label="Forged digest for message ‖ padding ‖ suffix" value={a.forged_digest} tone={a.attack_succeeded ? 'danger' : undefined} copy={false} />
            <Output label="What the secret holder actually computes for that same input" value={a.genuine_digest} copy={false} />
          </div>
          <div style={{ marginTop: '1rem' }}>
            {a.attack_succeeded
              ? <Callout tone="danger">Forged. The two digests match, so the server accepts a message the attacker extended — including the appended <span className="mono">{suffix}</span> — without knowing the secret.</Callout>
              : <Callout tone="ok">The guessed secret length is wrong, so the glue padding is wrong and the forgery fails. An attacker simply tries every plausible length until one works.</Callout>}
          </div>
        </>
      )}
      <Note title="The fix">
        Use HMAC. Its outer hash means the tag you publish is not the internal state of the message hash, so there is nothing to
        resume — the panel above uses the same secret and message and cannot be extended. SHA-3 and BLAKE2 are also immune by
        construction, being sponges rather than Merkle–Damgård.
      </Note>
    </Panel>
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

      <Sha256InternalsPanel ready={ready} />

      <LengthExtensionPanel ready={ready} />

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
