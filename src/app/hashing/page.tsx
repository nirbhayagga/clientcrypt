'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { hexToBytes, hammingDistanceHex } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Range, Output, Stat, Status, ErrorText, Callout, Tag, Button } from '@/components/ui';

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

        <Panel title="Querying without revealing the query" refs={['k-anonymity']}>
          <p className="muted small">
            Suppose you want to know whether a password appears in a corpus of two billion breached hashes that lives on
            someone else&apos;s server. Sending the password is out of the question; sending its full hash is nearly as bad,
            since the corpus <em>is</em> a list of hashes, so the server would learn exactly which one you asked about.
          </p>
          <p className="muted small">
            The k-anonymity trick is to send only a <strong>prefix</strong> — the first 5 hex digits, 20 bits — and ask for
            every hash that starts with it. There are around two thousand of those, so the server learns only that you asked
            about one of a crowd of two thousand (the “k”), and the matching happens on your machine. Padding the reply to a
            fixed size hides even the crowd&apos;s exact size. It is a general technique, not a password one: the same shape
            protects DNS-over-HTTPS resolvers, certificate-revocation checks and safe-browsing lookups.
          </p>
          <Note title="Why there is no live demo">
            This site makes no network requests at all — open the network tab and check — and that guarantee is worth more
            here than one lookup. The offline dictionary check in §7 covers the practical question the lookup would answer.
          </Note>
        </Panel>
      </div>

      <Sha256InternalsPanel ready={ready} />

      <LengthExtensionPanel ready={ready} />

      <MerklePanel ready={ready} />

      <LamportPanel ready={ready} />

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

/* Merkle trees ----------------------------------------------------------------- */

interface MerkleTree { levels: string[][]; root: string; leaves: number; proof_length: number }
interface ProofStep { sibling: string; right: boolean }
interface MerkleProof { index: number; leaf: string; leaf_hash: string; steps: ProofStep[]; root: string }
interface MerkleVerifyResult { computed_root: string; matches: boolean; trail: string[] }

const MERKLE_DEFAULT = ['alice pays bob 5', 'bob pays carol 3', 'carol pays dan 8', 'dan pays erin 2', 'erin pays alice 1', 'frank pays grace 13'].join('\n');

function MerklePanel({ ready }: { ready: boolean }) {
  const [records, setRecords] = useState(MERKLE_DEFAULT);
  const [index, setIndex] = useState(2);
  const [claim, setClaim] = useState<string | null>(null);

  const lines = records.split('\n').filter((l) => l.trim() !== '');
  const idx = Math.min(index, Math.max(0, lines.length - 1));
  const tree = ready ? attempt(() => wasm.Merkle.tree(records) as MerkleTree) : null;
  const proof = ready ? attempt(() => wasm.Merkle.proof(records, idx) as MerkleProof) : null;
  const claimed = claim ?? (lines[idx] ?? '');
  const verify = ready && tree?.ok && proof?.ok
    ? attempt(() => wasm.Merkle.verify(claimed, proof.value.steps, tree.value.root) as MerkleVerifyResult)
    : null;

  return (
    <Panel title="Merkle trees: one hash for a million records" refs={['RFC 6962 hashing']}>
      <p className="muted small">
        {'Hash each record (with a 00 prefix), then hash pairs upward (with 01) until one '}<strong>root</strong>{' remains. '}
        {'That single digest now commits to every record — and any one of them can be proved present with just the '}
        {'log₂(n) sibling hashes along its path. Certificate Transparency logs, Bitcoin block headers and software-update '}
        {'transparency all hand out exactly this proof so verifiers never need the whole data set.'}
      </p>
      <Field label="Records — one per line" hint="up to 64">{(id) => (
        <TextArea id={id} mono rows={4} value={records} onChange={(e) => { setRecords(e.target.value); setClaim(null); }} disabled={!ready} />
      )}</Field>
      <ErrorText error={tree && !tree.ok ? tree.error : null} />
      {tree?.ok && (
        <>
          <div style={{ marginTop: '0.5rem', overflowX: 'auto' }}>
            {[...tree.value.levels].reverse().map((level, li) => (
              <div key={li} className="mono small" style={{ display: 'flex', gap: '0.6rem', justifyContent: 'center', padding: '0.15rem 0' }}>
                {level.map((h, i) => {
                  const isRoot = li === 0;
                  return <span key={i} style={{ color: isRoot ? 'var(--accent)' : undefined }} className={isRoot ? '' : 'muted'}>{h.slice(0, 8)}</span>;
                })}
              </div>
            ))}
          </div>
          <div style={{ marginTop: '0.5rem' }}>
            <Output label="Merkle root" value={tree.value.root} tone="accent" ariaLabel="Merkle root" />
          </div>
          <hr className="divider" />
          <div className="grid-2">
            <Field label="Prove this record">{(id) => (
              <Select id={id} value={idx} onChange={(e) => { setIndex(Number(e.target.value)); setClaim(null); }} disabled={!ready}>
                {lines.map((l, i) => <option key={i} value={i}>{`#${i} — ${l.slice(0, 40)}`}</option>)}
              </Select>
            )}</Field>
            <Field label="Record as claimed to the verifier" hint="edit it to watch the proof fail">{(id) => (
              <TextInput id={id} mono value={claimed} onChange={(e) => setClaim(e.target.value)} disabled={!ready} />
            )}</Field>
          </div>
          {proof?.ok && (
            <div className="stack" style={{ marginTop: '0.5rem' }}>
              <Output label={`Inclusion proof — ${proof.value.steps.length} sibling hash${proof.value.steps.length === 1 ? '' : 'es'} instead of ${tree.value.leaves} records`}
                value={proof.value.steps.map((st, i) => `${i + 1}. ${st.right ? 'right' : 'left '} ${st.sibling}`).join('\n')} copy={false} scroll />
            </div>
          )}
          {verify?.ok && (
            <div className="grid-2" style={{ marginTop: '0.75rem' }}>
              <Stat label="Recomputed root" value={verify.value.computed_root.slice(0, 16) + '…'} sub="leaf hash folded with each sibling" />
              <Stat label="Proof verdict" value={verify.value.matches ? 'included' : 'NOT in the tree'} tone={verify.value.matches ? 'ok' : 'danger'}
                sub={verify.value.matches ? 'the claimed record is committed by the root' : 'one changed character moves every hash on the path'} />
            </div>
          )}
        </>
      )}
      <Note title="Why the 00/01 prefixes matter">
        Without domain separation a 64-byte “record” equal to two concatenated hashes would collide with an interior node,
        letting an attacker prove a record that was never logged (CVE-2012-2459 hit Bitcoin over exactly this class of
        confusion). Prefixing leaves with 00 and nodes with 01 — as Certificate Transparency specifies — makes the two
        hash domains disjoint. The crate&apos;s tests pin this property.
      </Note>
    </Panel>
  );
}

/* Lamport one-time signatures --------------------------------------------------- */

interface LamportKey { secret: [string, string][]; public: [string, string][] }
interface LamportSig { message: string; bits: number[]; reveal: string[] }
interface LamportVerifyResult { bits: number[]; bit_ok: boolean[]; verified: boolean }
interface LamportForgeryResult {
  free_positions: number[]; forgeable_digests: number; forged_message: string | null;
  forged_reveal: string[]; attempts: number; verified: boolean;
}

function LamportPanel({ ready }: { ready: boolean }) {
  const [key, setKey] = useState<LamportKey | null>(null);
  const [msg1, setMsg1] = useState('pay Alice 5');
  const [msg2, setMsg2] = useState('pay Bob 999');
  const [prefix, setPrefix] = useState('pay Mallory ');
  const [sig1, setSig1] = useState<LamportSig | null>(null);
  const [sig2, setSig2] = useState<LamportSig | null>(null);
  const [forgery, setForgery] = useState<LamportForgeryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const flat = (pairs: [string, string][]) => pairs.flat();
  const keygen = () => {
    const r = attempt(() => wasm.Lamport.keygen() as LamportKey);
    if (r.ok) { setKey(r.value); setSig1(null); setSig2(null); setForgery(null); setError(null); } else setError(r.error);
  };
  const sign = (msg: string, set: (s: LamportSig) => void) => {
    if (!key) return;
    const r = attempt(() => wasm.Lamport.sign(flat(key.secret), msg) as LamportSig);
    if (r.ok) { set(r.value); setForgery(null); setError(null); } else setError(r.error);
  };
  const forge = () => {
    if (!sig1 || !sig2) return;
    const r = attempt(() => wasm.Lamport.forge(sig1.message, sig1.reveal, sig2.message, sig2.reveal, prefix) as LamportForgeryResult);
    if (r.ok) { setForgery(r.value); setError(null); } else setError(r.error);
  };

  const check = (msg: string, reveal: string[]) => key
    ? attempt(() => wasm.Lamport.verify(flat(key.public), msg, reveal) as LamportVerifyResult)
    : null;
  const v1 = sig1 ? check(sig1.message, sig1.reveal) : null;
  const vForged = forgery?.forged_message ? check(forgery.forged_message, forgery.forged_reveal) : null;

  return (
    <Panel title="Hash-based signatures — and why they are one-time" refs={['Lamport 1979']}
      action={<Button variant="primary" onClick={keygen} disabled={!ready}>Generate a one-time key</Button>}>
      <p className="muted small">
        {'A signature scheme built from nothing but SHA-256. For each bit of the message digest the signer keeps two random '}
        {'secrets and publishes their hashes; signing reveals, per bit, the secret on that bit’s side. Forging means finding '}
        {'a preimage — no factoring, no curves, which is why hash-based designs (SPHINCS+, standardised as SLH-DSA) are the '}
        {'conservative post-quantum choice: Grover halves the exponent and nothing else is known to bite. Toy-sized here: '}
        {'16 digest bits instead of 256.'}
      </p>
      {key && (
        <>
          <div className="stack">
            <Output label="Public key — H(secret) per bit and side (truncated)" copy={false} scroll
              value={key.public.map((p, i) => `bit ${String(i).padStart(2)}: 0→${p[0].slice(0, 12)}… 1→${p[1].slice(0, 12)}…`).join('\n')} />
          </div>
          <hr className="divider" />
          <div className="grid-2">
            <Field label="Message 1">{(id) => <TextInput id={id} mono value={msg1} onChange={(e) => setMsg1(e.target.value)} disabled={!ready} />}</Field>
            <div style={{ alignSelf: 'flex-end' }}><Button onClick={() => sign(msg1, setSig1)} disabled={!ready}>Sign message 1</Button></div>
          </div>
          {sig1 && v1?.ok && (
            <div className="stack" style={{ marginTop: '0.5rem' }}>
              <Output label={`Digest bits ${sig1.bits.join('')} — the signature reveals one secret per bit`} copy={false} scroll
                value={sig1.reveal.map((r, i) => `bit ${String(i).padStart(2)} = ${sig1.bits[i]}: ${r.slice(0, 12)}…`).join('\n')} />
              <Stat label="Signature verifies" value={v1.value.verified ? 'yes' : 'no'} tone={v1.value.verified ? 'ok' : 'danger'}
                sub="verifier hashes each revealed secret and compares to the public key" />
            </div>
          )}
          {sig1 && (
            <>
              <hr className="divider" />
              <div className="grid-2">
                <Field label="Message 2 — breaking the one-time rule" hint="same key, second signature">{(id) => (
                  <TextInput id={id} mono value={msg2} onChange={(e) => setMsg2(e.target.value)} disabled={!ready} />
                )}</Field>
                <div style={{ alignSelf: 'flex-end' }}><Button onClick={() => sign(msg2, setSig2)} disabled={!ready}>Sign message 2</Button></div>
              </div>
            </>
          )}
          {sig1 && sig2 && (
            <>
              <div className="grid-2" style={{ marginTop: '0.5rem' }}>
                <Field label="Attacker's message prefix" hint="the forger appends a counter">{(id) => (
                  <TextInput id={id} mono value={prefix} onChange={(e) => setPrefix(e.target.value)} disabled={!ready} />
                )}</Field>
                <div style={{ alignSelf: 'flex-end' }}><Button variant="primary" onClick={forge} disabled={!ready}>Forge a signature (no key needed)</Button></div>
              </div>
              {forgery && (
                <div style={{ marginTop: '0.75rem' }}>
                  <div className="grid-3">
                    <Stat label="Positions with both secrets" value={forgery.free_positions.length} sub={`bits where the two digests differ`} />
                    <Stat label="Digests now signable" value={forgery.forgeable_digests.toLocaleString()} sub={`of ${(2 ** 16).toLocaleString()} possible`} />
                    <Stat label="Search attempts" value={forgery.attempts.toLocaleString()} sub="counters tried against the revealed bits" />
                  </div>
                  {forgery.forged_message && vForged?.ok ? (
                    <div className="stack" style={{ marginTop: '0.75rem' }}>
                      <Output label="Forged message — never signed by the key holder" value={forgery.forged_message} tone="danger" ariaLabel="Forged Lamport message" />
                      <Stat label="Forged signature verifies against the real public key" value={vForged.value.verified ? 'yes' : 'no'}
                        tone={vForged.value.verified ? 'danger' : 'ok'} sub="assembled purely from the two published signatures" />
                    </div>
                  ) : (
                    <p className="muted small" style={{ marginTop: '0.5rem' }}>No forgeable message found in the search budget — try a different prefix.</p>
                  )}
                </div>
              )}
            </>
          )}
        </>
      )}
      <ErrorText error={error} />
      <Note title="From one-time to many">
        One key, one signature — that is the entire contract, and the forgery above is what its breach costs. Real systems
        stack one-time keys into a Merkle tree (the panel above signs the tree root, in effect) so one root authenticates
        thousands of one-time keys: that is XMSS, and with more machinery, SPHINCS+. Bitcoin&apos;s advice never to reuse an
        address echoes the same instinct.
      </Note>
    </Panel>
  );
}
