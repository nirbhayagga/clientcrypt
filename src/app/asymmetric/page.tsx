'use client';

import { useEffect, useRef, useState } from 'react';
import { useWasm, wasm, attempt, errorMessage } from '@/lib/wasm';
import { hexToText } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, Select, Segmented, Output, Stat, Status, ErrorText, Button, Callout, Tag } from '@/components/ui';

interface RsaComponents { bits: number; n: string; e: string; d: string; p: string; q: string }
interface Group { name: string; bits: number; p_hex: string; g_hex: string; safe_prime: boolean }

const bitLength = (hex: string) => (hex ? BigInt(`0x${hex}`).toString(2).length : 0);
const fmtNum = (hex: string, base: 'hex' | 'dec') => (!hex ? '' : base === 'hex' ? hex : BigInt(`0x${hex}`).toString(10));

export default function AsymmetricPage() {
  const state = useWasm();
  const ready = state === 'ready';
  const A = wasm.AsymmetricCrypto;

  /* RSA ------------------------------------------------------------------ */
  const [rsaBits, setRsaBits] = useState(1024);
  const [busy, setBusy] = useState(false);
  const [keys, setKeys] = useState<{ sk: string; pk: string; comp: RsaComponents } | null>(null);
  const [rsaError, setRsaError] = useState<string | null>(null);
  const [encScheme, setEncScheme] = useState<'pkcs1v15' | 'oaep-sha256'>('oaep-sha256');
  const [msg, setMsg] = useState('Attack at dawn');
  const [ct, setCt] = useState('');
  const [pt, setPt] = useState('');
  const [sigScheme, setSigScheme] = useState<'pkcs1v15-sha256' | 'pss-sha256'>('pss-sha256');
  const [sigMsg, setSigMsg] = useState('I owe you £10');
  const [sig, setSig] = useState('');
  const [verdict, setVerdict] = useState<boolean | null>(null);
  const [base, setBase] = useState<'hex' | 'dec'>('hex');

  const generate = () => {
    setBusy(true); setRsaError(null); setCt(''); setPt(''); setSig(''); setVerdict(null);
    setTimeout(() => {
      try {
        const [sk, pk] = A.rsa_generate_keys(rsaBits);
        setKeys({ sk, pk, comp: A.rsa_key_components(sk) as RsaComponents });
      } catch (e) { setRsaError(errorMessage(e)); }
      setBusy(false);
    }, 30);
  };
  const maxLen = keys ? attempt(() => A.rsa_max_message_len(keys.pk, encScheme)) : null;
  const msgBytes = new TextEncoder().encode(msg);

  /* Finite-field DH -------------------------------------------------------- */
  const [groupChoice, setGroupChoice] = useState('ffdhe2048');
  const [group, setGroup] = useState<Group | null>(null);
  const [genBits, setGenBits] = useState(128);
  const [dhBusy, setDhBusy] = useState(false);
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [dhError, setDhError] = useState<string | null>(null);

  const loadGroup = (choice: string) => {
    setGroupChoice(choice); setDhError(null);
    if (choice === 'random') {
      setDhBusy(true);
      setTimeout(() => {
        try { const g = A.dh_generate_group(genBits) as Group; setGroup(g); setA(A.dh_private(g.p_hex)); setB(A.dh_private(g.p_hex)); } catch (e) { setDhError(errorMessage(e)); }
        setDhBusy(false);
      }, 30);
    } else {
      try { const g = A.dh_group(choice) as Group; setGroup(g); setA(A.dh_private(g.p_hex)); setB(A.dh_private(g.p_hex)); } catch (e) { setDhError(errorMessage(e)); }
    }
  };
  if (ready && !group && !dhBusy) loadGroup('ffdhe2048');

  const pubA = group && a ? attempt(() => A.dh_public(group.p_hex, group.g_hex, a)) : null;
  const pubB = group && b ? attempt(() => A.dh_public(group.p_hex, group.g_hex, b)) : null;
  const sharedA = group && pubB?.ok && a ? attempt(() => A.dh_shared(group.p_hex, pubB.value, a)) : null;
  const sharedB = group && pubA?.ok && b ? attempt(() => A.dh_shared(group.p_hex, pubA.value, b)) : null;
  const agree = sharedA?.ok && sharedB?.ok && sharedA.value === sharedB.value;

  /* X25519 ------------------------------------------------------------------ */
  const [ed, setEd] = useState<[string, string] | null>(null);
  const [edMsg, setEdMsg] = useState('Transfer £100 to Bob');
  const [edSig, setEdSig] = useState('');
  const [edVerdict, setEdVerdict] = useState<boolean | null>(null);
  if (ready && !ed) setEd(A.ed25519_keypair() as [string, string]);

  const [xa, setXa] = useState<[string, string] | null>(null);
  const [xb, setXb] = useState<[string, string] | null>(null);
  if (ready && !xa) { setXa(A.x25519_keypair() as [string, string]); setXb(A.x25519_keypair() as [string, string]); }
  const xsA = xa && xb ? attempt(() => A.x25519_shared(xa[0], xb[1])) : null;
  const xsB = xa && xb ? attempt(() => A.x25519_shared(xb[0], xa[1])) : null;

  return (
    <Page kicker="§6 · Public-key cryptography" title="RSA, Diffie–Hellman, X25519 and Ed25519"
      lede="Public-key schemes rest on problems believed hard in one direction: factoring n = pq for RSA, and discrete logarithms in a prime-order group for Diffie–Hellman. The private computations below use the same libraries as production software; only the parameter sizes are chosen for speed.">
      <Status state={state} />

      <Panel title="RSA key generation" refs={['RFC 8017', 'FIPS 186-5']}
        action={<Segmented label="Number base" value={base} onChange={setBase} options={[{ value: 'hex', label: 'hex' }, { value: 'dec', label: 'decimal' }]} />}>
        <div className="row" style={{ marginBottom: '1rem' }}>
          <Field label="Modulus size">{(id) => (
            <Select id={id} value={rsaBits} onChange={(e) => setRsaBits(Number(e.target.value))} disabled={!ready || busy}>
              <option value={1024}>1024 bits — demonstration only</option>
              <option value={2048}>2048 bits — current minimum</option>
              <option value={3072}>3072 bits — 128-bit security</option>
              <option value={4096}>4096 bits — slow to generate</option>
            </Select>
          )}</Field>
          <div style={{ alignSelf: 'flex-end' }}><Button variant="primary" onClick={generate} disabled={!ready || busy}>{busy ? 'Generating…' : 'Generate key pair'}</Button></div>
        </div>
        <ErrorText error={rsaError} />
        {keys ? (
          <>
            <div className="grid-2">
              <Output label="Public key (PKCS#1 PEM)" value={keys.pk} scroll />
              <Output label="Private key (PKCS#1 PEM)" value={keys.sk} scroll tone="danger" />
            </div>
            <hr className="divider" />
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Component</th><th>Bits</th><th>Value</th></tr></thead>
                <tbody>
                  {([['n = p · q (modulus)', keys.comp.n], ['e (public exponent)', keys.comp.e], ['d = e⁻¹ mod λ(n) (private exponent)', keys.comp.d], ['p', keys.comp.p], ['q', keys.comp.q]] as const).map(([label, v]) => (
                    <tr key={label}><td style={{ whiteSpace: 'nowrap' }}>{label}</td><td className="mono">{bitLength(v)}</td><td className="mono">{fmtNum(v, base)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted small" style={{ marginTop: '0.75rem' }}>
              Encryption is c = mᵉ mod n; decryption m = cᵈ mod n. Anyone who factors n recovers d. The public exponent 65537 = 2¹⁶ + 1 has only two set bits, making the public operation cheap.
            </p>
          </>
        ) : <p className="faint small">Generate a key pair to continue. Generation is probabilistic: two random primes of half the modulus size are found by Miller–Rabin testing.</p>}
      </Panel>

      <div className="grid-2">
        <Panel title="RSA encryption" refs={['PKCS#1 v1.5', 'OAEP']}>
          <div className="stack">
            <Field label="Padding scheme">{(id) => (
              <Select id={id} value={encScheme} onChange={(e) => { setEncScheme(e.target.value as typeof encScheme); setCt(''); setPt(''); }} disabled={!keys}>
                <option value="oaep-sha256">RSAES-OAEP with SHA-256 (recommended)</option>
                <option value="pkcs1v15">RSAES-PKCS1-v1_5 (legacy)</option>
              </Select>
            )}</Field>
            <Field label="Message" hint={maxLen?.ok ? `${msgBytes.length} / ${maxLen.value} bytes` : undefined}>
              {(id) => <TextInput id={id} value={msg} onChange={(e) => setMsg(e.target.value)} disabled={!keys} invalid={!!maxLen?.ok && msgBytes.length > maxLen.value} />}
            </Field>
            <div className="row">
              <Button variant="primary" disabled={!keys} onClick={() => { const r = attempt(() => A.rsa_encrypt(keys!.pk, encScheme, msgBytes)); setCt(r.ok ? r.value : ''); setPt(''); setRsaError(r.ok ? null : r.error); }}>Encrypt with public key</Button>
              <Button disabled={!ct} onClick={() => { const r = attempt(() => hexToText(Array.from(A.rsa_decrypt(keys!.sk, encScheme, ct)).map((x) => x.toString(16).padStart(2, '0')).join(''))); setPt(r.ok ? r.value : ''); setRsaError(r.ok ? null : r.error); }}>Decrypt with private key</Button>
            </div>
            <Output label={`Ciphertext (${ct.length / 2 || 0} bytes = modulus size)`} value={ct} scroll />
            {pt && <Callout tone="ok">Decrypted: “{pt}”</Callout>}
          </div>
          <Note title="Why padding matters">
            Textbook RSA is deterministic and malleable. PKCS#1 v1.5 adds random bytes but is vulnerable to Bleichenbacher&apos;s
            padding-oracle attack (1998); OAEP is provably secure under the RSA assumption. Both limit the message to well under the modulus size —
            in practice RSA encrypts a symmetric key, never the data.
          </Note>
        </Panel>

        <Panel title="RSA signatures" refs={['RSASSA-PKCS1-v1_5', 'RSASSA-PSS']}>
          <div className="stack">
            <Field label="Scheme">{(id) => (
              <Select id={id} value={sigScheme} onChange={(e) => { setSigScheme(e.target.value as typeof sigScheme); setSig(''); setVerdict(null); }} disabled={!keys}>
                <option value="pss-sha256">RSASSA-PSS with SHA-256 (recommended)</option>
                <option value="pkcs1v15-sha256">RSASSA-PKCS1-v1_5 with SHA-256</option>
              </Select>
            )}</Field>
            <Field label="Message">{(id) => <TextInput id={id} value={sigMsg} onChange={(e) => { setSigMsg(e.target.value); setVerdict(null); }} disabled={!keys} />}</Field>
            <div className="row">
              <Button variant="primary" disabled={!keys} onClick={() => { const r = attempt(() => A.rsa_sign(keys!.sk, sigScheme, new TextEncoder().encode(sigMsg))); setSig(r.ok ? r.value : ''); setVerdict(null); setRsaError(r.ok ? null : r.error); }}>Sign with private key</Button>
              <Button disabled={!sig} onClick={() => { const r = attempt(() => A.rsa_verify(keys!.pk, sigScheme, new TextEncoder().encode(sigMsg), sig)); setVerdict(r.ok ? r.value : false); }}>Verify with public key</Button>
            </div>
            <Output label="Signature" value={sig} scroll />
            {verdict !== null && (verdict ? <Callout tone="ok">Signature valid for the current message.</Callout> : <Callout tone="danger">Signature invalid — the message or signature has changed.</Callout>)}
          </div>
          <Note title="Sign, then edit">
            Sign the message, change one character, and verify again. PSS is randomised (a fresh salt each time), so two signatures of the same message differ; PKCS#1 v1.5 signatures are deterministic.
          </Note>
        </Panel>
      </div>

      <Panel title="Finite-field Diffie–Hellman" refs={['RFC 7919', 'RFC 2631']}
        action={group && <Tag tone={group.safe_prime ? 'ok' : 'danger'}>{group.bits}-bit safe prime · g = 2</Tag>}>
        <div className="row" style={{ marginBottom: '1rem' }}>
          <Field label="Group">{(id) => (
            <Select id={id} value={groupChoice} onChange={(e) => loadGroup(e.target.value)} disabled={!ready || dhBusy}>
              <option value="ffdhe2048">ffdhe2048 — TLS 1.3 named group (RFC 7919)</option>
              <option value="ffdhe3072">ffdhe3072 — RFC 7919</option>
              <option value="ffdhe4096">ffdhe4096 — RFC 7919</option>
              <option value="random">Generate a random safe prime (demonstration)</option>
            </Select>
          )}</Field>
          {groupChoice === 'random' && (
            <Field label="Bits">{(id) => (
              <Select id={id} value={genBits} onChange={(e) => setGenBits(Number(e.target.value))} disabled={dhBusy}>
                {[64, 96, 128, 192, 256].map((v) => <option key={v} value={v}>{v}</option>)}
              </Select>
            )}</Field>
          )}
          {groupChoice === 'random' && <div style={{ alignSelf: 'flex-end' }}><Button onClick={() => loadGroup('random')} disabled={dhBusy}>{dhBusy ? 'Searching…' : 'Generate'}</Button></div>}
        </div>
        <ErrorText error={dhError} />
        <Output label={`p (${group?.bits ?? 0} bits)`} value={group ? fmtNum(group.p_hex, base) : ''} scroll />
        <p className="muted small" style={{ marginTop: '0.5rem' }}>
          p = 2q + 1 with q prime, so g = 2 generates a subgroup of large prime order and small-subgroup attacks are impossible. The RFC 7919 primes are
          derived from the digits of e (a “nothing-up-my-sleeve” construction); the random option runs Miller–Rabin in WebAssembly.
        </p>
        <hr className="divider" />
        <div className="grid-2">
          {([['Alice', a, setA, pubA, sharedA, 'a', 'A = gᵃ mod p', 'Bᵃ mod p'], ['Bob', b, setB, pubB, sharedB, 'b', 'B = gᵇ mod p', 'Aᵇ mod p']] as const).map(([who, priv, setPriv, pub, shared, sym, pubLabel, sharedLabel]) => (
            <div key={who} className="stack">
              <h3 style={{ fontSize: '1rem' }}>{who}</h3>
              <Field label={`private ${sym} (secret)`} hint={<button type="button" className="btn btn-ghost btn-sm" onClick={() => group && setPriv(A.dh_private(group.p_hex))} disabled={!group}>random</button>}>
                {(id) => <TextInput id={id} mono value={priv} onChange={(e) => setPriv(e.target.value.trim())} disabled={!group} invalid={!!pub && !pub.ok} />}
              </Field>
              <Output label={`${pubLabel} (sent in clear)`} value={pub?.ok ? fmtNum(pub.value, base) : ''} scroll />
              <ErrorText error={pub && !pub.ok ? pub.error : shared && !shared.ok ? shared.error : null} />
              <Output label={`shared secret ${sharedLabel}`} value={shared?.ok ? fmtNum(shared.value, base) : ''} scroll tone="accent" />
            </div>
          ))}
        </div>
        {sharedA?.ok && sharedB?.ok && (agree
          ? <div style={{ marginTop: '1rem' }}><Callout tone="ok">Both parties hold the same secret gᵃᵇ mod p; an eavesdropper sees only p, g, A and B.</Callout></div>
          : <div style={{ marginTop: '1rem' }}><Callout tone="danger">Secrets differ.</Callout></div>)}
      </Panel>

      <Panel title="Ed25519 signatures" refs={['RFC 8032']}
        action={<Button size="sm" onClick={() => { setEd(A.ed25519_keypair() as [string, string]); setEdSig(''); setEdVerdict(null); }} disabled={!ready}>New key</Button>}>
        <p className="muted small">
          The signature scheme on the same curve, and the default for SSH keys, Git commit signing and modern certificates.
          Keys are 32 bytes and signatures 64 — against 256 and 256 bytes for a 2048-bit RSA key — and signing is
          deterministic: the per-signature nonce is derived by hashing the private key with the message, so there is no random
          value to leak. That single design choice removes the failure that cost Sony the PlayStation 3 signing key.
        </p>
        <div className="grid-2">
          <Output label="Private key (seed)" value={ed?.[0] ?? ''} tone="danger" />
          <Output label="Public key" value={ed?.[1] ?? ''} />
        </div>
        <div style={{ marginTop: '0.75rem' }}>
          <Field label="Message">{(id) => <TextInput id={id} value={edMsg} onChange={(e) => { setEdMsg(e.target.value); setEdVerdict(null); }} disabled={!ready} />}</Field>
        </div>
        <div className="row" style={{ marginTop: '0.75rem' }}>
          <Button variant="primary" disabled={!ed} onClick={() => { const r = attempt(() => A.ed25519_sign(ed![0], new TextEncoder().encode(edMsg))); setEdSig(r.ok ? r.value : ''); setEdVerdict(null); }}>Sign</Button>
          <Button disabled={!edSig} onClick={() => { const r = attempt(() => A.ed25519_verify(ed![1], new TextEncoder().encode(edMsg), edSig)); setEdVerdict(r.ok ? r.value : false); }}>Verify</Button>
        </div>
        <div style={{ marginTop: '0.75rem' }}>
          <Output label="Signature (64 bytes)" value={edSig} scroll />
        </div>
        {edVerdict !== null && (
          <div style={{ marginTop: '0.75rem' }}>
            {edVerdict ? <Callout tone="ok">Valid for this message under this public key.</Callout>
                       : <Callout tone="danger">Invalid — the message, signature or key does not match.</Callout>}
          </div>
        )}
        <Note title="Deterministic, and why that is safer">
          Sign the same message twice and you get identical bytes, unlike RSA-PSS or ECDSA. That is not a weakness: the nonce
          still varies between different messages because it is derived from the message itself. What it removes is any
          dependence on the quality of the random number generator at signing time — see §5.
        </Note>
      </Panel>

      <Panel title="X25519" refs={['RFC 7748']} action={<Button size="sm" onClick={() => { setXa(A.x25519_keypair() as [string, string]); setXb(A.x25519_keypair() as [string, string]); }} disabled={!ready}>New keys</Button>}>
        <p className="muted small">
          Elliptic-curve Diffie–Hellman on Curve25519: 32-byte keys, 128-bit security, and the default key exchange in TLS 1.3 and SSH. The private scalar is
          “clamped” (low three bits cleared, bit 254 set) so every key lies in the prime-order subgroup and the ladder runs in constant time.
        </p>
        <div className="grid-2">
          {([['Alice', xa, xsA], ['Bob', xb, xsB]] as const).map(([who, kp, shared]) => (
            <div key={who} className="stack">
              <h3 style={{ fontSize: '1rem' }}>{who}</h3>
              <Output label="private scalar" value={kp?.[0] ?? ''} tone="danger" />
              <Output label="public point u" value={kp?.[1] ?? ''} />
              <Output label="shared secret" value={shared?.ok ? shared.value : ''} tone="accent" />
            </div>
          ))}
        </div>
        {xsA?.ok && xsB?.ok && <div style={{ marginTop: '1rem' }}><Callout tone={xsA.value === xsB.value ? 'ok' : 'danger'}>{xsA.value === xsB.value ? 'Both sides derive the same 32-byte secret; TLS feeds it into HKDF (§8) rather than using it directly.' : 'Secrets differ.'}</Callout></div>}
      </Panel>

      <EcCurvePanel ready={ready} />
      <EcDhPanel ready={ready} />
    </Page>
  );
}

/* Elliptic curves, visibly ----------------------------------------------------- */

interface EcPoint { x: number; y: number }
interface EcSubgroup { multiples: EcPoint[]; order: number; curve_points: number }
interface EcScalarStep { bit: number; op: string; point: EcPoint | null }
interface EcScalarMult { result: EcPoint | null; steps: EcScalarStep[] }
interface EcDhResult {
  alice_public: EcPoint | null; bob_public: EcPoint | null;
  shared_alice: EcPoint | null; shared_bob: EcPoint | null;
  agree: boolean; dlog_found: number;
}

function CurvePlot({ p, pts, g, target }: { p: number; pts: EcPoint[]; g: EcPoint | null; target: EcPoint | null }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;
    const S = c.width;
    const scale = (S - 14) / Math.max(1, p - 1);
    const px = (v: number) => 7 + v * scale;
    const py = (v: number) => S - 7 - v * scale;
    ctx.fillStyle = '#090b0e';
    ctx.fillRect(0, 0, S, S);
    for (const pt of pts) {
      ctx.fillStyle = '#5b6472';
      ctx.beginPath();
      ctx.arc(px(pt.x), py(pt.y), 2.5, 0, 2 * Math.PI);
      ctx.fill();
    }
    if (g) {
      ctx.fillStyle = '#d9a441';
      ctx.beginPath();
      ctx.arc(px(g.x), py(g.y), 4, 0, 2 * Math.PI);
      ctx.fill();
    }
    if (target) {
      ctx.strokeStyle = '#d9a441';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(px(target.x), py(target.y), 7, 0, 2 * Math.PI);
      ctx.stroke();
    }
  }, [p, pts, g, target]);
  return (
    <div className="canvas-box">
      <canvas ref={ref} width={260} height={260} aria-label={`The ${pts.length} affine points of the elliptic curve`} />
      <div className="cap">{'every (x, y) with y² ≡ x³ + ax + b — filled dot: G, ring: kG'}</div>
    </div>
  );
}

function EcCurvePanel({ ready }: { ready: boolean }) {
  const [p, setP] = useState('17');
  const [a, setA] = useState('2');
  const [b, setB] = useState('2');
  const [gx, setGx] = useState('5');
  const [gy, setGy] = useState('1');
  const [k, setK] = useState('5');

  const num = (s: string) => Number(s.trim() || 'NaN');
  const pts = ready ? attempt(() => wasm.Ecc.points(num(p), num(a), num(b)) as EcPoint[]) : null;
  const sub = ready ? attempt(() => wasm.Ecc.subgroup(num(p), num(a), num(b), num(gx), num(gy)) as EcSubgroup) : null;
  const mult = ready ? attempt(() => wasm.Ecc.scalar_mult(num(p), num(a), num(b), num(gx), num(gy), num(k)) as EcScalarMult) : null;
  const error = [pts, sub, mult].find((r) => r && !r.ok);
  const kG = mult?.ok ? mult.value.result : null;

  return (
    <Panel title="Elliptic curves, visibly" refs={['toy curve over F_p']}>
      <p className="muted small">
        {'X25519 above treats the curve as a black box. This is the box: over a field of only '}{ready && pts?.ok ? String(num(p)) : 'p'}
        {' elements, the “curve” y² = x³ + ax + b is a scatter of points — and they form a group. Adding two points means '}
        {'drawing the line through them and reflecting the third intersection; adding a point to itself uses the tangent. '}
        {'Repeated addition is the one-way street: computing kG is fast (double-and-add, below), but recovering k from kG '}
        {'means walking the whole group. Here that walk is trivial; on Curve25519 it is 2¹²⁶ steps.'}
      </p>
      <div className="grid-3">
        <Field label="Prime p" hint="3–997">{(id) => <TextInput id={id} mono value={p} onChange={(e) => setP(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Curve a">{(id) => <TextInput id={id} mono value={a} onChange={(e) => setA(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Curve b">{(id) => <TextInput id={id} mono value={b} onChange={(e) => setB(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <div className="grid-3">
        <Field label="Generator G: x">{(id) => <TextInput id={id} mono value={gx} onChange={(e) => setGx(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Generator G: y">{(id) => <TextInput id={id} mono value={gy} onChange={(e) => setGy(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Scalar k" hint="compute kG">{(id) => <TextInput id={id} mono value={k} onChange={(e) => setK(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={error && !error.ok ? error.error : null} />
      {pts?.ok && sub?.ok && (
        <div className="grid-2" style={{ marginTop: '0.75rem', alignItems: 'start' }}>
          <CurvePlot p={num(p)} pts={pts.value} g={{ x: num(gx), y: num(gy) }} target={kG ?? null} />
          <div className="stack">
            <Stat label="Points on the curve" value={sub.value.curve_points} sub="including the point at infinity O" />
            <Stat label="Order of G" value={sub.value.order} sub="smallest k with kG = O" />
            <Stat label={`kG for k = ${num(k) || '—'}`} value={kG ? `(${kG.x}, ${kG.y})` : 'O (infinity)'} tone="accent" sub="ringed on the plot" />
          </div>
        </div>
      )}
      {mult?.ok && (
        <>
          <div className="label" style={{ margin: '0.75rem 0 0.4rem' }}><span>{'Double-and-add: k in binary, one step per bit'}</span></div>
          <div className="mono small" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem 1.2rem' }}>
            {mult.value.steps.map((st, i) => (
              <span key={i} className="muted">{`${i + 1}. ${st.op} → ${st.point ? `(${st.point.x}, ${st.point.y})` : 'O'}`}</span>
            ))}
          </div>
        </>
      )}
      <Note title="Why curves won">
        The best discrete-log attacks in ℤ_p* (index calculus) exploit the fact that integers factor; curve points do not,
        so the generic attack (Pollard&apos;s rho, √n steps) is the best known. That is why 256-bit curves match 3072-bit RSA/DH:
        no shortcut structure to exploit — assuming a curve with nothing up its sleeve, which is exactly the argument for
        Curve25519&apos;s fully-explained constants.
      </Note>
    </Panel>
  );
}

function EcDhPanel({ ready }: { ready: boolean }) {
  const [alice, setAlice] = useState('3');
  const [bob, setBob] = useState('7');

  const num = (s: string) => Number(s.trim() || 'NaN');
  const dh = ready ? attempt(() => wasm.Ecc.dh(17, 2, 2, 5, 1, num(alice), num(bob)) as EcDhResult) : null;
  const r = dh?.ok ? dh.value : null;
  const fmt = (pt: EcPoint | null) => (pt ? `(${pt.x}, ${pt.y})` : 'O');

  return (
    <Panel title="ECDH on the toy curve — and why the toy falls" refs={['y² = x³ + 2x + 2 over F₁₇, G = (5, 1)']}>
      <p className="muted small">
        {'The X25519 exchange above, replayed where you can check every step by hand: Alice sends aG, Bob sends bG, both '}
        {'compute abG. The eavesdropper sees aG and bG — and on this curve simply walks G, 2G, 3G… until Alice’s point '}
        {'appears, recovering her secret. The entire security difference between this and Curve25519 is the size of that walk.'}
      </p>
      <div className="grid-2">
        <Field label="Alice's secret a" hint="an integer ≥ 1">{(id) => <TextInput id={id} mono value={alice} onChange={(e) => setAlice(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Bob's secret b">{(id) => <TextInput id={id} mono value={bob} onChange={(e) => setBob(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <ErrorText error={dh && !dh.ok ? dh.error : null} />
      {r && (
        <>
          <div className="grid-2" style={{ marginTop: '0.5rem' }}>
            <Output label="Alice sends aG" value={fmt(r.alice_public)} copy={false} />
            <Output label="Bob sends bG" value={fmt(r.bob_public)} copy={false} />
            <Output label="Alice computes a·(bG)" value={fmt(r.shared_alice)} copy={false} tone="accent" ariaLabel="Toy ECDH shared secret" />
            <Output label="Bob computes b·(aG)" value={fmt(r.shared_bob)} copy={false} tone="accent" />
          </div>
          <div className="grid-2" style={{ marginTop: '0.75rem' }}>
            <Stat label="Shared secrets agree" value={r.agree ? 'yes' : 'no'} tone={r.agree ? 'ok' : 'danger'} sub="abG = baG — scalar multiplication commutes" />
            <Stat label="Eavesdropper brute-forced a" value={`${r.dlog_found} steps`} tone="danger" sub="Curve25519 would need ~2¹²⁶ — see §14 for what that costs" />
          </div>
        </>
      )}
    </Panel>
  );
}
