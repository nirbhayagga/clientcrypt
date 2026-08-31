'use client';

import { useEffect, useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Output, Stat, Status, ErrorText, Button, Callout, Tag } from '@/components/ui';

/* Shared helpers ----------------------------------------------------------- */

const b64url = (bytes: Uint8Array) =>
  btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const enc = (s: string) => new TextEncoder().encode(s);
const hexToB64url = (hex: string) => b64url(Uint8Array.from(hex.match(/.{2}/g) ?? [], (h) => parseInt(h, 16)));

/* WPA2 ---------------------------------------------------------------------- */

function Wpa2Panel({ ready }: { ready: boolean }) {
  const [passphrase, setPassphrase] = useState('password');
  const [ssid, setSsid] = useState('IEEE');
  const pmk = ready ? attempt(() => wasm.Protocols.wpa2_pmk(passphrase, ssid)) : null;
  return (
    <Panel title="Wi-Fi: WPA2-PSK key derivation" refs={['IEEE 802.11i', 'RFC 8018']}>
      <p className="muted small">
        Joining a WPA2-Personal network turns the passphrase into the 256-bit pairwise master key:
        PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 iterations). The network name is the salt, so a table of
        precomputed PMKs only works for one SSID. The defaults reproduce the IEEE 802.11i test vector.
      </p>
      <div className="grid-2">
        <Field label="Passphrase" hint="8–63 characters">{(id) => <TextInput id={id} mono value={passphrase} onChange={(e) => setPassphrase(e.target.value)} disabled={!ready} invalid={!!pmk && !pmk.ok} />}</Field>
        <Field label="SSID (network name)" hint="acts as the salt">{(id) => <TextInput id={id} mono value={ssid} onChange={(e) => setSsid(e.target.value)} disabled={!ready} />}</Field>
      </div>
      <hr className="divider" />
      <Output label="Pairwise master key (PMK)" value={pmk?.ok ? pmk.value : ''} tone="accent" ariaLabel="WPA2 PMK" />
      <ErrorText error={pmk && !pmk.ok ? pmk.error : null} />
      <Note title="Why home Wi-Fi passwords get cracked">
        The 4-way handshake that follows derives session keys from the PMK and is sent in the clear, so anyone who records it
        can test passphrase guesses offline at 4096 SHA-1 iterations each — cheap for a GPU. The defence is exactly §5:
        a passphrase with enough entropy. WPA3&apos;s SAE replaces this construction with a PAKE, which removes the offline attack.
      </Note>
    </Panel>
  );
}

/* TOTP ---------------------------------------------------------------------- */

function TotpPanel({ ready }: { ready: boolean }) {
  const [secret, setSecret] = useState('12345678901234567890');
  const [digits, setDigits] = useState(6);
  const [step, setStep] = useState(30);
  const [alg, setAlg] = useState('sha1');
  // The clock only starts on the client: a time-dependent first render would
  // not match the prerendered HTML and would fail hydration.
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, []);
  const unix = now === null ? null : Math.floor(now / 1000);
  const counter = unix === null ? null : Math.floor(unix / step);
  const remaining = unix === null ? null : step - (unix % step);
  const code = ready && unix !== null ? attempt(() => wasm.Protocols.totp(enc(secret), BigInt(unix), step, digits, alg)) : null;
  const prev = ready && counter !== null ? attempt(() => wasm.Protocols.hotp(enc(secret), BigInt(counter - 1), digits, alg)) : null;
  return (
    <Panel title="One-time passwords: HOTP and TOTP" refs={['RFC 4226', 'RFC 6238']}>
      <p className="muted small">
        Authenticator codes are HMAC in disguise: HOTP truncates HMAC(secret, counter) to a few decimal digits, and TOTP
        sets counter = ⌊unix&nbsp;time / step⌋ so both sides derive it from their clocks. The default secret is the RFC test key
        (ASCII <code>12345678901234567890</code>); real apps share the secret as a Base32 QR code.
      </p>
      <div className="grid" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr' }}>
        <Field label="Shared secret" hint="text, UTF-8">{(id) => <TextInput id={id} mono value={secret} onChange={(e) => setSecret(e.target.value)} disabled={!ready} />}</Field>
        <Field label="Digits">{(id) => <Select id={id} value={digits} onChange={(e) => setDigits(Number(e.target.value))} disabled={!ready}>{[6, 7, 8].map((d) => <option key={d} value={d}>{d}</option>)}</Select>}</Field>
        <Field label="Step (s)">{(id) => <Select id={id} value={step} onChange={(e) => setStep(Number(e.target.value))} disabled={!ready}>{[30, 60].map((d) => <option key={d} value={d}>{d}</option>)}</Select>}</Field>
        <Field label="HMAC hash">{(id) => <Select id={id} value={alg} onChange={(e) => setAlg(e.target.value)} disabled={!ready}><option value="sha1">SHA-1 (standard)</option><option value="sha256">SHA-256</option><option value="sha512">SHA-512</option></Select>}</Field>
      </div>
      <hr className="divider" />
      <div className="grid-3">
        <Stat label="Current code" value={code?.ok ? code.value : '—'} tone="accent" sub={remaining === null ? 'starting…' : `valid ${remaining} s`} />
        <Stat label="Counter T = ⌊t/step⌋" value={counter === null ? '—' : counter.toLocaleString()} sub={unix === null ? '' : `unix time ${unix}`} />
        <Stat label="Previous code" value={prev?.ok ? prev.value : '—'} sub="servers accept ±1 step of drift" />
      </div>
      <ErrorText error={code && !code.ok ? code.error : null} />
      <Note title="Truncation">
        The last nibble of the HMAC tag picks an offset; four bytes there, with the sign bit cleared, are reduced mod 10^digits.
        SHA-1&apos;s brokenness does not matter here — HMAC needs only PRF security, not collision resistance. What does matter is that
        the secret is symmetric: anyone who reads the server&apos;s TOTP database can generate valid codes.
      </Note>
    </Panel>
  );
}

/* JWT ------------------------------------------------------------------------ */

function JwtPanel({ ready }: { ready: boolean }) {
  const [alg, setAlg] = useState<'HS256' | 'RS256'>('HS256');
  const [secret, setSecret] = useState('a-string-secret-at-least-256-bits-long');
  const [payload, setPayload] = useState('{"sub":"1234567890","name":"Alice","admin":false}');
  const [rsaKeys, setRsaKeys] = useState<[string, string] | null>(null);
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);

  const sign = () => {
    setError(null);
    const r = attempt(() => {
      JSON.parse(payload);
      const head = b64url(enc(JSON.stringify({ alg, typ: 'JWT' })));
      const body = b64url(enc(JSON.stringify(JSON.parse(payload))));
      const signingInput = `${head}.${body}`;
      const sig = alg === 'HS256'
        ? hexToB64url(wasm.Hasher.hmac('sha256', enc(secret), enc(signingInput)))
        : hexToB64url(wasm.AsymmetricCrypto.rsa_sign(rsaKeys![0], 'pkcs1v15-sha256', enc(signingInput)));
      return `${signingInput}.${sig}`;
    });
    if (r.ok) setToken(r.value); else setError(r.error);
  };

  const genRsa = () => {
    setBusy(true); setError(null); setToken('');
    setTimeout(() => {
      const r = attempt(() => wasm.AsymmetricCrypto.rsa_generate_keys(1024) as [string, string]);
      if (r.ok) setRsaKeys(r.value); else setError(r.error);
      setBusy(false);
    }, 30);
  };

  // Live verification of whatever is in the token box (edit it to see it fail).
  const verdict = ready && token ? attempt(() => {
    const [h, b, s] = token.trim().split('.');
    if (!h || !b || s === undefined) throw new Error('A JWT has three dot-separated parts');
    const input = `${h}.${b}`;
    if (alg === 'HS256') return hexToB64url(wasm.Hasher.hmac('sha256', enc(secret), enc(input))) === s;
    if (!rsaKeys) return false;
    const sigHex = Array.from(Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0)), (x) => x.toString(16).padStart(2, '0')).join('');
    return wasm.AsymmetricCrypto.rsa_verify(rsaKeys[1], 'pkcs1v15-sha256', enc(input), sigHex);
  }) : null;
  const decoded = token ? attempt(() => token.trim().split('.').slice(0, 2).map((p) => JSON.stringify(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(p.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (p.length % 4)) % 4)), (c) => c.charCodeAt(0)))), null, 1).replace(/\n\s*/g, ' '))) : null;

  return (
    <Panel title="JSON Web Tokens" refs={['RFC 7519', 'RFC 7515']}
      action={<Segmented label="Algorithm" value={alg} onChange={(v) => { setAlg(v); setToken(''); }} disabled={!ready}
        options={[{ value: 'HS256', label: 'HS256 (HMAC)' }, { value: 'RS256', label: 'RS256 (RSA)' }]} />}>
      <p className="muted small">
        A JWT is base64url(header) ‖ &quot;.&quot; ‖ base64url(payload) ‖ &quot;.&quot; ‖ signature. Nothing is encrypted — the payload is readable by
        anyone — the signature only prevents modification. HS256 signs with HMAC-SHA256 (one shared secret signs <em>and</em> verifies);
        RS256 signs with an RSA private key so verifiers need only the public key.
      </p>
      <div className="grid-2">
        <Field label="Payload (JSON claims)">{(id) => <TextArea id={id} mono rows={3} value={payload} onChange={(e) => setPayload(e.target.value)} disabled={!ready} />}</Field>
        {alg === 'HS256'
          ? <Field label="Shared secret">{(id) => <TextInput id={id} mono value={secret} onChange={(e) => setSecret(e.target.value)} disabled={!ready} />}</Field>
          : <div className="stack">
              <div className="row"><Button onClick={genRsa} disabled={!ready || busy}>{busy ? 'Generating…' : rsaKeys ? 'New RSA key pair' : 'Generate RSA key pair'}</Button>{rsaKeys && <Tag tone="ok">1024-bit key ready</Tag>}</div>
              <p className="faint small">The private key signs; the public key below could be published in a JWKS for verifiers.</p>
            </div>}
      </div>
      <div className="row" style={{ marginTop: '0.75rem' }}>
        <Button variant="primary" onClick={sign} disabled={!ready || (alg === 'RS256' && !rsaKeys)}>Sign token</Button>
      </div>
      <ErrorText error={error} />
      {token && (
        <>
          <hr className="divider" />
          <Field label="Token (edit any character to break the signature)">{(id) => <TextArea id={id} mono rows={4} value={token} onChange={(e) => setToken(e.target.value)} />}</Field>
          {decoded?.ok && <p className="muted small" style={{ marginTop: '0.5rem' }}>header {decoded.value[0]} · payload {decoded.value[1]}</p>}
          <div style={{ marginTop: '0.75rem' }}>
            {verdict?.ok && verdict.value && <Callout tone="ok">Signature valid under the current {alg === 'HS256' ? 'secret' : 'public key'}.</Callout>}
            {verdict?.ok && !verdict.value && <Callout tone="danger">Signature invalid — the token was altered, or the {alg === 'HS256' ? 'secret' : 'key'} changed.</Callout>}
            {verdict && !verdict.ok && <Callout tone="warn">Not a decodable JWT: {verdict.error}</Callout>}
          </div>
        </>
      )}
      <Note title="Classic pitfalls">
        Header <code>alg</code> is attacker-controlled: servers must pin the expected algorithm, or an attacker can switch RS256 to
        HS256 and use the <em>public</em> key as the HMAC secret, or to <code>none</code>. Verification here ignores the header and uses
        the selected algorithm only.
      </Note>
    </Panel>
  );
}

/* WireGuard ------------------------------------------------------------------ */

interface WgResult {
  construction_hash: string; initiator_static_pub: string; responder_static_pub: string;
  initiator_ephemeral_pub: string; responder_ephemeral_pub: string;
  encrypted_static: string; encrypted_timestamp: string; encrypted_empty: string;
  initiator_chaining_key: string; responder_chaining_key: string; keys_agree: boolean;
  initiator_sending_key: string; initiator_receiving_key: string;
  responder_sending_key: string; responder_receiving_key: string;
}

function WireGuardPanel({ ready }: { ready: boolean }) {
  const [psk, setPsk] = useState('');
  const [hs, setHs] = useState<WgResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = () => {
    const r = attempt(() => wasm.WireGuard.handshake(psk, BigInt(Math.floor(Date.now() / 1000))) as WgResult);
    if (r.ok) { setHs(r.value); setError(null); } else { setError(r.error); }
  };
  return (
    <Panel title="WireGuard handshake" refs={['Noise IKpsk2', 'Curve25519', 'ChaCha20-Poly1305', 'BLAKE2s']}
      action={<Button variant="primary" onClick={run} disabled={!ready}>{hs ? 'Run again' : 'Run handshake'}</Button>}>
      <p className="muted small">
        WireGuard replaces TLS&apos;s negotiation with one fixed construction: a 1-RTT Noise IK handshake in which the initiator already
        knows the responder&apos;s static public key. Two messages later both peers hold identical transport keys for ChaCha20-Poly1305.
        Fresh keys are generated on every run; the optional pre-shared key is mixed in for post-quantum hedging.
      </p>
      <Field label="Pre-shared key (optional)" hint="32 bytes hex; empty = none">
        {(id) => <TextInput id={id} mono value={psk} onChange={(e) => setPsk(e.target.value.trim())} disabled={!ready} placeholder="empty — the all-zero PSK" />}
      </Field>
      <ErrorText error={error} />
      {hs && (
        <>
          <hr className="divider" />
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Step</th><th>Field</th><th>Value</th></tr></thead>
              <tbody>
                <tr><td>Setup</td><td>H(construction)</td><td className="mono">{hs.construction_hash}</td></tr>
                <tr><td rowSpan={3}>Message 1 (initiator → responder)</td><td>ephemeral public key</td><td className="mono">{hs.initiator_ephemeral_pub}</td></tr>
                <tr><td>static public key, encrypted</td><td className="mono">{hs.encrypted_static}</td></tr>
                <tr><td>timestamp, encrypted</td><td className="mono">{hs.encrypted_timestamp}</td></tr>
                <tr><td rowSpan={2}>Message 2 (responder → initiator)</td><td>ephemeral public key</td><td className="mono">{hs.responder_ephemeral_pub}</td></tr>
                <tr><td>empty AEAD (authentication tag only)</td><td className="mono">{hs.encrypted_empty}</td></tr>
                <tr><td rowSpan={2}>Transport keys</td><td>initiator → responder</td><td className="mono">{hs.initiator_sending_key}</td></tr>
                <tr><td>responder → initiator</td><td className="mono">{hs.responder_sending_key}</td></tr>
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: '1rem' }}>
            {hs.keys_agree
              ? <Callout tone="ok">Both peers independently derived the same chaining key and the same pair of transport keys ({hs.initiator_sending_key.slice(0, 16)}… / {hs.responder_sending_key.slice(0, 16)}…).</Callout>
              : <Callout tone="danger">Key derivation diverged.</Callout>}
          </div>
        </>
      )}
      <Note title="Compared with TLS (§6)">
        Same ingredients, different trade-offs: identity hiding (the initiator&apos;s static key travels encrypted), no certificates or
        negotiation (trust is &quot;this exact public key&quot;, so there is no downgrade surface), and the whole handshake fits in one round trip.
        The chaining-key / hash ladder shown in §6 for HKDF-SHA256 runs here with HMAC-BLAKE2s. Encrypted fields and derived keys differ on
        every run because the ephemerals are fresh; the first row is the fixed BLAKE2s hash of the construction name.
      </Note>
    </Panel>
  );
}

/* Page ------------------------------------------------------------------------ */

export default function ProtocolsPage() {
  const state = useWasm();
  const ready = state === 'ready';
  return (
    <Page kicker="§7 · Applied protocols" title="Protocols in the field"
      lede="Four places the primitives from §1–§6 turn up between real machines: your Wi-Fi password, the six digits from an authenticator app, the token in an Authorization header, and a VPN tunnel.">
      <Status state={state} />
      <Wpa2Panel ready={ready} />
      <TotpPanel ready={ready} />
      <JwtPanel ready={ready} />
      <WireGuardPanel ready={ready} />
    </Page>
  );
}