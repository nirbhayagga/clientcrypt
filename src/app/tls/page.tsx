'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt, errorMessage } from '@/lib/wasm';
import { Page, Panel, Note, Field, TextInput, Output, Status, ErrorText, Button, Callout } from '@/components/ui';

interface Hello { random: string; key_share: string; cipher_suite: string; group: string }
interface Schedule {
  shared_secret: string; early_secret: string; derived_early: string; handshake_secret: string; transcript_hash: string;
  client_handshake_traffic_secret: string; server_handshake_traffic_secret: string; derived_handshake: string; master_secret: string;
  client_application_traffic_secret: string; server_application_traffic_secret: string; client_key: string; client_iv: string; server_key: string; server_iv: string;
}
interface Record { sequence: number; nonce: string; header: string; inner_plaintext: string; ciphertext: string }

const STEPS = [
  { title: 'ClientHello', body: 'Client random, supported versions/cipher suites, and a key_share extension carrying an ephemeral X25519 public key.' },
  { title: 'ServerHello', body: 'Server random, the selected suite TLS_AES_128_GCM_SHA256, and its own X25519 key share. From here on everything is encrypted.' },
  { title: 'Key schedule', body: 'Both sides compute the X25519 shared secret and run HKDF-Extract / Derive-Secret to obtain handshake, master and traffic secrets.' },
  { title: 'Record protection', body: 'Application data is encrypted with AES-128-GCM under the traffic key; the nonce is the IV XORed with the record sequence number.' },
];

export default function TlsPage() {
  const state = useWasm();
  const ready = state === 'ready';

  const [hs, setHs] = useState<InstanceType<typeof wasm.TlsHandshake> | null>(null);
  const [step, setStep] = useState(0);
  const [client, setClient] = useState<Hello | null>(null);
  const [server, setServer] = useState<Hello | null>(null);
  const [sched, setSched] = useState<Schedule | null>(null);
  const [record, setRecord] = useState<Record | null>(null);
  const [appData, setAppData] = useState('GET / HTTP/1.1\r\nHost: example.org\r\n\r\n');
  const [seq, setSeq] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const reset = () => { setHs(null); setStep(0); setClient(null); setServer(null); setSched(null); setRecord(null); setSeq(0); setError(null); };

  const next = () => {
    setError(null);
    try {
      const h = hs ?? new wasm.TlsHandshake();
      if (!hs) setHs(h);
      if (step === 0) { setClient(h.client_hello() as Hello); setStep(1); }
      else if (step === 1) { setServer(h.server_hello() as Hello); setStep(2); }
      else if (step === 2) { setSched(h.key_schedule() as Schedule); setStep(3); }
    } catch (e) { setError(errorMessage(e)); }
  };

  const encrypt = () => {
    if (!hs) return;
    const r = attempt(() => hs.encrypt_record(new TextEncoder().encode(appData), BigInt(seq)) as Record);
    if (r.ok) { setRecord(r.value); setStep(4); } else setError(r.error);
  };

  const rows: [string, string, string][] = sched ? [
    ['ECDHE shared secret', 'X25519(client_sk, server_pk) = X25519(server_sk, client_pk)', sched.shared_secret],
    ['Early Secret', 'HKDF-Extract(salt = 0, IKM = 0³²)  — no PSK', sched.early_secret],
    ['Derived', 'Derive-Secret(Early Secret, "derived", "")', sched.derived_early],
    ['Handshake Secret', 'HKDF-Extract(salt = Derived, IKM = shared secret)', sched.handshake_secret],
    ['Transcript hash', 'H(ClientHello ‖ ServerHello) — stand-in, see note', sched.transcript_hash],
    ['client_handshake_traffic_secret', 'Derive-Secret(Handshake Secret, "c hs traffic", transcript)', sched.client_handshake_traffic_secret],
    ['server_handshake_traffic_secret', 'Derive-Secret(Handshake Secret, "s hs traffic", transcript)', sched.server_handshake_traffic_secret],
    ['Derived', 'Derive-Secret(Handshake Secret, "derived", "")', sched.derived_handshake],
    ['Master Secret', 'HKDF-Extract(salt = Derived, IKM = 0³²)', sched.master_secret],
    ['client_application_traffic_secret_0', 'Derive-Secret(Master Secret, "c ap traffic", transcript)', sched.client_application_traffic_secret],
    ['server_application_traffic_secret_0', 'Derive-Secret(Master Secret, "s ap traffic", transcript)', sched.server_application_traffic_secret],
    ['client write key / IV', 'HKDF-Expand-Label(secret, "key", "", 16) · ("iv", "", 12)', `${sched.client_key} · ${sched.client_iv}`],
    ['server write key / IV', 'HKDF-Expand-Label(secret, "key", "", 16) · ("iv", "", 12)', `${sched.server_key} · ${sched.server_iv}`],
  ] : [];

  return (
    <Page kicker="§6 · TLS 1.3 handshake" title="TLS 1.3: key exchange and key schedule"
      lede="One round trip establishes forward-secret keys: each side contributes an ephemeral X25519 share, and HKDF turns the shared secret and the handshake transcript into separate keys for each direction and each phase.">
      <Status state={state} />

      <Panel title="Handshake" refs={['RFC 8446 §4', '§7.1', '§5.2']}
        action={<div className="row"><Button variant="primary" onClick={next} disabled={!ready || step >= 3}>{step === 0 ? 'Send ClientHello' : step === 1 ? 'Send ServerHello' : step === 2 ? 'Run key schedule' : 'Handshake complete'}</Button><Button onClick={reset} disabled={!ready || step === 0}>Reset</Button></div>}>
        <div className="steps">
          {STEPS.map((s, i) => (
            <div key={s.title} className={`step ${i < step ? 'done' : i === step ? 'active' : ''}`}>
              <div className="step-num">{i + 1}</div>
              <div><div className="step-title">{s.title}</div><div className="step-body">{s.body}</div></div>
            </div>
          ))}
        </div>
        <ErrorText error={error} />
      </Panel>

      <div className="grid-2">
        <Panel title="Client → ClientHello">
          {client ? (
            <div className="stack">
              <Output label="client_random (32 bytes)" value={client.random} />
              <Output label="key_share: x25519 public key" value={client.key_share} tone="accent" />
              <div className="row"><span className="tag">{client.cipher_suite}</span><span className="tag">{client.group}</span><span className="tag">supported_versions: TLS 1.3 (0x0304)</span></div>
            </div>
          ) : <p className="faint small">Pending.</p>}
        </Panel>
        <Panel title="Server → ServerHello">
          {server ? (
            <div className="stack">
              <Output label="server_random (32 bytes)" value={server.random} />
              <Output label="key_share: x25519 public key" value={server.key_share} tone="accent" />
              <div className="row"><span className="tag">{server.cipher_suite}</span><span className="tag">{server.group}</span></div>
            </div>
          ) : <p className="faint small">Pending.</p>}
        </Panel>
      </div>

      <Panel title="Key schedule" refs={['RFC 8446 §7.1', 'RFC 5869']}>
        {sched ? (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Secret</th><th>Derivation</th><th>Value</th></tr></thead>
              <tbody>
                {rows.map(([name, how, value]) => (
                  <tr key={name}><td style={{ whiteSpace: 'nowrap' }}>{name}</td><td className="muted small">{how}</td><td className="mono">{value}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="faint small">Computed after ServerHello.</p>}
        <Note title="HKDF-Expand-Label">
          Every arrow is HKDF-Expand-Label(secret, label, context, length) with info = length ‖ &quot;tls13 &quot; + label ‖ context. Binding the transcript hash
          into the traffic secrets means any tampering with the Hello messages yields different keys on the two sides, which the Finished MACs would
          then detect. The key-schedule code is checked against the RFC 8448 trace values in the crate&apos;s tests.
        </Note>
      </Panel>

      <Panel title="Record protection" refs={['RFC 8446 §5.2', 'AES-128-GCM']}
        action={<Button variant="primary" onClick={encrypt} disabled={!sched}>Encrypt record</Button>}>
        <div className="grid-2">
          <Field label="Application data (client → server)">{(id) => <TextInput id={id} mono value={appData} onChange={(e) => setAppData(e.target.value)} disabled={!sched} />}</Field>
          <Field label="Record sequence number" hint="never reused under one key">{(id) => <TextInput id={id} type="number" min={0} value={seq} onChange={(e) => setSeq(Math.max(0, Number(e.target.value) || 0))} disabled={!sched} />}</Field>
        </div>
        {record && (
          <div className="stack" style={{ marginTop: '1rem' }}>
            <div className="grid-2">
              <Output label="nonce = client_iv ⊕ pad(sequence)" value={record.nonce} />
              <Output label="record header (AAD): type 0x17, version 0x0303, length" value={record.header} />
            </div>
            <Output label="TLSInnerPlaintext = data ‖ content type (0x17)" value={record.inner_plaintext} />
            <Output label="encrypted_record = AES-GCM ciphertext ‖ 16-byte tag" value={record.ciphertext} tone="accent" />
            <Callout tone="ok">On the wire: {record.header}{record.ciphertext.slice(0, 24)}… — the real content type is hidden inside the encryption; the outer header always says application_data.</Callout>
          </div>
        )}
      </Panel>

      <Note title="What is simplified here">
        No certificate, CertificateVerify or Finished messages — so this handshake is unauthenticated and would fall to an active attacker;
        the transcript hash covers the Hello fields rather than the exact message bytes; and there is no PSK, 0-RTT, HelloRetryRequest or key update.
        Everything shown for the key exchange, KDF labels, traffic keys and record layout follows the specification.
      </Note>
    </Page>
  );
}
