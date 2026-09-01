'use client';

import { useEffect, useRef, useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { bytesToHex, hexToBytes, hexToText, isHex, randomHex, textToHex } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Range, Output, Stat, Status, ErrorText, Button, Tag } from '@/components/ui';

type Mode = 'ecb' | 'cbc' | 'ctr' | 'gcm';
type Dir = 'encrypt' | 'decrypt';
type Fmt = 'text' | 'hex';

const MODES: { value: Mode; label: string; iv: string; ivBytes: number; note: string }[] = [
  { value: 'ecb', label: 'ECB — Electronic Codebook', iv: '', ivBytes: 0, note: 'Each block encrypted independently. Deterministic: equal plaintext blocks give equal ciphertext blocks. Never use for data longer than one block.' },
  { value: 'cbc', label: 'CBC — Cipher Block Chaining', iv: 'IV', ivBytes: 16, note: 'Each plaintext block is XORed with the previous ciphertext block before encryption. Needs an unpredictable IV and padding; decryption error handling can leak a padding oracle.' },
  { value: 'ctr', label: 'CTR — Counter', iv: 'Initial counter', ivBytes: 16, note: 'Turns the block cipher into a stream cipher: keystream = E(K, counter). No padding, parallel, but no integrity — flipping a ciphertext bit flips the same plaintext bit.' },
  { value: 'gcm', label: 'GCM — Galois/Counter (AEAD)', iv: 'Nonce', ivBytes: 12, note: 'CTR encryption plus a GHASH authentication tag over ciphertext and associated data. The recommended mode; a nonce must never repeat under one key.' },
];

const FIPS_KEY = '000102030405060708090a0b0c0d0e0f';
const FIPS_PT = '00112233445566778899aabbccddeeff';

export default function BlockCiphersPage() {
  const state = useWasm();
  const ready = state === 'ready';
  const B = wasm.BlockCiphers;

  const [keyBits, setKeyBits] = useState<128 | 192 | 256>(128);
  const [key, setKey] = useState(FIPS_KEY);
  const [mode, setMode] = useState<Mode>('ecb');
  const [iv, setIv] = useState('000102030405060708090a0b0c0d0e0f');
  const [nonce, setNonce] = useState('000000000000000000000000');
  const [aad, setAad] = useState('');
  const [dir, setDir] = useState<Dir>('encrypt');
  const [fmt, setFmt] = useState<Fmt>('hex');
  const [input, setInput] = useState(FIPS_PT + FIPS_PT);

  const modeInfo = MODES.find((m) => m.value === mode)!;
  const ivValue = mode === 'gcm' ? nonce : iv;
  const inputHex = fmt === 'hex' ? input.replace(/\s+/g, '') : textToHex(input);
  const inputValid = isHex(inputHex) && isHex(key) && key.length === keyBits / 4 && (mode === 'ecb' || (isHex(ivValue) && ivValue.length === modeInfo.ivBytes * 2)) && isHex(aad);

  const result = ready && inputValid ? attempt(() => {
    if (mode === 'gcm') return dir === 'encrypt' ? B.aes_gcm_encrypt(key, nonce, aad, inputHex) : B.aes_gcm_decrypt(key, nonce, aad, inputHex);
    return dir === 'encrypt' ? B.aes_encrypt(mode, key, iv, inputHex) : B.aes_decrypt(mode, key, iv, inputHex);
  }) : null;
  const outHex = result?.ok ? result.value : '';
  const outText = dir === 'decrypt' && outHex ? attempt(() => hexToText(outHex)) : null;
  const padded = ready && isHex(inputHex) && (mode === 'ecb' || mode === 'cbc') && dir === 'encrypt' ? B.pkcs7_pad_hex(inputHex) : '';

  // Block view of the output
  const body = mode === 'gcm' && dir === 'encrypt' ? outHex.slice(0, -32) : outHex;
  const tag = mode === 'gcm' && dir === 'encrypt' ? outHex.slice(-32) : '';
  const blocks = body.match(/.{1,32}/g) ?? [];
  const firstIndex = new Map<string, number>();
  blocks.forEach((b, i) => { if (!firstIndex.has(b)) firstIndex.set(b, i); });

  const setKeySize = (bits: 128 | 192 | 256) => { setKeyBits(bits); setKey(randomHex(bits / 8)); };
  const resetIv = () => (mode === 'gcm' ? setNonce(randomHex(12)) : setIv(randomHex(16)));

  const validationError = !inputValid ? (
    !isHex(key) || key.length !== keyBits / 4 ? `Key must be ${keyBits / 4} hex characters (${keyBits / 8} bytes).` :
    !isHex(inputHex) ? 'Input must be an even-length hex string.' :
    mode !== 'ecb' && (!isHex(ivValue) || ivValue.length !== modeInfo.ivBytes * 2) ? `${modeInfo.iv} must be ${modeInfo.ivBytes} bytes (${modeInfo.ivBytes * 2} hex characters).` :
    'Associated data must be hex.'
  ) : null;

  return (
    <Page kicker="§2 · Block ciphers" title="AES and modes of operation"
      lede="A block cipher is a keyed permutation of 128-bit blocks. A mode of operation defines how a message longer than one block is processed — and it, not the cipher, decides whether patterns leak and whether tampering is detected.">
      <Status state={state} />

      <Panel title="AES" refs={['FIPS 197', 'SP 800-38A', 'SP 800-38D']}>
        <div className="grid-2">
          <div className="stack">
            <div className="grid-2">
              <Field label="Key size">{(id) => (
                <Select id={id} value={keyBits} onChange={(e) => setKeySize(Number(e.target.value) as 128 | 192 | 256)} disabled={!ready}>
                  <option value={128}>AES-128 (10 rounds)</option>
                  <option value={192}>AES-192 (12 rounds)</option>
                  <option value={256}>AES-256 (14 rounds)</option>
                </Select>
              )}</Field>
              <Field label="Mode">{(id) => (
                <Select id={id} value={mode} onChange={(e) => setMode(e.target.value as Mode)} disabled={!ready}>
                  {MODES.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
                </Select>
              )}</Field>
            </div>
            <Field label="Key" hint={<><span>{keyBits / 8} bytes · </span><button type="button" className="btn btn-ghost btn-sm" onClick={() => setKey(randomHex(keyBits / 8))} disabled={!ready}>random</button></>}>
              {(id) => <TextInput id={id} mono value={key} onChange={(e) => setKey(e.target.value.trim())} invalid={!isHex(key) || key.length !== keyBits / 4} disabled={!ready} />}
            </Field>
            {mode !== 'ecb' && (
              <Field label={modeInfo.iv} hint={<><span>{modeInfo.ivBytes} bytes · </span><button type="button" className="btn btn-ghost btn-sm" onClick={resetIv} disabled={!ready}>random</button></>}>
                {(id) => <TextInput id={id} mono value={ivValue} onChange={(e) => (mode === 'gcm' ? setNonce(e.target.value.trim()) : setIv(e.target.value.trim()))} disabled={!ready} />}
              </Field>
            )}
            {mode === 'gcm' && (
              <Field label="Associated data (AAD)" hint="hex, authenticated but not encrypted">
                {(id) => <TextInput id={id} mono value={aad} onChange={(e) => setAad(e.target.value.trim())} disabled={!ready} />}
              </Field>
            )}
          </div>
          <div className="stack">
            <div className="row">
              <Segmented label="Direction" value={dir} onChange={setDir} disabled={!ready} options={[{ value: 'encrypt', label: 'Encrypt' }, { value: 'decrypt', label: 'Decrypt' }]} />
              <Segmented label="Input format" value={fmt} onChange={setFmt} disabled={!ready} options={[{ value: 'hex', label: 'Hex' }, { value: 'text', label: 'Text' }]} />
              <Button size="sm" variant="ghost" onClick={() => { setKeyBits(128); setKey(FIPS_KEY); setMode('ecb'); setFmt('hex'); setDir('encrypt'); setInput(FIPS_PT); }} disabled={!ready}>FIPS-197 vector</Button>
            </div>
            <Field label={dir === 'encrypt' ? 'Plaintext' : mode === 'gcm' ? 'Ciphertext ‖ tag' : 'Ciphertext'} hint={fmt === 'hex' ? `${inputHex.length / 2} bytes` : `${inputHex.length / 2} bytes UTF-8`}>
              {(id) => <TextArea id={id} mono rows={5} value={input} onChange={(e) => setInput(e.target.value)} invalid={!isHex(inputHex)} disabled={!ready} />}
            </Field>
          </div>
        </div>
        <hr className="divider" />
        <Output label={dir === 'encrypt' ? (mode === 'gcm' ? 'Ciphertext ‖ tag (hex)' : 'Ciphertext (hex)') : 'Plaintext (hex)'} value={outHex} ariaLabel="AES output" />
        <ErrorText error={validationError ?? (result && !result.ok ? result.error : null)} />
        {outText?.ok && <div style={{ marginTop: '0.75rem' }}><Output label="Plaintext (UTF-8)" value={outText.value} /></div>}
        <p className="muted small" style={{ marginTop: '0.75rem' }}>{modeInfo.note}</p>
      </Panel>

      <div className="grid-2">
        <Panel title="Block structure of the output">
          {blocks.length ? (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>#</th><th>16-byte block</th><th></th></tr></thead>
                <tbody>
                  {blocks.map((b, i) => {
                    const dup = firstIndex.get(b)! !== i;
                    return (
                      <tr key={i} style={dup ? { color: 'var(--danger)' } : undefined}>
                        <td className="mono">{i}</td>
                        <td className="mono">{b}</td>
                        <td>{dup ? <Tag tone="danger">= block {firstIndex.get(b)}</Tag> : null}</td>
                      </tr>
                    );
                  })}
                  {tag && <tr><td className="mono">tag</td><td className="mono" style={{ color: 'var(--accent)' }}>{tag}</td><td><Tag tone="accent">GHASH</Tag></td></tr>}
                </tbody>
              </table>
            </div>
          ) : <p className="faint small">No output.</p>}
          <p className="muted small" style={{ marginTop: '0.75rem' }}>
            With ECB and a repeated plaintext block, the repetition survives encryption. Every other mode ties each block to its position through the IV/counter chain.
          </p>
        </Panel>

        <Panel title="PKCS#7 padding" refs={['RFC 5652 §6.3']}>
          {padded ? (
            <>
              <div className="hexdiff" aria-label="Padded plaintext">
                {padded.slice(0, inputHex.length)}<span className="d">{padded.slice(inputHex.length)}</span>
              </div>
              <p className="muted small" style={{ marginTop: '0.75rem' }}>
                {inputHex.length / 2} bytes → {padded.length / 2} bytes: {(padded.length - inputHex.length) / 2} bytes of value 0x{((padded.length - inputHex.length) / 2).toString(16).padStart(2, '0')} are appended.
                A full block of padding is added when the input is already a multiple of 16, so unpadding is unambiguous.
              </p>
            </>
          ) : <p className="faint small">{mode === 'ctr' || mode === 'gcm' ? 'Counter modes need no padding.' : 'Padding is shown when encrypting.'}</p>}
          <Note title="Padding oracle">
            Decryption here checks every padding byte and reports one generic error. A server that distinguishes “bad padding” from
            “bad MAC” lets an attacker decrypt CBC ciphertext one byte at a time (Vaudenay, 2002) — the reason AEAD modes exist.
          </Note>
        </Panel>
      </div>

      <ChaChaPanel ready={ready} />

      <EcbImageDemo ready={ready} />

      <ReducedRoundPanel ready={ready} />

      <KeystreamReusePanel ready={ready} />
    </Page>
  );
}

function ChaChaPanel({ ready }: { ready: boolean }) {
  const RFC_KEY = '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f';
  const RFC_NONCE = '070000004041424344454647';
  const RFC_AAD = '50515253c0c1c2c3c4c5c6c7';
  const [key, setKey] = useState(RFC_KEY);
  const [nonce, setNonce] = useState(RFC_NONCE);
  const [aad, setAad] = useState(RFC_AAD);
  const [text, setText] = useState("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const [dir, setDir] = useState<Dir>('encrypt');
  const [ct, setCt] = useState('');

  const input = dir === 'encrypt' ? textToHex(text) : ct.replace(/\s+/g, '');
  const out = ready && isHex(input) && isHex(key) && isHex(nonce) && isHex(aad)
    ? attempt(() => (dir === 'encrypt'
        ? wasm.BlockCiphers.chacha20_encrypt(key, nonce, aad, input)
        : wasm.BlockCiphers.chacha20_decrypt(key, nonce, aad, input)))
    : null;
  const value = out?.ok ? out.value : '';
  const asText = dir === 'decrypt' && value ? attempt(() => hexToText(value)) : null;

  return (
    <Panel title="ChaCha20-Poly1305" refs={['RFC 8439']}
      action={<Segmented label="Direction" value={dir} onChange={setDir} disabled={!ready}
        options={[{ value: 'encrypt', label: 'Seal' }, { value: 'decrypt', label: 'Open' }]} />}>
      <p className="muted small">
        Not a block cipher at all: ChaCha20 is a stream cipher, and Poly1305 is a one-time authenticator. Together they form
        the AEAD that TLS and WireGuard use where AES hardware is absent. Because it is built from additions, XORs and
        rotations on 32-bit words rather than table lookups, a straightforward software implementation is already constant-time
        — which is exactly the property AES in software struggles to guarantee.
      </p>
      <div className="grid-2">
        <div className="stack">
          <Field label="Key" hint="32 bytes">{(id) => <TextInput id={id} mono value={key} onChange={(e) => setKey(e.target.value.trim())} invalid={!isHex(key) || key.length !== 64} disabled={!ready} />}</Field>
          <Field label="Nonce" hint="12 bytes, never reused under one key">{(id) => <TextInput id={id} mono value={nonce} onChange={(e) => setNonce(e.target.value.trim())} invalid={!isHex(nonce) || nonce.length !== 24} disabled={!ready} />}</Field>
          <Field label="Associated data" hint="authenticated, not encrypted">{(id) => <TextInput id={id} mono value={aad} onChange={(e) => setAad(e.target.value.trim())} invalid={!isHex(aad)} disabled={!ready} />}</Field>
        </div>
        <Field label={dir === 'encrypt' ? 'Plaintext' : 'Ciphertext ‖ tag (hex)'}>
          {(id) => dir === 'encrypt'
            ? <TextArea id={id} rows={6} value={text} onChange={(e) => setText(e.target.value)} disabled={!ready} />
            : <TextArea id={id} mono rows={6} value={ct} onChange={(e) => setCt(e.target.value)} invalid={!isHex(ct.replace(/\s+/g, ''))} disabled={!ready} />}
        </Field>
      </div>
      <hr className="divider" />
      <Output label={dir === 'encrypt' ? 'Ciphertext ‖ 16-byte tag' : 'Plaintext (hex)'} value={value} ariaLabel="ChaCha20 output" scroll />
      <ErrorText error={out && !out.ok ? out.error : null} />
      {asText?.ok && <div style={{ marginTop: '0.75rem' }}><Output label="Plaintext (UTF-8)" value={asText.value} /></div>}
      {dir === 'encrypt' && value && (
        <div className="row" style={{ marginTop: '0.75rem' }}>
          <Button size="sm" onClick={() => { setCt(value); setDir('decrypt'); }}>Open this ciphertext</Button>
          {key === RFC_KEY && nonce === RFC_NONCE && aad === RFC_AAD && <Tag tone="ok">matches the RFC 8439 §2.8.2 vector</Tag>}
        </div>
      )}
      <Note title="Nonce reuse is fatal here too">
        A stream cipher XORs a keystream derived from (key, nonce) with the data. Encrypt two different messages under the same
        pair and their ciphertexts XOR to the XOR of the plaintexts, with the key never entering into it. Poly1305 is worse
        still under reuse: it is a one-time authenticator, and two tags under one key leak enough to forge others.
      </Note>
    </Panel>
  );
}

/* --------------------------------------------------------------------------
   The classic "ECB penguin": encrypt raw RGBA pixels with each mode and view
   the ciphertext as an image. Alpha is forced opaque for display.
   ---------------------------------------------------------------------- */
const SIZE = 128;

function drawScene(ctx: CanvasRenderingContext2D) {
  ctx.fillStyle = '#e8e4d8';
  ctx.fillRect(0, 0, SIZE, SIZE);
  ctx.fillStyle = '#1f2a44';
  ctx.beginPath(); ctx.arc(64, 56, 40, 0, Math.PI * 2); ctx.fill();
  ctx.fillStyle = '#e8e4d8';
  ctx.beginPath(); ctx.arc(64, 62, 26, 0, Math.PI * 2); ctx.fill();
  ctx.fillStyle = '#1f2a44';
  ctx.beginPath(); ctx.arc(52, 48, 5, 0, Math.PI * 2); ctx.arc(76, 48, 5, 0, Math.PI * 2); ctx.fill();
  ctx.fillStyle = '#d9a441';
  ctx.beginPath(); ctx.moveTo(56, 60); ctx.lineTo(72, 60); ctx.lineTo(64, 70); ctx.closePath(); ctx.fill();
  ctx.fillRect(40, 100, 48, 10);
  ctx.fillStyle = '#1f2a44';
  ctx.font = 'bold 14px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('AES', 64, 122);
}

function EcbImageDemo({ ready }: { ready: boolean }) {
  const refs = { plain: useRef<HTMLCanvasElement>(null), ecb: useRef<HTMLCanvasElement>(null), cbc: useRef<HTMLCanvasElement>(null), ctr: useRef<HTMLCanvasElement>(null) };
  const [seed, setSeed] = useState(0);
  const [keyHex, setKeyHex] = useState('');

  useEffect(() => {
    const plain = refs.plain.current;
    if (!plain || !ready) return;
    const ctx = plain.getContext('2d')!;
    drawScene(ctx);
    const rgba = ctx.getImageData(0, 0, SIZE, SIZE).data;
    const key = new Uint8Array(16); crypto.getRandomValues(key);
    const iv = new Uint8Array(16); crypto.getRandomValues(iv);
    setKeyHex(bytesToHex(key));
    for (const mode of ['ecb', 'cbc', 'ctr'] as const) {
      const out = wasm.BlockCiphers.aes_encrypt_bytes(mode, key, iv, new Uint8Array(rgba));
      for (let i = 3; i < out.length; i += 4) out[i] = 255;
      const c = refs[mode].current!.getContext('2d')!;
      c.putImageData(new ImageData(new Uint8ClampedArray(out), SIZE, SIZE), 0, 0);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, seed]);

  return (
    <Panel title="ECB pattern leakage" refs={['raw RGBA pixels']} action={<Button size="sm" onClick={() => setSeed((s) => s + 1)} disabled={!ready}>New random key</Button>}>
      <p className="muted small">
        The {SIZE}×{SIZE} RGBA bitmap below ({SIZE * SIZE * 4} bytes) is encrypted byte-for-byte with AES-128 under key <code>{keyHex || '…'}</code>.
        Areas of flat colour are runs of identical 16-byte blocks; ECB maps each of them to the same ciphertext block, so the shapes remain visible.
      </p>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
        {(['plain', 'ecb', 'cbc', 'ctr'] as const).map((k) => (
          <div key={k} className="canvas-box">
            <canvas ref={refs[k]} width={SIZE} height={SIZE} aria-label={k === 'plain' ? 'Original image' : `Image encrypted with AES-${k.toUpperCase()}`} />
            <div className="cap">{k === 'plain' ? 'plaintext' : `AES-128-${k.toUpperCase()}`}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* --------------------------------------------------------------------------
   Reduced-round AES: the same image, encrypted with the standard round
   function cut short. AES-128 is defined as ten rounds; running fewer shows
   what those rounds are actually buying, round by round.
   ---------------------------------------------------------------------- */
function ReducedRoundPanel({ ready }: { ready: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const outRef = useRef<HTMLCanvasElement>(null);
  const rgbaRef = useRef<Uint8ClampedArray | null>(null);
  const [rounds, setRounds] = useState(1);
  const [seed, setSeed] = useState(0);
  const [keyHex, setKeyHex] = useState('');

  // Draws the plaintext and picks a fresh key once per "New key" click — not
  // on every round change, or scrubbing the slider would compare ciphertexts
  // under different keys instead of the same key at different round counts.
  useEffect(() => {
    const plain = canvasRef.current;
    if (!plain || !ready) return;
    const ctx = plain.getContext('2d')!;
    drawScene(ctx);
    rgbaRef.current = ctx.getImageData(0, 0, SIZE, SIZE).data;
    const key = new Uint8Array(16); crypto.getRandomValues(key);
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setKeyHex(bytesToHex(key));
  }, [ready, seed]);

  // Redraws only the ciphertext canvas as the round count changes; a pure DOM
  // update with no state to synchronise back into React.
  useEffect(() => {
    const out = outRef.current, rgba = rgbaRef.current;
    if (!out || !rgba || !keyHex) return;
    const encrypted = wasm.AesRounds.encrypt(hexToBytes(keyHex), new Uint8Array(rgba), rounds);
    for (let i = 3; i < encrypted.length; i += 4) encrypted[i] = 255;
    out.getContext('2d')!.putImageData(new ImageData(new Uint8ClampedArray(encrypted), SIZE, SIZE), 0, 0);
  }, [rounds, keyHex]);

  const avalanche = keyHex ? attempt(() => wasm.AesRounds.avalanche(hexToBytes(keyHex), rounds)) : null;

  return (
    <Panel title="What the rounds are for" refs={['reduced-round AES']}
      action={<Button size="sm" onClick={() => setSeed((s) => s + 1)} disabled={!ready}>New key</Button>}>
      <p className="muted small">
        AES-128 is defined as exactly ten rounds of SubBytes, ShiftRows, MixColumns and AddRoundKey — this is a separate,
        from-scratch implementation of that same round function with the count made adjustable, so the standard&apos;s choice
        of ten can be seen rather than taken on faith. At ten rounds it reproduces the FIPS-197 test vectors exactly.
      </p>
      <Range label="Rounds" min={1} max={10} value={rounds} onChange={setRounds} disabled={!ready} />
      <div className="grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', marginTop: '1rem' }}>
        <div className="canvas-box">
          <canvas ref={canvasRef} width={SIZE} height={SIZE} aria-label="Original image" />
          <div className="cap">plaintext</div>
        </div>
        <div className="canvas-box">
          <canvas ref={outRef} width={SIZE} height={SIZE} aria-label={`Image encrypted with ${rounds}-round AES-128`} />
          <div className="cap">AES-128, {rounds} round{rounds === 1 ? '' : 's'} · key {keyHex.slice(0, 8)}…</div>
        </div>
      </div>
      <div style={{ marginTop: '1rem' }}>
        <Stat label="Avalanche at this round count" value={avalanche?.ok ? `${(avalanche.value * 100).toFixed(1)}%` : '—'}
          tone={avalanche?.ok && avalanche.value > 0.45 && avalanche.value < 0.55 ? 'ok' : 'warn'}
          sub="fraction of output bits that flip when one key bit does — ideal is 50%" />
      </div>
      <Note title="Reading the picture">
        At one or two rounds the outline is still visible: SubBytes and ShiftRows have barely mixed the state, and
        MixColumns has only touched one column at a time. By four rounds every output byte depends on every input byte and
        the avalanche has already reached its ceiling near 50% — the standard runs six more rounds beyond that not because
        diffusion needs it, but as a security margin against attacks that shave rounds off through structural shortcuts.
      </Note>
    </Panel>
  );
}

/* --------------------------------------------------------------------------
   Keystream reuse: two different images encrypted under the same CTR
   key and nonce. XOR-ing the ciphertexts cancels the keystream and leaves
   the XOR of the two plaintexts — the many-time-pad break.
   ---------------------------------------------------------------------- */
function drawScene2(ctx: CanvasRenderingContext2D) {
  ctx.fillStyle = '#e8e4d8';
  ctx.fillRect(0, 0, SIZE, SIZE);
  ctx.strokeStyle = '#1f2a44';
  ctx.lineWidth = 6;
  ctx.beginPath(); ctx.arc(64, 52, 20, Math.PI, 0); ctx.stroke();
  ctx.fillStyle = '#1f2a44';
  ctx.fillRect(34, 52, 60, 46);
  ctx.fillStyle = '#d9a441';
  ctx.beginPath(); ctx.arc(64, 72, 8, 0, Math.PI * 2); ctx.fill();
  ctx.fillRect(60, 72, 8, 16);
}

function KeystreamReusePanel({ ready }: { ready: boolean }) {
  const refs = { a: useRef<HTMLCanvasElement>(null), b: useRef<HTMLCanvasElement>(null), ca: useRef<HTMLCanvasElement>(null), cb: useRef<HTMLCanvasElement>(null), xor: useRef<HTMLCanvasElement>(null) };
  const [seed, setSeed] = useState(0);
  const [keyHex, setKeyHex] = useState('');

  useEffect(() => {
    if (!ready) return;
    const key = new Uint8Array(16); crypto.getRandomValues(key);
    const nonce = new Uint8Array(16); crypto.getRandomValues(nonce);
    setKeyHex(bytesToHex(key));

    const pa = refs.a.current!.getContext('2d')!; drawScene(pa);
    const pb = refs.b.current!.getContext('2d')!; drawScene2(pb);
    const rgbaA = pa.getImageData(0, 0, SIZE, SIZE).data;
    const rgbaB = pb.getImageData(0, 0, SIZE, SIZE).data;

    const ctA = wasm.BlockCiphers.aes_encrypt_bytes('ctr', key, nonce, new Uint8Array(rgbaA));
    const ctB = wasm.BlockCiphers.aes_encrypt_bytes('ctr', key, nonce, new Uint8Array(rgbaB));

    const xored = new Uint8Array(ctA.length);
    for (let i = 0; i < ctA.length; i += 4) {
      xored[i] = ctA[i] ^ ctB[i];
      xored[i + 1] = ctA[i + 1] ^ ctB[i + 1];
      xored[i + 2] = ctA[i + 2] ^ ctB[i + 2];
      xored[i + 3] = 255; // alpha would XOR to 0 (both forced 255) and vanish
    }
    for (let i = 3; i < ctA.length; i += 4) { ctA[i] = 255; ctB[i] = 255; }

    refs.ca.current!.getContext('2d')!.putImageData(new ImageData(new Uint8ClampedArray(ctA), SIZE, SIZE), 0, 0);
    refs.cb.current!.getContext('2d')!.putImageData(new ImageData(new Uint8ClampedArray(ctB), SIZE, SIZE), 0, 0);
    refs.xor.current!.getContext('2d')!.putImageData(new ImageData(new Uint8ClampedArray(xored), SIZE, SIZE), 0, 0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, seed]);

  return (
    <Panel title="Reusing a key and nonce" refs={['many-time pad']}
      action={<Button size="sm" onClick={() => setSeed((s) => s + 1)} disabled={!ready}>New key and nonce</Button>}>
      <p className="muted small">
        CTR mode turns AES into a stream cipher: ciphertext = plaintext XOR keystream, where the keystream depends only on
        the key and nonce, never the data. That is fine exactly once per (key, nonce) pair. Encrypt two different images
        under the <em>same</em> key and nonce and XOR the two ciphertexts together — the identical keystream cancels out,
        leaving the XOR of the two plaintexts, with the key never entering the calculation at all.
      </p>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(5, minmax(0, 1fr))' }}>
        {([['a', 'image A'], ['b', 'image B'], ['ca', 'ciphertext A'], ['cb', 'ciphertext B'], ['xor', 'ciphertext A ⊕ ciphertext B']] as const).map(([k, label]) => (
          <div key={k} className="canvas-box">
            <canvas ref={refs[k]} width={SIZE} height={SIZE} aria-label={label} />
            <div className="cap">{label}</div>
          </div>
        ))}
      </div>
      <p className="muted small" style={{ marginTop: '0.75rem' }}>
        Key <code>{keyHex.slice(0, 16)}…</code> reused for both. The two ciphertexts on their own are indistinguishable
        from noise; their XOR is not.
      </p>
      <Note title="Why nonces have rules">
        This is the same failure as a one-time pad reused twice — the &quot;time&quot; in one-time is load-bearing. It has broken
        real systems: Microsoft&apos;s PPTP implementation, an early Wi-Fi WEP design, and multiple VPN products all reused a
        keystream somewhere. The fix is procedural, not cryptographic: a nonce must never repeat under a given key, which
        is why GCM (§2 above) and TLS (§8) derive it from a counter that can only go forward.
      </Note>
    </Panel>
  );
}
