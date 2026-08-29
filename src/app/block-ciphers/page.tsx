'use client';

import { useEffect, useRef, useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { bytesToHex, hexToText, isHex, randomHex, textToHex } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Output, Status, ErrorText, Button, Tag } from '@/components/ui';

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

      <EcbImageDemo ready={ready} />
    </Page>
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
