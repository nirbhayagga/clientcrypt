'use client';

import { useState } from 'react';
import { attempt } from '@/lib/wasm';
import { bytesToHex, hexToBytes } from '@/lib/bytes';
import { Page, Panel, Note, Field, TextArea, Select, Segmented, Output, ErrorText } from '@/components/ui';

type Fmt = 'base64' | 'base64url' | 'hex' | 'url' | 'binary';
const FORMATS: { id: Fmt; name: string; std: string }[] = [
  { id: 'base64', name: 'Base64', std: 'RFC 4648 §4' },
  { id: 'base64url', name: 'Base64url (unpadded)', std: 'RFC 4648 §5' },
  { id: 'hex', name: 'Hexadecimal (Base16)', std: 'RFC 4648 §8' },
  { id: 'url', name: 'Percent-encoding', std: 'RFC 3986 §2.1' },
  { id: 'binary', name: 'Binary', std: '—' },
];

const b64 = (bytes: Uint8Array) => btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(''));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function encode(bytes: Uint8Array, fmt: Fmt): string {
  switch (fmt) {
    case 'base64': return b64(bytes);
    case 'base64url': return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    case 'hex': return bytesToHex(bytes);
    case 'url': return Array.from(bytes, (b) => (/[A-Za-z0-9\-_.~]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, '0')}`)).join('');
    case 'binary': return Array.from(bytes, (b) => b.toString(2).padStart(8, '0')).join(' ');
  }
}

function decode(text: string, fmt: Fmt): Uint8Array {
  const s = text.trim();
  switch (fmt) {
    case 'base64': return unb64(s);
    case 'base64url': return unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
    case 'hex': return hexToBytes(s);
    case 'url': { const out: number[] = []; for (let i = 0; i < s.length; i++) { if (s[i] === '%') { out.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2; } else out.push(s.charCodeAt(i)); } return Uint8Array.from(out); }
    case 'binary': return Uint8Array.from(s.split(/\s+/).filter(Boolean).map((b) => parseInt(b, 2)));
  }
}

export default function EncodingPage() {
  const [dir, setDir] = useState<'encode' | 'decode'>('encode');
  const [fmt, setFmt] = useState<Fmt>('base64');
  const [text, setText] = useState('Grüße, 世界! 🔐');
  const [encoded, setEncoded] = useState('SGVsbG8sIFdvcmxkIQ==');

  const bytes = dir === 'encode' ? new TextEncoder().encode(text) : attempt(() => decode(encoded, fmt));
  const decodedBytes = dir === 'encode' ? bytes as Uint8Array : (bytes as { ok: boolean; value?: Uint8Array }).ok ? (bytes as { value: Uint8Array }).value : null;
  const error = dir === 'decode' && !(bytes as { ok: boolean }).ok ? (bytes as { error: string }).error : null;
  const chars = decodedBytes ? Array.from(new TextDecoder().decode(decodedBytes)) : [];

  return (
    <Page kicker="§9 · Encodings" title="Binary-to-text encodings"
      lede="Encodings change the representation of bytes, not their secrecy: anyone can reverse them without a key. They appear throughout cryptography — PEM files are Base64, JWTs are Base64url, digests are printed as hex — which is exactly why they are often mistaken for encryption.">
      <Panel title="Convert" refs={FORMATS.map((f) => f.std).filter((s) => s !== '—').filter((v, i, a) => a.indexOf(v) === i)}
        action={<Segmented label="Direction" value={dir} onChange={setDir} options={[{ value: 'encode', label: 'Text → encoding' }, { value: 'decode', label: 'Encoding → text' }]} />}>
        <div className="grid-2">
          {dir === 'encode'
            ? <Field label="Text" hint={`${decodedBytes?.length ?? 0} UTF-8 bytes`}>{(id) => <TextArea id={id} rows={4} value={text} onChange={(e) => setText(e.target.value)} />}</Field>
            : <Field label="Encoded input">{(id) => <TextArea id={id} mono rows={4} value={encoded} onChange={(e) => setEncoded(e.target.value)} invalid={!!error} />}</Field>}
          <Field label="Format">{(id) => (
            <Select id={id} value={fmt} onChange={(e) => setFmt(e.target.value as Fmt)}>
              {FORMATS.map((f) => <option key={f.id} value={f.id}>{f.name} — {f.std}</option>)}
            </Select>
          )}</Field>
        </div>
        <hr className="divider" />
        <ErrorText error={error} />
        {dir === 'encode'
          ? <div className="stack">{FORMATS.map((f) => <Output key={f.id} label={f.name} value={decodedBytes ? encode(decodedBytes, f.id) : ''} tone={f.id === fmt ? 'accent' : undefined} />)}</div>
          : <Output label="Decoded text (UTF-8)" value={decodedBytes ? new TextDecoder().decode(decodedBytes) : ''} tone="accent" />}
      </Panel>

      <Panel title="Code points and UTF-8 bytes">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Character</th><th>Code point</th><th>UTF-8 bytes</th><th>Length</th></tr></thead>
            <tbody>
              {chars.slice(0, 64).map((ch, i) => {
                const b = new TextEncoder().encode(ch);
                return <tr key={i}><td className="mono">{ch === ' ' ? '␠' : ch}</td><td className="mono">U+{ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}</td><td className="mono">{Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(' ')}</td><td className="mono">{b.length}</td></tr>;
              })}
              {chars.length > 64 && <tr><td colSpan={4} className="faint">… {chars.length - 64} more</td></tr>}
            </tbody>
          </table>
        </div>
        <Note title="Why the byte layer matters">
          Every primitive on this site consumes bytes, so a string must be encoded first — and the same characters in UTF-8, UTF-16 or Latin-1 hash
          to different values. Base64 expands data by 4/3, hex by 2×; both are shown here so that outputs elsewhere on the site can be read in either form.
        </Note>
      </Panel>
    </Page>
  );
}
