'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Field, TextInput, TextArea, Select, Segmented, Range, Output, Stat, Status, ErrorText, Button } from '@/components/ui';

const COPRIME_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
const LETTERS = Array.from({ length: 26 }, (_, i) => String.fromCharCode(65 + i));

const SAMPLE = 'It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way.';

type Mode = 'encrypt' | 'decrypt';
type Shift = 'caesar' | 'atbash' | 'affine';

export default function ClassicalCiphers() {
  const state = useWasm();
  const ready = state === 'ready';
  const C = wasm.ClassicalCipher;

  // Monoalphabetic ciphers
  const [text, setText] = useState('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG');
  const [cipher, setCipher] = useState<Shift>('caesar');
  const [shift, setShift] = useState(3);
  const [a, setA] = useState(5);
  const [b, setB] = useState(8);
  const [mode, setMode] = useState<Mode>('encrypt');

  const mono = ready ? attempt(() => {
    if (cipher === 'atbash') return C.atbash(text);
    if (cipher === 'affine') return mode === 'encrypt' ? C.affine_encrypt(text, a, b) : C.affine_decrypt(text, a, b);
    return mode === 'encrypt' ? C.caesar_encrypt(text, shift) : C.caesar_decrypt(text, shift);
  }) : null;
  const monoOut = mono?.ok ? mono.value : '';

  // Exhaustive Caesar search on whatever is currently in the output box
  const searchTarget = mode === 'encrypt' ? monoOut : text;
  const candidates = ready && searchTarget ? C.caesar_brute_force(searchTarget).map((pt, i) => ({ shift: i + 1, pt, chi: C.chi_squared_english(pt) })) : [];
  const bestShift = candidates.length ? candidates.reduce((m, c) => (c.chi < m.chi ? c : m)).shift : 0;

  // Vigenère
  const [vText, setVText] = useState('ATTACK AT DAWN');
  const [vKey, setVKey] = useState('LEMON');
  const [vMode, setVMode] = useState<Mode>('encrypt');
  const vig = ready ? attempt(() => (vMode === 'encrypt' ? C.vigenere_encrypt(vText, vKey) : C.vigenere_decrypt(vText, vKey))) : null;
  const vOut = vig?.ok ? vig.value : '';
  const freqText = vOut || vText;
  const freqs = ready ? Array.from(C.letter_frequencies(freqText)) : [];
  const english = ready ? Array.from(C.english_frequencies()) : [];
  const ioc = ready ? C.index_of_coincidence(freqText) : 0;
  const maxFreq = Math.max(1, ...freqs, ...english);

  // Cryptanalysis
  const [ctInput, setCtInput] = useState('');
  const [period, setPeriod] = useState<number | null>(null);
  const sampleCt = ready ? C.vigenere_encrypt(SAMPLE, 'LEMON') : '';
  const ct = ctInput.trim() ? ctInput : sampleCt;
  const nLetters = ct.replace(/[^A-Za-z]/g, '').length;
  const maxPeriod = Math.min(20, Math.max(1, Math.floor(nLetters / 15)));
  const iocs = ready && ct ? Array.from(C.ioc_by_period(ct, maxPeriod)) : [];
  // Multiples of the key length also score high, so take the smallest period
  // that reaches the English value rather than the global maximum.
  const firstEnglish = iocs.findIndex((v) => v >= 0.064);
  const autoPeriod = iocs.length ? (firstEnglish >= 0 ? firstEnglish + 1 : iocs.indexOf(Math.max(...iocs)) + 1) : 1;
  const chosen = period ?? autoPeriod;
  const recovered = ready && ct ? attempt(() => C.vigenere_recover_key(ct, chosen)) : null;
  const recoveredKey = recovered?.ok ? recovered.value : '';
  const broken = ready && recoveredKey ? attempt(() => C.vigenere_decrypt(ct, recoveredKey)) : null;

  return (
    <Page kicker="§1 · Classical ciphers" title="Classical ciphers"
      lede="Substitution ciphers operate on the 26-letter alphabet; other characters pass through unchanged. Every one of them is broken by counting letters — the same statistics are shown here for the attacker's side.">
      <Status state={state} />

      <Panel title="Monoalphabetic substitution" refs={['shift cipher', 'affine']}>
        <div className="grid-2">
          <Field label="Text">{(id) => <TextArea id={id} mono value={text} onChange={(e) => setText(e.target.value)} rows={5} disabled={!ready} />}</Field>
          <div className="stack">
            <Field label="Cipher">{(id) => (
              <Select id={id} value={cipher} onChange={(e) => setCipher(e.target.value as Shift)} disabled={!ready}>
                <option value="caesar">Caesar — E(x) = x + k mod 26</option>
                <option value="affine">Affine — E(x) = a·x + b mod 26</option>
                <option value="atbash">Atbash — E(x) = 25 − x</option>
              </Select>
            )}</Field>
            {cipher === 'caesar' && <Range label="Shift k" min={1} max={25} value={shift} onChange={setShift} disabled={!ready} />}
            {cipher === 'affine' && (
              <div className="grid-2">
                <Field label="a" hint="coprime with 26">{(id) => (
                  <Select id={id} value={a} onChange={(e) => setA(Number(e.target.value))} disabled={!ready}>
                    {COPRIME_A.map((v) => <option key={v} value={v}>{v}</option>)}
                  </Select>
                )}</Field>
                <Field label="b">{(id) => (
                  <Select id={id} value={b} onChange={(e) => setB(Number(e.target.value))} disabled={!ready}>
                    {Array.from({ length: 26 }, (_, i) => <option key={i} value={i}>{i}</option>)}
                  </Select>
                )}</Field>
              </div>
            )}
            {cipher !== 'atbash' && (
              <Segmented label="Direction" value={mode} onChange={setMode} disabled={!ready}
                options={[{ value: 'encrypt', label: 'Encrypt' }, { value: 'decrypt', label: 'Decrypt' }]} />
            )}
          </div>
        </div>
        <hr className="divider" />
        <Output label={mode === 'encrypt' || cipher === 'atbash' ? 'Ciphertext' : 'Plaintext'} value={monoOut} ariaLabel="Substitution output" />
        <ErrorText error={mono && !mono.ok ? mono.error : null} />
        {cipher === 'affine' && (
          <p className="muted small" style={{ marginTop: '0.75rem' }}>
            Key space: 12 choices of <code>a</code> × 26 of <code>b</code> = 312 keys; Caesar is the special case a = 1. Decryption uses a⁻¹ = {ready ? COPRIME_A.find((x) => (x * a) % 26 === 1) : '…'} (mod 26).
          </p>
        )}
      </Panel>

      <Panel title="Exhaustive key search" refs={['χ² statistic']}>
        <p className="muted small">
          A Caesar key space of 25 is searched by trial. Candidates are ranked by the chi-squared distance between their letter
          distribution and English; the lowest value is almost always the plaintext once the text exceeds a few dozen letters.
          Applied to the {mode === 'encrypt' ? 'ciphertext above' : 'input above'}.
        </p>
        <div className="table-wrap" style={{ minHeight: '31rem' }}>
          <table className="table">
            <thead><tr><th>Shift</th><th>χ²</th><th>Candidate</th></tr></thead>
            <tbody>
              {candidates.map((c) => (
                <tr key={c.shift} style={c.shift === bestShift ? { color: 'var(--ok)' } : undefined}>
                  <td className="mono">{c.shift}</td>
                  <td className="mono">{Number.isFinite(c.chi) ? c.chi.toFixed(1) : '—'}</td>
                  <td className="mono">{c.pt.length > 72 ? `${c.pt.slice(0, 72)}…` : c.pt}</td>
                </tr>
              ))}
              {!candidates.length && <tr><td colSpan={3} className="faint">No ciphertext yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Vigenère cipher" refs={['polyalphabetic']}>
        <div className="grid-2">
          <Field label="Text">{(id) => <TextArea id={id} mono value={vText} onChange={(e) => setVText(e.target.value)} rows={4} disabled={!ready} />}</Field>
          <div className="stack">
            <Field label="Key" hint="letters only">{(id) => <TextInput id={id} mono value={vKey} onChange={(e) => setVKey(e.target.value)} disabled={!ready} invalid={!!vig && !vig.ok} />}</Field>
            <Segmented label="Direction" value={vMode} onChange={setVMode} disabled={!ready}
              options={[{ value: 'encrypt', label: 'Encrypt' }, { value: 'decrypt', label: 'Decrypt' }]} />
          </div>
        </div>
        <hr className="divider" />
        <Output label={vMode === 'encrypt' ? 'Ciphertext' : 'Plaintext'} value={vOut} ariaLabel="Vigenère output" />
        <ErrorText error={vig && !vig.ok ? vig.error : null} />
        <hr className="divider" />
        <div className="grid" style={{ gridTemplateColumns: 'minmax(0, 3fr) minmax(0, 1fr)' }}>
          <div>
            <div className="label" style={{ marginBottom: '0.5rem' }}><span>Letter frequencies of the {vOut ? 'output' : 'input'}</span><span className="hint">bars: text · ticks: English</span></div>
            <div className="bars" role="img" aria-label="Letter frequency histogram">
              {LETTERS.map((L, i) => (
                <div key={L} className="bar">
                  <div className="bar-value">{freqs[i] > 0 ? freqs[i].toFixed(0) : ''}</div>
                  <div style={{ width: '100%', position: 'relative', height: `${(Math.max(freqs[i] ?? 0, 0) / maxFreq) * 100}%` }}>
                    <div className="bar-fill" style={{ height: '100%' }} />
                  </div>
                  <div className="bar-label">{L}</div>
                </div>
              ))}
            </div>
            <div className="bars" style={{ height: 40, borderBottom: 0, marginTop: 2 }} aria-hidden="true">
              {LETTERS.map((L, i) => (
                <div key={L} className="bar"><div className="bar-fill ref" style={{ height: `${((english[i] ?? 0) / maxFreq) * 100}%` }} /></div>
              ))}
            </div>
          </div>
          <Stat label="Index of coincidence" value={ready ? ioc.toFixed(4) : '—'}
            sub={<>English ≈ 0.0667 · uniform ≈ 0.0385. {ioc > 0.055 ? 'Monoalphabetic or plaintext.' : ioc > 0.0 ? 'Flattened: polyalphabetic.' : ''}</>}
            tone={ioc > 0.055 ? 'ok' : 'accent'} />
        </div>
        <Note title="Why it flattens">
          Each key letter selects a different Caesar alphabet, so a plaintext letter no longer maps to a single ciphertext
          letter. The histogram of the ciphertext becomes flatter and the index of coincidence drops toward the uniform value — but
          only when the whole text is considered together.
        </Note>
      </Panel>

      <Panel title="Cryptanalysis: recovering a Vigenère key" refs={['Friedman test', 'χ² per column']}
        action={<Button size="sm" onClick={() => { setCtInput(vOut); setPeriod(null); }} disabled={!vOut}>Use Vigenère output</Button>}>
        <Field label="Ciphertext" hint="empty = built-in sample (Dickens, key LEMON)">{(id) => (
          <TextArea id={id} mono rows={4} value={ctInput} placeholder={sampleCt.slice(0, 200)} onChange={(e) => { setCtInput(e.target.value); setPeriod(null); }} disabled={!ready} />
        )}</Field>
        <hr className="divider" />
        <div className="label" style={{ marginBottom: '0.5rem' }}><span>Step 1 — mean index of coincidence by assumed key length</span><span className="hint">click a bar to choose</span></div>
        <div className="bars" role="group" aria-label="Index of coincidence by period">
          {iocs.map((v, i) => {
            const p = i + 1;
            return (
              <button key={p} type="button" className="bar" onClick={() => setPeriod(p)} aria-pressed={p === chosen} title={`period ${p}: IoC ${v.toFixed(4)}`}
                style={{ background: 'none', border: 0, padding: 0, cursor: 'pointer' }}>
                <div className="bar-value">{v.toFixed(3)}</div>
                <div className="bar-fill" style={{ height: `${(v / 0.08) * 100}%`, opacity: p === chosen ? 1 : 0.4 }} />
                <div className="bar-label">{p}</div>
              </button>
            );
          })}
        </div>
        <p className="muted small" style={{ marginTop: '0.6rem' }}>
          Splitting the text into <em>p</em> interleaved columns undoes the polyalphabetic mixing only when <em>p</em> is the key
          length (or a multiple): each column is then a plain Caesar cipher and its IoC returns to the English value.
        </p>
        <div className="grid-3" style={{ marginTop: '0.75rem' }}>
          <Stat label="Chosen key length" value={chosen} sub={period === null ? 'first period with IoC ≥ 0.064' : 'manual'} />
          <Stat label="Step 2 — recovered key" value={recoveredKey || '—'} tone="accent" sub="best χ² shift per column" />
          <Stat label="Letters analysed" value={nLetters} sub={`periods up to ${maxPeriod} (≥ 15 letters per column)`} />
        </div>
        <ErrorText error={recovered && !recovered.ok ? recovered.error : null} />
        <div style={{ marginTop: '0.75rem' }}>
          <Output label="Step 3 — plaintext under the recovered key" value={broken?.ok ? broken.value : ''} scroll ariaLabel="Recovered plaintext" />
        </div>
      </Panel>
    </Page>
  );
}
