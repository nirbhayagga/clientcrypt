'use client';

import { useState } from 'react';
import { useWasm, wasm, attempt } from '@/lib/wasm';
import { Page, Panel, Note, Callout, Field, TextInput, TextArea, Select, Segmented, Range, Output, Stat, Status, ErrorText, Button, Tag } from '@/components/ui';
import { randomHex } from '@/lib/bytes';

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

  // Exhaustive key search on whatever is currently in the output box,
  // ranked by the crate (chi-squared against English, lowest first).
  const searchTarget = mode === 'encrypt' ? monoOut : text;
  const candidates: { key: string; chi: number; text: string }[] =
    ready && searchTarget && cipher !== 'atbash'
      ? (C.key_search(cipher, searchTarget) as { key: string; chi: number; text: string }[])
      : [];
  const shown = cipher === 'affine' ? candidates.slice(0, 12) : candidates;

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

      <Panel title="Exhaustive key search" refs={['χ² statistic']}
        action={cipher !== 'atbash' ? <Tag>{cipher === 'affine' ? '312 keys' : '25 keys'}</Tag> : undefined}>
        {cipher === 'atbash' ? (
          <Note title="Nothing to search">
            Atbash has no key: E(x) = 25 − x is one fixed permutation, and it is an involution, so applying it a second
            time already returns the plaintext. A cipher with a key space of one offers no security to search through.
          </Note>
        ) : (
          <>
            <p className="muted small">
              {`The whole ${cipher === 'affine' ? 'affine key space — 12 valid values of a × 26 of b = 312 keys —' : 'Caesar key space of 25 shifts'} is tried against the ${mode === 'encrypt' ? 'ciphertext above' : 'input above'} and ranked by the chi-squared distance between each candidate's letter distribution and English. The lowest value is almost always the plaintext once the text exceeds a few dozen letters${cipher === 'affine' ? '; only the 12 most English-like candidates are shown' : ''}.`}
            </p>
            <div className="table-wrap" style={{ minHeight: '31rem' }}>
              <table className="table">
                <thead><tr><th>Rank</th><th>Key</th><th>χ²</th><th>Candidate</th></tr></thead>
                <tbody>
                  {shown.map((c, i) => (
                    <tr key={c.key} style={i === 0 ? { color: 'var(--ok)' } : undefined}>
                      <td className="mono">{i + 1}</td>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{c.key}</td>
                      <td className="mono">{Number.isFinite(c.chi) ? c.chi.toFixed(1) : '—'}</td>
                      <td className="mono">{c.text.length > 64 ? `${c.text.slice(0, 64)}…` : c.text}</td>
                    </tr>
                  ))}
                  {!shown.length && <tr><td colSpan={4} className="faint">No ciphertext yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </>
        )}
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

      <EnigmaPanel ready={ready} />
      <OneTimePadPanel ready={ready} />
      <TwoTimePadPanel ready={ready} />
    </Page>
  );
}

/* Enigma --------------------------------------------------------------------- */

interface EnigmaResult { output: string; end_positions: string; letters_enciphered: number }

const ROTOR_NAMES = ['I', 'II', 'III', 'IV', 'V'];

function EnigmaPanel({ ready }: { ready: boolean }) {
  const [rotors, setRotors] = useState<[number, number, number]>([0, 1, 2]);
  const [positions, setPositions] = useState('AAA');
  const [rings, setRings] = useState('AAA');
  const [plugboard, setPlugboard] = useState('AV BS CG DL FU');
  const [text, setText] = useState('WEATHER REPORT FOR SECTOR SEVEN');

  const res = ready ? attempt(() => {
    const r = wasm.Enigma.run(new Uint32Array(rotors), positions, rings, plugboard, text) as EnigmaResult;
    // Running the output back through the same settings must return the input.
    const back = wasm.Enigma.run(new Uint32Array(rotors), positions, rings, plugboard, r.output) as EnigmaResult;
    return { ...r, roundtrip: back.output };
  }) : null;
  const r = res?.ok ? res.value : null;

  const setRotor = (slot: number, value: number) => {
    setRotors((prev) => prev.map((v, i) => (i === slot ? value : v)) as [number, number, number]);
  };

  return (
    <Panel title="The Enigma machine" refs={['Wehrmacht Enigma I', 'reflector B']}>
      <p className="muted small">
        Three rotors chosen from five, each a fixed scrambling of the alphabet that rotates as you type; a reflector that
        sends the signal back through all three; and a plugboard swapping letter pairs before and after. The wirings below
        are the historical ones. Because the signal path is symmetric, encryption and decryption are the <em>same</em>{' '}
        operation — type the ciphertext with the same settings and the plaintext comes back.
      </p>
      <div className="grid-3">
        {(['Left (slow)', 'Middle', 'Right (fast)'] as const).map((label, slot) => (
          <Field key={label} label={`${label} rotor`}>{(id) => (
            <Select id={id} value={rotors[slot]} onChange={(e) => setRotor(slot, Number(e.target.value))} disabled={!ready}>
              {ROTOR_NAMES.map((name, i) => <option key={name} value={i}>Rotor {name}</option>)}
            </Select>
          )}</Field>
        ))}
      </div>
      <div className="grid-3">
        <Field label="Rotor positions" hint="the day key, three letters">{(id) => (
          <TextInput id={id} mono value={positions} onChange={(e) => setPositions(e.target.value.toUpperCase())} maxLength={3} disabled={!ready} />
        )}</Field>
        <Field label="Ring settings" hint="offsets the wiring inside each rotor">{(id) => (
          <TextInput id={id} mono value={rings} onChange={(e) => setRings(e.target.value.toUpperCase())} maxLength={3} disabled={!ready} />
        )}</Field>
        <Field label="Plugboard pairs" hint="space-separated, e.g. AV BS">{(id) => (
          <TextInput id={id} mono value={plugboard} onChange={(e) => setPlugboard(e.target.value.toUpperCase())} disabled={!ready} />
        )}</Field>
      </div>
      <Field label="Message">{(id) => (
        <TextArea id={id} mono rows={2} value={text} onChange={(e) => setText(e.target.value)} disabled={!ready} />
      )}</Field>
      <ErrorText error={res && !res.ok ? res.error : null} />
      {r && (
        <>
          <div className="stack">
            <Output label="Enciphered" value={r.output} tone="accent" ariaLabel="Enigma output" />
            <Output label="The output run back through the same settings" value={r.roundtrip} copy={false} ariaLabel="Enigma roundtrip" />
          </div>
          <div className="grid-2" style={{ marginTop: '0.75rem' }}>
            <Stat label="Rotor windows after" value={r.end_positions} sub={`advanced by ${r.letters_enciphered} keystrokes`} />
            <Stat label="Settings space" value="~1.07 × 10²³" sub="rotor order × positions × rings × 10 plug pairs" />
          </div>
        </>
      )}
      <Note title="Strong machine, broken procedure">
        Notice that no letter ever encrypts to itself — the reflector guarantees it. That one property let Bletchley Park
        slide a guessed plaintext (&quot;WETTERBERICHT&quot;, a weather report) along the ciphertext and discard every position with a
        letter match, turning an astronomical key space into a bombe-sized search. Enigma fell not to a weakness in the rotor
        wiring but to predictable messages, reused indicator procedures, and this structural tell — the recurring lesson of
        this site: operating procedure is part of the cipher.
      </Note>
    </Panel>
  );
}

/* One-time pad ---------------------------------------------------------------- */

interface OtpCiphertext { key_hex: string; ciphertext_hex: string; length: number }
interface PadReuse { c1_hex: string; c2_hex: string; xor_hex: string }
interface CribHit { position: number; revealed: string }

function OneTimePadPanel({ ready }: { ready: boolean }) {
  const [msg, setMsg] = useState('ATTACK AT DAWN');
  const [enc, setEnc] = useState<OtpCiphertext | null>(null);
  const [encError, setEncError] = useState<string | null>(null);
  const [desired, setDesired] = useState('RETREAT AT SIX');

  const encrypt = () => {
    const r = attempt(() => wasm.Otp.encrypt(msg) as OtpCiphertext);
    if (r.ok) { setEnc(r.value); setEncError(null); } else { setEnc(null); setEncError(r.error); }
  };

  const forged = enc && ready ? attempt(() => {
    const key = wasm.Otp.forge_key(enc.ciphertext_hex, desired) as string;
    return { key, plaintext: wasm.Otp.decrypt(enc.ciphertext_hex, key) as string };
  }) : null;

  return (
    <Panel title="The one-time pad: the unbreakable exception" refs={['Vernam 1917', 'Shannon 1949']}
      action={<Button variant="primary" onClick={encrypt} disabled={!ready}>Encrypt with a fresh pad</Button>}>
      <p className="muted small">
        {'Every cipher above falls to statistics. This one provably cannot: XOR the message with a truly random key of '}
        <em>exactly</em>{' its own length, used '}<em>once</em>{'. Shannon proved the intercepted ciphertext is then independent of the '}
        {'message — and the demo below makes that concrete: for any claimed plaintext of the right length, a key exists that '}
        {'“decrypts” to it, so the ciphertext cannot testify against any of them.'}
      </p>
      <Field label="Message" hint={`${new TextEncoder().encode(msg).length} bytes — the pad will match it exactly`}>{(id) => (
        <TextInput id={id} mono value={msg} onChange={(e) => { setMsg(e.target.value); setEnc(null); }} disabled={!ready} />
      )}</Field>
      <ErrorText error={encError} />
      {enc && (
        <>
          <div className="stack">
            <Output label="The pad (random, same length, never reused)" value={enc.key_hex} ariaLabel="One-time pad key" />
            <Output label="Ciphertext = message ⊕ pad" value={enc.ciphertext_hex} tone="accent" ariaLabel="One-time pad ciphertext" />
          </div>
          <hr className="divider" />
          <Field label="Now claim it says something else" hint="any text with the same byte count">{(id) => (
            <TextInput id={id} mono value={desired} onChange={(e) => setDesired(e.target.value)} disabled={!ready} />
          )}</Field>
          <ErrorText error={forged && !forged.ok ? forged.error : null} />
          {forged?.ok && (
            <>
              <div className="stack">
                <Output label="A key computed as ciphertext ⊕ claimed plaintext" value={forged.value.key} copy={false} />
                <Output label="…which “decrypts” the very same ciphertext to" value={forged.value.plaintext} copy={false} ariaLabel="Forged decryption" />
              </div>
              <div style={{ marginTop: '0.75rem' }}>
                <Callout tone="info">
                  {'Both keys are uniformly random strings; nothing distinguishes the real one. An adversary holding only the '}
                  {'ciphertext faces every '}{String(enc.length)}{'-byte message as an equally plausible decryption — that is perfect '}
                  {'secrecy, and it holds against unlimited computing power. Only the length leaks.'}
                </Callout>
              </div>
            </>
          )}
        </>
      )}
      <Note title="Why it secures almost nothing">
        The proof charges full price: the key must be as long as all traffic ever sent, generated from true randomness,
        delivered secretly in advance, and destroyed after one use — at which point you might as well have handed over the
        message. The Moscow–Washington hotline really did run on couriered one-time tapes; everyone else buys{' '}
        <em>computational</em> secrecy instead: a stream cipher (§2) stretches a 256-bit key into an endless pseudorandom pad,
        secure only because nobody can afford the search — §14 puts numbers on what “afford” means.
      </Note>
    </Panel>
  );
}

// A fixed 32-byte pad so the reuse demo renders deterministically; the XOR of
// the two ciphertexts is independent of its value anyway — that is the flaw.
const DEMO_PAD = '8f3a1c96d24be0755eaf01c3b8d94a26e7135f80ca6d92b4076e58d13c2af9e4';

function TwoTimePadPanel({ ready }: { ready: boolean }) {
  const [m1, setM1] = useState('the attack begins at dawn');
  const [m2, setM2] = useState('the retreat is now sounded');
  const [pad, setPad] = useState(DEMO_PAD);
  const [crib, setCrib] = useState('attack');

  const reused = ready ? attempt(() => wasm.Otp.pad_reuse(m1, m2, pad) as PadReuse) : null;
  const r = reused?.ok ? reused.value : null;
  const dragged = r && crib ? attempt(() => wasm.Otp.crib_drag(r.xor_hex, crib) as CribHit[]) : null;
  const hits = dragged?.ok ? dragged.value : [];

  return (
    <Panel title="Break it yourself: the two-time pad" refs={['VENONA']}
      action={<Button size="sm" onClick={() => setPad(randomHex(32))} disabled={!ready}>New pad</Button>}>
      <p className="muted small">
        {'The “time” in one-time is load-bearing. Encrypt two messages under the same pad and XOR the two ciphertexts: the '}
        {'pad cancels out entirely, leaving the two plaintexts XORed with each other — no key involved. Then '}
        <strong>crib-drag</strong>{': slide a guessed word along that stream; wherever the guess is right, the other message '}
        {'shows through. Change the pad — the XOR below does not move.'}
      </p>
      <div className="grid-2">
        <Field label="Message 1">{(id) => (
          <TextInput id={id} mono value={m1} onChange={(e) => setM1(e.target.value)} disabled={!ready} />
        )}</Field>
        <Field label="Message 2">{(id) => (
          <TextInput id={id} mono value={m2} onChange={(e) => setM2(e.target.value)} disabled={!ready} />
        )}</Field>
      </div>
      <ErrorText error={reused && !reused.ok ? reused.error : null} />
      {r && (
        <>
          <div className="stack">
            <Output label="Ciphertext 1 = message 1 ⊕ pad" value={r.c1_hex} copy={false} />
            <Output label="Ciphertext 2 = message 2 ⊕ pad" value={r.c2_hex} copy={false} />
            <Output label="Ciphertext 1 ⊕ ciphertext 2 — the pad is gone" value={r.xor_hex} tone="accent" ariaLabel="Two-time pad XOR" />
          </div>
          <hr className="divider" />
          <Field label="Crib — a word you guess appears in one message" hint="try “dawn”, “the ”, or “sounded”">{(id) => (
            <TextInput id={id} mono value={crib} onChange={(e) => setCrib(e.target.value)} disabled={!ready} />
          )}</Field>
          <ErrorText error={dragged && !dragged.ok ? dragged.error : null} />
          {dragged?.ok && (
            <div className="table-wrap" style={{ marginTop: '0.5rem' }}>
              <table className="table">
                <thead><tr><th>Offset</th><th>Crib ⊕ stream — the other message, where the guess fits</th></tr></thead>
                <tbody>
                  {hits.map((h) => (
                    <tr key={h.position}><td className="mono">{h.position}</td><td className="mono">{h.revealed}</td></tr>
                  ))}
                  {hits.length === 0 && <tr><td colSpan={2} className="muted">No offset yields printable text — wrong guess.</td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      <Note title="VENONA">
        Under wartime pressure, Soviet cipher clerks reprinted about 35,000 one-time pad pages into duplicate books. That
        single procedural failure let US and UK cryptanalysts — reading pairs of messages exactly as above, with names and
        stock phrases as cribs — decrypt intelligence traffic for four decades, exposing the Rosenberg and Cambridge Five
        networks. The mathematics was perfect; the logistics were not. Nonce reuse in a modern stream cipher (§2) is this
        same failure wearing new clothes.
      </Note>
    </Panel>
  );
}
