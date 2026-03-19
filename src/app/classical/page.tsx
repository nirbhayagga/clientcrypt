'use client';

import { useState, useEffect } from 'react';
import init, { ClassicalCipher } from '../../../public/pkg/wasm_crypto';

export default function ClassicalCiphers() {
  const [isReady, setIsReady] = useState(false);
  
  // Caesar State
  const [caesarInput, setCaesarInput] = useState('HELLO SECRETS');
  const [caesarShift, setCaesarShift] = useState(3);
  const [caesarAction, setCaesarAction] = useState<'encrypt'|'decrypt'>('encrypt');
  const [caesarOutput, setCaesarOutput] = useState('');
  const [bruteForceResults, setBruteForceResults] = useState<string[]>([]);
  
  // Vigenere State
  const [vigenereInput, setVigenereInput] = useState('HELLO SECRETS');
  const [vigenereKey, setVigenereKey] = useState('KEY');
  const [vigenereAction, setVigenereAction] = useState<'encrypt'|'decrypt'>('encrypt');
  const [vigenereOutput, setVigenereOutput] = useState('');
  const [freqData, setFreqData] = useState<number[]>([]);

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => setIsReady(true)).catch(console.error);
  }, []);

  useEffect(() => {
    if (!isReady) return;
    try {
      if (caesarAction === 'encrypt') {
        setCaesarOutput(ClassicalCipher.caesar_encrypt(caesarInput, caesarShift));
      } else {
        setCaesarOutput(ClassicalCipher.caesar_decrypt(caesarInput, caesarShift));
      }
    } catch (e) {
      console.error(e);
    }
  }, [caesarInput, caesarShift, caesarAction, isReady]);

  useEffect(() => {
    if (!isReady) return;
    try {
      let out = '';
      if (vigenereAction === 'encrypt') {
        out = ClassicalCipher.vigenere_encrypt(vigenereInput, vigenereKey);
      } else {
        out = ClassicalCipher.vigenere_decrypt(vigenereInput, vigenereKey);
      }
      setVigenereOutput(out);
      const freqs = ClassicalCipher.vigenere_frequency_analysis(out || vigenereInput);
      setFreqData(Array.from(freqs));
    } catch (e) {
      console.error(e);
    }
  }, [vigenereInput, vigenereKey, vigenereAction, isReady]);

  const handleBruteForce = () => {
    if (!isReady) return;
    try {
      const results = ClassicalCipher.caesar_brute_force(caesarOutput || caesarInput);
      setBruteForceResults(results);
    } catch (e) {
      console.error(e);
    }
  };

  if (!isReady) return <div style={{ padding: '2rem' }}>Loading Crypto Engine...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Classical Ciphers</h1>

      <section className="glass-panel">
        <h2 className="card-title">Caesar Cipher</h2>
        <div className="responsive-grid" style={{ marginBottom: '1.5rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 500 }}>Text Input</label>
            <textarea
              style={{ width: '100%', minHeight: '140px', resize: 'vertical', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '8px', padding: '1rem', fontFamily: 'var(--font-mono)' }}
              value={caesarInput}
              onChange={(e) => setCaesarInput(e.target.value.toUpperCase())}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 500 }}>Shift Amount: <span style={{ color: 'var(--accent-cyan)' }}>{caesarShift}</span></label>
            <input 
              type="range" min="1" max="25" 
              value={caesarShift} onChange={(e) => setCaesarShift(parseInt(e.target.value))}
              style={{ width: '100%', marginBottom: '1.5rem' }}
            />
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
              <button 
                onClick={() => setCaesarAction('encrypt')}
                style={{ flex: 1, padding: '0.8rem', background: caesarAction==='encrypt' ? 'var(--accent-cyan)' : 'var(--panel-bg)', color: caesarAction==='encrypt' ? '#000' : 'white', border: '1px solid var(--panel-border)', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, transition: 'all 0.2s' }}
              >Encrypt</button>
              <button 
                onClick={() => setCaesarAction('decrypt')}
                style={{ flex: 1, padding: '0.8rem', background: caesarAction==='decrypt' ? 'var(--accent-cyan)' : 'var(--panel-bg)', color: caesarAction==='decrypt' ? '#000' : 'white', border: '1px solid var(--panel-border)', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, transition: 'all 0.2s' }}
              >Decrypt</button>
            </div>
            <button 
              onClick={handleBruteForce}
              style={{ width: '100%', padding: '0.8rem', background: 'rgba(45, 212, 191, 0.1)', border: '1px solid var(--accent-teal)', color: 'var(--accent-teal)', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, transition: 'all 0.2s' }}
            >Execute Brute-Force Attack</button>
          </div>
        </div>
        
        <div>
          <label style={{ display: 'block', marginBottom: '0.5rem' }}>Output</label>
          <pre style={{ minHeight: '60px', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{caesarOutput}</pre>
        </div>

        {bruteForceResults.length > 0 && (
          <div className="animate-fade-in" style={{ marginTop: '1rem', background: 'var(--panel-bg)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
            <h3 style={{ marginBottom: '0.5rem', fontSize: '1rem', color: 'var(--accent-cyan)' }}>Brute-Force Diagnostics</h3>
            <div style={{ maxHeight: '200px', overflowY: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              {bruteForceResults.map((res, i) => (
                <div key={i} style={{ fontSize: '0.9rem', padding: '0.2rem', fontFamily: 'var(--font-mono)' }}>{res}</div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="glass-panel">
        <h2 className="card-title">Vigenere Cipher</h2>
        <div className="responsive-grid" style={{ marginBottom: '1.5rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 500 }}>Text Input</label>
            <textarea
              style={{ width: '100%', minHeight: '140px', resize: 'vertical', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '8px', padding: '1rem', fontFamily: 'var(--font-mono)' }}
              value={vigenereInput}
              onChange={(e) => setVigenereInput(e.target.value.toUpperCase())}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 500 }}>Key String</label>
            <input 
              type="text" 
              value={vigenereKey} onChange={(e) => setVigenereKey(e.target.value.toUpperCase())}
              style={{ width: '100%', marginBottom: '1.5rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '6px', padding: '0.8rem', fontFamily: 'var(--font-mono)' }}
            />
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button 
                onClick={() => setVigenereAction('encrypt')}
                style={{ flex: 1, padding: '0.8rem', background: vigenereAction==='encrypt' ? 'var(--accent-teal)' : 'var(--panel-bg)', color: vigenereAction==='encrypt' ? '#000' : 'white', border: '1px solid var(--panel-border)', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, transition: 'all 0.2s' }}
              >Encrypt</button>
              <button 
                onClick={() => setVigenereAction('decrypt')}
                style={{ flex: 1, padding: '0.8rem', background: vigenereAction==='decrypt' ? 'var(--accent-teal)' : 'var(--panel-bg)', color: vigenereAction==='decrypt' ? '#000' : 'white', border: '1px solid var(--panel-border)', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, transition: 'all 0.2s' }}
              >Decrypt</button>
            </div>
          </div>
        </div>

        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ display: 'block', marginBottom: '0.5rem' }}>Output</label>
          <pre style={{ minHeight: '60px', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{vigenereOutput}</pre>
        </div>

        <div>
           <h3 style={{ marginBottom: '1rem', fontSize: '1rem', color: 'var(--accent-teal)' }}>Frequency Analysis Distribution (A-Z)</h3>
           <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '100px', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.2rem' }}>
             {freqData.map((pct, i) => (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', alignItems: 'center', height: '100%' }}>
                  <span style={{ fontSize: '9px', opacity: 0.7, marginBottom: '4px', display: pct > 0 ? 'block' : 'none' }}>{pct.toFixed(1)}%</span>
                  <div style={{ width: '100%', background: 'var(--accent-teal)', height: `${Math.max(pct, 1)}%`, borderRadius: '2px 2px 0 0', opacity: pct > 0 ? 1 : 0.2 }}></div>
                  <span style={{ fontSize: '10px', marginTop: '4px', fontWeight: 600 }}>{String.fromCharCode(65 + i)}</span>
                </div>
             ))}
           </div>
        </div>
      </section>
    </div>
  );
}
