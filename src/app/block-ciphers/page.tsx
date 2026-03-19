'use client';

import { useState, useEffect } from 'react';
import init, { BlockCiphers } from '../../../public/pkg/wasm_crypto';

export default function BlockCiphersPage() {
  const [isReady, setIsReady] = useState(false);
  
  // AES State
  const [hexInput, setHexInput] = useState('00112233445566778899aabbccddeeff');
  const [hexKey, setHexKey] = useState('000102030405060708090a0b0c0d0e0f');
  const [hexIv, setHexIv] = useState('0f0e0d0c0b0a09080706050403020100');
  const [aesMode, setAesMode] = useState<'ECB'|'CBC'>('CBC');
  const [aesAction, setAesAction] = useState<'encrypt'|'decrypt'>('encrypt');
  const [hexOutput, setHexOutput] = useState('');

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => setIsReady(true)).catch(console.error);
  }, []);

  const handleExecute = () => {
    if (!isReady) return;
    try {
      let res = '';
      if (aesMode === 'ECB') {
        if (aesAction === 'encrypt') res = BlockCiphers.aes128_ecb_encrypt(hexKey, hexInput);
        else res = BlockCiphers.aes128_ecb_decrypt(hexKey, hexInput);
      } else {
        if (aesAction === 'encrypt') res = BlockCiphers.aes128_cbc_encrypt(hexKey, hexIv, hexInput);
        else res = BlockCiphers.aes128_cbc_decrypt(hexKey, hexIv, hexInput);
      }
      setHexOutput(res);
    } catch (e: any) {
      setHexOutput("Error: " + e.toString());
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Block Ciphers</h1>

      <section className="glass-panel">
        <h2 className="card-title">AES-128 Operations</h2>
        
        <div className="responsive-grid" style={{ marginBottom: '1.5rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Mode</label>
            <select 
              value={aesMode} onChange={(e) => setAesMode(e.target.value as any)}
              style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px' }}
            >
              <option value="ECB">Electronic Codebook (ECB)</option>
              <option value="CBC">Cipher Block Chaining (CBC)</option>
            </select>
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Action</label>
            <select 
              value={aesAction} onChange={(e) => setAesAction(e.target.value as any)}
              style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px' }}
            >
              <option value="encrypt">Encrypt</option>
              <option value="decrypt">Decrypt</option>
            </select>
          </div>
        </div>

        <div className="responsive-grid" style={{ marginBottom: '1.5rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Key (32 hex chars / 16 bytes)</label>
            <input 
              type="text" value={hexKey} onChange={(e) => setHexKey(e.target.value)}
              style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}
            />
          </div>
          {aesMode === 'CBC' && (
            <div className="animate-fade-in">
              <label style={{ display: 'block', marginBottom: '0.5rem' }}>Initialization Vector (32 hex chars / 16 bytes)</label>
              <input 
                type="text" value={hexIv} onChange={(e) => setHexIv(e.target.value)}
                style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}
              />
            </div>
          )}
        </div>

        <div style={{ marginBottom: '1rem' }}>
          <label style={{ display: 'block', marginBottom: '0.5rem' }}>{aesAction === 'encrypt' ? 'Plaintext (Hex)' : 'Ciphertext (Hex)'}</label>
          <textarea 
            value={hexInput} onChange={(e) => setHexInput(e.target.value)}
            style={{ width: '100%', height: '80px', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}
          />
        </div>

        <button 
          onClick={handleExecute} disabled={!isReady}
          style={{ width: '100%', padding: '0.8rem', background: 'var(--accent-cyan)', color: 'black', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 600, marginBottom: '1rem' }}
        >{isReady ? `Execute AES-128 ${aesMode}` : 'Loading WASM...'}</button>

        <div>
          <label style={{ display: 'block', marginBottom: '0.5rem' }}>Output (Hex)</label>
          <pre style={{ minHeight: '60px', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{hexOutput}</pre>
        </div>
      </section>
      
      <section className="glass-panel">
         <h2 className="card-title">ECB vs CBC Mode Visualization</h2>
         <p style={{ opacity: 0.8, marginBottom: '1.5rem', lineHeight: 1.6 }}>
           In Electronic Codebook (ECB) mode, identical plaintext blocks are encrypted to identical ciphertext blocks.
           This leads to pattern leakage. Cipher Block Chaining (CBC) prevents this by XOR-ing each block with the previous ciphertext block.
         </p>
         <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2rem', justifyContent: 'space-between', alignItems: 'center' }}>
           <div style={{ flex: 1, textAlign: 'center' }}>
             <div style={{ width: '100%', aspectRatio: '1', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#ccc', color: '#111', fontWeight: 'bold', fontSize: '2rem', borderRadius: '8px' }}>
               [IMAGE]
             </div>
             <p style={{ marginTop: '0.5rem', fontWeight: 500 }}>Original Image</p>
           </div>
           
           <div style={{ fontSize: '2rem', opacity: 0.5 }}>-&gt;</div>
           
           <div style={{ flex: 1, textAlign: 'center' }}>
             <div style={{ width: '100%', aspectRatio: '1', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'radial-gradient(circle, #333 10px, #111 11px) 0 0 / 20px 20px', borderRadius: '8px'}}>
               <span style={{ fontSize: '2rem', filter: 'grayscale(100%) contrast(1000%)' }}>[IMAGE]</span>
             </div>
             <p style={{ marginTop: '0.5rem', fontWeight: 500, color: 'var(--accent-cyan)' }}>ECB Mode (Leaks Pattern)</p>
           </div>
           
           <div style={{ fontSize: '2rem', opacity: 0.5 }}>-&gt;</div>
           
           <div style={{ flex: 1, textAlign: 'center' }}>
             <div style={{ width: '100%', aspectRatio: '1', background: 'repeating-linear-gradient(45deg, #111, #111 10px, #222 10px, #222 20px)', borderRadius: '8px', opacity: 0.8, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
               <span style={{ fontSize: '1rem', color: '#555', fontFamily: 'var(--font-mono)' }}>0x...</span>
             </div>
             <p style={{ marginTop: '0.5rem', fontWeight: 500, color: 'var(--accent-teal)' }}>CBC Mode (Secure)</p>
           </div>
         </div>
      </section>
    </div>
  );
}
