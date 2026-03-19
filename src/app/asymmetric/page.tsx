'use client';

import { useState, useEffect } from 'react';
import init, { AsymmetricCrypto, Hasher } from '../../../public/pkg/wasm_crypto';

export default function AsymmetricPage() {
  const [isReady, setIsReady] = useState(false);
  
  // RSA Config
  const [rsaBits, setRsaBits] = useState(512); // Small for browser demo speed
  const [privKey, setPrivKey] = useState('');
  const [pubKey, setPubKey] = useState('');
  
  // RSA Encrypt/Decrypt
  const [ptInput, setPtInput] = useState('Secret Message');
  const [ctOutput, setCtOutput] = useState('');
  const [decryptedOutput, setDecryptedOutput] = useState('');

  // DH Config
  const [dhBits, setDhBits] = useState(256);
  const [dhP, setDhP] = useState('');
  const [dhG, setDhG] = useState('');
  
  // DH Alice
  const [alicePriv, setAlicePriv] = useState('12345');
  const [alicePub, setAlicePub] = useState('');
  const [aliceShared, setAliceShared] = useState('');

  // DH Bob
  const [bobPriv, setBobPriv] = useState('67890');
  const [bobPub, setBobPub] = useState('');
  const [bobShared, setBobShared] = useState('');

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => setIsReady(true)).catch(console.error);
  }, []);

  const handleGenRsa = () => {
    try {
      const keys = AsymmetricCrypto.rsa_generate_keys(rsaBits);
      setPrivKey(keys[0]);
      setPubKey(keys[1]);
      setCtOutput('');
      setDecryptedOutput('');
    } catch(e) { console.error(e); }
  };

  const handleRsaEncrypt = () => {
    try {
      const ct = AsymmetricCrypto.rsa_encrypt(pubKey, ptInput);
      setCtOutput(ct);
    } catch(e) { console.error(e); }
  };

  const handleRsaDecrypt = () => {
    try {
      const pt = AsymmetricCrypto.rsa_decrypt(privKey, ctOutput);
      setDecryptedOutput(pt);
    } catch(e) { console.error(e); }
  };

  const handleGenDhParams = () => {
    try {
      const params = AsymmetricCrypto.dh_generate_params(dhBits);
      setDhP(params[0]);
      setDhG(params[1]);
    } catch(e) { console.error(e); }
  };

  const handleDhAliceCompute = () => {
    try {
      const pub = AsymmetricCrypto.dh_compute_public(dhP, dhG, alicePriv);
      setAlicePub(pub);
    } catch(e) { console.error(e); }
  };

  const handleDhBobCompute = () => {
    try {
      const pub = AsymmetricCrypto.dh_compute_public(dhP, dhG, bobPriv);
      setBobPub(pub);
    } catch(e) { console.error(e); }
  };

  const handleDhAliceShared = () => {
    try {
      const shared = AsymmetricCrypto.dh_compute_shared(dhP, bobPub, alicePriv);
      setAliceShared(shared);
    } catch(e) { console.error(e); }
  };

  const handleDhBobShared = () => {
    try {
      const shared = AsymmetricCrypto.dh_compute_shared(dhP, alicePub, bobPriv);
      setBobShared(shared);
    } catch(e) { console.error(e); }
  };

  if (!isReady) return <div>Loading WASM...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Asymmetric Cryptography</h1>

      <section className="glass-panel">
        <h2 className="card-title">RSA (Rivest-Shamir-Adleman)</h2>
        <p style={{ opacity: 0.8, marginBottom: '1rem' }}>Generate real RSA keys locally in your browser.</p>
        
        <div style={{ marginBottom: '1rem' }}>
          <label style={{ marginRight: '1rem' }}>Key Size (bits):</label>
          <select value={rsaBits} onChange={(e) => setRsaBits(Number(e.target.value))} style={{ padding: '0.4rem', background: 'var(--panel-bg)', color: 'white' }}>
            <option value={512}>512 (Fast Demo)</option>
            <option value={1024}>1024</option>
            <option value={2048}>2048 (Slow in WASM without threads)</option>
          </select>
          <button onClick={handleGenRsa} style={{ marginLeft: '1rem', padding: '0.4rem 1rem', background: 'var(--accent-cyan)', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>Generate Keys</button>
        </div>

        <div className="responsive-grid" style={{ marginBottom: '2rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--accent-teal)' }}>Public Key (PEM)</label>
            <textarea readOnly value={pubKey} style={{ width: '100%', height: '150px', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }} />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: '#ff4444' }}>Private Key (PEM)</label>
            <textarea readOnly value={privKey} style={{ width: '100%', height: '150px', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }} />
          </div>
        </div>

        <div className="responsive-grid">
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
             <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Encrypt (uses Public Key)</h3>
             <input type="text" value={ptInput} onChange={(e) => setPtInput(e.target.value)} style={{ width: '100%', padding: '0.6rem', marginBottom: '1rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)' }} />
             <button onClick={handleRsaEncrypt} style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--accent-cyan)', cursor: 'pointer' }}>Encrypt Data</button>
             <div style={{ marginTop: '1rem', wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>{ctOutput}</div>
          </div>
          
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
             <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Decrypt (uses Private Key)</h3>
             <button onClick={handleRsaDecrypt} disabled={!ctOutput} style={{ width: '100%', padding: '0.6rem', background: ctOutput ? 'var(--panel-bg)' : 'rgba(255,255,255,0.1)', color: 'white', border: '1px solid #ff4444', cursor: 'pointer' }}>Decrypt Ciphertext</button>
             <div style={{ marginTop: '1rem', fontSize: '1.2rem', fontWeight: 'bold' }}>{decryptedOutput}</div>
          </div>
        </div>
      </section>

      <section className="glass-panel">
        <h2 className="card-title">Diffie-Hellman Key Exchange</h2>
        <p style={{ opacity: 0.8, marginBottom: '1rem' }}>Two parties agree on a shared secret over an insecure channel without transmitting the secret itself.</p>

        <div style={{ marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
           <button onClick={handleGenDhParams} style={{ padding: '0.5rem 1rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', cursor: 'pointer' }}>1. Generate Global Parameters (P, G)</button>
           <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '400px' }}>
              P: {dhP}  |  G: {dhG}
           </div>
        </div>

        <div className="responsive-grid">
          {/* Alice */}
          <div style={{ background: 'rgba(0, 240, 255, 0.05)', padding: '1.5rem', borderRadius: '8px', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
            <h3 style={{ color: 'var(--accent-cyan)', marginBottom: '1rem' }}>Alice</h3>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Private Component (a):</label>
            <input type="text" value={alicePriv} onChange={(e) => setAlicePriv(e.target.value)} style={{ width: '100%', padding: '0.4rem', border: 'none', borderRadius: '4px', background: 'var(--panel-bg)', color: 'white', marginBottom: '1rem' }} />
            
            <button onClick={handleDhAliceCompute} disabled={!dhP} style={{ width: '100%', padding: '0.6rem', background: 'var(--accent-cyan)', color: 'black', border: 'none', cursor: 'pointer', marginBottom: '1rem', fontWeight: 'bold' }}>2. Compute Public Component (A = G^a mod P)</button>
            <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginBottom: '1rem' }}>{alicePub}</div>

            <button onClick={handleDhAliceShared} disabled={!alicePriv || !bobPub} style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'var(--accent-cyan)', border: '1px solid var(--accent-cyan)', cursor: 'pointer', marginBottom: '1rem' }}>4. Compute Shared Secret (B^a mod P)</button>
            <div style={{ fontSize: '1.2rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{aliceShared}</div>
          </div>

          {/* Bob */}
          <div style={{ background: 'rgba(0, 210, 255, 0.05)', padding: '1.5rem', borderRadius: '8px', border: '1px solid rgba(0, 210, 255, 0.2)' }}>
            <h3 style={{ color: 'var(--accent-teal)', marginBottom: '1rem' }}>Bob</h3>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem' }}>Private Component (b):</label>
            <input type="text" value={bobPriv} onChange={(e) => setBobPriv(e.target.value)} style={{ width: '100%', padding: '0.4rem', border: 'none', borderRadius: '4px', background: 'var(--panel-bg)', color: 'white', marginBottom: '1rem' }} />
            
            <button onClick={handleDhBobCompute} disabled={!dhP} style={{ width: '100%', padding: '0.6rem', background: 'var(--accent-teal)', color: 'black', border: 'none', cursor: 'pointer', marginBottom: '1rem', fontWeight: 'bold' }}>3. Compute Public Component (B = G^b mod P)</button>
            <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginBottom: '1rem' }}>{bobPub}</div>

            <button onClick={handleDhBobShared} disabled={!bobPriv || !alicePub} style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'var(--accent-teal)', border: '1px solid var(--accent-teal)', cursor: 'pointer', marginBottom: '1rem' }}>4. Compute Shared Secret (A^b mod P)</button>
            <div style={{ fontSize: '1.2rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-teal)', wordBreak: 'break-all' }}>{bobShared}</div>
          </div>
        </div>

        {aliceShared && bobShared && aliceShared === bobShared && (
          <div className="animate-fade-in" style={{ marginTop: '2rem', padding: '1rem', background: 'rgba(0,255,0,0.1)', border: '1px solid #00ff00', borderRadius: '8px', textAlign: 'center', color: '#00ff00', fontWeight: 'bold' }}>
            Secrets Match! Both parties securely derived the same key.
          </div>
        )}
      </section>
    </div>
  );
}
