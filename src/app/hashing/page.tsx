'use client';

import { useState, useEffect } from 'react';
import init, { Hasher } from '../../../public/pkg/wasm_crypto';

export default function HashingPage() {
  const [isReady, setIsReady] = useState(false);
  
  const [inputText, setInputText] = useState('SuperSecretPassword');
  const [hmacKey, setHmacKey] = useState('SecretKey123');
  
  const [sha256Hash, setSha256Hash] = useState('');
  const [sha1Hash, setSha1Hash] = useState('');
  const [hmacHash, setHmacHash] = useState('');
  
  const [pwnedStatus, setPwnedStatus] = useState<string | null>(null);

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => setIsReady(true)).catch(console.error);
  }, []);

  useEffect(() => {
    if (!isReady) return;
    try {
      setSha256Hash(Hasher.sha256(inputText));
      setSha1Hash(Hasher.sha1(inputText));
      setHmacHash(Hasher.hmac_sha256(hmacKey, inputText));
      setPwnedStatus(null); // reset status on input change
    } catch (e) {
      console.error(e);
    }
  }, [inputText, hmacKey, isReady]);

  const checkPwned = async () => {
    if (!sha1Hash) return;
    try {
      const prefix = sha1Hash.substring(0, 5).toUpperCase();
      const suffix = sha1Hash.substring(5).toUpperCase();
      
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!res.ok) throw new Error("HIBP API Error");
      
      const text = await res.text();
      const lines = text.split('\n');
      
      let found = false;
      for (const line of lines) {
        if (line.startsWith(suffix)) {
          const count = line.split(':')[1].trim();
          setPwnedStatus(`[WARNING] This password has been seen ${count} times in data breaches! (k-anonymity verified)`);
          found = true;
          break;
        }
      }
      if (!found) {
        setPwnedStatus("[OK] Good news! This password was not found in known data breaches.");
      }
    } catch (e) {
      console.error(e);
      setPwnedStatus("Error fetching from Have I Been Pwned API.");
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Secure Hashing & MACs</h1>

      <section className="glass-panel">
        <h2 className="card-title">Live Hashing Input</h2>
        <div className="responsive-grid" style={{ marginBottom: '1.5rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>Data</label>
            <input 
              type="text" value={inputText} onChange={(e) => setInputText(e.target.value)}
              style={{ width: '100%', padding: '0.8rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontSize: '1.1rem' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>HMAC Key</label>
            <input 
              type="text" value={hmacKey} onChange={(e) => setHmacKey(e.target.value)}
              style={{ width: '100%', padding: '0.8rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}
            />
          </div>
        </div>
      </section>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
        <section className="glass-panel">
          <h2 className="card-title">SHA-256 (Modern Standard)</h2>
          <pre style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap', color: 'var(--accent-teal)' }}>
            {isReady ? sha256Hash : 'Loading...'}
          </pre>
        </section>

        <section className="glass-panel">
          <h2 className="card-title">HMAC-SHA256</h2>
          <pre style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap', color: 'var(--accent-cyan)' }}>
            {isReady ? hmacHash : 'Loading...'}
          </pre>
        </section>

        <section className="glass-panel" style={{ gridColumn: '1 / -1' }}>
          <h2 className="card-title">SHA-1 and k-Anonymity (HIBP Integration)</h2>
          <p style={{ opacity: 0.8, marginBottom: '1rem' }}>
            We securely check if your password was leaked using Troy Hunt's "Have I Been Pwned" API. 
            We only send the first 5 characters of your SHA-1 hash over the network (k-Anonymity).
          </p>
          <pre style={{ wordBreak: 'break-all', whiteSpace: 'pre-wrap', marginBottom: '1rem' }}>
            {isReady ? <><span style={{ color: '#ff4444' }}>{sha1Hash.substring(0, 5)}</span>{sha1Hash.substring(5)}</> : 'Loading...'}
          </pre>
          <button 
            onClick={checkPwned} disabled={!isReady}
            style={{ padding: '0.6rem 1.5rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', cursor: 'pointer', fontWeight: 600 }}
          >Check Have I Been Pwned (Prefix: {sha1Hash.substring(0, 5).toUpperCase()})</button>

          {pwnedStatus && (
            <div className="animate-fade-in" style={{ marginTop: '1rem', padding: '1rem', background: pwnedStatus.includes('[WARNING]') ? 'rgba(255, 68, 68, 0.1)' : 'rgba(0, 255, 0, 0.1)', border: `1px solid ${pwnedStatus.includes('[WARNING]') ? '#ff4444' : '#00ff00'}`, borderRadius: '8px' }}>
              {pwnedStatus}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
