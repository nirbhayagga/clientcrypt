'use client';

import { useState, useEffect } from 'react';
import init, { PasswordSecurity } from '../../../public/pkg/wasm_crypto';

export default function PasswordsPage() {
  const [isReady, setIsReady] = useState(false);
  const [password, setPassword] = useState('MyP@ssw0rd!');
  const [entropy, setEntropy] = useState(0);
  const [timeClassical, setTimeClassical] = useState(0);
  const [timeQuantum, setTimeQuantum] = useState(0);

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => setIsReady(true)).catch(console.error);
  }, []);

  useEffect(() => {
    if (!isReady) return;
    try {
      const e = PasswordSecurity.calculate_entropy(password);
      setEntropy(e);
      setTimeClassical(PasswordSecurity.time_to_crack_classical(e));
      setTimeQuantum(PasswordSecurity.time_to_crack_quantum(e));
    } catch (err) {
      console.error(err);
    }
  }, [password, isReady]);

  const formatTime = (seconds: number) => {
    if (seconds < 1) return "< 1 second";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    const years = seconds / 31536000;
    if (years > 1000000) return "> 1 Million Years";
    return `${Math.round(years)} years`;
  };

  const getEntropyColor = () => {
    if (entropy < 40) return '#ff4444'; // Red
    if (entropy < 60) return '#ffbb33'; // Orange
    if (entropy < 80) return '#00C851'; // Green
    return 'var(--accent-cyan)'; // Strong
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Password Security</h1>

      <section className="glass-panel">
        <h2 className="card-title">Live Entropy Analysis</h2>
        <div style={{ marginBottom: '2rem' }}>
          <input 
            type="text" 
            value={password} 
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Type a password to test..."
            style={{ width: '100%', padding: '1rem', fontSize: '1.5rem', background: 'var(--panel-bg)', color: 'white', border: `2px solid ${getEntropyColor()}`, borderRadius: '8px', transition: 'border-color 0.3s' }}
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--panel-border)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontSize: '0.9rem', opacity: 0.8, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.5rem' }}>Entropy Bits</div>
            <div style={{ fontSize: '3rem', fontWeight: 700, color: getEntropyColor() }}>
              {Math.round(entropy)}
            </div>
          </div>
          
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--panel-border)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontSize: '0.9rem', opacity: 0.8, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.5rem' }}>Classical Crack Time</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 600, color: 'white', textAlign: 'center' }}>
              {formatTime(timeClassical)}
            </div>
            <div style={{ fontSize: '0.8rem', opacity: 0.5, marginTop: '0.5rem' }}>(@ 10 Billion guesses/sec)</div>
          </div>

          <div style={{ background: 'rgba(0, 240, 255, 0.05)', padding: '1.5rem', borderRadius: '8px', border: '1px solid rgba(0,240,255,0.2)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontSize: '0.9rem', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.5rem' }}>Quantum Crack Time</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--accent-cyan)', textAlign: 'center' }}>
              {formatTime(timeQuantum)}
            </div>
            <div style={{ fontSize: '0.8rem', opacity: 0.7, color: 'var(--accent-cyan)', marginTop: '0.5rem' }}>(Grover's Algorithm Speedup)</div>
          </div>
        </div>
      </section>

      <section className="glass-panel">
        <h2 className="card-title">Dictionary Attacks</h2>
        <p style={{ opacity: 0.8, marginBottom: '1rem' }}>
          Even if a password has high entropy mathematically, if it exists in a leaked dictionary or is easily guessable (like "Password123!"), its practical entropy is nearly zero.
        </p>
        <button disabled style={{ padding: '0.6rem 1.5rem', background: '#333', color: '#999', border: 'none', borderRadius: '4px', cursor: 'not-allowed' }}>
          Check against embedded Top 1000 wordlist (WASM integration demo)
        </button>
      </section>
    </div>
  );
}
