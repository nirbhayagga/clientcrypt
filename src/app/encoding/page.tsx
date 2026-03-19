'use client';

import { useState } from 'react';

export default function EncodingPage() {
  const [input, setInput] = useState('Hello World!');
  const [encoding, setEncoding] = useState('base64');
  
  const getEncoded = () => {
    try {
      if (encoding === 'base64') return btoa(input);
      if (encoding === 'hex') return Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2, '0')).join('');
      if (encoding === 'url') return encodeURIComponent(input);
      return input;
    } catch (e) {
      return "Invalid Input for Encoding";
    }
  };

  const getDecoded = () => {
    try {
      if (encoding === 'base64') return atob(input);
      if (encoding === 'hex') {
        const hex = input.replace(/[^0-9a-fA-F]/g, '');
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) bytes[i/2] = parseInt(hex.substring(i, i+2), 16);
        return new TextDecoder().decode(bytes);
      }
      if (encoding === 'url') return decodeURIComponent(input);
      return input;
    } catch (e) {
      return "Invalid Input for Decoding";
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Encoding Utilities</h1>
      <p style={{ opacity: 0.8, maxWidth: '800px' }}>
        Frequently used data conversion tools. These run entirely locally in your browser leveraging Web APIs and Javascript.
      </p>

      <section className="glass-panel">
        <h2 className="card-title">Data Conversion</h2>
        
        <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
          <select value={encoding} onChange={(e) => setEncoding(e.target.value)} style={{ padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', borderRadius: '4px', border: '1px solid var(--panel-border)' }}>
            <option value="base64">Base64</option>
            <option value="hex">Hexadecimal</option>
            <option value="url">URL Encoding</option>
          </select>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--accent-cyan)' }}>Input Text / Data</label>
            <textarea value={input} onChange={(e) => setInput(e.target.value)} rows={4} style={{ width: '100%', padding: '0.6rem', background: 'var(--panel-bg)', color: 'white', border: '1px solid var(--panel-border)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }} />
          </div>
          
          <div className="responsive-grid">
             <div style={{ background: 'rgba(0, 240, 255, 0.05)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
                <strong style={{ color: 'var(--accent-cyan)', display: 'block', marginBottom: '0.5rem' }}>Result (Encoded):</strong>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', wordBreak: 'break-all' }}>{getEncoded()}</div>
             </div>
             
             <div style={{ background: 'rgba(0, 210, 255, 0.05)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(0, 210, 255, 0.2)' }}>
                <strong style={{ color: 'var(--accent-teal)', display: 'block', marginBottom: '0.5rem' }}>Result (Decoded):</strong>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', wordBreak: 'break-all' }}>{getDecoded()}</div>
             </div>
          </div>
        </div>
      </section>
    </div>
  );
}
