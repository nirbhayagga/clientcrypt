'use client';

import { useState, useEffect } from 'react';
import init, { TlsSimulator } from '../../../public/pkg/wasm_crypto';

export default function TlsPage() {
  const [isReady, setIsReady] = useState(false);
  const [sim, setSim] = useState<any>(null);
  const [step, setStep] = useState(0);

  // States
  const [clientRandom, setClientRandom] = useState('');
  const [serverRandom, setServerRandom] = useState('');
  const [dhParams, setDhParams] = useState<string[]>([]); // P, G, ServerPub
  const [clientPub, setClientPub] = useState('');
  const [deriveResult, setDeriveResult] = useState('');
  const [sessionKey, setSessionKey] = useState('');

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => {
      setIsReady(true);
      setSim(new TlsSimulator());
    }).catch(console.error);
  }, []);

  const handleNextStep = () => {
    if (!sim) return;
    try {
      if (step === 0) {
        // Client Hello
        let cr = sim.client_hello();
        setClientRandom(cr);
        setStep(1);
      } else if (step === 1) {
        // Server Hello
        let res = sim.server_hello();
        setServerRandom(res[0]);
        setDhParams([res[1], res[2], res[3]]);
        setStep(2);
      } else if (step === 2) {
        // Client Key Exchange
        let cp = sim.client_key_exchange();
        setClientPub(cp);
        setStep(3);
      } else if (step === 3) {
        // Server Derive Key
        let r = sim.server_derive_key();
        setDeriveResult(r);
        setSessionKey(sim.get_session_key());
        setStep(4);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleReset = () => {
    if (isReady) {
      setSim(new TlsSimulator());
      setStep(0);
      setClientRandom('');
      setServerRandom('');
      setDhParams([]);
      setClientPub('');
      setDeriveResult('');
      setSessionKey('');
    }
  };

  if (!isReady) return <div>Loading Simulator...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>TLS 1.3 Simulator (Educational)</h1>
      <p style={{ opacity: 0.8, maxWidth: '800px' }}>
        This module simulates a simplified TLS handshake using the real cryptographic primitives compiled to WASM.
        Watch how randomness and Diffie-Hellman combine to generate a secure AES session key.
      </p>

      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
         <button onClick={handleNextStep} disabled={step >= 4} style={{ padding: '0.8rem 2rem', background: step >= 4 ? 'var(--panel-bg)' : 'var(--accent-cyan)', color: step >= 4 ? '#888' : 'black', border: 'none', borderRadius: '4px', cursor: step >= 4 ? 'not-allowed' : 'pointer', fontWeight: 'bold', fontSize: '1.1rem' }}>
            {step === 0 ? 'Start Handshake (Client Hello)' : 
             step === 1 ? 'Server Hello & Key Share' : 
             step === 2 ? 'Client Key Exchange' : 
             step === 3 ? 'Server Key Derivation & Finish' : 'Handshake Complete'}
         </button>
         <button onClick={handleReset} style={{ padding: '0.8rem 2rem', background: 'transparent', color: 'var(--accent-teal)', border: '1px solid var(--accent-teal)', borderRadius: '4px', cursor: 'pointer' }}>
            Reset Simulation
         </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
        {/* Client Side */}
        <section className="glass-panel" style={{ border: step === 0 || step === 2 ? '1px solid var(--accent-cyan)' : '1px solid var(--panel-border)' }}>
           <h2 className="card-title">Client</h2>
           
           <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', marginBottom: '1rem', minHeight: '80px', opacity: step >= 1 ? 1 : 0.3 }}>
             <strong style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--accent-cyan)' }}>Client Random:</strong>
             <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all' }}>{clientRandom || 'Pending...'}</div>
           </div>

           <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', marginBottom: '1rem', minHeight: '80px', opacity: step >= 3 ? 1 : 0.3 }}>
             <strong style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--accent-cyan)' }}>Client Public DH (A):</strong>
             <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all', maxHeight: '100px', overflowY: 'auto' }}>{clientPub || 'Pending...'}</div>
           </div>
        </section>

        {/* Server Side */}
        <section className="glass-panel" style={{ border: step === 1 || step === 3 ? '1px solid var(--accent-teal)' : '1px solid var(--panel-border)' }}>
           <h2 className="card-title" style={{ color: 'var(--accent-teal)' }}>Server</h2>
           
           <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', marginBottom: '1rem', minHeight: '80px', opacity: step >= 2 ? 1 : 0.3 }}>
             <strong style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--accent-teal)' }}>Server Random:</strong>
             <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all' }}>{serverRandom || 'Pending...'}</div>
           </div>

           <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', marginBottom: '1rem', minHeight: '80px', opacity: step >= 2 ? 1 : 0.3 }}>
             <strong style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--accent-teal)' }}>Server Params (P, G, B):</strong>
             <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all', maxHeight: '100px', overflowY: 'auto' }}>
               {dhParams.length > 0 ? (
                 <>
                  <div>P: {dhParams[0]}</div>
                  <div>G: {dhParams[1]}</div>
                  <div style={{ marginTop: '0.5rem' }}>Pub (B): {dhParams[2]}</div>
                 </>
               ) : 'Pending...'}
             </div>
           </div>
        </section>
      </div>

      {step >= 4 && (
        <section className="glass-panel animate-fade-in" style={{ borderColor: 'var(--accent-cyan)', background: 'rgba(0, 240, 255, 0.05)' }}>
          <h2 style={{ color: 'var(--accent-cyan)', marginBottom: '1rem' }}>Secure Channel Established</h2>
          <div style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
            <div style={{ flex: 1, padding: '1rem', background: 'var(--background)', borderRadius: '8px', fontFamily: 'var(--font-mono)' }}>
               <strong style={{ display: 'block', marginBottom: '0.5rem' }}>Derived AES Session Key (Hex):</strong>
               <span style={{ color: '#00ff00', fontSize: '1.2rem' }}>{sessionKey}</span>
            </div>
            <div style={{ flex: 1 }}>
               <strong style={{ display: 'block', marginBottom: '0.5rem' }}>Server Verification:</strong>
               <span style={{ color: deriveResult.includes('Success') ? '#00ff00' : '#ff4444', fontWeight: 'bold' }}>{deriveResult}</span>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
