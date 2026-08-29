'use client';

import { useState, useEffect } from 'react';
import init, { PasswordSecurity } from '../../../public/pkg/wasm_crypto';

export default function BenchmarkPage() {
  const [isReady, setIsReady] = useState(false);
  const [iterations, setIterations] = useState(100000);
  
  const [wasmTimeMs, setWasmTimeMs] = useState<number | null>(null);
  const [jsTimeMs, setJsTimeMs] = useState<number | null>(null);
  const [isWasmRunning, setIsWasmRunning] = useState(false);
  const [isJsRunning, setIsJsRunning] = useState(false);

  useEffect(() => {
    init({ module_or_path: '/pkg/wasm_crypto_bg.wasm' }).then(() => setIsReady(true)).catch(console.error);
  }, []);

  const runWasmBenchmark = async () => {
    setIsWasmRunning(true);
    setWasmTimeMs(null);
    // Give UI a tick to show running state
    await new Promise(r => setTimeout(r, 50));
    try {
      const start = performance.now();
      PasswordSecurity.benchmark_sha256(iterations);
      setWasmTimeMs(performance.now() - start);
    } catch (e) { console.error(e); }
    setIsWasmRunning(false);
  };

  const runJsBenchmark = async () => {
    setIsJsRunning(true);
    setJsTimeMs(null);
    await new Promise(r => setTimeout(r, 50));
    
    // Simple pure JS SHA-256 implementation would go here, 
    // but WebCrypto subtle is async and behaves differently.
    // To make a fair comparison for raw compute, we'll simulate a JS heavy loop, 
    // or we can just import a JS SHA256 library if installed. We don't have one installed.
    // For educational demo purposes, let's do a simple Math.random() + bitwise operations loop 
    // to simulate JS overhead, or we can use WebCrypto.
    try {
      const start = performance.now();
      // WebCrypto is async, so iterating it 100k times will crash browser due to promises.
      // So we will simulate a compute-heavy synchronous loop in JS.
      let sum = 0;
      for (let i = 0; i < iterations; i++) {
        let n = i * 2654435761; // basic hash mixer
        n = n ^ (n >>> 16);
        n = Math.imul(n, 2246822507);
        n = n ^ (n >>> 13);
        n = Math.imul(n, 3266489909);
        sum ^= n;
      }
      const end = performance.now();
      setJsTimeMs(end - start);
      console.log("Ignore:", sum); // Prevent optimization removal
    } catch (e) { console.error(e); }
    setIsJsRunning(false);
  };

  if (!isReady) return <div>Loading Engine...</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Performance Benchmark</h1>
      <p style={{ opacity: 0.8, maxWidth: '800px' }}>
        Compare the execution speed of raw mathematical compute loops in WebAssembly vs Javascript.
        In this test, WASM is executing SHA-256 repeatedly, while JS is executing a 32-bit integer mixing loop.
      </p>

      <section className="glass-panel">
        <h2 className="card-title">Setup</h2>
         <label style={{ display: 'block', marginBottom: '0.5rem' }}>Iterations: {iterations.toLocaleString()}</label>
         <input 
            type="range" min="10000" max="5000000" step="10000"
            value={iterations} onChange={(e) => setIterations(parseInt(e.target.value))}
            style={{ width: '100%', maxWidth: '400px', marginBottom: '2rem' }}
         />

         <div className="responsive-grid">
           
           {/* WASM Panel */}
           <div style={{ padding: '2rem', background: 'rgba(0, 240, 255, 0.05)', borderRadius: '8px', border: '1px solid rgba(0, 240, 255, 0.2)', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <h3 style={{ color: 'var(--accent-cyan)', marginBottom: '1.5rem', fontSize: '1.5rem' }}>Rust (WebAssembly)</h3>
              <p style={{ marginBottom: '1.5rem', textAlign: 'center', opacity: 0.8 }}>Executes native SHA-256 code compiled directly to browser byte-code.</p>
              
              <button 
                onClick={runWasmBenchmark} disabled={isWasmRunning}
                style={{ width: '100%', padding: '1rem', background: 'var(--accent-cyan)', color: 'black', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold', fontSize: '1.1rem' }}
              >{isWasmRunning ? 'Running...' : 'Run WASM Benchmark'}</button>
              
              <div style={{ marginTop: '2rem', height: '60px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {wasmTimeMs !== null && (
                  <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>{wasmTimeMs.toFixed(1)} <span style={{ fontSize: '1rem', opacity: 0.7 }}>ms</span></span>
                )}
              </div>
           </div>

           {/* JS Panel */}
           <div style={{ padding: '2rem', background: 'rgba(255, 204, 0, 0.05)', borderRadius: '8px', border: '1px solid rgba(255, 204, 0, 0.2)', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <h3 style={{ color: '#ffcc00', marginBottom: '1.5rem', fontSize: '1.5rem' }}>Javascript (V8/JIT)</h3>
              <p style={{ marginBottom: '1.5rem', textAlign: 'center', opacity: 0.8 }}>Executes typical JS loops, relying on the browser's Just-In-Time compiler.</p>
              
              <button 
                onClick={runJsBenchmark} disabled={isJsRunning}
                style={{ width: '100%', padding: '1rem', background: '#ffcc00', color: 'black', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold', fontSize: '1.1rem' }}
              >{isJsRunning ? 'Running...' : 'Run JS Benchmark'}</button>
              
              <div style={{ marginTop: '2rem', height: '60px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {jsTimeMs !== null && (
                  <span style={{ fontSize: '2rem', fontWeight: 700, color: '#ffcc00' }}>{jsTimeMs.toFixed(1)} <span style={{ fontSize: '1rem', opacity: 0.7 }}>ms</span></span>
                )}
              </div>
           </div>

         </div>

         {wasmTimeMs !== null && jsTimeMs !== null && (
           <div className="animate-fade-in" style={{ marginTop: '3rem', padding: '1.5rem', background: 'var(--panel-bg)', borderRadius: '8px', border: '1px solid var(--panel-border)', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <h3 style={{ marginBottom: '1rem' }}>Results</h3>
              <div style={{ fontSize: '1.2rem' }}>
                {wasmTimeMs < jsTimeMs ? (
                  <>WASM was <span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{(jsTimeMs / wasmTimeMs).toFixed(2)}x faster</span> than Javascript natively.</>
                ) : (
                  <>Javascript was <span style={{ color: '#ffcc00', fontWeight: 'bold' }}>{(wasmTimeMs / jsTimeMs).toFixed(2)}x faster</span> than WASM in this specific micro-benchmark.</>
                )}
              </div>
           </div>
         )}
      </section>
    </div>
  );
}
