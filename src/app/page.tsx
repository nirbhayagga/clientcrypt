import Link from 'next/link';

export default function Home() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3rem', width: '100%', maxWidth: '1200px', margin: '0 auto', paddingBottom: '4rem' }}>
      
      {/* Hero Section */}
      <section style={{ 
        position: 'relative', 
        padding: '6rem 2rem', 
        borderRadius: '24px', 
        textAlign: 'center',
        background: 'radial-gradient(ellipse at top, rgba(34, 211, 238, 0.15) 0%, transparent 70%)',
        overflow: 'hidden'
      }}>
        <div style={{ position: 'absolute', top: '10%', left: '10%', animation: 'float 6s infinite ease-in-out', opacity: 0.3, fontFamily: 'var(--font-mono)', fontSize: '2rem', color: 'var(--accent-teal)' }}>{'{ }'}</div>
        <div style={{ position: 'absolute', bottom: '20%', right: '10%', animation: 'float 8s infinite ease-in-out reverse', opacity: 0.3, fontFamily: 'var(--font-mono)', fontSize: '3rem', color: 'var(--accent-indigo)' }}>{'/'}</div>
        
        <div style={{ display: 'inline-block', padding: '0.4rem 1rem', background: 'rgba(34, 211, 238, 0.1)', color: 'var(--accent-cyan)', borderRadius: '20px', fontSize: '0.9rem', fontWeight: 600, marginBottom: '2rem', border: '1px solid rgba(34, 211, 238, 0.2)' }}>
          WASM-Powered Crypto Engine
        </div>
        
        <h1 style={{ fontSize: '4.5rem', marginBottom: '1.5rem', lineHeight: 1.1, letterSpacing: '-0.04em' }}>
          Welcome to <br />
          <span className="text-gradient">ClientCrypt</span>
        </h1>
        
        <p style={{ fontSize: '1.3rem', opacity: 0.7, maxWidth: '600px', margin: '0 auto 3rem auto', lineHeight: 1.6 }}>
          Explore military-grade cryptography running near-natively in your browser. Complete privacy, zero server processing, stunningly fast.
        </p>

        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
          <Link href="/classical" style={{ padding: '1rem 2rem', background: 'var(--accent-cyan)', color: '#000', textDecoration: 'none', borderRadius: '12px', fontWeight: 600, fontSize: '1.1rem', transition: 'transform 0.2s, box-shadow 0.2s', boxShadow: '0 4px 14px 0 rgba(34, 211, 238, 0.39)' }}>
            Start Computing
          </Link>
          <a href="https://github.com" target="_blank" rel="noreferrer" style={{ padding: '1rem 2rem', background: 'rgba(255,255,255,0.05)', color: '#fff', textDecoration: 'none', borderRadius: '12px', fontWeight: 600, fontSize: '1.1rem', border: '1px solid var(--panel-border)', transition: 'background 0.2s' }}>
            View Source
          </a>
        </div>
      </section>

      {/* Features Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '2rem' }}>
        <div className="glass-panel animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <h2 className="card-title">Privacy-First Architecture</h2>
          <p style={{ opacity: 0.8, lineHeight: 1.6 }}>Every algorithm - from AES-128 encryption to generating 2048-bit RSA keys - happens strictly on your device using Rust WebAssembly modules.</p>
        </div>
        
        <div className="glass-panel animate-fade-in" style={{ animationDelay: '0.2s' }}>
          <h2 className="card-title">Interactive Education</h2>
          <p style={{ opacity: 0.8, lineHeight: 1.6 }}>Visualize ECB pattern leaks, perform live frequency analysis on Classical ciphers, and watch a step-by-step TLS 1.3 handshake simulation.</p>
        </div>
        
        <div className="glass-panel animate-fade-in" style={{ animationDelay: '0.3s' }}>
          <h2 className="card-title">Near-Native Speeds</h2>
          <p style={{ opacity: 0.8, lineHeight: 1.6 }}>Bypass the dynamic limitations of pure JavaScript. ClientCrypt executes brute-force dictionary attacks and intensive hashing at native Rust velocity.</p>
        </div>
      </div>
    </div>
  );
}
