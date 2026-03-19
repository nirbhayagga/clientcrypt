export default function Home() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem', maxWidth: '1000px', margin: '0 auto', width: '100%' }}>
      <header className="glass-panel" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <h1 style={{ fontSize: '3rem', marginBottom: '1rem' }}>
          Welcome to <span className="text-gradient">ClientCrypt</span>
        </h1>
        <p style={{ fontSize: '1.2rem', opacity: 0.8, maxWidth: '600px', margin: '0 auto' }}>
          Explore military-grade cryptography running securely in your browser. No server processing. True privacy via WebAssembly.
        </p>
      </header>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
        <div className="glass-panel">
          <h2 className="card-title">Privacy-First Architecture</h2>
          <p>Every algorithm you run—from AES encryption to RSA key generation—happens directly on your device using near-native Rust modules.</p>
        </div>
        
        <div className="glass-panel">
          <h2 className="card-title">Educational Demos</h2>
          <p>See ECB pattern leaks, watch a simulated TLS 1.3 handshake, and learn why padding matters.</p>
        </div>
        
        <div className="glass-panel">
          <h2 className="card-title">Lightning Fast</h2>
          <p>By compiling compute-heavy tasks to WebAssembly, ClientCrypt can perform dictionary attacks and password hashing at incredible speeds.</p>
        </div>
      </div>
    </div>
  );
}
