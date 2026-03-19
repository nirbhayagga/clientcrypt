import type { Metadata } from "next";
import "./globals.css";
import Link from "next/link";

export const metadata: Metadata = {
  title: "ClientCrypt Security Suite",
  description: "Educational WASM-powered cryptographic analysis platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <div className="app-container">
          <aside className="glass-panel sidebar">
            <div style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1.5rem', padding: '0 0.5rem', textAlign: 'center' }}>
              <span className="text-gradient">ClientCrypt</span>
            </div>
            
            <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', flex: 1, overflowY: 'auto' }}>
              <Link href="/" className="nav-link">Dashboard</Link>
              <Link href="/classical" className="nav-link">Classical Ciphers</Link>
              <Link href="/block-ciphers" className="nav-link">Block Ciphers</Link>
              <Link href="/hashing" className="nav-link">Hashing & HMAC</Link>
              <Link href="/asymmetric" className="nav-link">Asymmetric Crypto</Link>
              <Link href="/passwords" className="nav-link">Password Security</Link>
              <Link href="/tls" className="nav-link">TLS Simulator</Link>
              <Link href="/encoding" className="nav-link">Encoding Utilities</Link>
              <Link href="/benchmark" className="nav-link">Performance</Link>
            </nav>
            
            <div style={{ padding: '1rem', fontSize: '0.8rem', opacity: 0.7, textAlign: 'center', marginTop: 'auto' }}>
              Powered by Rust & WASM
            </div>
          </aside>
          
          <main className="main-content animate-fade-in">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
