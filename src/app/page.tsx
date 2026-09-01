import Link from 'next/link';
import { Panel, Note } from '@/components/ui';

const CONTENTS: { num: string; href: string; title: string; topics: string; std: string }[] = [
  { num: '§1', href: '/classical/', title: 'Classical ciphers', topics: 'Caesar, Atbash, affine, Vigenère; frequency analysis, index of coincidence, exhaustive search and key recovery', std: '—' },
  { num: '§2', href: '/block-ciphers/', title: 'Block ciphers', topics: 'AES-128/192/256 in ECB, CBC, CTR and GCM; PKCS#7 padding; ECB pattern leakage', std: 'FIPS 197 · SP 800-38A/D' },
  { num: '§3', href: '/hashing/', title: 'Hash functions & MACs', topics: 'MD5, SHA-1, SHA-256, SHA-512, SHA3-256; the SHA-256 compression function round by round; length extension; HMAC; k-anonymity lookup', std: 'FIPS 180-4 · FIPS 202 · RFC 2104' },
  { num: '§4', href: '/numbers/', title: 'Number theory', topics: 'Square-and-multiply modular exponentiation, extended Euclid and modular inverses, RSA and Diffie–Hellman worked by hand', std: '—' },
  { num: '§5', href: '/asymmetric/', title: 'Public-key cryptography', topics: 'RSA key generation, PKCS#1 v1.5 and OAEP encryption, signatures; finite-field Diffie–Hellman; X25519', std: 'RFC 8017 · RFC 7919 · RFC 7748' },
  { num: '§6', href: '/passwords/', title: 'Password security', topics: 'Entropy estimation, guessing-time model, common-password lookup, PBKDF2, scrypt and Argon2id cost', std: 'RFC 8018 · RFC 7914 · RFC 9106' },
  { num: '§7', href: '/tls/', title: 'TLS 1.3 handshake', topics: 'Key share, HKDF key schedule, traffic secrets — step by step', std: 'RFC 8446 · RFC 5869' },
  { num: '§8', href: '/protocols/', title: 'Applied protocols', topics: 'WPA2-PSK key derivation, TOTP/HOTP one-time passwords, JWT signing, and the WireGuard handshake', std: 'IEEE 802.11i · RFC 6238 · RFC 7519' },
  { num: '§9', href: '/encoding/', title: 'Encodings', topics: 'Base64, Base64url, hex, URL and binary encodings; these are not encryption', std: 'RFC 4648' },
  { num: '§10', href: '/benchmark/', title: 'WASM vs JS benchmark', topics: 'Identical SHA-256 workload in Rust/WebAssembly, plain JavaScript and WebCrypto', std: '—' },
];

const CRATES: [string, string][] = [
  ['aes, aes-gcm', 'AES block cipher and GCM AEAD (RustCrypto)'],
  ['sha1, sha2, sha3, md-5', 'Hash functions (RustCrypto)'],
  ['hmac, hkdf', 'HMAC (RFC 2104) and HKDF (RFC 5869)'],
  ['rsa', 'RSA key generation, PKCS#1 v1.5, OAEP, signatures'],
  ['x25519-dalek', 'X25519 Diffie–Hellman (RFC 7748)'],
  ['num-bigint', 'Finite-field arithmetic for classical Diffie–Hellman'],
  ['pbkdf2, argon2', 'Password-based key derivation'],
  ['wasm-bindgen', 'JavaScript ↔ WebAssembly bindings'],
];

export default function Home() {
  return (
    <>
      <header className="page-head">
        <div className="kicker">§0 · Overview</div>
        <h1>ClientCrypt</h1>
        <p className="lede">
          An interactive reference for cryptographic primitives and protocols. Every computation runs in the
          browser: the algorithms are Rust implementations compiled to WebAssembly, and no input is sent to a server.
        </p>
      </header>

      <div className="stack">
        <Panel title="Abstract">
          <p>
            This site accompanies an introductory study of cryptography. Each section pairs a working implementation
            with the parameters that matter in practice — key and block sizes, modes of operation, padding, nonces,
            group parameters — so that the behaviour of an algorithm can be observed directly rather than described.
            The implementations are the audited RustCrypto crates, not toy re-implementations; the classical ciphers
            and the handshake simulator are written for exposition.
          </p>
          <p className="muted small">
            The only network request the application can make is the optional <em>Have I Been Pwned</em> range
            query in §3, which transmits the first five hexadecimal digits of a SHA-1 digest and nothing else.
          </p>
        </Panel>

        <Panel title="Contents">
          <div className="table-wrap">
            <table className="toc">
              <thead className="sr-only"><tr><th>Section</th><th>Title and topics</th><th>Standards</th></tr></thead>
              <tbody>
                {CONTENTS.map((c) => (
                  <tr key={c.num}>
                    <td className="num">{c.num}</td>
                    <td>
                      <Link href={c.href}>{c.title}</Link>
                      <div className="muted small">{c.topics}</div>
                    </td>
                    <td className="std">{c.std}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="grid-2">
          <Panel title="Conventions">
            <ul className="muted small" style={{ margin: 0, paddingLeft: '1.1rem' }}>
              <li>Byte strings are shown as lowercase hexadecimal; text inputs are UTF-8 encoded before processing.</li>
              <li>Key, block and digest sizes are given in bits; lengths of hex fields in bytes.</li>
              <li>Random values come from the browser CSPRNG (<code>crypto.getRandomValues</code>) through <code>getrandom</code>.</li>
              <li>Demonstration parameters (512-bit RSA, small Diffie–Hellman primes) are labelled as such and are not secure.</li>
            </ul>
          </Panel>
          <Panel title="Implementation">
            <table className="table">
              <thead><tr><th>Crate</th><th>Role</th></tr></thead>
              <tbody>
                {CRATES.map(([name, what]) => (
                  <tr key={name}><td className="mono">{name}</td><td className="muted small">{what}</td></tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </div>

        <Note title="Scope">
          This is teaching material. The user interface is not constant-time, keys are held in JavaScript strings, and
          nothing here should be used to protect real data. For that, use the platform&apos;s WebCrypto API or a vetted library.
        </Note>
      </div>
    </>
  );
}
