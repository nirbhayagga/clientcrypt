'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export const SECTIONS = [
  { href: '/classical/', num: '§1', label: 'Classical ciphers' },
  { href: '/block-ciphers/', num: '§2', label: 'Block ciphers' },
  { href: '/hashing/', num: '§3', label: 'Hash functions & MACs' },
  { href: '/asymmetric/', num: '§4', label: 'Public-key cryptography' },
  { href: '/passwords/', num: '§5', label: 'Password security' },
  { href: '/tls/', num: '§6', label: 'TLS 1.3 handshake' },
  { href: '/protocols/', num: '§7', label: 'Applied protocols' },
  { href: '/encoding/', num: '§8', label: 'Encodings' },
  { href: '/benchmark/', num: '§9', label: 'WASM vs JS benchmark' },
] as const;

export default function Sidebar({ version }: { version: string }) {
  const pathname = usePathname();
  const norm = pathname.endsWith('/') ? pathname : `${pathname}/`;
  return (
    <aside className="sidebar">
      <Link href="/" className="brand">
        ClientCrypt
        <small>cryptography, client-side</small>
      </Link>
      <nav className="nav" aria-label="Sections">
        <Link href="/" className="nav-link" aria-current={norm === '/' ? 'page' : undefined}>
          <span className="num">§0</span><span>Overview</span>
        </Link>
        {SECTIONS.map((s) => (
          <Link key={s.href} href={s.href} className="nav-link" aria-current={norm === s.href ? 'page' : undefined}>
            <span className="num">{s.num}</span><span>{s.label}</span>
          </Link>
        ))}
      </nav>
      <div className="sidebar-foot">
        v{version}<br />
        Rust → WebAssembly<br />
        No data leaves the browser.
      </div>
    </aside>
  );
}
