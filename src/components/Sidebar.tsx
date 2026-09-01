'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { SECTIONS } from '@/lib/sections';

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
        v{version} · <a href="https://github.com/nirbhayagga/clientcrypt" target="_blank" rel="noreferrer">source</a> · <Link href="/privacy/">privacy</Link><br />
        Rust → WebAssembly<br />
        No data leaves the browser.
      </div>
    </aside>
  );
}
