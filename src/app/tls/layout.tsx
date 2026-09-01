import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§7 TLS 1.3 handshake',
  description: 'X25519 key share, the HKDF key schedule of RFC 8446 and AEAD record protection, step by step.',
  alternates: { canonical: '/tls/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
