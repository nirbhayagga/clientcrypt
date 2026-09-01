import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§3 Hash functions & MACs',
  description: 'MD5, SHA-1, SHA-256, SHA-512 and SHA3-256 digests, HMAC, the avalanche effect, and how a corpus can be queried without revealing the query.',
  alternates: { canonical: '/hashing/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
