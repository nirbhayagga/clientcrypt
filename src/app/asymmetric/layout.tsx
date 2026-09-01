import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§5 Public-key cryptography',
  description: 'RSA key generation, OAEP and PSS, finite-field Diffie–Hellman with RFC 7919 groups, and X25519.',
  alternates: { canonical: '/asymmetric/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
