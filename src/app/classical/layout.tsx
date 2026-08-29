import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§1 Classical ciphers',
  description: 'Caesar, Atbash, affine and Vigenère ciphers with frequency analysis, index of coincidence and key recovery.',
  alternates: { canonical: '/classical/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
