import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§4 Number theory',
  description: 'The modular arithmetic under RSA and Diffie–Hellman at sizes you can follow by hand: square-and-multiply exponentiation, the extended Euclidean algorithm, and worked key generation.',
  alternates: { canonical: '/numbers/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
