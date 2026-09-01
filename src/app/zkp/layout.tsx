import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§11 Zero-knowledge proofs',
  description: 'The Schnorr identification protocol run interactively: prove knowledge of a discrete logarithm without revealing it, then apply the Fiat–Shamir transform and watch the proof become a signature.',
  alternates: { canonical: '/zkp/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
