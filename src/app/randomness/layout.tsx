import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§5 Randomness',
  description: 'Why pseudorandom is not random: lattice structure in a bad generator, NIST statistical tests, and collecting real physical entropy from pointer movement and CPU timing jitter.',
  alternates: { canonical: '/randomness/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
