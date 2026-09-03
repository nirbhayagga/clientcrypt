import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§12 Secret sharing',
  description: 'Shamir’s threshold scheme run live: split a secret into n shares with a random polynomial, reconstruct it from any k by Lagrange interpolation, and watch k−1 shares stay consistent with every possible secret.',
  alternates: { canonical: '/sharing/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
