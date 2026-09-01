import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§7 Password security',
  description: 'Entropy and guessing-time model, common-password lookup, PBKDF2 and Argon2id cost.',
  alternates: { canonical: '/passwords/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
