import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§10 Attacks',
  description: 'Two active attacks run end to end: the CBC padding-oracle attack that recovers plaintext from a single bit of server feedback, and a man-in-the-middle on unauthenticated Diffie–Hellman.',
  alternates: { canonical: '/attacks/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
