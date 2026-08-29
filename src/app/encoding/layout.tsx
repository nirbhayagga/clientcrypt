import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§7 Encodings',
  description: 'Base64, Base64url, hex, percent and binary encodings with a code-point and UTF-8 byte view.',
  alternates: { canonical: '/encoding/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
