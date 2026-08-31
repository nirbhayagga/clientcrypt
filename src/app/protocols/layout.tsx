import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§7 Applied protocols',
  description: 'How the primitives combine in the field: WPA2-PSK key derivation, TOTP/HOTP one-time passwords, JSON Web Token signing, and the WireGuard handshake.',
  alternates: { canonical: '/protocols/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
