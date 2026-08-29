import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§2 Block ciphers',
  description: 'AES-128/192/256 in ECB, CBC, CTR and GCM, PKCS#7 padding and the ECB pattern-leakage demonstration.',
  alternates: { canonical: '/block-ciphers/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
