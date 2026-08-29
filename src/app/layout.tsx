import type { Metadata, Viewport } from 'next';
import { IBM_Plex_Sans, IBM_Plex_Serif, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';
import Sidebar from '@/components/Sidebar';
import pkg from '../../package.json';

const sans = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-sans', display: 'swap' });
const serif = IBM_Plex_Serif({ subsets: ['latin'], weight: ['500', '600'], variable: '--font-serif', display: 'swap' });
const mono = IBM_Plex_Mono({ subsets: ['latin'], weight: ['400', '500'], variable: '--font-mono', display: 'swap' });

const SITE = 'https://clientcrypt.nirbhay.dev';
const DESCRIPTION = 'An interactive reference for cryptographic primitives and protocols — AES, SHA-2/3, HMAC, RSA, Diffie–Hellman, X25519, TLS 1.3 — executed entirely in the browser with Rust compiled to WebAssembly.';

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: { default: 'ClientCrypt', template: '%s · ClientCrypt' },
  description: DESCRIPTION,
  alternates: { canonical: '/' },
  manifest: '/site.webmanifest',
  icons: {
    icon: [{ url: '/favicon.ico', sizes: '48x48' }, { url: '/favicon.svg', type: 'image/svg+xml' }],
    apple: '/apple-touch-icon.png',
  },
  openGraph: {
    type: 'website',
    url: SITE,
    siteName: 'ClientCrypt',
    title: 'ClientCrypt — cryptography, client-side',
    description: DESCRIPTION,
    images: [{ url: '/og-image.png', width: 1200, height: 630, alt: 'ClientCrypt' }],
  },
  twitter: { card: 'summary_large_image', title: 'ClientCrypt', description: DESCRIPTION, images: ['/og-image.png'] },
};

export const viewport: Viewport = { themeColor: '#0c0e12', colorScheme: 'dark' };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${sans.variable} ${serif.variable} ${mono.variable}`}>
      <body>
        <div className="app">
          <Sidebar version={pkg.version} />
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
