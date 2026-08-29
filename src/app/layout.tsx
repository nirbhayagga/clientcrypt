import type { Metadata } from 'next';
import { IBM_Plex_Sans, IBM_Plex_Serif, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';
import Sidebar from '@/components/Sidebar';
import pkg from '../../package.json';

const sans = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-sans', display: 'swap' });
const serif = IBM_Plex_Serif({ subsets: ['latin'], weight: ['500', '600'], variable: '--font-serif', display: 'swap' });
const mono = IBM_Plex_Mono({ subsets: ['latin'], weight: ['400', '500'], variable: '--font-mono', display: 'swap' });

export const metadata: Metadata = {
  title: { default: 'ClientCrypt', template: '%s · ClientCrypt' },
  description: 'An interactive reference for cryptographic primitives and protocols, executed entirely in the browser with Rust compiled to WebAssembly.',
};

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
