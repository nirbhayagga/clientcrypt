import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: '§10 Benchmark',
  description: 'The same chained SHA-256 workload in Rust/WebAssembly, JavaScript and WebCrypto.',
  alternates: { canonical: '/benchmark/' },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
