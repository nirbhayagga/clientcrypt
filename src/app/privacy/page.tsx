import type { Metadata } from 'next';
import Link from 'next/link';
import { Panel, Note } from '@/components/ui';

export const metadata: Metadata = {
  title: 'Privacy',
  description: 'ClientCrypt collects nothing and makes no network requests. This page says how to verify that rather than take it on trust.',
  alternates: { canonical: '/privacy/' },
};

export default function PrivacyPage() {
  return (
    <>
      <header className="page-head">
        <div className="kicker">Privacy</div>
        <h1>What this site does with your input</h1>
        <p className="lede">
          Nothing. It makes no network requests at all — not one. This page exists so that claim can be checked rather than trusted.
        </p>
      </header>

      <div className="stack">
        <Panel title="No collection, no requests">
          <p>
            There are no accounts, no cookies, no <code>localStorage</code>, no analytics, and no server that ever receives
            what you type. Every algorithm on this site is Rust compiled to WebAssembly and runs in your browser; the
            passwords, keys and messages you enter stay in the tab and disappear when you close it.
          </p>
          <p className="muted small">
            This is enforced, not just intended. The site ships a Content-Security-Policy whose <code>connect-src</code> is
            <code>&apos;self&apos;</code> — the browser will refuse any attempt by this page to contact another origin, whether
            that attempt came from the site&apos;s own code or from something injected into it.
          </p>
        </Panel>

        <Panel title="Hosting">
          <p>
            The site is static files served by Cloudflare Workers. Like any web server, Cloudflare records ordinary request
            metadata — IP address, user agent, timestamps, which files were fetched — for delivery and abuse prevention. That
            logging is outside this project&apos;s control and applies whether or not you interact with anything.
          </p>
          <p className="muted small">
            You can avoid it entirely: the site is a folder of static files, so you can run it yourself from the published
            container image or by building the repository, with no internet connection at all.
          </p>
        </Panel>

        <Panel title="No third-party assets">
          <p>
            Fonts, icons, styles and the WebAssembly module are all served from this domain. Nothing is loaded from a font CDN,
            a script host or a tag manager, so no third party learns that you visited — a leak most sites that claim privacy
            still have through embedded fonts alone.
          </p>
        </Panel>

        <Note title="Verifying any of this">
          Open your browser&apos;s network panel and use the site: apart from the page and its own assets you will see no requests,
          ever. The policy that enforces it is in <code>public/_headers</code>, mirrored in <code>docker/nginx.conf</code>, and
          the source contains no <code>fetch</code> call. Everything is in{' '}
          <a href="https://github.com/nirbhayagga/clientcrypt" target="_blank" rel="noreferrer">the repository</a>, MIT licensed.
        </Note>

        <p className="muted small">
          <Link href="/">Back to the overview</Link>
        </p>
      </div>
    </>
  );
}
