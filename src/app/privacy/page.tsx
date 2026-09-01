import type { Metadata } from 'next';
import Link from 'next/link';
import { Panel, Note } from '@/components/ui';

export const metadata: Metadata = {
  title: 'Privacy',
  description: 'What ClientCrypt collects (nothing), the single outbound request it can make, and what the host logs regardless.',
  alternates: { canonical: '/privacy/' },
};

export default function PrivacyPage() {
  return (
    <>
      <header className="page-head">
        <div className="kicker">Privacy</div>
        <h1>What this site does with your input</h1>
        <p className="lede">
          Nothing, with one exception you have to click. This page exists so that claim can be checked rather than trusted.
        </p>
      </header>

      <div className="stack">
        <Panel title="No collection">
          <p>
            There are no accounts, no cookies, no <code>localStorage</code>, no analytics and no server that receives what you
            type. Every algorithm on this site is Rust compiled to WebAssembly, executed in your browser; the passwords, keys and
            messages you enter stay in the tab and disappear when you close it.
          </p>
          <p className="muted small">
            This is enforced, not just intended. The site ships a Content-Security-Policy whose <code>connect-src</code> permits
            exactly two origins: this site and the one API below. A script on this page cannot send your input anywhere else,
            because the browser refuses the connection.
          </p>
        </Panel>

        <Panel title="The one outbound request">
          <p>
            §3 offers a check against the <em>Have I Been Pwned</em> breach corpus. It runs only when you press the button, and it
            uses k-anonymity: your password is hashed locally with SHA-1 and only the <strong>first five hexadecimal
            characters</strong> of that digest are sent — never the password, never the full hash.
          </p>
          <p>
            The server returns every hash suffix sharing that prefix, and the comparison happens in your browser. The request also
            asks for a padded response, so the number of results cannot be used to infer anything either. Cloudflare, who operate
            that API, see your IP address and a five-character prefix shared by many thousands of passwords.
          </p>
          <p className="muted small">
            If you never press that button, this site makes no third-party requests at all.
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
            container image or by building the repository, with no network access at all beyond the optional lookup above.
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
          Open your browser&apos;s network panel and use the site: apart from the page itself you will see no requests until you run
          the §3 lookup. The policy that enforces it is in <code>public/_headers</code>, and the single <code>fetch</code> call is in
          the §3 source. Everything is in{' '}
          <a href="https://github.com/nirbhayagga/clientcrypt" target="_blank" rel="noreferrer">the repository</a>, MIT licensed.
        </Note>

        <p className="muted small">
          <Link href="/">Back to the overview</Link>
        </p>
      </div>
    </>
  );
}
