import type { Metadata } from 'next';
import Link from 'next/link';
import { SECTIONS } from '@/lib/sections';

export const metadata: Metadata = {
  title: 'Page not found',
  description: 'That page does not exist on ClientCrypt.',
};

export default function NotFound() {
  return (
    <>
      <header className="page-head">
        <div className="kicker">404 · Not found</div>
        <h1>No such page</h1>
        <p className="lede">
          That address does not match anything here. Nothing was sent anywhere — this site has no server to ask.
        </p>
      </header>

      <section className="panel">
        <div className="panel-head"><h2>Sections</h2></div>
        <table className="toc">
          <tbody>
            <tr>
              <td className="num">§0</td>
              <td><Link href="/">Overview</Link></td>
            </tr>
            {SECTIONS.map((s) => (
              <tr key={s.href}>
                <td className="num">{s.num}</td>
                <td><Link href={s.href}>{s.label}</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
