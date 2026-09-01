/** Node-only checks of the TypeScript helpers (no browser). */
import { test, expect } from '@playwright/test';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { sha256, chainSha256 } from '../src/lib/sha256';
import { bytesToHex, hexToBytes, hammingDistanceHex, formatDuration } from '../src/lib/bytes';

test.describe('pure-JS SHA-256', () => {
  test('FIPS 180-4 vectors', () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(bytesToHex(sha256(enc('')))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(bytesToHex(sha256(enc('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(bytesToHex(sha256(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
    expect(bytesToHex(sha256(new Uint8Array(1000).fill(0x61)))).toBe('41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3');
  });
  test('chained workload is deterministic', () => {
    expect(bytesToHex(chainSha256(3))).toBe(bytesToHex(sha256(sha256(sha256(new Uint8Array(32))))));
  });
});

test.describe('byte helpers', () => {
  test('hex round trip and hamming distance', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
    expect(() => hexToBytes('0g')).toThrow();
    expect(hammingDistanceHex('00', 'ff')).toBe(8);
    expect(hammingDistanceHex('0f0f', 'f0f0')).toBe(16);
    expect(formatDuration(0.5)).toBe('500 ms');
    expect(formatDuration(3.2e9)).toContain('years');
  });
});

test.describe('static export', () => {
  test('ships headers, robots, sitemap and the wasm module', () => {
    for (const f of ['out/_headers', 'out/robots.txt', 'out/sitemap.xml', 'out/pkg/wasm_crypto_bg.wasm', 'out/404.html', 'out/classical/index.html', 'out/numbers/index.html', 'out/protocols/index.html', 'out/privacy/index.html', 'out/randomness/index.html']) {
      expect(existsSync(f), f).toBe(true);
    }
    const headers = readFileSync('out/_headers', 'utf8');
    expect(headers).toContain("'wasm-unsafe-eval'");
    // The site makes no network requests: connect-src is exactly 'self', and
    // the privacy page's stated guarantee is backed by a source scan.
    expect(headers).toMatch(/connect-src 'self';/);
    expect(headers).not.toContain('pwnedpasswords');
  });

  test('the source makes no network requests', () => {
    // The privacy page states this as a guarantee, so it is a test, not prose.
    const walk = (dir: string): string[] => readdirSync(dir).flatMap((name) => {
      const p = join(dir, name);
      return statSync(p).isDirectory() ? walk(p) : /\.(tsx?|mjs|js)$/.test(name) ? [p] : [];
    });
    const offenders = walk('src').filter((f) => /\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon/.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
    // The 404 is ours, not the framework default.
    expect(readFileSync('out/404.html', 'utf8')).toContain('No such page');
    // Every route is listed in the sitemap.
    const sitemap = readFileSync('out/sitemap.xml', 'utf8');
    for (const r of ['', 'numbers/', 'randomness/', 'protocols/', 'privacy/', 'benchmark/']) {
      expect(sitemap, r).toContain(`https://clientcrypt.nirbhay.dev/${r}<`);
    }
  });
});
