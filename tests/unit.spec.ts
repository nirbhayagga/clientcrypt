/** Node-only checks of the TypeScript helpers (no browser). */
import { test, expect } from '@playwright/test';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { sha256, chainSha256 } from '../src/lib/sha256';
import { bytesToHex, hexToBytes, hammingDistanceHex, formatDuration } from '../src/lib/bytes';
import { TARGETS, expectedBreakSeconds, universeAges, formatBig } from '../src/lib/attack';

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

test.describe('attack-cost arithmetic', () => {
  test('replays Deep Crack and the cosmic scales in the §13 prose', () => {
    // EFF's Deep Crack searched ~9.2×10¹⁰ DES keys/s; expected time ≈ 4.5 days
    // (the 1998 run found the RSA challenge key in 56 hours, a lucky draw).
    const days = expectedBreakSeconds(56, 9.2e10) / 86_400;
    expect(days).toBeGreaterThan(4);
    expect(days).toBeLessThan(5);
    // The panel's headline claim: AES-128 against every Bitcoin ASIC on earth
    // (~10²¹ ops/s) still expects ~5 billion years.
    const years = expectedBreakSeconds(128, 1e21) / 31_557_600;
    expect(years).toBeGreaterThan(4e9);
    expect(years).toBeLessThan(7e9);
    // AES-256 costs exactly 2¹²⁸ times more, as the Callout states.
    expect(expectedBreakSeconds(256, 1e21) / expectedBreakSeconds(128, 1e21)).toBe(2 ** 128);
    expect(universeAges(4.35e17)).toBe(1);
    expect(formatBig(5.39e20)).toBe('5.4 × 10²⁰');
    expect(formatBig(123)).toBe('123');
    // SP 800-57 equivalences the table depends on.
    const bits = Object.fromEntries(TARGETS.map((t) => [t.name, t.bits]));
    expect(bits['RSA-2048']).toBe(112);
    expect(bits['RSA-3072']).toBe(bits['AES-128']);
    expect(bits['X25519 / P-256']).toBe(128);
  });
});

test.describe('static export', () => {
  test('ships headers, robots, sitemap and the wasm module', () => {
    for (const f of ['out/_headers', 'out/robots.txt', 'out/sitemap.xml', 'out/pkg/wasm_crypto_bg.wasm', 'out/404.html', 'out/classical/index.html', 'out/numbers/index.html', 'out/protocols/index.html', 'out/privacy/index.html', 'out/randomness/index.html', 'out/attacks/index.html', 'out/zkp/index.html', 'out/sw.js']) {
      expect(existsSync(f), f).toBe(true);
    }
    // The generated service worker precaches the whole export by route URL.
    const sw = readFileSync('out/sw.js', 'utf8');
    expect(sw).toMatch(/clientcrypt-[0-9a-f]{16}/);
    for (const asset of ['"/"', '"/zkp/"', '"/pkg/wasm_crypto_bg.wasm"', '"/site.webmanifest"']) {
      expect(sw, asset).toContain(asset);
    }
    expect(sw).not.toContain('index.html"'); // routes, not file paths
    expect(sw).not.toContain('_headers');
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
    for (const r of ['', 'numbers/', 'randomness/', 'protocols/', 'attacks/', 'zkp/', 'privacy/', 'benchmark/']) {
      expect(sitemap, r).toContain(`https://clientcrypt.nirbhay.dev/${r}<`);
    }
  });
});
