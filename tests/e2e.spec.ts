import { test, expect } from '@playwright/test';
import { ROUTES, open, field } from './helpers';

test.describe('every route', () => {
  for (const route of ROUTES) {
    test(`${route} renders without console errors`, async ({ page }) => {
      const errors = await open(page, route);
      expect(errors).toEqual([]);
      await expect(page.locator('.nav-link[aria-current="page"]')).toHaveCount(1);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
      expect(overflow).toBe(false);
    });
  }
});

test('classical: Caesar, Vigenère known answers and key recovery', async ({ page }) => {
  await open(page, '/classical/');
  await expect(page.getByLabel('Substitution output')).toContainText('WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ');
  await expect(page.getByLabel('Vigenère output')).toContainText('LXFOPV EF RNHR');
  await expect(page.getByText('Step 2 — recovered key').locator('..').locator('.stat-value')).toHaveText('LEMON');
  await expect(page.getByLabel('Recovered plaintext')).toContainText('It was the best of times');
  // Exhaustive search ranks the true shift first (highlighted row).
  await page.getByRole('group', { name: 'Direction' }).first().getByRole('button', { name: 'Decrypt' }).click();
  await expect(page.getByLabel('Substitution output')).toContainText('QEB NRFZH');
});

test('block ciphers: FIPS-197 vector, duplicate-block detection, GCM tamper detection', async ({ page }) => {
  await open(page, '/block-ciphers/');
  await expect(page.getByLabel('AES output')).toContainText('69c4e0d86a7b0430d8cdb78070b4c55a69c4e0d86a7b0430d8cdb78070b4c55a');
  await expect(page.getByText('= block 0')).toBeVisible();
  await field(page, 'Mode').selectOption('gcm');
  const out = await page.getByLabel('AES output').innerText();
  const ct = out.replace(/copy$/, '').trim();
  expect(ct.length).toBe((32 + 16) * 2);
  await page.getByRole('group', { name: 'Direction' }).getByRole('button', { name: 'Decrypt' }).click();
  await field(page, /Ciphertext ‖ tag/).fill(ct);
  await expect(page.getByLabel('AES output')).toContainText('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  await field(page, /Ciphertext ‖ tag/).fill('1' + ct.slice(1));
  await expect(page.locator('p[role="alert"]')).toContainText('Authentication failed');
});

test('hashing: digests, HMAC and avalanche', async ({ page }) => {
  await open(page, '/hashing/');
  await field(page, 'Message').first().fill('abc');
  await expect(page.getByText('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad').first()).toBeVisible();
  await expect(page.getByText('a9993e364706816aba3e25717850c26c9cd0d89d')).toBeVisible();
  await expect(page.getByLabel('HMAC tag')).toContainText('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  const changed = await page.getByText('Bits changed', { exact: true }).locator('..').locator('.stat-value').innerText();
  const n = Number(changed.split('/')[0]);
  expect(n).toBeGreaterThan(90);
  expect(n).toBeLessThan(166);
});

test('public key: RSA round trip, signature, DH and X25519 agreement', async ({ page }) => {
  test.slow();
  await open(page, '/asymmetric/');
  await expect(page.getByText('Both parties hold the same secret')).toBeVisible();
  await expect(page.getByText('Both sides derive the same 32-byte secret')).toBeVisible();
  await page.getByRole('button', { name: 'Generate key pair' }).click();
  await expect(page.getByText('BEGIN RSA PRIVATE KEY')).toBeVisible({ timeout: 60_000 });
  await page.getByRole('button', { name: 'Encrypt with public key' }).click();
  await page.getByRole('button', { name: 'Decrypt with private key' }).click();
  await expect(page.getByText('Decrypted: “Attack at dawn”')).toBeVisible();
  await page.getByRole('button', { name: 'Sign with private key' }).click();
  await page.getByRole('button', { name: 'Verify with public key' }).click();
  await expect(page.getByText('Signature valid')).toBeVisible();
  const msg = page.locator('section', { hasText: 'RSA signatures' }).getByLabel('Message');
  await msg.fill('I owe you £100');
  await page.getByRole('button', { name: 'Verify with public key' }).click();
  await expect(page.getByText('Signature invalid')).toBeVisible();
});

test('passwords: common-password rank and KDF timing', async ({ page }) => {
  test.slow();
  await open(page, '/passwords/');
  await field(page, 'Password').fill('123456');
  await expect(page.getByText('#1', { exact: true })).toBeVisible();
  await field(page, /PBKDF2-HMAC-SHA256 iterations/).selectOption('1000');
  await field(page, /Argon2id memory/).selectOption('1024');
  await page.getByRole('button', { name: 'Derive keys and time them' }).click();
  await expect(page.getByText('Argon2id tag')).toBeVisible({ timeout: 60_000 });
});

test('tls: full handshake and record protection', async ({ page }) => {
  await open(page, '/tls/');
  await page.getByRole('button', { name: 'Send ClientHello' }).click();
  await page.getByRole('button', { name: 'Send ServerHello' }).click();
  await page.getByRole('button', { name: 'Run key schedule' }).click();
  await expect(page.getByText('33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a')).toBeVisible(); // early secret without PSK
  await expect(page.getByText('6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba')).toBeVisible(); // derived
  await page.getByRole('button', { name: 'Encrypt record' }).click();
  await expect(page.getByText('On the wire:')).toContainText('1703030');
});

test('encoding: base64 round trip', async ({ page }) => {
  await open(page, '/encoding/');
  await field(page, 'Text').fill('Hello, World!');
  await expect(page.getByText('SGVsbG8sIFdvcmxkIQ==')).toBeVisible();
  await page.getByRole('button', { name: 'Encoding → text' }).click();
  await expect(page.locator('.out-wrap', { hasText: 'Decoded text' }).locator('.out')).toContainText('Hello, World!');
});

test('benchmark: WASM and JS agree on the final digest', async ({ page }) => {
  test.slow();
  await open(page, '/benchmark/');
  await page.getByRole('button', { name: 'Run all' }).click();
  await expect(page.getByText('All runs agree on the final digest')).toBeVisible({ timeout: 120_000 });
});
