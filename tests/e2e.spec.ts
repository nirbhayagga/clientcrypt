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
  // Exhaustive search ranks the true key first for Caesar and affine, and
  // explains that Atbash has no key space at all.
  const searchRow = page.locator('section', { hasText: 'Exhaustive key search' }).locator('tbody tr').first();
  await expect(searchRow).toContainText('k = 3');
  await field(page, 'Text').first().fill('It was the best of times, it was the worst of times, it was the age of wisdom');
  await page.getByLabel('Cipher', { exact: true }).selectOption('affine');
  await expect(searchRow).toContainText('a = 5, b = 8');
  await expect(searchRow).toContainText('It was the best of times');
  await page.getByLabel('Cipher', { exact: true }).selectOption('atbash');
  await expect(page.getByText('Nothing to search')).toBeVisible();
  await page.getByLabel('Cipher', { exact: true }).selectOption('caesar');
  await page.getByRole('group', { name: 'Direction' }).first().getByRole('button', { name: 'Decrypt' }).click();
  await expect(page.getByLabel('Substitution output')).toContainText('Fq txp qeb ybpq lc qfjbp');
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

test('block ciphers: reduced-round avalanche and keystream reuse', async ({ page }) => {
  await open(page, '/block-ciphers/');

  // Avalanche rises from near-zero at one round to ~50% by ten, without the
  // key changing under the fixed-key comparison.
  const rounds = page.locator('section', { hasText: 'What the rounds are for' });
  const avalanche = rounds.getByText('Avalanche at this round count').locator('..').locator('.stat-value');
  const keyLabel = rounds.locator('.cap').last();
  // The caption carries both the round count and the key; only the key must
  // stay fixed while scrubbing, so compare that part alone.
  const keyOf = async () => (await keyLabel.innerText()).replace(/^.*· /, '');
  const keyAt1 = await keyOf();
  const av1 = parseFloat((await avalanche.innerText()).replace('%', ''));
  expect(av1).toBeLessThan(20);

  const slider = rounds.getByRole('slider');
  await slider.focus();
  for (let i = 0; i < 9; i++) await slider.press('ArrowRight');
  await expect(avalanche).not.toHaveText(`${av1}%`);
  const av10 = parseFloat((await avalanche.innerText()).replace('%', ''));
  expect(av10).toBeGreaterThan(45);
  expect(av10).toBeLessThan(55);
  expect(await keyOf()).toBe(keyAt1); // same key throughout the scrub

  // XOR-ing two ciphertexts under a reused (key, nonce) recovers the XOR of
  // the two plaintexts — a canvas that isn't just noise.
  const keystream = page.locator('section', { hasText: 'Reusing a key and nonce' });
  await expect(keystream.locator('canvas')).toHaveCount(5);
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
  await page.locator('section', { hasText: 'Guessing-resistance model' }).getByLabel(/Password/).fill('123456');
  await expect(page.getByText('#1', { exact: true })).toBeVisible();
  await field(page, /PBKDF2-HMAC-SHA256 iterations/).selectOption('1000');
  await field(page, /Argon2id memory/).selectOption('1024');
  await page.getByRole('button', { name: 'Derive keys and time them' }).click();
  await expect(page.getByText('Argon2id tag')).toBeVisible({ timeout: 60_000 });

  // Dictionary attack: a fast hash cracks a listed password, and Argon2id
  // finds the same word far more slowly per guess.
  const dict = page.locator('section', { hasText: 'Dictionary attack' });
  await dict.getByRole('button', { name: 'Run the attack' }).click();
  await expect(dict.getByText('cracked')).toBeVisible({ timeout: 30_000 });
  await expect(dict.getByText('found at rank #10')).toBeVisible();
  await dict.getByLabel('Stored hash').selectOption('argon2');
  await dict.getByRole('button', { name: 'Run the attack' }).click();
  await expect(dict.getByText('cracked')).toBeVisible({ timeout: 30_000 });
  await expect(dict.getByText('48 candidates hashed')).toBeVisible();
});

test('attacks: padding oracle recovers plaintext and DH MITM gives Mallory both keys', async ({ page }) => {
  test.slow();
  await open(page, '/attacks/');

  // Padding oracle: the recovered plaintext matches the secret message, with
  // no key used by the attack.
  const oracle = page.locator('section', { hasText: 'padding-oracle' });
  await oracle.getByRole('button', { name: 'Run the attack' }).click();
  await expect(oracle.getByText('plaintext recovered')).toBeVisible({ timeout: 30_000 });
  await expect(oracle.locator('.out.tone-danger')).toContainText('transfer approved');
  await expect(oracle.getByText('reconstructed')).toBeVisible();

  // DH MITM: Mallory shares a key with each victim; the victims share none.
  const mitm = page.locator('section', { hasText: 'Man-in-the-middle' });
  await expect(mitm.getByText('Alice ↔ Mallory').locator('..').locator('.stat-value')).toHaveText('shared key');
  await expect(mitm.getByText('Bob ↔ Mallory').locator('..').locator('.stat-value')).toHaveText('shared key');
  await expect(mitm.getByText('Alice ↔ Bob', { exact: true }).locator('..').locator('.stat-value')).toHaveText('no shared key');
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

test('hashing internals: SHA-256 rounds and the length extension forgery', async ({ page }) => {
  await open(page, '/hashing/');
  const internals = page.locator('section', { hasText: 'Inside SHA-256' });
  // "abc" is one block; the state leaving it is the digest.
  await expect(internals.getByText('1 block · 64 bytes padded')).toBeVisible();
  await expect(internals.getByText('W[0] = 61626380')).toBeVisible(); // schedule word 0 is "abc" + 0x80
  await expect(internals.getByText('ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad')).toBeVisible();

  // The forgery succeeds with the right secret length and fails with a wrong one.
  const ext = page.locator('section', { hasText: 'Length extension' });
  await expect(ext.getByText('Forged.')).toBeVisible();
  await ext.getByRole('slider').fill('20');
  await expect(ext.getByText('guessed secret length is wrong')).toBeVisible();
});

test('numbers: modular exponentiation, Euclid, RSA and DH by hand', async ({ page }) => {
  await open(page, '/numbers/');
  // 4^13 mod 497 = 445 in four squarings rather than twelve multiplications.
  await expect(page.getByText('445', { exact: true }).first()).toBeVisible();
  // Extended Euclid gives the RSA inverse 17^-1 mod 3120 = 2753.
  await expect(page.getByText('a⁻¹ mod b = 2753')).toBeVisible();
  // The textbook RSA example: 61 × 53 = 3233, d = 413, 65 -> 2790 -> 65.
  const rsa = page.locator('section', { hasText: 'RSA key generation, worked by hand' });
  await expect(rsa.getByText('61 × 53 = 3233')).toBeVisible();
  await expect(rsa.getByText('(3233, 413)')).toBeVisible();
  await expect(rsa.getByText('65 → 2790 → 65')).toBeVisible();
  // Diffie-Hellman with p = 23 lands on the shared secret 2.
  await expect(page.getByText('Both sides hold 2.')).toBeVisible();
});

test('privacy: no-requests claim matches the shipped policy, reachable from every page', async ({ page }) => {
  await open(page, '/classical/');
  await page.getByRole('link', { name: 'privacy' }).click();
  await expect(page.locator('h1')).toHaveText('What this site does with your input');
  await expect(page.getByText('no network requests at all')).toBeVisible();
  // The page's central claim must match the shipped policy: connect-src is
  // exactly 'self', with no other origin permitted.
  const headers = await (await page.request.get('/_headers')).text();
  expect(headers).toMatch(/connect-src 'self';/);
  expect(headers).not.toContain('pwnedpasswords');
});

test('randomness: RANDU fails in 3D, the CSPRNG passes the NIST tests', async ({ page }) => {
  test.slow();
  await open(page, '/randomness/');
  // Three plots, defaulting to the 3D view where RANDU's lattice shows.
  const lattice = page.locator('section', { hasText: 'Seeing the difference' });
  await expect(lattice.locator('canvas')).toHaveCount(3);
  await lattice.getByRole('button', { name: '2D pairs' }).click();
  await expect(lattice.getByText('two dimensions are not enough')).toBeVisible();

  // Neither the CSPRNG nor a plain counter is rejected — that is the lesson.
  const tests = page.locator('section', { hasText: 'Statistical tests' });
  await expect(tests.getByText('not rejected').first()).toBeVisible();
  await tests.getByLabel('Source', { exact: true }).selectOption('counter');
  await expect(tests.getByText('Monobit p').locator('..').locator('.stat-value')).toHaveText('1.0000');
  await expect(tests.getByText('Runs p').locator('..').locator('.stat-value')).toHaveText('1.0000');
  // A broken LCG, by contrast, is caught.
  await tests.getByLabel('Source', { exact: true }).selectOption('lcg');
  await expect(tests.getByText('Distinct bytes')).toBeVisible();

  // Timing jitter yields a conditioned 256-bit key.
  await page.getByRole('button', { name: 'CPU jitter' }).click();
  await page.getByRole('button', { name: /Measure/ }).click();
  await expect(page.getByText('Conditioned to a 256-bit key')).toBeVisible({ timeout: 30_000 });
});

test('ChaCha20-Poly1305 and Ed25519 reproduce their RFC vectors', async ({ page }) => {
  await open(page, '/block-ciphers/');
  const chacha = page.locator('section', { hasText: 'ChaCha20-Poly1305' });
  await expect(chacha.getByLabel('ChaCha20 output')).toContainText('d31a8d34648e60db7b86afbc53ef7ec2');
  await expect(chacha.getByLabel('ChaCha20 output')).toContainText('1ae10b594f09e26a7e902ecbd0600691');
  await expect(chacha.getByText('matches the RFC 8439')).toBeVisible();

  await open(page, '/asymmetric/');
  const ed = page.locator('section', { hasText: 'Ed25519 signatures' });
  await ed.getByRole('button', { name: 'Sign', exact: true }).click();
  await ed.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByText('Valid for this message')).toBeVisible();
  await ed.getByLabel('Message').fill('Transfer £9000 to Mallory');
  await ed.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByText('Invalid —')).toBeVisible();
});

test('404: a missing page gets the custom not-found', async ({ page }) => {
  const res = await page.goto('/no-such-page/');
  expect(res?.status()).toBe(404);
  await expect(page.locator('h1')).toHaveText('No such page');
  await expect(page.getByRole('link', { name: 'Number theory', exact: true })).toBeVisible();
});

test('protocols: WPA2 vector, TOTP, JWT tamper detection, WireGuard agreement', async ({ page }) => {
  test.slow();
  await open(page, '/protocols/');

  // WPA2: the IEEE 802.11i test vector, and the SSID really is the salt.
  await expect(page.getByLabel('WPA2 PMK')).toContainText('f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e');
  await field(page, 'SSID').fill('ThisIsASSID');
  await field(page, 'Passphrase').fill('ThisIsAPassword');
  await expect(page.getByLabel('WPA2 PMK')).toContainText('0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af');

  // TOTP: a live code of the requested width, from the RFC test secret.
  const code = page.getByText('Current code').locator('..').locator('.stat-value');
  await expect(code).toHaveText(/^\d{6}$/);
  await field(page, 'Digits').selectOption('8');
  await expect(code).toHaveText(/^\d{8}$/);

  // JWT: sign, verify, then tamper with the payload segment.
  await page.getByRole('button', { name: 'Sign token' }).click();
  await expect(page.getByText('Signature valid')).toBeVisible();
  const token = page.getByLabel(/^Token/);
  const signed = (await token.inputValue()).split('.');
  await token.fill(`${signed[0]}.${signed[1].slice(0, -2)}XY.${signed[2]}`);
  await expect(page.getByText('Signature invalid')).toBeVisible();

  // WireGuard: both peers must land on the same transport keys.
  await page.getByRole('button', { name: 'Run handshake' }).click();
  await expect(page.getByText('Both peers independently derived the same chaining key')).toBeVisible();
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

test('classical: Enigma matches the known vector and inverts itself', async ({ page }) => {
  await open(page, '/classical/');
  const panel = page.locator('section', { hasText: 'The Enigma machine' });
  await panel.getByLabel('Plugboard pairs').fill('');
  await panel.getByLabel('Message').fill('AAAAA');
  // Rotors I II III, positions AAA, rings AAA: the classic AAAAA → BDZGO.
  await expect(page.getByLabel('Enigma output')).toContainText('BDZGO');
  await expect(page.getByLabel('Enigma roundtrip')).toContainText('AAAAA');
  // With the plugboard restored, the involution still holds on a real sentence.
  await panel.getByLabel('Plugboard pairs').fill('AV BS CG DL FU');
  await panel.getByLabel('Message').fill('WEATHER REPORT');
  await expect(page.getByLabel('Enigma roundtrip')).toContainText('WEATHER REPORT');
});

test('randomness: CSPRNG stream is deterministic, commit-reveal catches a cheat', async ({ page }) => {
  await open(page, '/randomness/');
  // Same seed produces the same stream; a flipped seed bit changes ~half the output.
  const csprng = page.locator('section', { hasText: 'Stretching a seed' });
  await expect(csprng.getByText('same seed → identical every time')).toBeVisible();
  await expect(csprng.getByText(/% of bits differ/)).toBeVisible();
  // Birthday bound: 16-bit values collide after roughly 321 draws, not 65,536.
  const birthday = page.locator('section', { hasText: 'The birthday bound' });
  await birthday.getByLabel('Value size').selectOption('16');
  await birthday.getByRole('button', { name: 'Draw until values collide' }).click();
  await expect(birthday.getByText('Theory: 1.25 · √space').locator('..')).toContainText('321');
  // Commit–reveal: honest reveal verifies; revealing the other bit is caught.
  const coin = page.locator('section', { hasText: 'commit–reveal coin flip' });
  await expect(coin.getByText(/Commitment verifies.*heads/)).toBeVisible();
  await coin.getByRole('group', { name: "Alice's behaviour" }).getByRole('button', { name: 'Cheat' }).click();
  await expect(coin.getByText(/Caught/)).toBeVisible();
});

test('passwords: diceware generates a countable-entropy passphrase', async ({ page }) => {
  await open(page, '/passwords/');
  const panel = page.locator('section', { hasText: 'diceware' });
  await panel.getByRole('button', { name: 'Generate' }).click();
  const phrase = await page.getByLabel('Generated passphrase').textContent();
  expect(phrase!.trim().split('-')).toHaveLength(6);
  await expect(panel.getByText('Entropy', { exact: true }).locator('..')).toContainText('77.5 bits');
});

test('zkp: Schnorr proof verifies and the Fiat-Shamir signature detects tampering', async ({ page }) => {
  await open(page, '/zkp/');
  await page.getByRole('button', { name: 'Issue a random challenge' }).click();
  const verdict = page.getByText('Verdict').locator('..');
  await expect(verdict).toContainText('accepted');
  await page.getByRole('button', { name: 'Sign the message' }).click();
  await expect(page.getByText('Signature verifies').locator('..')).toContainText('yes');
  await expect(page.getByText('Same signature on a tampered message').locator('..')).toContainText('rejected');
});
