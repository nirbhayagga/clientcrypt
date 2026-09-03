# ClientCrypt

An interactive reference for cryptographic primitives and protocols. Every computation runs in the browser: the algorithms are Rust implementations (the RustCrypto crates) compiled to WebAssembly, and no input is sent to a server.

https://clientcrypt.nirbhay.dev

| §  | Section                   | Contents                                                                                      | Standards                        |
|----|---------------------------|-----------------------------------------------------------------------------------------------|----------------------------------|
| 1  | Classical ciphers         | Caesar, Atbash, affine, Vigenère; χ²-ranked exhaustive search, index of coincidence, key recovery; an Enigma I with historical rotor wirings; the one-time pad's perfect secrecy (forge a key for any claimed plaintext) and the two-time-pad crib-drag attack | Shannon 1949   |
| 2  | Block ciphers             | AES-128/192/256 in ECB, CBC, CTR, GCM; ChaCha20-Poly1305; reduced-round and keystream-reuse image demos; strict PKCS#7; ECB leakage | FIPS 197, SP 800-38A/D, RFC 8439 |
| 3  | Hash functions & MACs     | MD5 through SHA3-256; the SHA-256 compression function round by round; the length extension attack; HMAC; avalanche; the k-anonymity query pattern | FIPS 180-4, FIPS 202, RFC 2104 |
| 4  | Number theory             | Square-and-multiply modular exponentiation, extended Euclid and modular inverses, RSA and Diffie–Hellman worked by hand at toy sizes | —          |
| 5  | Randomness                | RANDU's lattice in 3D, NIST monobit/runs tests, von Neumann extraction of pointer and CPU-jitter entropy, a ChaCha20 CSPRNG from a seed, modulo bias vs rejection sampling, Fisher–Yates, the birthday bound, Monte Carlo π, a commit–reveal coin flip | NIST SP 800-22 |
| 6  | Public-key cryptography   | RSA (PKCS#1 v1.5, OAEP, PSS, key components); finite-field DH with RFC 7919 groups; X25519 agreement; Ed25519 signatures | RFC 8017, RFC 7919, RFC 7748, RFC 8032 |
| 7  | Password security         | Entropy bound, attacker-rate table, an EFF-wordlist diceware generator, a timed dictionary attack over fast vs memory-hard hashes, PBKDF2/scrypt/Argon2id | RFC 8018, RFC 7914, RFC 9106 |
| 8  | TLS 1.3 handshake         | X25519 key share, HKDF key schedule, traffic keys, AEAD record protection                     | RFC 8446, RFC 5869               |
| 9  | Applied protocols         | WPA2-PSK key derivation, HOTP/TOTP one-time passwords, JWT signing (HS256/RS256), the WireGuard handshake | IEEE 802.11i, RFC 4226/6238, RFC 7519, Noise IKpsk2 |
| 10 | Attacks                   | The CBC padding-oracle attack recovering plaintext from a one-bit oracle, and a man-in-the-middle on unauthenticated Diffie–Hellman | Vaudenay 2002 |
| 11 | Zero-knowledge proofs     | The Schnorr identification protocol run interactively, then made non-interactive (a signature) with Fiat–Shamir | Schnorr 1991                     |
| 12 | Encodings                 | Base64, Base64url, hex, percent, binary; code-point and UTF-8 byte view                       | RFC 4648                         |
| 13 | Benchmark                 | Identical chained SHA-256 workload in WebAssembly, JavaScript and WebCrypto; expected break times for DES through AES-256 and RSA/ECC at SP 800-57 equivalent strengths, from your measured rate up to the whole Bitcoin network | NIST SP 800-57 |

The application makes **no network requests at all**: `connect-src` is `'self'` in the shipped Content-Security-Policy, and the source contains no `fetch` call. Open the network tab and nothing leaves the page.

It is also an installable PWA that works fully offline: a generated service worker precaches the entire static export (including the WebAssembly module), so after one visit the site runs with the network cable unplugged.

## Correctness

`wasm-crypto` carries known-answer tests for every primitive it exposes: FIPS-197 Appendix C (AES-128/192/256), SP 800-38A (CBC, CTR), the GCM specification test cases, FIPS 180-4 and FIPS 202 digests, RFC 2202/4231 HMAC, RFC 6070-style PBKDF2-SHA256, the RFC 9106 Argon2id vector, RFC 7748 X25519, RFC 5869 HKDF, the RFC 8448 TLS 1.3 key-schedule trace, the IEEE 802.11i WPA2 PMK vectors, the RFC 4226 / RFC 6238 HOTP and TOTP vectors, the RFC 7914 scrypt vector, the RFC 8439 ChaCha20-Poly1305 vector, and the RFC 8032 Ed25519 vectors. The hand-written SHA-256 used for the round-by-round view is checked against the `sha2` crate at every padding boundary, and the length extension attack is verified to forge a digest that matches the genuine one. The WireGuard handshake is checked by having both peers derive their transport keys independently and requiring agreement. The RFC 7919 primes are checked to be safe primes. Playwright drives the same vectors through the UI.

```bash
cargo test --manifest-path wasm-crypto/Cargo.toml   # crate tests
npm test                                            # builds, serves out/, runs Playwright (unit + e2e + phone viewport)
npm run lighthouse                                  # Lighthouse CI against out/ (set CHROME_PATH if needed)
```

## Development

Requires Node 22, a stable Rust toolchain with the `wasm32-unknown-unknown` target, and `wasm-pack` (installed as an npm dev dependency).

```bash
rustup target add wasm32-unknown-unknown
npm ci
npm run build:wasm     # wasm-pack → public/pkg (git-ignored)
npm run dev            # Next.js dev server
npm run build          # wasm + static export to out/
npm run preview        # serve out/
```

Layout: `wasm-crypto/src/*.rs` is one module per section, exported through `wasm-bindgen`; `src/lib/wasm.ts` loads the module once and exposes `useWasm()`; `src/app/<section>/page.tsx` is the UI, built from the components in `src/components/ui.tsx`. All fallible exports return a JavaScript `Error` rather than panicking.

## Deployment

The build is a static export (`out/`), so any static host works.

**Cloudflare Workers (static assets)** — `wrangler.jsonc` is included. In Workers Builds use build command `npm run build:cloudflare` (the build image has no Rust; the script installs a minimal toolchain), deploy command `npx wrangler deploy`, and `NODE_VERSION = 22`. Alternatively the CI workflow deploys after tests when the repository variable `DEPLOY_CLOUDFLARE=true` and the `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` secrets are set.

**Container** — `docker compose up -d` pulls `ghcr.io/nirbhayagga/clientcrypt:latest` (nginx serving `out/`, security headers and CSP in `docker/nginx.conf`); add `--build` to build from source.

**GitHub Pages** — set repository variable `DEPLOY_PAGES=true` and Pages source "GitHub Actions".

`public/_headers` and `docker/nginx.conf` carry the same headers: a CSP that allows `'wasm-unsafe-eval'` and Next.js's inline hydration scripts, with `connect-src 'self'` — no cross-origin request is possible.

## CI

One workflow, `.github/workflows/ci.yml`: build → `cargo test` → lint/type-check → Playwright → Lighthouse, then on pushes to `main` or `v*` tags a GHCR image and the optional deploy jobs. Dependabot version updates are disabled on purpose (see `.github/dependabot.yml`); apply updates by hand in batches.

## Related

[Stepwise](https://stepwise.nirbhay.dev) is the companion site for algorithms and data structures, and the two cross-link where a topic has both a data-structure and a cryptographic reading: hash *tables* (chaining, probing, rehashing) and the sieve of Eratosthenes live there; cryptographic hash functions and modular arithmetic for RSA/Diffie–Hellman live here.

## License

MIT — see `LICENSE`. The embedded password list is from [SecLists](https://github.com/danielmiessler/SecLists) (MIT).
