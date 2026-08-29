# ClientCrypt

An interactive reference for cryptographic primitives and protocols. Every computation runs in the browser: the algorithms are Rust implementations (the RustCrypto crates) compiled to WebAssembly, and no input is sent to a server.

https://clientcrypt.nirbhay.dev

| §  | Section                   | Contents                                                                                      | Standards                        |
|----|---------------------------|-----------------------------------------------------------------------------------------------|----------------------------------|
| 1  | Classical ciphers         | Caesar, Atbash, affine, Vigenère; χ²-ranked exhaustive search, index of coincidence, key recovery | —                             |
| 2  | Block ciphers             | AES-128/192/256 in ECB, CBC, CTR, GCM; strict PKCS#7; block view; ECB image leakage demo       | FIPS 197, SP 800-38A/D           |
| 3  | Hash functions & MACs     | MD5, SHA-1, SHA-256, SHA-512, SHA3-256; HMAC; avalanche effect; HIBP k-anonymity lookup        | FIPS 180-4, FIPS 202, RFC 2104   |
| 4  | Public-key cryptography   | RSA (PKCS#1 v1.5, OAEP, PSS, key components); finite-field DH with RFC 7919 groups or generated safe primes; X25519 | RFC 8017, RFC 7919, RFC 7748 |
| 5  | Password security         | Entropy bound, attacker-rate table, top-1000 lookup, PBKDF2 and Argon2id timing               | RFC 8018, RFC 9106               |
| 6  | TLS 1.3 handshake         | X25519 key share, HKDF key schedule, traffic keys, AEAD record protection                     | RFC 8446, RFC 5869               |
| 7  | Encodings                 | Base64, Base64url, hex, percent, binary; code-point and UTF-8 byte view                       | RFC 4648                         |
| 8  | Benchmark                 | Identical chained SHA-256 workload in WebAssembly, JavaScript and WebCrypto                   | —                                |

The only network request the application can make is the optional Have I Been Pwned range query in §3 (first five hex digits of a SHA-1 digest).

## Correctness

`wasm-crypto` carries known-answer tests for every primitive it exposes: FIPS-197 Appendix C (AES-128/192/256), SP 800-38A (CBC, CTR), the GCM specification test cases, FIPS 180-4 and FIPS 202 digests, RFC 2202/4231 HMAC, RFC 6070-style PBKDF2-SHA256, the RFC 9106 Argon2id vector, RFC 7748 X25519, RFC 5869 HKDF, and the RFC 8448 TLS 1.3 key-schedule trace. The RFC 7919 primes are checked to be safe primes. Playwright drives the same vectors through the UI.

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

`public/_headers` and `docker/nginx.conf` carry the same headers: a CSP that allows `'wasm-unsafe-eval'` and Next.js's inline hydration scripts, and `connect-src` limited to the HIBP API.

## CI

One workflow, `.github/workflows/ci.yml`: build → `cargo test` → lint/type-check → Playwright → Lighthouse, then on pushes to `main` or `v*` tags a GHCR image and the optional deploy jobs. Dependabot version updates are disabled on purpose (see `.github/dependabot.yml`); apply updates by hand in batches.

## License

MIT — see `LICENSE`. The embedded password list is from [SecLists](https://github.com/danielmiessler/SecLists) (MIT).
