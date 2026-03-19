# ClientCrypt - Professional Security Suite

Educational WASM-powered cryptographic analysis platform. All crypto runs client-side in Rust/WASM for privacy and performance. Inspired by developer tools like CyberChef, IT-Tools, and DevToys, but specifically focused on providing a deep, interactive educational experience for cryptography utilizing WebAssembly.

### Features
- Classical Ciphers (Caesar, Vigenere)
- Block Ciphers (AES ECB and CBC)
- Asymmetric Crypto (RSA, Diffie-Hellman)
- Secure Hashing (SHA-256, HMAC)
- Password Security Analysis (Entropy, Dictionary attacks, Benchmarks)
- TLS 1.3 Handshake Simulation

## Deployment

ClientCrypt can be easily self-hosted.

### Option 1: Docker Compose with Traefik (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/clientcrypt.git
   cd clientcrypt
   ```
2. Start the container using Docker Compose:
   ```bash
   docker-compose up -d --build
   ```
This will build the static export using the multi-stage Dockerfile and serve it via NGINX. Traefik labels are included in `docker-compose.yml` for automatic SSL and reverse proxy configuration. If you are not using Traefik, uncomment the `ports` section in `docker-compose.yml`.

### Option 2: Local Node.js Build

1. Install dependencies:
   ```bash
   npm install
   ```
2. Build the Next.js static export:
   ```bash
   npm run build
   ```
3. Serve the `out/` directory using any static file server (like `npx serve out`).

## Development

```bash
# Frontend dev
npm run dev

# WASM build (requires Rust and wasm-pack)
# Ensure ~/.cargo/bin is in your PATH
cd wasm-crypto
wasm-pack build --target web --out-dir ../public/pkg
```
