# Stage 1: compile the Rust crate to WebAssembly with wasm-pack.
FROM rust:1-slim-bookworm AS wasm
ARG WASM_PACK_VERSION=0.15.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add wasm32-unknown-unknown \
 && ARCH="$(uname -m)" \
 && curl -fsSL "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-${ARCH}-unknown-linux-musl.tar.gz" \
    | tar -xz --strip-components=1 -C /usr/local/bin "wasm-pack-v${WASM_PACK_VERSION}-${ARCH}-unknown-linux-musl/wasm-pack"
WORKDIR /src/wasm-crypto
COPY wasm-crypto/ ./
RUN wasm-pack build --release --target web --out-dir /src/public/pkg

# Stage 2: type-check and build the static site.
FROM node:22-alpine AS web
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
COPY --from=wasm /src/public/pkg ./public/pkg
RUN npm run build:web

# Stage 3: serve out/ with nginx (~50 MB image).
FROM nginx:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=web /app/out /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1/ > /dev/null || exit 1
