import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  // Fully static export: `out/` is servable by any static host (nginx,
  // Cloudflare Workers assets, GitHub Pages). trailingSlash makes every route a
  // directory with an index.html so no host needs rewrite rules.
  output: "export",
  trailingSlash: true,
};

export default nextConfig;
