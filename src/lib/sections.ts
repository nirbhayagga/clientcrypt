/** The section list. Imported by both the client Sidebar and the server-
 *  rendered 404 page, so it cannot live inside a 'use client' module. */
export const SECTIONS = [
  { href: '/classical/', num: '§1', label: 'Classical ciphers' },
  { href: '/block-ciphers/', num: '§2', label: 'Block ciphers' },
  { href: '/hashing/', num: '§3', label: 'Hash functions & MACs' },
  { href: '/numbers/', num: '§4', label: 'Number theory' },
  { href: '/randomness/', num: '§5', label: 'Randomness' },
  { href: '/asymmetric/', num: '§6', label: 'Public-key cryptography' },
  { href: '/passwords/', num: '§7', label: 'Password security' },
  { href: '/tls/', num: '§8', label: 'TLS 1.3 handshake' },
  { href: '/protocols/', num: '§9', label: 'Applied protocols' },
  { href: '/attacks/', num: '§10', label: 'Attacks' },
  { href: '/zkp/', num: '§11', label: 'Zero-knowledge proofs' },
  { href: '/sharing/', num: '§12', label: 'Secret sharing' },
  { href: '/encoding/', num: '§13', label: 'Encodings' },
  { href: '/benchmark/', num: '§14', label: 'WASM vs JS benchmark' },
] as const;
