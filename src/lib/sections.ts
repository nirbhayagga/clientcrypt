/** The section list. Imported by both the client Sidebar and the server-
 *  rendered 404 page, so it cannot live inside a 'use client' module. */
export const SECTIONS = [
  { href: '/classical/', num: '§1', label: 'Classical ciphers' },
  { href: '/block-ciphers/', num: '§2', label: 'Block ciphers' },
  { href: '/hashing/', num: '§3', label: 'Hash functions & MACs' },
  { href: '/numbers/', num: '§4', label: 'Number theory' },
  { href: '/asymmetric/', num: '§5', label: 'Public-key cryptography' },
  { href: '/passwords/', num: '§6', label: 'Password security' },
  { href: '/tls/', num: '§7', label: 'TLS 1.3 handshake' },
  { href: '/protocols/', num: '§8', label: 'Applied protocols' },
  { href: '/encoding/', num: '§9', label: 'Encodings' },
  { href: '/benchmark/', num: '§10', label: 'WASM vs JS benchmark' },
] as const;
