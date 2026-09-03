'use client';

import { useEffect } from 'react';

/**
 * Registers the offline service worker. Production builds only: sw.js is
 * generated into out/ by scripts/gen-sw.mjs after `next build`, so next dev
 * has nothing to register.
 */
export default function Pwa() {
  useEffect(() => {
    if (process.env.NODE_ENV !== 'production' || !('serviceWorker' in navigator)) return;
    // Not under automation: every Playwright context would re-download the full
    // precache and overwhelm the test server. The PWA test registers explicitly.
    if (navigator.webdriver) return;
    navigator.serviceWorker.register('/sw.js').catch(() => {
      // Offline support is best-effort; the site works without it.
    });
  }, []);
  return null;
}
