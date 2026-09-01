import { expect, type Page } from '@playwright/test';

export const ROUTES = ['/', '/classical/', '/block-ciphers/', '/hashing/', '/numbers/', '/asymmetric/', '/passwords/', '/tls/', '/protocols/', '/encoding/', '/benchmark/'];

/** Navigates, waits for the WebAssembly module (if the page uses it) and collects console errors. */
export async function open(page: Page, route: string): Promise<string[]> {
  const errors: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(route);
  await expect(page.locator('h1')).toBeVisible();
  await expect(page.getByText('Loading WebAssembly module')).toHaveCount(0, { timeout: 30_000 });
  return errors;
}

export const field = (page: Page, label: string | RegExp) => page.getByLabel(label, { exact: false });
