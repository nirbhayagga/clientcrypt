import { test, expect } from '@playwright/test';
import { ROUTES, open } from './helpers';

for (const route of ROUTES) {
  test(`${route} fits a phone viewport`, async ({ page }) => {
    const errors = await open(page, route);
    expect(errors).toEqual([]);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    expect(overflow).toBe(false);
    await expect(page.locator('nav.nav')).toBeVisible();
  });
}
