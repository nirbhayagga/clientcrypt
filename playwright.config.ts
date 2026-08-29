import { defineConfig, devices } from '@playwright/test';

const PORT = 4173;
const isCI = !!process.env.CI;

export default defineConfig({
  testDir: 'tests',
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 1 : 0,
  reporter: isCI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] }, testMatch: /mobile\.spec\.ts/ },
  ],
  // CI builds explicitly before testing; locally `npm test` is self-contained.
  webServer: {
    command: `${isCI ? '' : 'npm run build && '}npx serve out -l ${PORT} --no-clipboard`,
    url: `http://localhost:${PORT}/`,
    reuseExistingServer: !isCI,
    timeout: 300_000,
  },
});
