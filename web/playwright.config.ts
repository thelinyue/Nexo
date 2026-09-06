import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4173",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    {
      name: "desktop-dark",
      use: {
        ...devices["Desktop Chrome"],
        colorScheme: "dark",
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "mobile-light",
      use: {
        ...devices["iPhone 13"],
        browserName: "chromium",
        colorScheme: "light",
        viewport: { width: 375, height: 812 },
      },
    },
    {
      name: "mobile-landscape",
      use: {
        ...devices["iPhone 13"],
        browserName: "chromium",
        colorScheme: "light",
        viewport: { width: 812, height: 375 },
      },
    },
  ],
});
