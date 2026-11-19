import { defineConfig, devices } from "@playwright/test";

const hostChecks = "**/agent-deployment.spec.ts";
const clipboardChecks = "**/clipboard.spec.ts";
// 专用于手机的文件和带标签的交互场景在手机项目运行。
const mobileChecks = /@mobile\b|(?:clipboard|domain-mobile|mobile-create|pwa-navigation)\.spec\.ts/;

export default defineConfig({
  testDir: "./tests",
  testIgnore: hostChecks,
  fullyParallel: true,
  workers: 3,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4173",
    screenshot: "only-on-failure",
    trace: "on-first-retry",
    serviceWorkers: "block",
  },
  webServer: {
    command: "npm run build && npm run preview -- --host 127.0.0.1 --port 4173",
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
      grep: mobileChecks,
      use: {
        ...devices["iPhone 13"],
        browserName: "chromium",
        colorScheme: "light",
        viewport: { width: 375, height: 812 },
      },
    },
    {
      name: "mobile-landscape",
      grep: /@landscape\b/,
      use: {
        ...devices["iPhone 13"],
        browserName: "chromium",
        colorScheme: "light",
        viewport: { width: 812, height: 375 },
      },
    },
    {
      name: "mobile-webkit",
      // 真实剪贴板权限由 Chromium 验证，WebKit 用例覆盖复制失败反馈。
      testIgnore: [hostChecks, clipboardChecks],
      grep: [mobileChecks, /@webkit\b/],
      use: {
        ...devices["iPhone 13"],
        browserName: "webkit",
        colorScheme: "light",
        viewport: { width: 390, height: 844 },
      },
    },
  ],
});
