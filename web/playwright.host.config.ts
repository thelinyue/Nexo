import { defineConfig } from "@playwright/test";

// 部署命令由宿主机 Docker Compose 和 Shell 验证，无需构建网页或启动浏览器。
export default defineConfig({
  testDir: "./tests",
  testMatch: "**/agent-deployment.spec.ts",
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: "line",
});
