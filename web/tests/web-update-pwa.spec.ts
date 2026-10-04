import { expect, test } from "@playwright/test";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";

/** 真实切换两份生产构建，避免仅模拟 SW 事件而漏掉缓存安装、接管和标签页刷新问题。 */
test("两份构建更新：PWA 等待用户刷新，其他标签页保留草稿，普通 HTTP 同样提示", async ({ browser }, info) => {
  test.skip(info.project.name !== "desktop-dark", "使用真实 Chromium Service Worker 与普通 HTTP 集中验收");
  test.setTimeout(90000);
  const directory = mkdtempSync(join(tmpdir(), "nexo-web-update-"));
  const oldBuild = join(directory, "old"); const newBuild = join(directory, "new");
  cpSync(fileURLToPath(new URL("../dist", import.meta.url)), oldBuild, { recursive: true });
  let deployed = oldBuild;
  const settings = { management_entry: null, public_url: "", public_ips: ["203.0.113.7"], relay_ipv4: "203.0.113.7", domains: [], caddy_enabled: true, status: "disabled", error: null };
  const server = createServer((request, response) => {
    const path = new URL(request.url!, "http://localhost").pathname;
    response.setHeader("Cache-Control", "no-cache");
    if (path.startsWith("/api/")) {
      const body = path === "/api/v1/auth/status" ? { initialized: true, authenticated: true, user_id: "admin", username: "admin", role: "system_admin", csrf_token: "test-csrf" }
        : path === "/api/v1/admin/server-settings" ? settings
        : path === "/api/v1/transport-identity" ? { server: { status: "valid", error: null }, ca_needs_attention: false } : [];
      response.setHeader("Content-Type", "application/json"); response.end(JSON.stringify(body)); return;
    }
    const types: Record<string, string> = { html: "text/html", js: "text/javascript", css: "text/css", webmanifest: "application/manifest+json", png: "image/png", webp: "image/webp", svg: "image/svg+xml" };
    const relative = path === "/" ? "index.html" : path.slice(1);
    try {
      const body = readFileSync(join(deployed, relative));
      response.setHeader("Content-Type", types[relative.split(".").at(-1)!] ?? "application/octet-stream"); response.end(body);
    } catch { response.writeHead(404); response.end(); }
  });
  const contexts: Awaited<ReturnType<typeof browser.newContext>>[] = [];
  try {
    await build({
      root: fileURLToPath(new URL("..", import.meta.url)), logLevel: "silent", build: { outDir: newBuild },
      plugins: [{ name: "test-update-marker", transform(code, id) { if (id.endsWith("/src/main.tsx")) return `${code}\ndocument.documentElement.dataset.testBuild = "new";`; } }],
    });
    await new Promise<void>(resolve => server.listen(0, "0.0.0.0", resolve));
    const port = (server.address() as { port: number }).port;
    const origin = `http://127.0.0.1:${port}`;
    const context = await browser.newContext({ serviceWorkers: "allow" }); contexts.push(context);
    const first = await context.newPage(); const second = await context.newPage();
    await first.goto(`${origin}/#/settings/server`);
    await first.evaluate(async () => {
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) await new Promise<void>(resolve => navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true }));
    });
    await second.goto(`${origin}/#/settings/server`);
    await second.getByLabel("公网 IPv4", { exact: true }).fill("203.0.113.8");
    await expect(first.locator(".web-update-notice")).toHaveCount(0);
    await expect(second.locator(".web-update-notice")).toHaveCount(0);

    const address = Object.values(networkInterfaces()).flat().find(item => item?.family === "IPv4" && !item.internal && item.address.startsWith("192.168."))
      ?? Object.values(networkInterfaces()).flat().find(item => item?.family === "IPv4" && !item.internal);
    expect(address, "普通 HTTP 验收需要本机非回环 IPv4 地址").toBeTruthy();
    const httpContext = await browser.newContext({ serviceWorkers: "allow" }); contexts.push(httpContext);
    const httpPage = await httpContext.newPage();
    await httpPage.goto(`http://${address!.address}:${port}/#/settings/server`);
    expect(await httpPage.evaluate(() => window.isSecureContext)).toBeFalsy();
    await expect(httpPage.locator(".web-update-notice")).toHaveCount(0);

    deployed = newBuild;
    await Promise.all([first, second, httpPage].map(page => page.evaluate(() => window.dispatchEvent(new Event("online")))));
    for (const page of [first, second, httpPage]) {
      await expect(page.locator(".web-update-notice")).toBeVisible({ timeout: 20000 });
      expect(await page.evaluate(() => document.documentElement.dataset.testBuild)).toBeUndefined();
    }
    await first.getByRole("button", { name: "刷新页面" }).click();
    await expect(first.locator("html")).toHaveAttribute("data-test-build", "new");
    await expect(first).toHaveURL(/#\/settings\/server$/);
    await expect(first.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
    await expect(first.locator(".web-update-notice")).toHaveCount(0);
    await expect(second.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.8");
    expect(await second.evaluate(() => document.documentElement.dataset.testBuild)).toBeUndefined();
    await second.getByRole("button", { name: "刷新页面" }).click();
    const discard = second.getByRole("dialog", { name: "放弃未保存的修改？" });
    await expect(discard).toBeVisible();
    await discard.getByRole("button", { name: "取消", exact: true }).click();
    await expect(second.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.8");
    await second.getByRole("button", { name: "刷新页面" }).click();
    await discard.getByRole("button", { name: "放弃修改", exact: true }).click();
    await expect(second.locator("html")).toHaveAttribute("data-test-build", "new");

    await httpPage.getByRole("button", { name: "刷新页面" }).click();
    await expect(httpPage.locator("html")).toHaveAttribute("data-test-build", "new");
    await expect(httpPage.locator(".web-update-notice")).toHaveCount(0);
    // 新版完成预缓存后，断网重新打开仍使用新版资源。
    await context.setOffline(true); await first.reload();
    await expect(first.locator("html")).toHaveAttribute("data-test-build", "new");
  } finally {
    for (const context of contexts) await context.close();
    server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
    rmSync(directory, { recursive: true, force: true });
  }
});
