import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const GiB = 1024 ** 3;
async function setup(page: import("@playwright/test").Page, role = "tenant", canManage = true, supported = true) {
  const state = await installApiMocks(page); state.authRole = role;
  const now = Math.floor(Date.now() / 1000);
  const quota = { monthly_limit_bytes: 100 * GiB as number | null, used_bytes: 80 * GiB, reserved_bytes: GiB, remaining_bytes: 19 * GiB as number | null, period_start: now - 1000, period_end: now + 86400, started_at: now - 1000, supported, exhausted: false, revision: 1 };
  const node = { id: "own", name: "自建节点", public_ipv4: "203.0.113.10", control_port: 9891, status: "online", approved: true, enabled: true, registered: true, connections: 2, services: [], latencies: [], version: "0.2.20", traffic_quota: quota, can_manage_quota: canManage };
  let failure = false; let created: Record<string, unknown> | null = null; let quotaGets = 0;
  await page.route("**/api/v1/nodes**", async route => {
    const req = route.request(); const path = new URL(req.url()).pathname;
    if (path.endsWith("/traffic/quota")) {
      if (req.method() === "PUT") {
        if (failure) return route.fulfill({ status: 500, json: { error: "节点额度保存失败" } });
        const limit = req.postDataJSON().monthly_limit_bytes;
        quota.monthly_limit_bytes = limit; quota.remaining_bytes = limit === null ? null : Math.max(0, limit - quota.used_bytes - quota.reserved_bytes); quota.exhausted = limit !== null && quota.used_bytes >= limit; quota.revision++;
      } else { quotaGets++; }
      return route.fulfill({ json: quota });
    }
    if (path === "/api/v1/nodes" && req.method() === "POST") {
      created = req.postDataJSON();
      return route.fulfill({ json: { id: "new", token: "test-token", server_url: "https://nexo.test", expires_at: now + 1800, version: "0.2.20", http_port: 80, data_port: 9891 } });
    }
    return route.fulfill({ json: path === "/api/v1/nodes" ? { nodes: [node], server_version: "0.2.20" } : node });
  });
  return { quota, node, setFailure: (value: boolean) => { failure = value; }, created: () => created, gets: () => quotaGets };
}

async function detail(page: import("@playwright/test").Page) {
  await page.goto("/#/nodes");
  await page.getByRole("article", { name: "自建节点" }).getByRole("button", { name: /详情|管理/ }).click();
  return page.getByRole("dialog", { name: "自建节点", exact: true });
}

test("添加者管理整台节点额度，草稿保留、失败重试和解除限制", async ({ page }, info) => {
  const state = await setup(page); const overview = await detail(page);
  await expect(overview).toContainText("80 GiB / 100 GiB");
  await expect(overview).toContainText("待结算占用 1 GiB");
  await expect(overview.getByRole("button", { name: "保存配置" })).toHaveCount(0);
  await overview.getByRole("button", { name: "设置流量限制" }).click();
  const form = page.getByRole("dialog", { name: "流量限制 · 自建节点" });
  await form.getByLabel("月额度（GiB）").fill("50");
  state.quota.used_bytes = 82 * GiB;
  await expect.poll(() => state.gets()).toBeGreaterThan(1);
  await expect(form.getByLabel("月额度（GiB）")).toHaveValue("50");
  await expect(form).toContainText("当前占用已达新额度。保存后暂停转发");
  state.setFailure(true);
  await form.getByRole("button", { name: "保存并断开连接" }).click();
  await expect(form).toContainText("节点额度保存失败");
  await expect(form.getByLabel("月额度（GiB）")).toHaveValue("50");
  state.setFailure(false);
  const sent = page.waitForRequest(req => req.method() === "PUT" && req.url().endsWith("/traffic/quota"));
  await form.getByRole("button", { name: "保存并断开连接" }).click();
  expect((await sent).headers()["x-nexo-csrf"]).toBeTruthy();
  await expect(form).toHaveCount(0);
  await expect(overview).toContainText("本月额度已用尽");
  await overview.getByRole("button", { name: "设置流量限制" }).click();
  await form.getByLabel("限制方式").selectOption("unlimited");
  await form.getByRole("button", { name: "保存", exact: true }).click();
  await expect(form).toHaveCount(0);
  expect(state.quota.monthly_limit_bytes).toBeNull();
  await expect(overview).toContainText("不限制");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("node-month-quota.png"), fullPage: true });
});

test("获授权用户只读，旧节点明确提示升级且不能启用限制", async ({ page }) => {
  await setup(page, "tenant", false); let overview = await detail(page);
  await expect(overview).toContainText("80 GiB / 100 GiB");
  await expect(overview.getByRole("button", { name: "设置流量限制" })).toHaveCount(0);
  await page.unroute("**/api/v1/nodes**");
  await setup(page, "system_admin", true, false); await page.reload();
  await page.getByRole("article", { name: "自建节点" }).getByRole("button", { name: "管理" }).click();
  overview = page.getByRole("dialog", { name: "自建节点", exact: true });
  await expect(overview).toContainText("升级节点后可计量流量");
  await overview.getByRole("button", { name: "设置流量限制" }).click();
  const form = page.getByRole("dialog", { name: "流量限制 · 自建节点" });
  await expect(form.getByLabel("月额度（GiB）")).toBeDisabled();
  await form.getByLabel("限制方式").selectOption("unlimited");
  await expect(form.getByRole("button", { name: "保存", exact: true })).toBeEnabled();
});

test("添加节点可预设月额度，非法输入不会提交", async ({ page }) => {
  const state = await setup(page); await page.goto("/#/nodes");
  await page.getByRole("button", { name: "添加 节点", exact: true }).first().click();
  const form = page.getByRole("dialog", { name: "添加节点", exact: true });
  await form.getByLabel("名称", { exact: true }).fill("新节点");
  await form.getByLabel("公网 IPv4").fill("203.0.113.21");
  await form.getByRole("combobox", { name: "流量限制", exact: true }).selectOption("limited");
  await form.getByLabel("月额度（GiB）").fill("0");
  await expect(form.getByRole("button", { name: "继续", exact: true })).toBeDisabled();
  await form.getByLabel("月额度（GiB）").fill("100");
  await form.getByRole("button", { name: "继续", exact: true }).click();
  await expect(form.getByRole("button", { name: "返回列表" })).toBeVisible();
  expect(state.created()?.monthly_limit_bytes).toBe(100 * GiB);
});
