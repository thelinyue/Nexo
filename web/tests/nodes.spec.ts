import { selectServiceOption } from "./service-actions";
import { expect, test } from "@playwright/test";
import { writeFile } from "node:fs/promises";
import { installApiMocks } from "./api-mocks";

async function setup(page: import("@playwright/test").Page, admin = true) {
  const state = await installApiMocks(page);
  state.authRole = admin ? "system_admin" : "tenant";
  const sample = (device_id: string, rtt_ms: number, fresh = true) => ({ device_id, device_name: `设备 ${device_id}`, rtt_ms, fresh, samples: 3, checked_at: Math.floor(Date.now() / 1000) - (fresh ? 1 : 90) });
  const base = { control_port: 9891, approved: true, enabled: true, registered: true, os: "Ubuntu 24.04", architecture: "aarch64", version: "0.2.11", connections: 12, services: [] as { id: string; name: string; enabled: boolean; alternatives: { id: string; name: string }[] }[], workspace_ids: ["default"] };
  const nodes = [
    { ...base, id: "hk", name: "香港 VPS", public_ipv4: "203.0.113.10", status: "online", latencies: [sample("NAS", 32), sample("办公室", 68)] },
    { ...base, id: "jp", name: "日本 VPS", public_ipv4: "203.0.113.11", status: "offline", latencies: [sample("NAS", 42, false)] },
    { ...base, id: "us", name: "美国 VPS", public_ipv4: "203.0.113.12", status: "online", latencies: [] },
  ];
  await page.route("**/api/v1/nodes**", route => route.fulfill({ json: new URL(route.request().url()).pathname === "/api/v1/nodes" ? { nodes, server_version: "0.2.12" } : nodes[0] }));
  return { state, nodes };
}

test("节点卡片展示实测范围、历史延迟和待测速，筛选及窄屏无溢出", async ({ page }, info) => {
  await setup(page);
  await page.goto("/#/nodes");
  const hk = page.getByRole("article", { name: "香港 VPS", exact: true });
  await expect(hk).toContainText("32–68 ms");
  await hk.getByRole("button", { name: "查看 香港 VPS 逐设备延迟" }).click();
  const detail = page.getByRole("dialog", { name: "香港 VPS" });
  await expect(detail).toContainText("设备到节点");
  await detail.getByText("逐设备延迟（2）").click();
  await expect(detail).toContainText("设备 NAS");
  await expect(detail).toContainText("32 ms");
  await detail.getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page.getByRole("article", { name: "日本 VPS" })).toContainText("已过期");
  await expect(page.getByRole("article", { name: "美国 VPS" })).toContainText("待测速");
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  await page.getByRole("button", { name: "批量更新", exact: true }).click();
  await expect(page.getByRole("button", { name: "继续", exact: true })).toBeDisabled();
  await page.getByLabel("选择 香港 VPS").check();
  await expect(page.getByRole("button", { name: "继续", exact: true })).toBeEnabled();
  await page.getByLabel("搜索节点名称或 IP").fill("203.0.113.11");
  await expect(page.getByRole("article")).toHaveCount(1);
  await page.getByLabel("搜索节点名称或 IP").clear();
  await page.getByLabel("筛选节点", { exact: true }).selectOption("offline");
  await expect(page.getByRole("article")).toHaveCount(1);
  await page.getByLabel("筛选节点", { exact: true }).selectOption("");
  await expect(page.getByLabel("选择 香港 VPS")).not.toBeChecked();
  await page.getByRole("region", { name: "批量更新选择" }).getByRole("button", { name: "取消", exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("node-latency-cards.png"), fullPage: true });
});

test("普通用户可读延迟和申请节点，不能操作维护", async ({ page }) => {
  await setup(page, false);
  await page.goto("/#/nodes");
  await expect(page.getByRole("article")).toHaveCount(3);
  await expect(page.getByRole("button", { name: "更新版本", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "批量更新", exact: true })).toHaveCount(0);
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  await page.getByRole("article", { name: "香港 VPS", exact: true }).getByRole("button", { name: "详情" }).click();
  const dialog = page.getByRole("dialog", { name: "香港 VPS" });
  await expect(dialog).toContainText("32–68 ms");
  await expect(dialog.getByRole("button", { name: "保存配置" })).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "移除节点" })).toHaveCount(0);
});

test("回源延迟优先与手动首选可编辑，IPv6 开关独立保留", async ({ page }) => {
  const { state } = await setup(page);
  state.tunnels[0].node_ids = ["hk", "jp"];
  state.tunnels[0].distribution_mode = "latency";
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  await expect(dialog.getByRole("combobox", { name: "选择策略", exact: true })).toHaveAttribute("value", "latency");
  await expect(dialog.getByRole("combobox", { name: "选择策略", exact: true })).toContainText("回源延迟优先");
  await expect(dialog.getByRole("switch", { name: "IPv6 直连" })).toBeEnabled();
  await selectServiceOption(dialog.getByRole("combobox", { name: "选择策略", exact: true }), "主备切换");
  await selectServiceOption(dialog.getByRole("combobox", { name: "首选节点", exact: true }), "香港 VPS");
  await expect(dialog).toContainText("恢复后自动切回");
});

test("节点组过滤、服务选择及管理员维护入口", async ({ page }, info) => {
  await setup(page);
  const groups = [{ id: "asia", name: "亚洲入口", node_ids: ["hk", "jp"], workspace_ids: ["default"] }];
  await page.route("**/api/v1/node-groups", route => route.fulfill({ json: groups }));
  await page.goto("/#/nodes");
  await page.getByLabel("筛选节点组").selectOption("asia");
  await expect(page.getByRole("article")).toHaveCount(2);
  await page.getByRole("button", { name: "节点组", exact: true }).click();
  const groupsDialog = page.getByRole("dialog", { name: "节点组", exact: true });
  await groupsDialog.getByRole("button", { name: "编辑", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "编辑节点组" });
  await expect(edit.getByLabel("名称", { exact: true })).toHaveValue("亚洲入口");
  await expect(edit.getByLabel("admin的工作空间")).toBeChecked();
  await expect(edit.getByRole("button", { name: "保存", exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("node-group-edit.png"), fullPage: true });
  await edit.getByRole("button", { name: "关闭", exact: true }).click();
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const service = page.getByRole("dialog", { name: "编辑服务" });
  await selectServiceOption(service.getByRole("combobox", { name: "节点来源", exact: true }), "亚洲入口 · 2 个节点");
  await expect(service.getByRole("combobox", { name: "选择策略", exact: true })).toHaveAttribute("value", "latency");
  const strategy = service.getByRole("combobox", { name: "选择策略", exact: true });
  await strategy.click();
  const strategies = service.getByRole("listbox", { name: "选择策略选项" });
  const single = strategies.getByRole("option", { name: "单节点", exact: true });
  await expect(single).toBeDisabled();
  // 使用真实指针坐标尝试点击禁用项，不能改变草稿或关闭菜单。
  await single.scrollIntoViewIfNeeded();
  await expect(single).toBeInViewport({ ratio: 1 });
  const box = (await single.boundingBox())!;
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await expect(strategy).toHaveAttribute("value", "latency");
  await expect(strategies).toBeVisible();
  await strategy.press("Home");
  await expect(strategies.getByRole("option", { name: "DNS 分流", exact: true })).toHaveAttribute("data-active", "true");
  await strategy.press("ArrowUp");
  await expect(strategies.getByRole("option", { name: "DNS 分流", exact: true })).toHaveAttribute("data-active", "true");
  await strategy.press("End");
  await expect(strategies.getByRole("option", { name: "主备切换", exact: true })).toHaveAttribute("data-active", "true");
  await strategy.press("Escape");
  await expect(strategy).toBeFocused();
  const members = service.getByRole("list", { name: "组内节点" });
  await expect(members.getByRole("listitem")).toHaveCount(2);
  await expect(members).toContainText("香港 VPS");
  await expect(members).toContainText("日本 VPS · 当前不可用");
  await expect(members).not.toContainText("美国 VPS");
  await expect(service.getByRole("checkbox", { name: "香港 VPS", exact: true })).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("service-node-group.png"), fullPage: true });
  await selectServiceOption(service.getByRole("combobox", { name: "节点来源", exact: true }), "手动选择");
  await expect(service.getByRole("checkbox", { name: "香港 VPS", exact: true })).toBeChecked();
  await expect(service.getByRole("checkbox", { name: "香港 VPS", exact: true })).toBeEnabled();
});

test("无节点组时直接创建并一次保存成员与分配", async ({ page }, info) => {
  await setup(page);
  let saved: unknown;
  await page.route("**/api/v1/node-groups", async route => {
    if (route.request().method() === "POST") saved = route.request().postDataJSON();
    await route.fulfill({ json: [] });
  });
  await page.goto("/#/nodes");
  await page.getByRole("button", { name: "节点组", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "创建节点组", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "创建", exact: true })).toBeDisabled();
  await dialog.getByLabel("名称", { exact: true }).fill("亚洲入口");
  await dialog.getByRole("checkbox", { name: /香港 VPS/ }).check();
  await dialog.getByRole("checkbox", { name: /日本 VPS/ }).check();
  await expect(dialog).toContainText("分配工作空间后，服务才能选择此组");
  await dialog.getByLabel("admin的工作空间").check();
  await expect(dialog).not.toContainText("分配工作空间后，服务才能选择此组");
  await expect(dialog).not.toContainText("成员变更");
  expect(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("node-group-create.png"), fullPage: true });
  await dialog.getByRole("button", { name: "创建", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(saved).toEqual({ name: "亚洲入口", node_ids: ["hk", "jp"], workspace_ids: ["default"] });
});

test("手机更多选择列表可关闭、导航和区分用户权限", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机导航");
  await setup(page, false);
  await page.goto("/#/nodes");
  const nav = page.getByRole("navigation", { name: "底部导航", exact: true });
  await expect(nav.getByRole("link")).toHaveText(["首页", "服务", "设备"]);
  const trigger = nav.getByRole("button", { name: "更多功能" });
  await trigger.click();
  const menu = page.getByRole("navigation", { name: "更多功能", exact: true });
  await expect(menu.getByRole("link")).toHaveText(["节点当前页面", "域名"]);
  await expect(menu.getByRole("link", { name: "用户管理" })).toHaveCount(0);
  await expect(trigger).toHaveAttribute("aria-expanded", "true");
  await page.screenshot({ path: info.outputPath("mobile-more.png") });
  await page.keyboard.press("Escape");
  await expect(menu).toBeHidden();
  await expect(trigger).toBeFocused();
  await trigger.click();
  await menu.getByRole("link", { name: "域名", exact: true }).click();
  await expect(page).toHaveURL(/#\/domains$/);
  await expect(menu).toBeHidden();
  await expect(trigger).toHaveClass("active");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("管理端更新时已是最新节点版本的 VPS 不提示更新，旧节点仍更新至节点版本", async ({ page }) => {
  const { nodes } = await setup(page);
  nodes[0].version = "0.2.18";
  nodes[2].version = "0.2.16";
  await page.route("**/api/v1/nodes", route => route.fulfill({ json: { nodes, server_version: "0.2.19" } }));
  await page.route("**/api/v1/node-releases", route => route.fulfill({ json: [{ version: "0.2.18", architectures: ["aarch64", "x86_64"] }] }));
  await page.goto("/#/nodes");
  const current = page.getByRole("article", { name: "香港 VPS", exact: true });
  await expect(current).toContainText("v0.2.18");
  await expect(current.getByRole("button", { name: "更新版本", exact: true })).toHaveCount(0);
  await page.getByRole("article", { name: "美国 VPS", exact: true }).getByRole("button", { name: "更新版本", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "顺序更新节点" });
  await expect(dialog.getByLabel("目标版本")).toHaveValue("0.2.18");
  await expect(dialog).toContainText("v0.2.16 → v0.2.18");
  await expect(dialog).not.toContainText("0.2.19");
});

test("更新展示逐服务备用入口，无备用时必须接受中断", async ({ page }) => {
  const { nodes } = await setup(page);
  nodes[0].services.push({ id: "media", name: "媒体服务", enabled: true, alternatives: [{ id: "us", name: "美国 VPS" }] }, { id: "files", name: "文件服务", enabled: true, alternatives: [] });
  let submitted: unknown;
  await page.route("**/api/v1/node-update-jobs", route => {
    if (route.request().method() === "POST") { submitted = route.request().postDataJSON(); return route.fulfill({ json: { id: "job", status: "queued" } }); }
    return route.fulfill({ json: [] });
  });
  await page.goto("/#/nodes");
  await page.getByRole("article", { name: "香港 VPS", exact: true }).getByRole("button", { name: "更新版本", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "顺序更新节点" });
  await expect(dialog).toContainText("媒体服务");
  await expect(dialog).toContainText("健康备用入口：美国 VPS");
  await expect(dialog).toContainText("文件服务");
  await expect(dialog).toContainText("暂无已确认的健康 IPv4 备用入口");
  await expect(dialog.getByRole("button", { name: "开始更新" })).toBeDisabled();
  expect(submitted).toBeUndefined();
  await dialog.getByRole("checkbox", { name: "若没有其他健康 IPv4 入口，我接受服务中断" }).check();
  await dialog.getByRole("button", { name: "开始更新" }).click();
  await expect(dialog).toBeHidden();
  expect(submitted).toEqual({ node_ids: ["hk"], target_version: "0.2.12", accept_interruption: true });
});

test("普通用户添加节点使用公网管理地址和自定义端口，并自动跟进接入状态", async ({ page }, info) => {
  await setup(page, false);
  const node = { id: "new", name: "新 VPS", public_ipv4: "8.8.8.8", control_port: 9892, status: "unregistered", approved: false, enabled: true, registered: false, can_enroll: true, assigned: false, latencies: [], services: [], connections: 0 };
  const enrollment = { id: node.id, token: "only-visible-in-copy", expires_at: Math.floor(Date.now() / 1000) + 1800, version: "0.2.18", server_url: "https://manage.example:8443", http_port: 8080, data_port: 9892 };
  let submitted: unknown;
  await page.route("**/api/v1/nodes", route => {
    if (route.request().method() === "POST") { submitted = route.request().postDataJSON(); return route.fulfill({ json: enrollment }); }
    return route.fulfill({ json: { nodes: [node], server_version: "0.2.19" } });
  });
  await page.route("**/api/v1/node-releases", route => route.fulfill({ json: [{ version: "0.2.18", architectures: ["aarch64", "x86_64"] }] }));
  await page.route("**/api/v1/nodes/new", route => route.fulfill({ json: node }));
  await page.goto("/#/nodes");
  await page.getByRole("button", { name: "添加 节点", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加节点" });
  await dialog.getByLabel("名称").fill("新 VPS");
  await dialog.getByLabel("公网 IPv4").fill("8.8.8.8");
  await dialog.getByRole("button", { name: "继续" }).click();
  expect(submitted).toEqual({ name: "新 VPS", public_ipv4: "8.8.8.8" });
  await expect(dialog.getByLabel("HTTPS 端口")).toBeHidden();
  await expect(dialog.getByRole("button", { name: "复制命令", exact: true })).toBeVisible();
  await dialog.getByText("安装选项 · HTTPS 443", { exact: true }).click();
  await expect(dialog.getByRole("combobox")).toHaveCount(0);
  await dialog.getByLabel("HTTPS 端口").fill("8443");
  const command = dialog.locator("pre");
  await expect(command).toContainText("https://manage.example:8443/api/v1/node/install.sh");
  await expect(command).toContainText("--version '0.2.18'");
  await expect(command).not.toContainText("0.2.19");
  await expect(command).toContainText("--http-port 8080 --https-port 8443 --data-port 9892");
  expect(await command.textContent()).toContain(`<<'NEXO_ENROLLMENT'\n${enrollment.token}\nNEXO_ENROLLMENT\n`);
  await writeFile(info.outputPath("install-command.sh"), (await command.textContent())! + "\n");
  await dialog.getByLabel("HTTPS 端口").fill("9892");
  await expect(dialog.getByRole("button", { name: "复制命令", exact: true })).toHaveCount(0);
  await expect(dialog.getByRole("alert")).toContainText("端口冲突");
  await dialog.getByLabel("HTTPS 端口").fill("8443");
  await dialog.getByText("安装选项 · HTTPS 8443", { exact: true }).click();
  await expect(dialog.getByRole("button", { name: "重新生成凭证", exact: true })).toBeHidden();
  await expect(dialog.getByRole("button", { name: "复制凭证", exact: true })).toHaveCount(0);
  await expect(dialog).toContainText("已包含接入凭证");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("node-enrollment.png"), fullPage: true });
  Object.assign(node, { registered: true, can_enroll: false, status: "pending" });
  await expect(dialog).toContainText("已注册，等待管理员审批与分配", { timeout: 10000 });
  await expect(dialog.getByRole("button", { name: "复制凭证", exact: true })).toHaveCount(0);
  Object.assign(node, { approved: true, status: "online" });
  await expect(dialog).toContainText("已审批，等待分配工作空间", { timeout: 10000 });
  Object.assign(node, { assigned: true });
  await expect(dialog).not.toContainText("已审批，等待分配工作空间", { timeout: 10000 });
  await expect(dialog).not.toContainText("已接入，可在服务中选择");
  await dialog.getByRole("button", { name: "返回列表" }).click();
  await expect(page.getByRole("article", { name: "新 VPS" })).toContainText("在线");
});

test("安装信息可从详情恢复，版本缺失和目录故障均可重试", async ({ page }) => {
  const { nodes } = await setup(page, false);
  Object.assign(nodes[0], { registered: false, approved: false, status: "expired", can_enroll: true, assigned: false });
  let renewals = 0;
  await page.route("**/api/v1/nodes/hk/enrollment", route => { renewals++; return route.fulfill({ json: { id: "hk", token: "rotated-secret", expires_at: Math.floor(Date.now() / 1000) + 1800, version: "0.2.12", server_url: "https://manage.example", http_port: 8080, data_port: 9891 } }); });
  let catalog: "empty" | "failed" | "ready" = "empty";
  await page.route("**/api/v1/node-releases", route => catalog === "failed" ? route.fulfill({ status: 400, json: { error: "官方版本目录暂不可用，请稍后重试" } }) : route.fulfill({ json: catalog === "empty" ? [] : [{ version: "0.2.12", architectures: ["x86_64"] }] }));
  await page.goto("/#/nodes");
  await page.getByRole("article", { name: "香港 VPS", exact: true }).getByRole("button", { name: "详情" }).click();
  const dialog = page.getByRole("dialog", { name: "香港 VPS" });
  await expect(dialog).toContainText("凭证已过期");
  await expect(dialog).toContainText("暂无正式安装包");
  await dialog.getByRole("button", { name: "生成新凭证" }).click();
  await expect.poll(() => renewals).toBe(1);
  await expect(dialog.locator("pre")).toHaveCount(0);
  catalog = "failed";
  await dialog.getByRole("button", { name: "刷新", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("官方版本目录暂不可用");
  catalog = "ready";
  await dialog.getByRole("button", { name: "重试", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制命令", exact: true })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "保存配置" })).toHaveCount(0);
});

test("管理员审批保存当前工作空间分配，未授权节点不进入服务候选", async ({ page }) => {
  const { nodes } = await setup(page);
  Object.assign(nodes[0], { registered: true, approved: false, assigned: false, status: "pending", workspace_ids: [] });
  Object.assign(nodes[1], { selectable: false });
  const actions: string[] = [];
  await page.route("**/api/v1/nodes/hk", route => {
    if (route.request().method() === "PUT") { actions.push("save"); Object.assign(nodes[0], route.request().postDataJSON(), { assigned: true }); }
    return route.fulfill({ json: nodes[0] });
  });
  await page.route("**/api/v1/nodes/hk/approve", route => { actions.push("approve"); Object.assign(nodes[0], { approved: true, status: "online" }); return route.fulfill({ json: { approved: true } }); });
  await page.goto("/#/nodes");
  await page.getByRole("article", { name: "香港 VPS", exact: true }).getByRole("button", { name: "管理" }).click();
  const dialog = page.getByRole("dialog", { name: "香港 VPS" });
  await dialog.getByRole("tab", { name: "配置", exact: true }).click();
  await dialog.getByLabel("admin的工作空间").check();
  await dialog.getByRole("button", { name: "批准并保存配置" }).click();
  await expect(dialog).toBeHidden();
  expect(actions).toEqual(["save", "approve"]);
  expect(nodes[0].workspace_ids).toEqual(["default"]);
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const service = page.getByRole("dialog", { name: "编辑服务" });
  await expect(service.getByLabel("香港 VPS", { exact: true })).toBeVisible();
  await expect(service.getByLabel(/日本 VPS/)).toHaveCount(0);
});

for (const [mode, label] of [["single", "单节点"], ["dns", "DNS 分流"], ["latency", "回源延迟优先"], ["manual", "主备切换"]]) {
  test(`服务节点策略 ${label} 保存后正确回填`, async ({ page }, info) => {
    const { state } = await setup(page);
    Object.assign(state.tunnels[0], { node_ids: ["hk", "us"], distribution_mode: "latency", preferred_node_id: "hk" });
    await page.goto("/#/services/t-1");
    await page.getByRole("button", { name: "编辑服务", exact: true }).click();
    const editor = page.getByRole("dialog", { name: "编辑服务" });
    const source = editor.getByRole("combobox", { name: "节点来源", exact: true });
    await expect(source).toContainText("手动选择");
    await expect(source.locator(".placeholder")).toHaveCount(0);
    await selectServiceOption(editor.getByRole("combobox", { name: "选择策略", exact: true }), label);
    if (mode === "manual") {
      await selectServiceOption(editor.getByRole("combobox", { name: "首选节点", exact: true }), "美国 VPS");
      await editor.locator(".service-node-section").scrollIntoViewIfNeeded();
      await page.screenshot({ path: info.outputPath("service-node-form.png"), animations: "disabled" });
      await editor.getByRole("combobox", { name: "选择策略", exact: true }).click();
      await page.screenshot({ path: info.outputPath("service-strategy-menu.png"), animations: "disabled" });
      await editor.getByRole("combobox", { name: "选择策略", exact: true }).press("Escape");
    }
    await editor.getByRole("button", { name: "保存服务" }).click();
    await expect(editor).toBeHidden();
    expect(state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-1")?.body).toMatchObject({
      distribution_mode: mode, node_group_id: "", node_ids: mode === "single" ? ["hk"] : ["hk", "us"], preferred_node_id: mode === "manual" ? "us" : "hk",
    });
    await page.getByRole("button", { name: "编辑服务", exact: true }).click();
    await expect(editor.getByRole("combobox", { name: "选择策略", exact: true })).toContainText(label);
    if (mode === "manual") await expect(editor.getByRole("combobox", { name: "首选节点", exact: true })).toContainText("美国 VPS");
    else await expect(editor.getByRole("combobox", { name: "首选节点", exact: true })).toHaveCount(0);
  });
}

test("节点菜单长名称在窄屏和低高度视口内可滚动选择", async ({ page }, info) => {
  await setup(page);
  const groups = Array.from({ length: 12 }, (_, i) => ({ id: `group-${i}`, name: `家庭与办公室的亚洲公网入口长名称节点组 ${i}`, node_ids: ["hk", "us"], selectable: true }));
  await page.route("**/api/v1/node-groups", route => route.fulfill({ json: groups }));
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  for (const viewport of [{ width: 320, height: 568 }, { width: 390, height: 420 }, { width: 812, height: 375 }]) {
    await page.setViewportSize(viewport);
    for (const label of ["节点来源", "选择策略", "内网协议"]) {
      const trigger = editor.getByRole("combobox", { name: label, exact: true });
      await trigger.click();
      const list = editor.getByRole("listbox", { name: `${label}选项` });
      await expect(list).toBeVisible();
      await expect.poll(async () => {
        const box = await list.boundingBox(); const body = await editor.locator(".modal-body").boundingBox();
        return Boolean(box && body && box.x >= 0 && box.x + box.width <= viewport.width && box.y >= body.y && box.y + box.height <= body.y + body.height && box.height >= 48);
      }).toBeTruthy();
      expect(await list.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
      await trigger.press("End");
      await expect(list.getByRole("option").last()).toBeInViewport({ ratio: 1 });
      await expect(editor.getByRole("button", { name: "保存服务" })).toBeInViewport();
      await page.screenshot({ path: info.outputPath(`${label}-${viewport.width}x${viewport.height}.png`), animations: "disabled" });
      if (label === "节点来源") {
        await trigger.press("Enter");
        await expect(trigger).toContainText(groups[11].name);
      } else await trigger.press("Escape");
      await expect(list).toBeHidden();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    }
  }
});

test("主备模式未选择节点时首选下拉禁用，补选后恢复", async ({ page }) => {
  const { state } = await setup(page);
  Object.assign(state.tunnels[0], { node_ids: ["hk", "us"], distribution_mode: "manual", preferred_node_id: "hk" });
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  for (const name of ["香港 VPS", "美国 VPS"]) await editor.getByRole("checkbox", { name, exact: true }).uncheck();
  const preferred = editor.getByRole("combobox", { name: "首选节点", exact: true });
  await expect(preferred).toBeDisabled();
  await expect(preferred).toContainText("选择节点");
  await editor.getByRole("checkbox", { name: "美国 VPS", exact: true }).check();
  await expect(preferred).toBeEnabled();
  await expect(preferred).toContainText("美国 VPS");
});
