import { expect, test } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

const fixture = (extension: string) => fileURLToPath(new URL(`./fixtures/service-icons/custom.${extension}`, import.meta.url));
const png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAFklEQVR4nGMUm5b5nwEPYMInOXwUAAAnjQIk3eIgUgAAAABJRU5ErkJggg==";

test("三种本地图片只预览，保存失败可重试，成功后共享并可恢复默认", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.tunnels[0].ipv6_direct_enabled = true;
  state.devices[0].status = "offline";
  await page.route("**/api/v1/devices/a-1/ipv6", route => route.fulfill({status:503,json:{error:"设备当前离线"}}));
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  for (const extension of ["png", "jpg", "webp"]) {
    await editor.getByRole("button", { name: "选择应用图标" }).click();
    await editor.getByLabel("上传图标图片").setInputFiles(fixture(extension));
    await expect(editor.getByRole("region", { name: "应用图标", exact: true })).toBeHidden();
    await expect(editor.locator(".service-icon-trigger img")).toHaveAttribute("src", /^blob:/);
  }
  expect(state.sharedIcons).toHaveLength(0);
  expect(state.calls.some(call => call.method === "POST" && call.path.includes("service-icons"))).toBe(false);
  state.failures.set("PUT /api/v1/tunnels/t-1", "保存失败测试");
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor.locator("#service-form-error")).toHaveText("保存失败测试");
  expect(state.sharedIcons).toHaveLength(0);
  await expect(editor.locator(".service-icon-trigger img")).toBeVisible();
  state.failures.clear();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.sharedIcons).toHaveLength(1);
  const body = state.calls.filter(call => call.method === "PUT").at(-1)!.body;
  expect(body).not.toHaveProperty("icon_id");
  expect(body.icon_upload.data_url).toMatch(/^data:image\/webp;base64,/);
  await page.reload();
  await expect(page.locator(".application-summary img")).toHaveAttribute("src", /\/api\/v1\/service-icons\/.+\/image/);
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "共享图标", exact: true }).click();
  await expect(editor.getByRole("button", { name: "使用 custom.webp", exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("shared-icon-picker.png"), animations: "disabled" });
  const overflow = await editor.evaluate(element => element.scrollWidth > element.clientWidth);
  expect(overflow).toBe(false);
  await editor.getByRole("button", { name: "默认图标", exact: true }).click();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.tunnels[0].icon_id).toBeNull();
  expect(state.sharedIcons).toHaveLength(1);
});

test("取消上传不入库，重复选择同一文件仍可预览，创建服务时入库", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services"); await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务", exact: true });
  for (let i = 0; i < 2; i++) {
    await editor.getByRole("button", { name: "选择应用图标" }).click();
    await editor.getByLabel("上传图标图片").setInputFiles(fixture("png"));
    await expect(editor.getByRole("region", { name: "应用图标", exact: true })).toBeHidden();
  }
  await editor.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  expect(state.sharedIcons).toHaveLength(0);
  await openServiceEditor(page);
  await editor.getByLabel("服务名称", { exact: true }).fill("上传测试");
  await editor.getByLabel("内网端口", { exact: true }).fill("8080");
  await editor.getByLabel("主机名", { exact: true }).fill("uploaded");
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByLabel("上传图标图片").setInputFiles(fixture("png"));
  await expect(editor.getByRole("region", { name: "应用图标", exact: true })).toBeHidden();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.sharedIcons).toHaveLength(1);
});

test("无效和过大图片保留原图标，链接导入失败和迟到响应不会覆盖选择", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels[0].icon_id = "border-radius/emby-1.png";
  await page.route("https://cdn.jsdelivr.net/**", route => route.abort());
  await page.goto("/#/services/t-1"); await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  for (const file of [
    { name: "bad.svg", mimeType: "image/svg+xml", buffer: Buffer.from("<svg/>") },
    { name: "bad.png", mimeType: "image/png", buffer: Buffer.from("broken") },
    { name: "huge.png", mimeType: "image/png", buffer: Buffer.alloc(2*1024*1024+1) },
  ]) {
    await editor.getByLabel("上传图标图片").setInputFiles(file);
    await expect(editor.getByRole("alert")).toBeVisible();
  }
  await editor.getByRole("button", { name: "输入链接", exact: true }).click();
  await editor.getByLabel("图片链接").fill("https://example.com/icon.png");
  state.failures.set("POST /api/v1/service-icons/preview", "图片下载超时，请重试");
  await editor.getByRole("button", { name: "导入预览" }).click();
  await expect(editor.getByRole("alert")).toHaveText("图片下载超时，请重试");
  state.failures.clear();
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/service-icons/preview", async route => { await pending; await route.fulfill({json:{name:"迟到.png",data_url:png}}); });
  const requestStarted = page.waitForRequest("**/api/v1/service-icons/preview");
  await editor.getByRole("button", { name: "导入预览" }).click(); await requestStarted;
  await expect(editor.getByRole("button", { name: "保存服务" })).toBeDisabled();
  await editor.getByRole("button", { name: "默认图标", exact: true }).click();
  const response = page.waitForResponse("**/api/v1/service-icons/preview"); release(); await response;
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.tunnels[0].icon_id).toBeNull(); expect(state.sharedIcons).toHaveLength(0);
});

test("普通用户复用共享图标、导入公网链接，内网导入被拒绝且没有删除入口", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant";
  state.sharedIcons.push({id:"upload/shared-test",name:"管理员的图标",created_at:1,data_url:png});
  await page.goto("/#/services/t-1"); await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "共享图标", exact: true }).click();
  await expect(editor.getByRole("button", { name: /^删除图标 / })).toHaveCount(0);
  await editor.getByRole("button", { name: "使用 管理员的图标", exact: true }).click();
  await editor.getByRole("button", { name: "保存服务" }).click(); await expect(editor).toBeHidden();
  expect(state.tunnels[0].icon_id).toBe("upload/shared-test");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "输入链接", exact: true }).click();
  await editor.getByLabel("图片链接").fill("http://192.168.10.20/icon.png");
  await editor.getByRole("button", { name: "导入预览" }).click();
  await expect(editor.getByRole("alert")).toHaveText("内网图片仅允许管理员导入");
  await editor.getByLabel("图片链接").fill("https://example.com/icon.png");
  await editor.getByLabel("图片链接").press("Enter");
  await expect(editor.getByRole("region", { name: "应用图标", exact: true })).toBeHidden();
  expect(state.sharedIcons).toHaveLength(1);
  await editor.getByRole("button", { name: "保存服务" }).click(); await expect(editor).toBeHidden();
  expect(state.sharedIcons).toHaveLength(2);
});

test("管理员内网链接预览不入库，共享图标删除需确认且不能删除正在使用的图标", async ({ page }, info) => {
  const state = await installApiMocks(page);
  const icon = {id:"upload/shared-test",name:"共享测试图标",created_at:1,data_url:png};
  state.sharedIcons.push(icon); state.tunnels[0].icon_id = icon.id;
  await page.goto("/#/services/t-1"); await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "输入链接", exact: true }).click();
  await editor.getByLabel("图片链接").fill("http://192.168.10.20/icon.png");
  await page.screenshot({path:info.outputPath("icon-link-import.png"),animations:"disabled"});
  await editor.getByRole("button", { name: "导入预览" }).click();
  await expect(editor.getByRole("region", { name: "应用图标", exact: true })).toBeHidden();
  expect(state.sharedIcons).toHaveLength(1);
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "共享图标", exact: true }).click();
  await editor.getByRole("button", { name: "删除图标 共享测试图标", exact: true }).click();
  const confirmation = page.getByRole("dialog", {name:"删除图标 共享测试图标？",exact:true});
  await confirmation.getByRole("button", {name:"删除图标",exact:true}).click();
  await expect(confirmation.getByRole("alert")).toContainText("图标正在被服务使用");
  await confirmation.getByRole("button", {name:"取消",exact:true}).click();
  await editor.getByRole("button", { name: "默认图标", exact: true }).click();
  await editor.getByRole("button", { name: "保存服务" }).click(); await expect(editor).toBeHidden();
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "共享图标", exact: true }).click();
  await editor.getByRole("button", { name: "删除图标 共享测试图标", exact: true }).click();
  await confirmation.getByRole("button", {name:"删除图标",exact:true}).click(); await expect(confirmation).toBeHidden();
  await expect(editor.getByRole("button", {name:"使用 共享测试图标",exact:true})).toHaveCount(0);
  expect(state.sharedIcons).toHaveLength(0);
});

test("管理员代管用户空间时，共享目录与图片仍从全局接口读取", async ({ page }) => {
  const state = await installApiMocks(page);
  const icon = { id:"upload/global-test", name:"全局共享图标", created_at:1, data_url:png };
  state.sharedIcons.push(icon);
  let saved: any;
  await page.route("**/api/v1/admin/workspaces/alice-space/tunnels/t-1", async route => {
    if (route.request().method() !== "PUT") return route.fallback();
    expect(route.request().headers()["x-nexo-csrf"]).toBe("test-csrf");
    saved = route.request().postDataJSON(); Object.assign(state.tunnels[0], saved);
    await route.fulfill({json:state.tunnels[0]});
  });
  await page.goto("/#/users");
  await page.locator(".page-slot:not([hidden])").getByRole("button",{name:"管理 alice 的空间",exact:true}).click();
  await expect(page.locator(".workspace-banner")).toBeVisible();
  await page.evaluate(() => { location.hash = "#/services/t-1"; });
  await page.getByRole("button",{name:"编辑服务",exact:true}).click();
  const editor = page.getByRole("dialog",{name:"编辑服务"});
  await editor.getByRole("button",{name:"选择应用图标"}).click();
  await editor.getByRole("button",{name:"共享图标",exact:true}).click();
  await editor.getByRole("button",{name:"使用 全局共享图标",exact:true}).click();
  await expect(editor.locator(".service-icon-trigger img")).toHaveAttribute("src","/api/v1/service-icons/global-test/image");
  await editor.getByRole("button",{name:"保存服务"}).click(); await expect(editor).toBeHidden();
  expect(saved.icon_id).toBe(icon.id);
  expect(state.calls.some(call => call.path === "/api/v1/service-icons")).toBe(true);
  expect(state.calls.some(call => call.path.includes("admin/workspaces/") && call.path.includes("service-icons"))).toBe(false);
});

test("反向代理使用同一本地上传流程", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await expect(page.locator(".service-row").first()).toBeVisible();
  await openServiceEditor(page,"reverse_proxy");
  const editor = page.getByRole("dialog",{name:"添加反向代理",exact:true});
  await editor.getByLabel("服务名称",{exact:true}).fill("代理图标");
  await editor.getByLabel("目标端口",{exact:true}).fill("8080");
  await editor.getByLabel("主机名",{exact:true}).fill("proxy-icon");
  await editor.getByRole("button",{name:"选择应用图标"}).click();
  await editor.getByLabel("上传图标图片").setInputFiles(fixture("jpg"));
  await expect(editor.getByRole("region",{name:"应用图标",exact:true})).toBeHidden();
  await editor.getByRole("button",{name:"保存服务"}).click(); await expect(editor).toBeHidden();
  const body = state.calls.find(call => call.method === "POST" && call.path === "/api/v1/tunnels")!.body;
  expect(body.service_mode).toBe("reverse_proxy"); expect(body.device_id).toBeNull(); expect(body.icon_upload.data_url).toMatch(/^data:image\/jpeg;base64,/);
  expect(state.sharedIcons).toHaveLength(1);
});
