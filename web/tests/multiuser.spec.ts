import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("普通用户只有本人资源和账号入口", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "alice", username: "alice", role: "tenant", workspace_id: "alice", csrf_token: "csrf" } }));
  await page.goto("/#/manage");
  await expect(page.getByRole("link", { name: /用户管理/ })).toHaveCount(0);
  await page.goto("/#/agents");
  await expect(page.getByRole("region", { name: "服务端内部证书" })).toHaveCount(0);
  expect(state.calls.some(call => call.path.startsWith("/api/v1/admin/") || call.path === "/api/v1/transport-identity")).toBeFalsy();
});

test("管理员代管空间时请求绑定该空间，账号安全仍访问本人", async ({ page }, info) => {
  const state = await installApiMocks(page);
  const scoped: string[] = [];
  await page.route("**/api/v1/admin/**", async route => {
    const path = new URL(route.request().url()).pathname; scoped.push(path);
    if (path === "/api/v1/admin/users") return route.fulfill({ json: [{ id: "alice", username: "alice", role: "tenant", workspace_id: "alice-space", workspace_name: "alice 的工作空间", enabled: true, devices: 1, services: 1, domains: 1 }] });
    if (path === "/api/v1/admin/invitations") return route.fulfill({ json: [] });
    const resource = path.split("/").at(-1);
    return route.fulfill({ json: resource === "tunnels" ? [{ ...state.tunnels[0], name: "alice 的服务" }] : resource === "devices" ? state.devices : resource === "public-domains" ? state.domains : [] });
  });
  await page.goto("/#/users");
  await page.getByRole("button", { name: "管理 alice 的空间" }).click();
  await expect(page.locator(".workspace-banner")).toContainText("alice 的工作空间");
  await expect(page.getByText("alice 的服务", { exact: true }).first()).toBeVisible();
  expect(scoped).toContain("/api/v1/admin/workspaces/alice-space/tunnels");
  await page.screenshot({ path: info.outputPath("managed-workspace.png"), fullPage: true });
  await page.evaluate(() => { window.location.hash = "#/manage"; });
  await expect(page.locator(".manage-page").getByRole("link", { name: /^Agent/ })).toContainText("1 台在线");
  expect(scoped).toContain("/api/v1/admin/workspaces/alice-space/devices");
  expect(scoped).toContain("/api/v1/admin/workspaces/alice-space/enrollments");
  await page.evaluate(() => { window.location.hash = "#/settings/sessions"; });
  await expect(page.getByText("当前会话", { exact: true })).toBeVisible();
  expect(state.calls.some(call => call.path === "/api/v1/auth/sessions")).toBeTruthy();
  expect(scoped.some(path => path.includes("/auth/"))).toBeFalsy();
  await page.getByRole("button", { name: "返回我的空间" }).click();
  await expect(page.locator(".workspace-banner")).toHaveCount(0);
  await expect(page.getByText("媒体中心", { exact: true }).first()).toBeVisible();
});

test("邀请链接清除地址栏凭据，注册失败保留输入且成功进入空间", async ({ page }, info) => {
  const state = await installApiMocks(page, { anonymous: true }); let fail = true;
  const token = "one-time-invitation-secret";
  await page.route("**/api/v1/auth/invitations/**", async route => {
    expect(route.request().postDataJSON().token).toBe(token);
    if (route.request().url().endsWith("/inspect")) return route.fulfill({ json: { expires_at: Date.now()/1000+86400 } });
    if (fail) return route.fulfill({ status: 409, json: { error: "用户名已被使用" } });
    state.authenticated = true; return route.fulfill({ status: 201, json: {} });
  });
  await page.goto(`/#/invite?token=${token}`);
  await expect(page.getByRole("heading", { name: "接受邀请" })).toBeVisible();
  expect(page.url()).not.toContain(token);
  await page.getByLabel("用户名").fill("alice");
  await page.getByLabel("密码", { exact: true }).fill("a-valid-new-password");
  await page.getByLabel("确认密码").fill("a-valid-new-password");
  await page.getByRole("button", { name: "创建账号" }).click();
  await expect(page.getByRole("alert")).toContainText("用户名已被使用");
  await expect(page.getByLabel("用户名")).toHaveValue("alice");
  await page.screenshot({ path: info.outputPath("invitation-form.png"), fullPage: true });
  expect(await page.evaluate(() => JSON.stringify(localStorage)+JSON.stringify(sessionStorage))).not.toContain(token);
  fail = false; await page.getByRole("button", { name: "创建账号" }).click();
  await expect(page.getByRole("button", { name: "创建服务" })).toBeVisible();
});

test("域名自助配置保留失败输入，兼容长 Token 并按域名保存 DNS 选项", async ({ page }, info) => {
  const state = await installApiMocks(page); const domain=state.domains[0];
  Object.assign(domain, { certificate_mode: "http01", verification_status: "pending", credential_configured: false, dns_resolvers: ["223.5.5.5:53", "223.6.6.6:53"], verification_record: { name: "_nexo-verification.example.com", value: "proof-for-this-workspace" } });
  let fail=true; const writes: any[]=[];
  await page.route("**/api/v1/public-domains/d-1**", async route => {
    const body=route.request().postDataJSON(); writes.push(body);
    if (route.request().url().endsWith("/cloudflare-credential")) {
      if (fail) return route.fulfill({ status: 400, json: { error: "Cloudflare 拒绝操作，请检查 Token 权限" } });
      Object.assign(domain,{ certificate_mode:"cloudflare_dns",credential_configured:true,verification_status:"verified",verification_record:null });
    } else Object.assign(domain,body);
    return route.fulfill({ json: domain });
  });
  await page.goto("/#/domains");await page.getByRole("button",{name:"验证与配置"}).click();
  const dialog=page.getByRole("dialog",{name:"配置 example.com"});
  await expect(dialog.getByText("proof-for-this-workspace",{exact:true})).toBeVisible();
  await dialog.getByLabel("证书验证方式").selectOption("cloudflare_dns");
  const token="cfat_"+"a".repeat(220);await dialog.getByLabel("Cloudflare API Token").fill(token);
  await dialog.getByRole("button",{name:"验证并保存 Token"}).click();
  await expect(dialog.getByRole("alert")).toContainText("检查 Token 权限");
  await expect(dialog.getByLabel("Cloudflare API Token")).toHaveValue(token);
  fail=false;await dialog.getByRole("button",{name:"验证并保存 Token"}).click();
  await expect(dialog.getByLabel("Cloudflare API Token")).toHaveCount(0);
  await dialog.getByRole("button", { name: "更新 Token", exact: true }).click();
  await expect(dialog.getByLabel("Cloudflare API Token")).toHaveValue("");
  await dialog.getByText("DNS 高级设置",{exact:true}).click();
  await expect(dialog.getByLabel("DNS 解析器")).toHaveValue("223.5.5.5:53, 223.6.6.6:53");
  await dialog.getByLabel("DNS 解析器").fill("1.1.1.1:53, [2606:4700:4700::1111]:53");
  await dialog.getByLabel("传播等待（秒）").fill("10");await dialog.getByLabel("传播超时（秒）").fill("90");
  await dialog.getByRole("button",{name:"保存证书配置"}).click();
  await expect(dialog.getByRole("status")).toContainText("证书配置已保存");
  expect(writes.at(-1)).toEqual({certificate_mode:"cloudflare_dns",dns_resolvers:["1.1.1.1:53","[2606:4700:4700::1111]:53"],dns_propagation_delay_seconds:10,dns_propagation_timeout_seconds:90});
  expect(writes.at(-1)).not.toHaveProperty("token");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({path:info.outputPath("domain-settings.png"),fullPage:true});
  await dialog.getByRole("button",{name:"关闭",exact:true}).click();
  await expect(dialog).toBeHidden();
});

test("管理员邀请和停用有明确反馈，失败不伪报成功", async ({ page }, info) => {
  await installApiMocks(page);let enabled=true;let fail=true;
  await page.route("**/api/v1/admin/**", async route => {
    const path=new URL(route.request().url()).pathname;const method=route.request().method();
    if(path==="/api/v1/admin/users")return route.fulfill({json:[{id:"alice",username:"alice",role:"tenant",workspace_id:"alice",workspace_name:"alice 的空间",enabled,devices:2,services:3,domains:1}]});
    if(path.endsWith("/users/alice")){if(fail)return route.fulfill({status:503,json:{error:"暂时无法停用，请重试"}});enabled=route.request().postDataJSON().enabled;return route.fulfill({json:{enabled}});}
    if(method==="POST")return route.fulfill({json:{token:"secret-invitation",expires_at:Date.now()/1000+86400}});
    return route.fulfill({json:[]});
  });
  await page.goto("/#/users");await page.getByRole("button",{name:"邀请用户"}).click();
  const link=page.getByRole("dialog",{name:"邀请链接"});await expect(link.locator("code")).toContainText("#/invite?token=secret-invitation");
  await link.getByRole("button",{name:"关闭",exact:true}).click();
  await page.getByRole("button",{name:"账号设置",exact:true}).click();
  await page.getByRole("button",{name:"停用用户",exact:true}).click();const confirm=page.getByRole("dialog",{name:"停用 alice？"});
  await expect(confirm).toContainText("断开全部转发");await confirm.getByRole("button",{name:"停用用户",exact:true}).click();
  await expect(confirm.getByRole("alert")).toContainText("暂时无法停用");fail=false;await confirm.getByRole("button",{name:"停用用户",exact:true}).click();
  await expect(page.getByRole("button",{name:"启用用户",exact:true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  await page.screenshot({path:info.outputPath("users.png"),fullPage:true});
});

test("恢复链接在已打开的登录页也可进入，凭据不留在 URL", async ({ page }) => {
  const state=await installApiMocks(page,{anonymous:true});
  await page.goto("/");await expect(page.getByRole("button",{name:"忘记密码"})).toBeVisible();
  await page.evaluate(() => { window.location.hash="#/recover?token=recovery-link-secret"; });
  await expect(page.getByLabel("一次性恢复码")).toHaveValue("recovery-link-secret");
  expect(page.url()).not.toContain("recovery-link-secret");
  await page.getByLabel("新密码",{exact:true}).fill("new-link-password");
  await page.getByLabel("确认新密码").fill("new-link-password");
  await page.getByRole("button",{name:"重设密码",exact:true}).click();
  await expect(page.getByRole("status")).toContainText("密码已重设");
  expect(state.calls.find(call=>call.path.endsWith("/recover"))?.body.recovery_code).toBe("recovery-link-secret");
});

test("代管空间中重新认证保留原空间及服务草稿", async ({ page }) => {
  const state=await installApiMocks(page);let expired=true;
  await page.route("**/api/v1/admin/**",async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path==="/api/v1/admin/users")return route.fulfill({json:[{id:"alice",username:"alice",role:"tenant",workspace_id:"alice",workspace_name:"alice 空间",enabled:true,devices:1,services:1,domains:1}]});
    if(path==="/api/v1/admin/invitations")return route.fulfill({json:[]});
    if(route.request().method()==="POST" && path.endsWith("/tunnels")) {
      if(expired)return route.fulfill({status:401,json:{code:"session_expired",error:"登录已过期"}});
      expect(path).toBe("/api/v1/admin/workspaces/alice/tunnels");
      return route.fulfill({json:{...route.request().postDataJSON(),id:"new"}});
    }
    return route.fulfill({json:path.endsWith("/devices")?state.devices:path.endsWith("/public-domains")?state.domains:path.endsWith("/tunnels")?state.tunnels:[]});
  });
  await page.goto("/#/users");await page.getByRole("button",{name:"管理 alice 的空间"}).click();
  await page.getByRole("button",{name:"创建服务"}).click();const editor=page.getByRole("dialog",{name:"创建服务"});
  await editor.getByLabel("服务名称").fill("保留代管草稿");await editor.getByLabel("本地端口").fill("8080");
  await editor.getByRole("button",{name:"保存服务"}).click();const login=page.getByRole("dialog",{name:"登录已过期"});
  await login.getByLabel("密码",{exact:true}).fill("admin-password");expired=false;
  await login.getByRole("button",{name:"登录",exact:true}).click();
  await expect(login).toBeHidden();await expect(editor.getByLabel("服务名称")).toHaveValue("保留代管草稿");
  await expect(page.locator(".workspace-banner")).toContainText("alice 空间");
  await editor.getByRole("button",{name:"保存服务"}).click();await expect(editor).toBeHidden();
});

test("唯一管理员可改名及管理自身安全，改名失败保留输入，成功用新名字登录", async ({ page }, info) => {
  const state = await installApiMocks(page); let username = "admin"; let fail = true;
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: state.authenticated, user_id: "admin", username, role: "system_admin", workspace_id: "default", csrf_token: "test-csrf" } }));
  await page.route("**/api/v1/admin/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/admin/users") return route.fulfill({ json: [{ id: "admin", username, role: "system_admin", enabled: true, workspace_id: "default", workspace_name: "默认工作空间", created_at: 1790000000, devices: 1, services: 2, domains: 1 }] });
    if (path === "/api/v1/admin/users/admin") {
      if (fail) return route.fulfill({ status: 409, json: { error: "用户名已被使用" } });
      username = route.request().postDataJSON().username; state.authenticated = false;
      return route.fulfill({ json: { username, reauthenticate: true } });
    }
    return route.fulfill({ json: [] });
  });
  await page.goto("/#/users");
  await expect(page.getByText("管理员 · 本人", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "删除用户", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "停用用户", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "账号设置", exact: true }).click();
  await expect(page.getByRole("button", { name: "删除用户", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "停用用户", exact: true })).toHaveCount(0);
  await page.locator(".user-card").getByRole("button", { name: "修改密码", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "修改密码" }).getByLabel("当前密码", { exact: true })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page.locator(".user-card").getByRole("link", { name: "登录会话" })).toHaveAttribute("href", "#/settings/sessions");
  await page.getByRole("button", { name: "修改用户名", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "修改用户名" });
  await dialog.getByLabel("新用户名").fill("owner");
  await dialog.getByRole("button", { name: "保存用户名" }).click();
  await expect(dialog.getByRole("alert")).toContainText("用户名已被使用");
  await expect(dialog.getByLabel("新用户名")).toHaveValue("owner");
  await page.screenshot({ path: info.outputPath("admin-rename.png"), fullPage: true });
  fail = false; await dialog.getByRole("button", { name: "保存用户名" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("status")).toContainText("用户名已改为 owner");
  await expect(page.getByLabel("用户名", { exact: true })).toHaveValue("owner");
  await page.getByLabel("密码", { exact: true }).fill("valid-owner-password");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByText("管理员 · 本人", { exact: true })).toBeVisible();
  expect(state.calls.find(call => call.path.endsWith("/login"))?.body.username).toBe("owner");
});

test("普通用户改名和整空间删除提供确认、失败重试与清理状态", async ({ page }, info) => {
  await installApiMocks(page); let fail = true; let removed = false; let username = "alice"; const writes: any[] = [];
  await page.route("**/api/v1/admin/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/admin/users") return route.fulfill({ json: removed ? [] : [{ id: "alice", username, role: "tenant", enabled: true, workspace_id: "alice-space", workspace_name: `${username}的工作空间`, created_at: 1790000000, devices: 2, services: 3, domains: 1 }] });
    if (path.endsWith("/users/alice")) {
      const body = route.request().postDataJSON(); writes.push({ method: route.request().method(), ...body });
      if (fail) return route.fulfill({ status: 503, json: { error: "暂时无法保存，请重试" } });
      if (route.request().method() === "PATCH") { username = body.username; return route.fulfill({ json: { username, reauthenticate: false } }); }
      removed = true; return route.fulfill({ json: { deleted: true, cleanup_pending: true, message: "用户及其资源已删除，公网配置和凭据清理正在重试" } });
    }
    return route.fulfill({ json: [] });
  });
  await page.goto("/#/users");
  await page.getByRole("button", { name: "账号设置", exact: true }).click();
  await page.getByRole("button", { name: "修改用户名", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "修改用户名" });
  await edit.getByLabel("新用户名").fill("alice-new");
  await edit.getByRole("button", { name: "保存用户名" }).click();
  await expect(edit.getByRole("alert")).toBeVisible();
  await expect(edit.getByLabel("新用户名")).toHaveValue("alice-new");
  fail = false; await edit.getByRole("button", { name: "保存用户名" }).click();
  await expect(page.getByRole("heading", { name: "alice-new", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "删除用户", exact: true }).click();
  const deletion = page.getByRole("dialog", { name: "删除用户", exact: true });
  await expect(deletion.locator(".user-resources dd")).toHaveText(["2", "3", "1"]);
  const submit = deletion.getByRole("button", { name: "永久删除" });
  await expect(submit).toBeDisabled();
  await deletion.getByLabel("输入用户名确认").fill("alice");
  await expect(submit).toBeDisabled();
  await deletion.getByLabel("输入用户名确认").fill("alice-new");
  fail = true; await submit.click();
  await expect(deletion.getByRole("alert")).toBeVisible();
  await expect(deletion.getByLabel("输入用户名确认")).toHaveValue("alice-new");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("delete-user-confirmation.png"), fullPage: true });
  fail = false; await submit.click();
  await expect(deletion).toBeHidden();
  await expect(page.getByRole("heading", { name: "alice-new", exact: true })).toHaveCount(0);
  await expect(page.getByText("用户及其资源已删除，公网配置和凭据清理正在重试", { exact: true })).toBeVisible();
  expect(writes.at(-1)).toEqual({ method: "DELETE", confirm_username: "alice-new" });
});

test("删除正在代管的用户后回到本人空间", async ({ page }) => {
  const state = await installApiMocks(page); let removed = false;
  await page.route("**/api/v1/admin/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/admin/users") return route.fulfill({ json: removed ? [] : [{ id: "alice", username: "alice", role: "tenant", enabled: true, workspace_id: "alice-space", workspace_name: "alice的工作空间", devices: 1, services: 1, domains: 1 }] });
    if (path === "/api/v1/admin/users/alice") { removed = true; return route.fulfill({ json: { deleted: true, cleanup_pending: false, message: "用户及其资源已删除" } }); }
    return route.fulfill({ json: path.endsWith("/tunnels") ? [{ ...state.tunnels[0], name: "alice服务" }] : [] });
  });
  await page.goto("/#/users"); await page.getByRole("button", { name: "管理 alice 的空间" }).click();
  await expect(page.locator(".workspace-banner")).toBeVisible();
  await page.evaluate(() => { location.hash = "#/users"; });
  await page.getByRole("button", { name: "账号设置", exact: true }).click();
  await page.getByRole("button", { name: "删除用户", exact: true }).click();
  await page.getByLabel("输入用户名确认").fill("alice");
  await page.getByRole("button", { name: "永久删除" }).click();
  await expect(page.locator(".workspace-banner")).toHaveCount(0);
  await expect(page.getByText("用户及其资源已删除", { exact: true })).toBeVisible();
  await page.evaluate(() => { location.hash = "#/services"; });
  await expect(page.getByText("媒体中心", { exact: true }).first()).toBeVisible();
});

test("重新认证可输入新用户名，切换账号清除代管和旧草稿", async ({ page }) => {
  const state = await installApiMocks(page); let switched = false;
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: switched ? "bob" : "admin", username: switched ? "bob-new" : "admin", role: switched ? "tenant" : "system_admin", workspace_id: switched ? "bob-space" : "default", csrf_token: "csrf" } }));
  await page.route("**/api/v1/auth/login", route => { expect(route.request().postDataJSON().username).toBe("bob-new"); switched = true; return route.fulfill({ json: {} }); });
  await page.route("**/api/v1/admin/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/admin/users") return route.fulfill({ json: [{ id: "alice", username: "alice", role: "tenant", enabled: true, workspace_id: "alice-space", workspace_name: "alice的工作空间", devices: 1, services: 1, domains: 1 }] });
    if (path.endsWith("/tunnels") && route.request().method() === "POST") return route.fulfill({ status: 401, json: { code: "session_expired", error: "登录已过期" } });
    return route.fulfill({ json: path.endsWith("/devices") ? state.devices : path.endsWith("/public-domains") ? state.domains : [] });
  });
  await page.goto("/#/users"); await page.getByRole("button", { name: "管理 alice 的空间" }).click();
  await page.getByRole("button", { name: "创建服务" }).click();
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("旧账号未保存草稿"); await editor.getByLabel("本地端口").fill("8080");
  await editor.getByRole("button", { name: "保存服务" }).click();
  const login = page.getByRole("dialog", { name: "登录已过期" });
  await login.getByLabel("用户名", { exact: true }).fill("bob-new");
  await login.getByLabel("密码", { exact: true }).fill("valid-bob-password");
  await login.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".workspace-banner")).toHaveCount(0);
  await page.getByRole("button", { name: "创建服务" }).click();
  await expect(page.getByLabel("服务名称")).toHaveValue("");
});

test("用户卡片精简字段，长用户名可展开查看且小屏不横向溢出", async ({ page }, info) => {
  await installApiMocks(page);
  const longName = "member_" + "a".repeat(57);
  const users = [
    { id: "admin", username: "admin", role: "system_admin", enabled: true },
    { id: "long", username: longName, role: "tenant", enabled: true },
    { id: "alice", username: "alice", role: "tenant", enabled: false },
  ].map(user => ({ ...user, workspace_id: user.id, workspace_name: `${user.username}的工作空间`, created_at: 1790000000, devices: 2, services: 12, domains: 3 }));
  await page.route("**/api/v1/admin/**", route => route.fulfill({ json: new URL(route.request().url()).pathname.endsWith("/users") ? users : [] }));
  await page.goto("/#/users");
  const cards = page.locator(".user-card");
  await expect(cards).toHaveCount(3);
  await expect(cards.getByRole("button")).toHaveCount(6);
  await expect(page.locator(".user-profile")).toHaveCount(0);
  await expect(cards.nth(1).getByRole("heading")).toHaveAttribute("title", longName);
  await expect(cards.first().locator(".user-resource-summary")).toHaveText("Agent 2 · 服务 12 · 域名 3");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("users-overview.png"), fullPage: true });
  await cards.nth(1).getByRole("button", { name: "账号设置" }).click();
  await expect(cards.nth(1).getByRole("heading")).toHaveText(longName);
  await expect(cards.nth(1).getByRole("heading")).toHaveCSS("white-space", "normal");
  await expect(cards.nth(1).getByRole("button", { name: "账号设置" })).toHaveAttribute("aria-expanded", "true");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("user-account-fields.png"), fullPage: true });
});
