#!/usr/bin/env node
// Node 22+，真实进程验收。数据、密钥和日志只写入独立测试目录，不访问公网 CA。
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createWriteStream } from "node:fs";
import path from "node:path";
import net from "node:net";
import tls from "node:tls";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { once } from "node:events";

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, i, list) => i % 2 ? pairs : [...pairs, [value.replace(/^--/, ""), list[i + 1]]], []));
assert(args["server-bin"] && args["agent-bin"], "需要 --server-bin 和 --agent-bin");
const serverBin = path.resolve(args["server-bin"]), agentBin = path.resolve(args["agent-bin"]);
const rootBase = path.resolve(args["test-dir"] ?? ".edge-screenshot/recovery-runtime");
await fs.mkdir(rootBase, { recursive: true });
const root = await fs.mkdtemp(path.join(rootBase, "run-"));
const passed = [], processes = [], logs = [];
let server, agent, cookie = "", csrf = "";
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function wait(check, label, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { try { const value = await check(); if (value) return value; } catch {} await delay(150); }
  throw Error(`等待超时：${label}。测试日志：${root}`);
}
async function port() { const listener = net.createServer(); listener.listen(0, "127.0.0.1"); await once(listener, "listening"); const value = listener.address().port; await new Promise(resolve => listener.close(resolve)); return value; }
const ports = { api: await port(), control: await port(), data: await port(), public: await port() };
const url = `http://127.0.0.1:${ports.api}`;
const serverEnv = { NEXO_DATA_DIR: path.join(root, "server"), NEXO_HTTP_ADDR: `127.0.0.1:${ports.api}`, NEXO_CONTROL_ADDR: `127.0.0.1:${ports.control}`, NEXO_TUNNEL_ADDR: `127.0.0.1:${ports.data}`, NEXO_TUNNEL_ENDPOINT: `127.0.0.1:${ports.data}`, NEXO_PUBLIC_BIND: "127.0.0.1", NEXO_CADDY_ENABLED: "false", NEXO_PUBLIC_URL: "", NEXO_TRUSTED_PROXIES: "", NEXO_PUBLIC_IPS: "127.0.0.1" };
const agentEnv = { NEXO_STATE_DIR: path.join(root, "agent"), NEXO_SERVER_URL: url, NEXO_ENROLLMENT_TOKEN: "", NEXO_CONTROL_ENDPOINT: `127.0.0.1:${ports.control}`, NEXO_TUNNEL_ENDPOINT: `127.0.0.1:${ports.data}` };
function launch(name, binary, environment, parameters = []) {
  const log = createWriteStream(path.join(root, `${name}-${processes.length}.log`)); logs.push(log);
  const child = spawn(binary, parameters, { env: { ...process.env, ...environment }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false }); processes.push(child);
  return child;
}
async function stop(child) { if (child && child.exitCode === null && child.signalCode === null) { const ended = once(child, "exit"); child.kill(); await ended; } }
async function call(route, method = "GET", body, headers = {}) {
  const response = await fetch(`${url}/api/v1/${route}`, { method, headers: { "content-type": "application/json", cookie, "x-nexo-csrf": csrf, ...headers }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) cookie = cookies.map(value => value.split(";")[0]).join("; ");
  const value = await response.json(); if (value.csrf_token) csrf = value.csrf_token;
  return { status: response.status, value, headers: response.headers, cookies };
}
async function api(...input) { const result = await call(...input); assert(result.status < 400, `API ${input[0]}：${result.status} ${result.value.error ?? ""}`); return result.value; }
function check(label) { passed.push(label); console.log("PASS", label); }
async function ready(id) { return (await api("tunnels")).find(item => item.id === id && item.apply_status === "ready"); }
async function echoThroughTunnel(payload = "真实 Tunnel 恢复成功") {
  const socket = net.connect(ports.public, "127.0.0.1"); socket.setTimeout(5000, () => socket.destroy(Error("TCP 超时")));
  await once(socket, "connect"); socket.write(payload); const [received] = await once(socket, "data"); assert.equal(received.toString(), payload); socket.destroy();
}
async function oldIdentityRejected(identity, data) {
  await new Promise((resolve, reject) => {
    let negotiated = false;
    const stream = tls.connect({ host: "127.0.0.1", port: data ? ports.data : ports.control, servername: "nexo-server", ca: identity.ca_pem, cert: identity.certificate_pem, key: identity.key_pem });
    stream.setTimeout(5000, () => { stream.destroy(); reject(Error("旧身份未被及时关闭")); });
    stream.on("error", error => negotiated ? resolve() : reject(error)); stream.on("close", () => negotiated ? resolve() : reject(Error("TLS 握手未成功，不能据此认定应用层拒绝了旧身份")));
    stream.on("data", () => { stream.destroy(); reject(Error("旧身份仍收到服务端应用响应")); });
    stream.on("secureConnect", () => { negotiated = true; if (!data) stream.write(JSON.stringify({ type: "hello", device_id: identity.device_id, agent_version: "test-old-identity" }) + "\n"); });
  });
}

const echo = net.createServer(socket => { socket.on("error", () => {}); socket.pipe(socket); });
echo.listen(0, "127.0.0.1"); await once(echo, "listening");
console.log("测试目录：", root);
try {
  server = launch("server", serverBin, serverEnv);
  await wait(async () => (await call("auth/status")).status === 200, "Server 启动");
  const bootstrap = (await fs.readFile(path.join(root, "server/bootstrap.code"), "utf8")).trim();
  await api("auth/initialize", "POST", { bootstrap_code: bootstrap, username: "admin", password: "old-test-password-1234" });
  assert.equal((await api("auth/status", "GET", undefined, { "x-forwarded-proto": "https" })).channel, "local_http");
  assert.equal((await call("auth/logout", "POST", {}, { Origin: "https://attacker.invalid" })).status, 403);
  assert.equal((await call("auth/logout", "POST", {}, { "x-nexo-csrf": "wrong" })).status, 403);
  check("未信任的 HTTPS 请求头无效，跨站和缺少 CSRF 的写入被拒绝");

  const invite = await api("enrollments", "POST", { ttl_seconds: 3600 });
  agent = launch("agent", agentBin, { ...agentEnv, NEXO_ENROLLMENT_TOKEN: invite.token });
  await wait(async () => (await api("enrollments")).some(item => item.id === invite.id && item.status === "awaiting_approval"), "首次 CSR");
  const device = (await api(`enrollments/${invite.id}/approve`, "POST", { device_name: "恢复验收 Agent" })).device_id;
  await wait(async () => (await api("devices")).some(item => item.id === device && item.status === "online"), "Agent 在线");
  const tunnel = await api("tunnels", "POST", { name: "恢复测试", protocol: "tcp", device_id: device, local_address: "127.0.0.1", local_port: echo.address().port, public_port: ports.public, enabled: true });
  await wait(() => ready(tunnel.id), "TCP 就绪"); await echoThroughTunnel();
  check("真实入网审批、mTLS 控制与 TCP 数据转发");

  const identityFile = path.join(root, "agent/identity.json");
  const oldBytes = await fs.readFile(identityFile), oldIdentity = JSON.parse(oldBytes);
  const previous = await api(`devices/${device}/recovery`, "POST");
  const recovery = await api(`devices/${device}/recovery`, "POST");
  assert.equal((await api(`enrollments/${previous.id}`)).status, "revoked");
  let recoveryProcess = launch("recover", agentBin, { ...agentEnv, NEXO_ENROLLMENT_TOKEN: recovery.token }, ["--recover-identity"]);
  await wait(async () => (await api(`enrollments/${recovery.id}`)).status === "awaiting_approval", "恢复 CSR");
  assert((await fs.readFile(identityFile)).equals(oldBytes));
  const key = await fs.readFile(path.join(root, "agent/recovery-key.json"));
  await stop(recoveryProcess);
  recoveryProcess = launch("recover-retry", agentBin, { ...agentEnv, NEXO_ENROLLMENT_TOKEN: recovery.token }, ["--recover-identity"]);
  await delay(500); assert((await fs.readFile(path.join(root, "agent/recovery-key.json"))).equals(key));
  const live = net.connect(ports.public, "127.0.0.1"); await once(live, "connect"); live.write("before"); await once(live, "data");
  const disconnected = new Promise(resolve => { live.on("error", () => {}); live.once("close", () => resolve(true)); });
  await api(`enrollments/${recovery.id}/approve`, "POST", {});
  assert(await Promise.race([disconnected, delay(5000).then(() => false)]), "批准恢复没有关闭旧 TCP 连接");
  await wait(() => recoveryProcess.exitCode !== null, "恢复命令退出"); assert.equal(recoveryProcess.exitCode, 0);
  const recovered = JSON.parse(await fs.readFile(identityFile));
  assert.equal(recovered.device_id, device); assert.notEqual(recovered.key_pem, oldIdentity.key_pem);
  await oldIdentityRejected(oldIdentity, false); await oldIdentityRejected(oldIdentity, true);
  check("恢复申请可重试，批准前保留旧身份；批准后撤销旧证书与既有连接");
  await stop(agent); agent = launch("agent-recovered", agentBin, agentEnv);
  await wait(() => ready(tunnel.id), "恢复后重新转发"); await echoThroughTunnel();
  assert.equal((await api("devices")).length, 1);
  const bound = (await api("tunnels")).find(item => item.id === tunnel.id);
  assert.equal(bound.device_id, device); assert.equal(bound.public_port, tunnel.public_port); assert.equal(bound.enabled, true);
  check("恢复后设备 ID、服务 ID、公网端口和启停状态保留，数据转发恢复");

  await stop(agent); await fs.rename(identityFile, identityFile + ".test-backup");
  const lost = await api(`devices/${device}/recovery`, "POST");
  const lostProcess = launch("recover-lost", agentBin, { ...agentEnv, NEXO_ENROLLMENT_TOKEN: lost.token }, ["--recover-identity"]);
  await wait(async () => (await api(`enrollments/${lost.id}`)).status === "awaiting_approval", "丢失私钥后的恢复申请");
  await api(`enrollments/${lost.id}/approve`, "POST", {});
  await wait(() => lostProcess.exitCode !== null, "丢失身份恢复完成"); assert.equal(lostProcess.exitCode, 0);
  agent = launch("agent-after-loss", agentBin, agentEnv); await wait(() => ready(tunnel.id), "丢失身份后重新转发"); await echoThroughTunnel();
  assert.equal(JSON.parse(await fs.readFile(identityFile)).device_id, device);
  check("身份文件和私钥丢失后可重新授权，原服务仍可用");

  const domain = await api("public-domains", "POST", { domain: "example.localhost", https_enabled: false });
  const instructions = await api(`public-domains/${domain.id}/access`);
  assert.equal(instructions.public_access, "unverified");
  assert.deepEqual(instructions.expected_addresses, ["127.0.0.1"]);
  const dns = await wait(async () => { const result = await api(`public-domains/${domain.id}/access`); return result.checked_at ? result : null; }, "DNS 未自动检查");
  assert.equal(dns.public_access, "unverified"); assert(dns.checked_at);
  const unresolved = dns.records.some(record => record.status === "unresolved");
  assert.equal(dns.retries_remaining, unresolved ? 3 : 0);
  assert.equal(dns.next_retry_at, unresolved ? dns.checked_at + 300 : null);
  assert((await api("public-domains")).find(item => item.id === domain.id)?.access.checked_at);
  const rechecked = await api(`public-domains/${domain.id}/access`, "POST");
  assert.equal(rechecked.public_access, "unverified"); assert(rechecked.checked_at);
  assert(rechecked.retries_remaining <= dns.retries_remaining, "手动检查重置了自动重试次数");
  check("域名解析在后台自动检查，列表读取结果，手动重试不冒充公网可达验证");

  const command = await promisify(execFile)(serverBin, ["admin", "recover", "--username", "admin"], { env: { ...process.env, ...serverEnv }, windowsHide: true });
  const code = command.stdout.match(/[a-f0-9]{64}/)?.[0]; assert(code, "CLI 未生成恢复码");
  await api("auth/recover", "POST", { recovery_code: code, new_password: "recovered-test-password-1234" });
  assert.equal((await call("devices")).value.code, "session_expired");
  assert.equal((await call("auth/recover", "POST", { recovery_code: code, new_password: "another-password-1234" })).status, 401);
  assert.equal((await call("auth/login", "POST", { username: "admin", password: "old-test-password-1234" })).status, 401);
  await api("auth/login", "POST", { username: "admin", password: "recovered-test-password-1234" });
  assert.equal((await api("devices"))[0].id, device);
  check("本机 CLI 生成一次性恢复码，重设密码撤销旧会话和旧密码，业务数据保留");

  await stop(server);
  server = launch("server-proxy", serverBin, { ...serverEnv, NEXO_PUBLIC_URL: "https://manage.example.test", NEXO_TRUSTED_PROXIES: "127.0.0.1" });
  await wait(async () => (await call("auth/status")).status === 403, "HTTPS 强制保护");
  const proxyHeaders = { "x-forwarded-proto": "https", Origin: "https://manage.example.test" };
  const secured = await call("auth/login", "POST", { username: "admin", password: "recovered-test-password-1234" }, proxyHeaders);
  assert.equal(secured.status, 200); assert(secured.cookies.every(value => value.includes("; Secure")));
  assert.equal((await api("auth/status", "GET", undefined, proxyHeaders)).local_http_warning, false);
  assert.equal((await call("auth/status", "GET", undefined, { "x-forwarded-proto": "https,http" })).status, 403);
  assert.equal((await call("auth/logout", "POST", {}, { ...proxyHeaders, Origin: "https://attacker.invalid" })).status, 403);
  check("可信代理 HTTPS 识别、Secure Cookie、管理入口约束和来源校验");
  let throttled = false;
  for (let attempt = 0; attempt < 12; attempt++) {
    const result = await call("auth/login", "POST", { username: "admin", password: "incorrect-password" }, proxyHeaders);
    if (result.status === 429) { throttled = true; break; }
  }
  assert(throttled); check("连续错误登录受到限流，返回可理解的重试提示");
  if (args.report) { const report = path.resolve(args.report); await fs.mkdir(path.dirname(report), { recursive: true }); await fs.writeFile(report, JSON.stringify({ passed, platform: process.platform, directory: root }, null, 2)); }
  console.log(`全部 ${passed.length} 项通过。`);
} finally {
  for (const child of processes.reverse()) await stop(child);
  for (const log of logs) log.end();
  echo.close();
}
