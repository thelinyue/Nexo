import { useEffect, useMemo, useRef, useState } from "react";
import { agentDeploymentContent, normalizeAgentServerUrl } from "./agent-deployment";
import type { DeploymentMethod } from "./agent-deployment";
import { Confirm, CopyButton, Modal, Notice, Status, useApi, useResource } from "./ui";
import type { Device } from "./ui";

declare const __AGENT_COMPOSE_TEMPLATE__: string;
type AccessKey = { token: string; created_at: number; updated_at: number };

/** 空间共享配置只驻留组件内存；每台主机的数据目录保存自己的设备身份。 */
export function AgentEnrollment({ csrf, onClose, onCreated }: { csrf?: string | null; onClose: () => void; onCreated: () => Promise<void> }) {
  const request = useApi();
  const credential = useResource(() => request<AccessKey>("/api/v1/agent-access-key", { method: "POST" }, csrf), true, false);
  const devices = useResource(() => request<Device[]>("/api/v1/devices"), true, true, true);
  const [serverUrl, setServerUrl] = useState(window.location.origin);
  const [name, setName] = useState("");
  const [method, setMethod] = useState<DeploymentMethod>("compose");
  const [resetting, setResetting] = useState(false);
  const addressField = useRef<HTMLDivElement>(null); const input = useRef<HTMLInputElement>(null);
  const normalizedUrl = normalizeAgentServerUrl(serverUrl);
  const isCompose = method === "compose";
  const deploymentName = isCompose ? "Compose 配置" : "docker run 命令";
  const token = credential.data?.token;
  const deployment = useMemo(() => {
    if (!token || !normalizedUrl) return { content: "", error: null };
    try { return { content: agentDeploymentContent(__AGENT_COMPOSE_TEMPLATE__, normalizedUrl, token, method, name), error: null }; }
    catch (e) { return { content: "", error: e instanceof Error ? e.message : "配置准备失败" }; }
  }, [token, normalizedUrl, method, name]);
  const recent = [...(devices.data ?? [])].sort((a, b) => (b.enrolled_at ?? 0) - (a.enrolled_at ?? 0)).slice(0, 5);
  useEffect(() => {
    const reveal = () => requestAnimationFrame(() => { if (document.activeElement === input.current) addressField.current?.scrollIntoView({ block: "nearest" }); });
    reveal(); window.visualViewport?.addEventListener("resize", reveal);
    return () => window.visualViewport?.removeEventListener("resize", reveal);
  }, [normalizedUrl]);
  const close = () => { onClose(); void onCreated(); };
  return <Modal title="添加设备" full onClose={close}>
    <div className="modal-form agent-enrollment">
      <div className="modal-body">
        <div ref={addressField}><label className="agent-server-label">Server 地址<input ref={input} type="url" inputMode="url" enterKeyHint="done" autoCapitalize="none" autoCorrect="off" spellCheck={false} value={serverUrl} aria-invalid={!normalizedUrl || undefined} aria-describedby={!normalizedUrl ? "agent-server-error" : undefined} onChange={e => setServerUrl(e.target.value)} onFocus={() => requestAnimationFrame(() => addressField.current?.scrollIntoView({ block: "nearest" }))} onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); e.currentTarget.blur(); } }} /></label>
        {!normalizedUrl && <p className="form-error" id="agent-server-error" role="alert">请输入 HTTP/HTTPS 地址，不含用户名、密码、查询参数或片段。</p>}</div>
        <label>设备名称（可选）<input value={name} maxLength={80} placeholder="例如：家庭 NAS" onChange={e => setName(e.target.value)} /></label>
        <div className="agent-deployment-method" role="group" aria-label="部署方式"><button type="button" aria-pressed={isCompose} onClick={() => setMethod("compose")}>Docker Compose</button><button type="button" aria-pressed={!isCompose} onClick={() => setMethod("docker")}>docker run</button></div>
        <p className="helper">{isCompose ? "保存为 compose.agent.yml，执行 docker compose -f compose.agent.yml up -d；也可粘贴到 NAS 的 Compose 项目。" : "在已安装 Docker 的 Linux / NAS 主机终端执行。"}</p>
        <p className="helper">含接入密钥，请勿分享。每台主机使用独立数据目录；已有设备保留原目录。</p>
        {credential.busy && !token && <p role="status">正在准备配置…</p>}
        <Notice error={credential.error ?? (credential.data && !token ? "服务器未返回接入密钥，请重试。" : null)} onRetry={() => void credential.reload()} />
        {deployment.content && <CopyButton value={deployment.content} label={`复制 ${deploymentName}`} />}
        {deployment.content && <details className="agent-command"><summary>查看 {deploymentName}</summary><pre tabIndex={0} aria-label={deploymentName}><code>{deployment.content}</code></pre></details>}
        <section className="enrollment-progress" aria-label="最近接入设备"><h3>最近接入</h3>
          <Notice error={devices.error} onRetry={() => void devices.reload()} />
          {!devices.data ? <p>正在读取设备…</p> : !recent.length ? <p>等待设备连接，启动后会自动接入。</p> : <ul className="recent-agents">{recent.map(device => <li key={device.id}><div><strong>{device.name}</strong><small title={device.id}>{device.id.slice(0, 8)}</small></div><Status kind="agent" value={device.status} /></li>)}</ul>}
        </section>
        {token && <details className="recovery-help"><summary>高级：接入密钥</summary><p>长期有效，可接入多台设备。重置只影响新设备接入，已接入设备不受影响。请勿分享配置或复制设备数据目录。</p><code className="token">{token}</code><div className="action-row"><CopyButton value={token} label="复制接入密钥" /><button className="text-button danger-text" onClick={() => setResetting(true)}>重置接入密钥</button></div></details>}
      </div>
      <footer className="modal-actions"><Notice error={deployment.error} />

        <button type="button" className="secondary-button" onClick={close}>完成</button>
      </footer>
    </div>
    {resetting && <Confirm title="重置接入密钥？" description="旧配置将不能用于新增设备。已接入设备和现有服务不受影响，请保存重置后的新配置。" label="重置密钥" onClose={() => setResetting(false)} onConfirm={async () => {
      const key = await request<AccessKey>("/api/v1/agent-access-key/reset", { method: "POST" }, csrf);
      credential.setData(key); setResetting(false);
    }} />}
  </Modal>;
}
