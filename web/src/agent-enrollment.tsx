import { useEffect, useMemo, useRef, useState } from "react";
import { agentDeploymentCommand, normalizeAgentServerUrl } from "./agent-deployment";
import type { DeploymentMethod } from "./agent-deployment";
import { CopyButton, Modal, Notice, dateText, errorText, useApi } from "./ui";
import type { Enrollment } from "./ui";

declare const __AGENT_COMPOSE_TEMPLATE__: string;

/** 入网凭证仅驻留弹窗内存；固定操作栏让手机上无需滚过整段脚本即可完成复制。 */
export function AgentEnrollment({ csrf, onClose, onCreated }: { csrf?: string | null; onClose: () => void; onCreated: () => Promise<void> }) {
  const request = useApi();
  const [invite, setInvite] = useState<Enrollment | null>(null);
  const [serverUrl, setServerUrl] = useState(window.location.origin);
  const [method, setMethod] = useState<DeploymentMethod>("compose");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now()); const [expanded, setExpanded] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const input = useRef<HTMLInputElement>(null); const addressField = useRef<HTMLDivElement>(null); const preview = useRef<HTMLDetailsElement>(null);
  const normalizedUrl = normalizeAgentServerUrl(serverUrl);
  const expired = Boolean(invite && (!Number.isFinite(invite.expires_at) || invite.expires_at * 1000 <= now));
  const deployment = useMemo(() => {
    if (!invite?.token || !normalizedUrl || expired) return { command: "", error: null };
    try { return { command: agentDeploymentCommand(__AGENT_COMPOSE_TEMPLATE__, normalizedUrl, invite.token, method), error: null }; }
    catch (e) { return { command: "", error: errorText(e) }; }
  }, [invite, normalizedUrl, expired, method]);

  useEffect(() => {
    if (!invite) return;
    const refresh = () => setNow(Date.now());
    const timer = window.setTimeout(refresh, Math.max(0, invite.expires_at * 1000 - Date.now()));
    window.addEventListener("focus", refresh); document.addEventListener("visibilitychange", refresh);
    return () => { clearTimeout(timer); window.removeEventListener("focus", refresh); document.removeEventListener("visibilitychange", refresh); };
  }, [invite]);
  useEffect(() => { setCopyState("idle"); }, [deployment.command]);
  useEffect(() => {
    if (copyState !== "copied") return;
    const timer = window.setTimeout(() => setCopyState("idle"), 2500);
    return () => clearTimeout(timer);
  }, [copyState]);
  useEffect(() => {
    // 输入及就近错误作为整体露出，避免键盘/操作栏只留下输入框而遮挡错误原因。
    const reveal = () => requestAnimationFrame(() => { if (document.activeElement === input.current) addressField.current?.scrollIntoView({ block: "nearest" }); });
    reveal();
    window.visualViewport?.addEventListener("resize", reveal);
    return () => window.visualViewport?.removeEventListener("resize", reveal);
  }, [normalizedUrl]);

  async function create() {
    setBusy(true); setError(null);
    try { setInvite(await request<Enrollment>("/api/v1/enrollments", { method: "POST", body: JSON.stringify({ ttl_seconds: 3600 }) }, csrf)); setNow(Date.now()); await onCreated(); }
    catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }
  async function copy() {
    if (!deployment.command || !invite || invite.expires_at * 1000 <= Date.now()) { setNow(Date.now()); return; }
    try { await navigator.clipboard.writeText(deployment.command); setCopyState("copied"); }
    catch { setCopyState("failed"); setExpanded(true); requestAnimationFrame(() => preview.current?.scrollIntoView({ block: "nearest" })); }
  }
  const credentialError = invite ? expired ? "凭证已过期，请关闭后重新生成。" : !invite.token ? "服务器未返回凭证，请关闭后重试。" : null : null;
  return <Modal title="添加 Agent" onClose={onClose} busy={busy} dirty={Boolean(invite?.token)}>
    <div className="modal-form agent-enrollment">
      <div className="modal-body"><ol className="steps">
        <li><strong>入网凭证</strong><p>有效期 1 小时，仅本次显示。部署命令会自动填入凭证。</p>{invite?.token && <><code className="token">{invite.token}</code><CopyButton value={invite.token} label="复制入网凭证" /><small>有效期至 {dateText(invite.expires_at)}</small></>}</li>
        <li><strong>部署并启动</strong><div ref={addressField}><label className="agent-server-label">Server 地址<input ref={input} type="url" inputMode="url" enterKeyHint="done" autoCapitalize="none" autoCorrect="off" spellCheck={false} value={serverUrl} aria-invalid={!normalizedUrl || undefined} aria-describedby={!normalizedUrl ? "agent-server-error" : "agent-server-hint"} onFocus={() => requestAnimationFrame(() => addressField.current?.scrollIntoView({ block: "nearest" }))} onChange={e => setServerUrl(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); e.currentTarget.blur(); } }} /></label>
          {!normalizedUrl ? <p className="form-error" id="agent-server-error" role="alert">请输入 HTTP/HTTPS 地址，不含用户名、密码、查询参数或片段。</p> : <p id="agent-server-hint">填写目标主机可访问的 Web/API 地址。</p>}
          </div><div className="agent-deployment-method" role="group" aria-label="部署方式"><button type="button" aria-pressed={method === "compose"} onClick={() => setMethod("compose")}>Docker Compose</button><button type="button" aria-pressed={method === "docker"} onClick={() => setMethod("docker")}>docker run</button></div>
          <p>Linux/amd64 · 需安装 Docker{method === "compose" ? " 和 Compose v2" : ""}。命令包含一次性凭证，仅在目标主机执行。</p>
          {deployment.command && <details className="agent-command" ref={preview} open={expanded} onToggle={e => setExpanded(e.currentTarget.open)}><summary>查看部署命令</summary><pre tabIndex={0} aria-label="部署命令"><code>{deployment.command}</code></pre></details>}
        </li>
        <li><strong>批准入网</strong><p>执行后返回 Agent 列表，核对申请并批准。</p></li>
      </ol></div>
      <footer className="modal-actions">
        <Notice error={error ?? credentialError ?? deployment.error} />
        {copyState === "failed" && <p className="form-error" role="alert">无法复制，请在展开的命令中长按选择并手动复制。</p>}
        {copyState === "copied" && <span className="copy-feedback" role="status">部署命令已复制</span>}
        <button type="button" className="primary-button" disabled={busy || Boolean(invite && !deployment.command)} onClick={() => void (invite ? copy() : create())}>{busy ? "生成中…" : invite ? copyState === "copied" ? "已复制部署命令" : "复制部署命令" : "生成凭证"}</button>
      </footer>
    </div>
  </Modal>;
}
