import { useState } from "react";
import { CopyButton, Modal, Notice, errorText, useApi } from "./ui";
import type { Domain } from "./ui";

/** 配置按域名保存；Token 只用于提交，响应和普通配置草稿都不保留凭据。 */
export function DomainSettings({ domain, csrf, onClose, onSaved, onDelete }: { domain: Domain; csrf?: string | null; onClose: () => void; onSaved: (value: Partial<Domain>) => void; onDelete: () => void }) {
  const request = useApi(); const [current, setCurrent] = useState(domain);
  const [mode, setMode] = useState(domain.certificate_mode ?? "http01"); const [token, setToken] = useState("");
  const [editingToken, setEditingToken] = useState(!domain.credential_configured);
  const [resolvers, setResolvers] = useState((domain.dns_resolvers ?? []).join(", "));
  const [delay, setDelay] = useState(domain.dns_propagation_delay_seconds?.toString() ?? ""); const [timeout, setTimeout] = useState(domain.dns_propagation_timeout_seconds?.toString() ?? "");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [notice, setNotice] = useState<string | null>(null);
  const path = `/api/v1/public-domains/${encodeURIComponent(domain.id)}`;
  const dirty = Boolean(token) || mode !== (current.certificate_mode ?? "http01") || resolvers !== (current.dns_resolvers ?? []).join(", ") || delay !== (current.dns_propagation_delay_seconds?.toString() ?? "") || timeout !== (current.dns_propagation_timeout_seconds?.toString() ?? "");
  async function perform(action: () => Promise<Partial<Domain>>, message: string) {
    setBusy(true); setError(null); setNotice(null);
    try { const value = await action(); setCurrent(previous => ({ ...previous, ...value })); onSaved(value); setNotice(message); return value; }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <Modal title={`配置 ${domain.domain}`} full dirty={dirty} busy={busy} onClose={onClose}><div className="modal-body domain-settings">
    {current.verification_status === "verified" ? <p className="helper">归属已验证</p> : <section><h3>域名归属</h3><p className="helper">添加以下 TXT 记录后检查，或使用 Cloudflare Token 自动验证。</p>{current.verification_record && <dl><dt>TXT 名称</dt><dd><code>{current.verification_record.name}</code><CopyButton compact label="复制 TXT 名称" value={current.verification_record.name} /></dd><dt>TXT 内容</dt><dd><code>{current.verification_record.value}</code><CopyButton label="复制 TXT 内容" value={current.verification_record.value} /></dd></dl>}<button className="secondary-button" disabled={busy} onClick={() => void perform(() => request<Domain>(`${path}/verification`, { method: "POST" }, csrf), "域名归属已验证。")}>检查归属记录</button></section>}
    <form onSubmit={async e => { e.preventDefault(); const value = await perform(() => request<Domain>(path, { method: "PATCH", body: JSON.stringify({ certificate_mode: mode, dns_resolvers: resolvers.split(/[\s,]+/).filter(Boolean), dns_propagation_delay_seconds: delay === "" ? null : Number(delay), dns_propagation_timeout_seconds: timeout === "" ? null : Number(timeout) }) }, csrf), "证书配置已保存，正在加载。"); if (value) { setResolvers((value.dns_resolvers ?? []).join(", ")); } }}>
      <fieldset disabled={busy}><label>证书验证方式<select value={mode} onChange={e => setMode(e.target.value as typeof mode)}><option value="http01">HTTP 验证</option><option value="cloudflare_dns">Cloudflare DNS 验证</option></select></label><p className="helper">{mode === "http01" ? "为各服务主机名单独签发证书。请将域名解析到 Server，并开放公网 TCP 80、443。" : "根域名和泛域名证书自动签发与续期。需要此域名的 Cloudflare Zone Read、DNS Edit 权限。"}</p>
      {mode === "cloudflare_dns" && <details><summary>DNS 高级设置</summary><div className="management-fields"><label>DNS 解析器<input value={resolvers} onChange={e => setResolvers(e.target.value)} placeholder="223.5.5.5:53, 223.6.6.6:53" autoCapitalize="none" spellCheck={false} /></label><p className="helper">最多 4 个，以逗号或空格分隔。支持 IPv4、IPv6，可附端口；留空使用阿里云公共 DNS（223.5.5.5、223.6.6.6）。仅影响证书验证。</p><label>传播等待（秒）<input type="number" min={0} max={120} step={1} value={delay} onChange={e => setDelay(e.target.value)} placeholder="默认" /></label><label>传播超时（秒）<input type="number" min={1} max={600} step={1} value={timeout} onChange={e => setTimeout(e.target.value)} placeholder="默认" /></label></div></details>}
      </fieldset><button className="primary-button" disabled={busy}>保存证书配置</button>
    </form>
    {mode === "cloudflare_dns" && (current.credential_configured && !editingToken ? <div className="credential-summary"><span>Cloudflare Token · 已配置</span><button className="text-button" disabled={busy} onClick={() => setEditingToken(true)}>更新 Token</button></div> : <form onSubmit={async e => { e.preventDefault(); const value = await perform(() => request<Domain>(`${path}/cloudflare-credential`, { method: "PUT", body: JSON.stringify({ token: token.trim() }) }, csrf), "凭据已验证并保存，正在加载证书配置。"); if (value) { setToken(""); setEditingToken(false); setMode("cloudflare_dns"); } }}><fieldset disabled={busy}><label>Cloudflare API Token<input type="password" autoComplete="off" autoCapitalize="none" spellCheck={false} value={token} onChange={e => setToken(e.target.value)} placeholder={current.credential_configured ? "输入新 Token" : "粘贴完整 Token"} required /></label><details className="recovery-help"><summary>Token 说明</summary><p>支持传统 Token、cfut_ 和 cfat_。提交时会创建并清理临时 TXT 记录以核对权限，Token 不会回显。</p></details></fieldset><button className="secondary-button" disabled={busy || !token.trim()}>{current.credential_configured ? "验证并更新 Token" : "验证并保存 Token"}</button></form>)}
    <Notice error={error} />{notice && <p role="status" className="action-status">{notice}</p>}
    <button className="danger-button danger-zone" disabled={busy} onClick={onDelete}>删除域名</button>
  </div></Modal>;
}
