import { useState } from "react";
import { CopyButton, Modal, Notice, errorText, useApi } from "./ui";
import type { Domain } from "./ui";

type Step = "verification" | "certificate" | "advanced";
/** 每一步独立提交和反馈，明确部分成功；凭据只驻留内存，不回显到普通配置。 */
export function DomainSettings({ domain, csrf, onClose, onSaved, onDelete }: { domain: Domain; csrf?: string | null; onClose: () => void; onSaved: (value: Partial<Domain>) => void; onDelete: () => void }) {
  const request = useApi(); const [current, setCurrent] = useState(domain);
  const [mode, setMode] = useState(domain.certificate_mode ?? "http01"); const [token, setToken] = useState("");
  const [editingToken, setEditingToken] = useState(!domain.credential_configured);
  const [resolvers, setResolvers] = useState((domain.dns_resolvers ?? []).join(", "));
  const [delay, setDelay] = useState(domain.dns_propagation_delay_seconds?.toString() ?? ""); const [timeout, setTimeout] = useState(domain.dns_propagation_timeout_seconds?.toString() ?? "");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Partial<Record<Step, { error?: string; notice?: string }>>>({});
  const path = `/api/v1/public-domains/${encodeURIComponent(domain.id)}`;
  const dirty = Boolean(token) || mode !== (current.certificate_mode ?? "http01") || resolvers !== (current.dns_resolvers ?? []).join(", ") || delay !== (current.dns_propagation_delay_seconds?.toString() ?? "") || timeout !== (current.dns_propagation_timeout_seconds?.toString() ?? "");
  async function perform(step: Step, action: () => Promise<Partial<Domain>>, message: string) {
    if (busy) return;
    setBusy(true); setFeedback(previous => ({ ...previous, [step]: {} }));
    try { const value = await action(); setCurrent(previous => ({ ...previous, ...value })); onSaved(value); setFeedback(previous => ({ ...previous, [step]: { notice: message } })); return value; }
    catch (e) { setFeedback(previous => ({ ...previous, [step]: { error: errorText(e) } })); } finally { setBusy(false); }
  }
  const result = (step: Step) => <><Notice error={feedback[step]?.error} />{feedback[step]?.notice && <p role="status" className="action-status">{feedback[step]?.notice}</p>}</>;
  const savingToken = mode === "cloudflare_dns" && editingToken;
  async function saveCertificate() {
    const value = savingToken
      ? await perform("certificate", () => request<Domain>(`${path}/cloudflare-credential`, { method: "PUT", body: JSON.stringify({ token: token.trim() }) }, csrf), "凭据已验证并保存，Cloudflare DNS 已启用。")
      : await perform("certificate", () => request<Domain>(path, { method: "PATCH", body: JSON.stringify({ certificate_mode: mode, dns_resolvers: current.dns_resolvers ?? [], dns_propagation_delay_seconds: current.dns_propagation_delay_seconds ?? null, dns_propagation_timeout_seconds: current.dns_propagation_timeout_seconds ?? null }) }, csrf), "证书配置已保存，签发状态见域名详情。");
    if (value && savingToken) { setToken(""); setEditingToken(false); setMode("cloudflare_dns"); }
  }
  return <Modal title={`配置 ${domain.domain}`} full dirty={dirty} busy={busy} onClose={onClose}>{close => <div className="modal-form">
    <div className="modal-body domain-settings">
      <section aria-label="域名归属"><h3>1. 验证域名归属</h3>{current.verification_status === "verified" ? <p className="helper">归属已验证</p> : <><p className="helper">添加 TXT 记录后检查，或使用 Cloudflare Token 自动验证。</p>{current.verification_record && <dl><dt>TXT 名称</dt><dd className="service-detail-address"><code>{current.verification_record.name}</code><CopyButton iconOnly label="复制 TXT 名称" value={current.verification_record.name} /></dd><dt>TXT 内容</dt><dd className="service-detail-address"><code>{current.verification_record.value}</code><CopyButton iconOnly label="复制 TXT 内容" value={current.verification_record.value} /></dd></dl>}<button className="secondary-button" disabled={busy} onClick={() => void perform("verification", () => request<Domain>(`${path}/verification`, { method: "POST" }, csrf), "域名归属已验证。")}>检查归属记录</button></>}{result("verification")}</section>
      <section aria-label="证书方式"><h3>2. 配置证书</h3><form id="certificate-settings" onSubmit={async e => { e.preventDefault(); await saveCertificate(); }}><fieldset disabled={busy}><label>证书验证方式<select value={mode} onChange={e => { setMode(e.target.value as typeof mode); setFeedback(previous => ({ ...previous, certificate: {} })); }}><option value="http01">HTTP 验证</option><option value="cloudflare_dns">Cloudflare DNS 验证</option></select></label><p className="helper">{mode === "http01" ? "每个服务单独签发证书。域名需解析到 Server，并开放 TCP 80、443。" : "根域名和泛域名证书自动签发与续期。需要此域名的 Cloudflare Zone Read、DNS Edit 权限；不会自动创建访问解析记录。"}</p>
      {mode === "cloudflare_dns" && (current.credential_configured && !editingToken ? <div className="credential-summary"><span>Cloudflare Token · 已配置</span><button type="button" className="text-button" onClick={() => setEditingToken(true)}>更新 Token</button></div> : <><label>Cloudflare API Token<input type="password" autoComplete="off" autoCapitalize="none" spellCheck={false} value={token} onChange={e => setToken(e.target.value)} placeholder={current.credential_configured ? "输入新 Token" : "粘贴完整 Token"} required /></label><details className="recovery-help"><summary>Token 说明</summary><p>支持传统 Token、cfut_ 和 cfat_。提交会创建并清理临时 TXT 记录核对权限，然后保存凭据并启用 Cloudflare DNS；Token 不会回显。</p></details>{current.credential_configured && <button type="button" className="text-button" onClick={() => { setToken(""); setEditingToken(false); }}>取消更新</button>}</>)}
      </fieldset>{result("certificate")}</form></section>
      {mode === "cloudflare_dns" && <section><details><summary>DNS 高级设置</summary><form onSubmit={async e => { e.preventDefault(); const value = await perform("advanced", () => request<Domain>(path, { method: "PATCH", body: JSON.stringify({ certificate_mode: current.certificate_mode ?? "http01", dns_resolvers: resolvers.split(/[\s,]+/).filter(Boolean), dns_propagation_delay_seconds: delay === "" ? null : Number(delay), dns_propagation_timeout_seconds: timeout === "" ? null : Number(timeout) }) }, csrf), "DNS 高级设置已保存。"); if (value) { setResolvers((value.dns_resolvers ?? []).join(", ")); setDelay(value.dns_propagation_delay_seconds?.toString() ?? ""); setTimeout(value.dns_propagation_timeout_seconds?.toString() ?? ""); } }}><fieldset disabled={busy}><div className="management-fields"><label>DNS 解析器<input value={resolvers} onChange={e => setResolvers(e.target.value)} placeholder="223.5.5.5:53, 223.6.6.6:53" autoCapitalize="none" spellCheck={false} /></label><p className="helper">最多 4 个，以逗号或空格分隔。支持 IPv4、IPv6，可附端口；留空使用阿里云公共 DNS（223.5.5.5、223.6.6.6）。仅影响证书验证。</p><label>传播等待（秒）<input type="number" min={0} max={120} step={1} value={delay} onChange={e => setDelay(e.target.value)} placeholder="默认" /></label><label>传播超时（秒）<input type="number" min={1} max={600} step={1} value={timeout} onChange={e => setTimeout(e.target.value)} placeholder="默认" /></label></div></fieldset>{result("advanced")}<button className="secondary-button" disabled={busy}>保存 DNS 设置</button></form></details></section>}
      <button className="danger-button danger-zone" disabled={busy} onClick={onDelete}>删除域名</button>
    </div><footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel" onClick={close} disabled={busy}>取消</button><button form="certificate-settings" className="primary-button" disabled={busy || (savingToken && !token.trim())}>{busy ? "处理中…" : savingToken ? "验证并启用" : "保存证书配置"}</button></footer>
  </div>}</Modal>;
}
