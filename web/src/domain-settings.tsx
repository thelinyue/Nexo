import { useState } from "react";
import { CopyButton, Modal, Notice, errorText, useApi } from "./ui";
import type { Domain } from "./ui";

type Step = "verification" | "certificate" | "advanced";
/** 每一步独立提交和反馈，明确部分成功；凭据只驻留内存，不回显到普通配置。 */
export function DomainSettings({ domain, csrf, onClose, onSaved, onDelete, showDnsReminder = false }: { domain: Domain; showDnsReminder?: boolean; csrf?: string | null; onClose: () => void; onSaved: (value: Partial<Domain>) => void; onDelete: () => void }) {
  const request = useApi(); const [current, setCurrent] = useState(domain);
  const [mode, setMode] = useState(domain.certificate_mode ?? "http01"); const [token, setToken] = useState("");
  const [provider, setProvider] = useState(domain.dns_provider ?? "cloudflare");
  const [keyId, setKeyId] = useState("");
  const providerName = provider === "cloudflare" ? "Cloudflare" : provider === "alidns" ? "阿里云 DNS" : "腾讯云 DNSPod";
  const [editingToken, setEditingToken] = useState(!domain.credential_configured);
  const [resolvers, setResolvers] = useState((domain.dns_resolvers ?? []).join(", "));
  const [delay, setDelay] = useState(domain.dns_propagation_delay_seconds?.toString() ?? ""); const [timeout, setTimeout] = useState(domain.dns_propagation_timeout_seconds?.toString() ?? "");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Partial<Record<Step, { error?: string; notice?: string }>>>({});
  const path = `/api/v1/public-domains/${encodeURIComponent(domain.id)}`;
  const dirty = Boolean(token) || Boolean(keyId) || provider !== (current.dns_provider ?? "cloudflare") || mode !== (current.certificate_mode ?? "http01") || resolvers !== (current.dns_resolvers ?? []).join(", ") || delay !== (current.dns_propagation_delay_seconds?.toString() ?? "") || timeout !== (current.dns_propagation_timeout_seconds?.toString() ?? "");
  async function perform(step: Step, action: () => Promise<Partial<Domain>>, message: string) {
    if (busy) return;
    setBusy(true); setFeedback(previous => ({ ...previous, [step]: {} }));
    try { const value = await action(); setCurrent(previous => ({ ...previous, ...value })); onSaved(value); setFeedback(previous => ({ ...previous, [step]: { notice: message } })); return value; }
    catch (e) { setFeedback(previous => ({ ...previous, [step]: { error: errorText(e) } })); } finally { setBusy(false); }
  }
  const result = (step: Step) => <><Notice error={feedback[step]?.error} />{feedback[step]?.notice && <p role="status" className="action-status">{feedback[step]?.notice}</p>}</>;
  const savingToken = mode === "cloudflare_dns" && (editingToken || provider !== (current.dns_provider ?? "cloudflare"));
  async function saveCertificate() {
    const value = savingToken
      ? await perform("certificate", () => request<Domain>(`${path}/${provider === "cloudflare" ? "cloudflare-credential" : "dns-credential"}`, { method: "PUT", body: JSON.stringify(provider === "cloudflare" ? { token: token.trim() } : provider === "alidns" ? { provider, access_key_id: keyId.trim(), access_key_secret: token.trim() } : { provider, secret_id: keyId.trim(), secret_key: token.trim() }) }, csrf), "已保存")
      : await perform("certificate", () => request<Domain>(path, { method: "PATCH", body: JSON.stringify({ certificate_mode: mode, dns_resolvers: current.dns_resolvers ?? [], dns_propagation_delay_seconds: current.dns_propagation_delay_seconds ?? null, dns_propagation_timeout_seconds: current.dns_propagation_timeout_seconds ?? null }) }, csrf), "已保存");
    if (value && savingToken) { setToken(""); setKeyId(""); setEditingToken(false); setMode("cloudflare_dns"); }
  }
  return <Modal title={`配置 ${domain.domain}`} full dirty={dirty} busy={busy} onClose={onClose}>{close => <div className="modal-form">
    <div className="modal-body domain-settings">
      {showDnsReminder && <p className="helper domain-dns-reminder">请为 {domain.domain} 和 *.{domain.domain} 添加 DNS 解析，指向服务器公网 IP。</p>}
      <section aria-label="证书配置"><form id="certificate-settings" onSubmit={async e => { e.preventDefault(); await saveCertificate(); }}><fieldset disabled={busy}><label>证书方式<select value={mode} onChange={e => { setMode(e.target.value as typeof mode); setFeedback(previous => ({ ...previous, certificate: {} })); }}><option value="http01">HTTP</option><option value="cloudflare_dns">DNS 验证</option></select></label><p className="helper">{mode === "http01" ? "按主机名签发，需开放公网 80、443。" : "签发根域名和泛域名证书。"}</p>
      {mode === "cloudflare_dns" && <label>DNS 服务商<select aria-label="DNS 服务商" value={provider} onChange={e => { setProvider(e.target.value as typeof provider); setToken(""); setKeyId(""); setEditingToken(true); }}><option value="cloudflare">Cloudflare</option><option value="alidns">阿里云 DNS</option><option value="tencentcloud">腾讯云 DNSPod</option></select></label>}
      {mode === "cloudflare_dns" && (current.credential_configured && !editingToken ? <div className="credential-summary"><span>{providerName} · 已配置</span><button type="button" className="text-button" onClick={() => setEditingToken(true)}>更新</button></div> : <>{provider !== "cloudflare" && <label>{provider === "alidns" ? "AccessKeyId" : "SecretId"}<input autoComplete="off" autoCapitalize="none" spellCheck={false} value={keyId} onChange={e => setKeyId(e.target.value)} required /></label>}<label>{provider === "cloudflare" ? "API Token" : provider === "alidns" ? "AccessKeySecret" : "SecretKey"}<input type="password" autoComplete="off" autoCapitalize="none" spellCheck={false} value={token} onChange={e => setToken(e.target.value)} placeholder={provider === "cloudflare" ? "输入 Token" : "输入密钥"} required /></label><details className="recovery-help"><summary>凭据说明</summary><p>需读取区域和编辑记录权限。凭据仅存于 Server。</p></details>{current.credential_configured && <button type="button" className="text-button" onClick={() => { setToken(""); setKeyId(""); setProvider(current.dns_provider ?? "cloudflare"); setEditingToken(false); }}>取消更新</button>}</>)}
      </fieldset>{result("certificate")}</form></section>
      {mode === "http01" && current.verification_status !== "verified" && <section aria-label="域名归属"><p className="helper">添加以下 TXT 记录以验证域名归属。</p>{current.verification_record && <dl><dt>TXT 名称</dt><dd className="service-detail-address"><code>{current.verification_record.name}</code><CopyButton iconOnly label="复制 TXT 名称" value={current.verification_record.name} /></dd><dt>TXT 内容</dt><dd className="service-detail-address"><code>{current.verification_record.value}</code><CopyButton iconOnly label="复制 TXT 内容" value={current.verification_record.value} /></dd></dl>}<button className="secondary-button" disabled={busy} onClick={() => void perform("verification", () => request<Domain>(`${path}/verification`, { method: "POST" }, csrf), "已验证")}>验证</button>{result("verification")}</section>}
      {mode === "http01" && current.verification_status === "verified" && result("verification")}
      {mode === "cloudflare_dns" && <section><details><summary>高级设置</summary><form onSubmit={async e => { e.preventDefault(); const value = await perform("advanced", () => request<Domain>(path, { method: "PATCH", body: JSON.stringify({ certificate_mode: current.certificate_mode ?? "http01", dns_resolvers: resolvers.split(/[\s,]+/).filter(Boolean), dns_propagation_delay_seconds: delay === "" ? null : Number(delay), dns_propagation_timeout_seconds: timeout === "" ? null : Number(timeout) }) }, csrf), "已保存"); if (value) { setResolvers((value.dns_resolvers ?? []).join(", ")); setDelay(value.dns_propagation_delay_seconds?.toString() ?? ""); setTimeout(value.dns_propagation_timeout_seconds?.toString() ?? ""); } }}><fieldset disabled={busy}><div className="management-fields"><label>DNS 解析器<input value={resolvers} onChange={e => setResolvers(e.target.value)} placeholder="默认" autoCapitalize="none" spellCheck={false} /></label><p className="helper">留空使用 Caddy 默认。最多 4 个，以逗号或空格分隔。</p><label>传播等待（秒）<input type="number" min={0} max={120} step={1} value={delay} onChange={e => setDelay(e.target.value)} placeholder="默认" /></label><label>传播超时（秒）<input type="number" min={1} max={600} step={1} value={timeout} onChange={e => setTimeout(e.target.value)} placeholder="默认" /></label></div></fieldset>{result("advanced")}<button className="secondary-button" disabled={busy}>保存</button></form></details></section>}
      <button className="danger-button danger-zone" disabled={busy} onClick={onDelete}>删除</button>
    </div><footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel" onClick={close} disabled={busy}>取消</button><button form="certificate-settings" className="primary-button" disabled={busy || (savingToken && (!token.trim() || (provider !== "cloudflare" && !keyId.trim())))}>{busy ? "处理中…" : savingToken ? "验证并启用" : "保存"}</button></footer>
  </div>}</Modal>;
}
