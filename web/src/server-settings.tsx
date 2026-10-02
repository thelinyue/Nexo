import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ServerIdentityCard } from "./management";
import { Confirm, CopyButton, Loading, Notice, PageHeader, errorText, request, useResource } from "./ui";
import type { Auth } from "./ui";

type Entry = { domain_id: string; hostname: string };
type Settings = { management_entry: Entry | null; public_url: string; public_ips: string[]; relay_ipv4?: string | null; domains: { id: string; domain: string }[]; caddy_enabled: boolean; status: string; error: string | null };
type Fields = { enabled: boolean; domain_id: string; hostname: string; relay_ipv4: string };
const fields = (value: Settings): Fields => ({ enabled: Boolean(value.management_entry), domain_id: value.management_entry?.domain_id ?? (value.domains.length === 1 ? value.domains[0].id : ""), hostname: value.management_entry?.hostname ?? "nexo", relay_ipv4: value.relay_ipv4 ?? value.public_ips.find(ip => !ip.includes(":")) ?? "" });
const statusLabel: Record<string, string> = { disabled: "未开启", pending: "正在配置", certificate_pending: "等待证书", ready: "已配置", failed: "配置失败" };

/** 服务器配置独立于个人账号；期望配置与运行状态分开保存，轮询只更新状态。
 * 页面复用既有离页事件保护草稿和提交，隐藏后停止读取，切换屏幕不重建表单。
 */
export function ServerSettingsPage({ auth, active }: { auth: Auth; active: boolean }) {
  const [saved, setSaved] = useState<Fields | null>(null);
  const [value, setValue] = useState<Fields | null>(null);
  const [busy, setBusy] = useState(false); const submitting = useRef(false);
  const [error, setError] = useState<string | null>(null); const [message, setMessage] = useState<string | null>(null);
  const [discard, setDiscard] = useState(false); const pendingNavigation = useRef<(() => void) | null>(null);
  const resource = useResource(() => request<Settings>("/api/v1/admin/server-settings"), active && !busy);
  const settings = resource.data;
  const dirty = Boolean(saved && value && JSON.stringify(value) !== JSON.stringify(saved));
  useEffect(() => {
    if (settings && !saved) { setSaved(fields(settings)); setValue(fields(settings)); }
  }, [settings, saved]);
  // 同步更新离页保护，保存成功后的第一次导航也能立即放行。
  useLayoutEffect(() => {
    if (!active || (!dirty && !busy)) return;
    const leave = (event: Event) => {
      event.preventDefault();
      // 页面接管离页，避免后续弹窗监听把已经打开的草稿确认关闭。
      event.stopImmediatePropagation();
      if (busy || submitting.current) return;
      pendingNavigation.current ??= (event as CustomEvent<{ resume: () => void }>).detail.resume;
      setDiscard(true);
    };
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("nexo:route-change", leave); window.addEventListener("beforeunload", unload);
    return () => { window.removeEventListener("nexo:route-change", leave); window.removeEventListener("beforeunload", unload); };
  }, [active, dirty, busy]);
  function update<K extends keyof Fields>(key: K, text: Fields[K]) {
    setValue(previous => previous && ({ ...previous, [key]: text })); setError(null); setMessage(null);
  }
  const selected = settings?.domains.find(domain => domain.id === value?.domain_id);
  const preview = value?.enabled && selected && value.hostname.trim() ? `https://${value.hostname.trim().toLowerCase()}.${selected.domain}` : "";
  return <div className="server-settings-page">
    <PageHeader title="服务器设置" showTitle />
    {auth.local_http_warning && <p className="notice" role="status">当前连接未加密，公网访问请使用 HTTPS。</p>}
    <div className="server-settings-layout"><form className="panel server-settings-form" aria-label="服务器配置" onSubmit={async event => {
      event.preventDefault(); if (!value || !saved || !settings || submitting.current || !dirty) return;
      submitting.current = true;
      setBusy(true); setError(null); setMessage(null);
      try {
        const result = await request<Settings>("/api/v1/admin/server-settings", { method: "PUT", body: JSON.stringify({ management_entry: value.enabled ? { domain_id: value.domain_id, hostname: value.hostname.trim() } : null, public_ips: settings.public_ips, ...(value.relay_ipv4 !== saved.relay_ipv4 ? { relay_ipv4: value.relay_ipv4.trim() } : {}) }) }, auth.csrf_token);
        resource.setData(result); setSaved(fields(result)); setValue(fields(result)); setMessage("设置已保存。");
      } catch (e) { setError(errorText(e)); } finally { submitting.current = false; setBusy(false); }
    }}>
      <div className="server-settings-body">
        <h2>网络与访问</h2>
        <Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} />
        {!settings && resource.busy && <Loading />}
        {value && settings && <fieldset disabled={busy}>
          <label>公网 IPv4<input value={value.relay_ipv4} onChange={e => update("relay_ipv4", e.target.value)} placeholder="填写 VPS 的公网 IPv4" inputMode="decimal" autoComplete="off" spellCheck={false} aria-describedby="relay-ipv4-help" /></label>
          <p className="helper" id="relay-ipv4-help">留空沿用部署配置。</p>
          <div className="server-entry-toggle"><label className="service-field service-toggle-field"><span>HTTPS 管理入口</span><span className="service-switch"><input type="checkbox" role="switch" checked={value.enabled} onChange={e => update("enabled", e.target.checked)} disabled={!settings.caddy_enabled && !value.enabled} /><span className="service-switch-track" aria-hidden="true" /></span></label></div>
          {!settings.caddy_enabled && <p className="notice">启用 Caddy 后可配置 HTTPS。</p>}
          {value.enabled && <>
            {(settings.domains.length > 1 || settings.domains.length === 1 && !selected) && <label>域名<select value={value.domain_id} onChange={e => update("domain_id", e.target.value)} required><option value="">选择域名</option>{settings.domains.map(domain => <option key={domain.id} value={domain.id}>{domain.domain}</option>)}</select></label>}
            {!settings.domains.length && <p className="helper">先在<a className="text-link" href="#/domains">域名管理</a>验证域名并开启 HTTPS。</p>}
            <label>子域名<input value={value.hostname} onChange={e => update("hostname", e.target.value)} placeholder="nexo" autoCapitalize="none" spellCheck={false} pattern="[a-zA-Z0-9](([a-zA-Z0-9]|-){0,61}[a-zA-Z0-9])?" required /></label>
            {preview && <div className="service-detail-address"><code>{preview}</code><CopyButton value={preview} iconOnly label="复制管理地址" /></div>}
            <p className="helper">子域名需解析到服务器；原 IP 入口保留。</p>
          </>}
          {settings.management_entry && <div role="status"><p>{statusLabel[settings.status] ?? "正在检查"}</p>{settings.error && <p className="form-error">{settings.error}</p>}{settings.status === "ready" && <a className="text-button" href={settings.public_url} target="_blank" rel="noopener noreferrer">打开管理入口</a>}</div>}
        </fieldset>}
        <Notice error={error} />
        {message && <p role="status" className="action-status">{message}</p>}
      </div>
      <footer className="server-settings-actions"><button className="primary-button" disabled={busy || !value || !dirty || (value.enabled && (!settings?.caddy_enabled || !selected))}>{busy ? "保存中…" : "保存设置"}</button></footer>
    </form>
    <ServerIdentityCard active={active} /></div>
    {discard && active && <Confirm title="放弃未保存的修改？" description="离开后，本次填写的服务器配置将丢失。" label="放弃修改" onClose={() => { pendingNavigation.current = null; setDiscard(false); }} onConfirm={async () => { const resume = pendingNavigation.current; pendingNavigation.current = null; setValue(saved); setError(null); setMessage(null); setDiscard(false); window.setTimeout(() => resume?.(), 0); }} />}
  </div>;
}
