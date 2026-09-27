import { useEffect, useState } from "react";
import { CopyButton, Loading, Modal, Notice, errorText, request } from "./ui";

type Entry = { domain_id: string; hostname: string };
type Settings = { management_entry: Entry | null; public_url: string; public_ips: string[]; domains: { id: string; domain: string }[]; caddy_enabled: boolean; status: string; error: string | null };
type Fields = { enabled: boolean; domain_id: string; hostname: string };
const fields = (value: Settings): Fields => ({ enabled: Boolean(value.management_entry), domain_id: value.management_entry?.domain_id ?? (value.domains.length === 1 ? value.domains[0].id : ""), hostname: value.management_entry?.hostname ?? "nexo" });
const statusLabel: Record<string, string> = { disabled: "未开启", pending: "正在配置", certificate_pending: "等待证书", ready: "已配置", failed: "配置失败" };

/** 表单只保存期望配置；轮询运行状态不覆盖草稿，证书签发期间仍可关闭或修正入口。 */
export function ServerSettings({ csrf, onClose }: { csrf?: string | null; onClose: () => void }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState<Fields | null>(null);
  const [value, setValue] = useState<Fields | null>(null);
  const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null); const [message, setMessage] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const dirty = JSON.stringify(value) !== JSON.stringify(saved);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(null);
    request<Settings>("/api/v1/admin/server-settings").then(result => {
      if (!cancelled) { setSettings(result); setSaved(fields(result)); setValue(fields(result)); }
    }).catch(e => { if (!cancelled) setError(errorText(e)); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [retry]);
  useEffect(() => {
    if (loading || busy || !settings) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void request<Settings>("/api/v1/admin/server-settings").then(result => { if (!cancelled) setSettings(result); }).catch(e => { if (!cancelled) setError(errorText(e)); });
    }, 5000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [loading, busy, Boolean(settings)]);
  function update<K extends keyof Fields>(key: K, text: Fields[K]) {
    setValue(previous => previous && ({ ...previous, [key]: text })); setError(null); setMessage(null);
  }
  const selected = settings?.domains.find(domain => domain.id === value?.domain_id);
  const preview = value?.enabled && selected && value.hostname.trim() ? `https://${value.hostname.trim().toLowerCase()}.${selected.domain}` : "";
  return <Modal title="服务器设置" full dirty={dirty} busy={busy} onClose={onClose}>{close =>
    <form className="modal-form" onSubmit={async event => {
      event.preventDefault(); if (!value || busy) return;
      setBusy(true); setError(null); setMessage(null);
      try {
        const result = await request<Settings>("/api/v1/admin/server-settings", { method: "PUT", body: JSON.stringify({ management_entry: value.enabled ? { domain_id: value.domain_id, hostname: value.hostname.trim() } : null, public_ips: settings?.public_ips ?? [] }) }, csrf);
        setSettings(result); setSaved(fields(result)); setValue(fields(result)); setMessage("设置已保存。");
      } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
    }}>
      <div className="modal-body">
        {loading && <Loading />}
        {value && settings && <fieldset disabled={busy}>
          <div className="service-field-group"><label className="service-field service-toggle-field"><span>HTTPS 管理入口</span><span className="service-switch"><input type="checkbox" role="switch" checked={value.enabled} onChange={e => update("enabled", e.target.checked)} disabled={!settings.caddy_enabled && !value.enabled} /><span className="service-switch-track" aria-hidden="true" /></span></label></div>
          {!settings.caddy_enabled && <p className="notice">内置 Caddy 未启用，请在服务器启动配置中启用。</p>}
          {value.enabled && <>
            <label>域名<select value={value.domain_id} onChange={e => update("domain_id", e.target.value)} required><option value="">选择域名</option>{settings.domains.map(domain => <option key={domain.id} value={domain.id}>{domain.domain}</option>)}</select></label>
            {!settings.domains.length && <p className="helper">请先关闭此窗口，到域名管理验证域名并开启 HTTPS。</p>}
            <label>子域名<input value={value.hostname} onChange={e => update("hostname", e.target.value)} placeholder="nexo" autoCapitalize="none" spellCheck={false} pattern="[a-zA-Z0-9](([a-zA-Z0-9]|-){0,61}[a-zA-Z0-9])?" required /></label>
            {preview && <div className="service-detail-address"><code>{preview}</code><CopyButton value={preview} iconOnly label="复制管理地址" /></div>}
            <p className="helper">已启用强制 HTTPS，证书沿用域名配置。请将此子域名解析到服务器。</p>
          </>}
          <p className="helper">原 IP 管理入口继续可用。</p>
          {settings.management_entry && <div role="status"><p>{statusLabel[settings.status] ?? "正在检查"}</p>{settings.error && <p className="form-error">{settings.error}</p>}{settings.status === "ready" && <a className="text-button" href={settings.public_url} target="_blank" rel="noopener noreferrer">打开管理入口</a>}</div>}
        </fieldset>}
        <Notice error={error} onRetry={!value && !loading ? () => setRetry(previous => previous + 1) : undefined} />
        {message && <p role="status" className="action-status">{message}</p>}
      </div>
      <footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={loading || busy || !value || !dirty || (value.enabled && (!settings?.caddy_enabled || !selected))}>{busy ? "保存中…" : "保存设置"}</button></footer>
    </form>}
  </Modal>;
}
