import { useEffect, useState } from "react";
import { Loading, Modal, Notice, errorText, request } from "./ui";

type Settings = { public_url: string; trusted_proxies: string[]; public_ips: string[] };
type Fields = { public_url: string; trusted_proxies: string; public_ips: string };
const fields = (value: Settings): Fields => ({ public_url: value.public_url, trusted_proxies: value.trusted_proxies.join(", "), public_ips: value.public_ips.join(", ") });
const addresses = (value: string) => value.split(/[\s,，]+/).filter(Boolean);

/** 平台设置不跟随代管空间；编辑失败保留输入，关闭和离开沿用弹窗的未保存保护。 */
export function ServerSettings({ csrf, onClose }: { csrf?: string | null; onClose: () => void }) {
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
      if (!cancelled) { setSaved(fields(result)); setValue(fields(result)); }
    }).catch(e => { if (!cancelled) setError(errorText(e)); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [retry]);
  function update(key: keyof Fields, text: string) {
    setValue(previous => previous && ({ ...previous, [key]: text })); setError(null); setMessage(null);
  }
  return <Modal title="服务器设置" full dirty={dirty} busy={busy} onClose={onClose}>
    <form className="modal-form" onSubmit={async event => {
      event.preventDefault(); if (!value || busy) return;
      setBusy(true); setError(null); setMessage(null);
      try {
        const result = await request<Settings>("/api/v1/admin/server-settings", { method: "PUT", body: JSON.stringify({ public_url: value.public_url.trim(), trusted_proxies: addresses(value.trusted_proxies), public_ips: addresses(value.public_ips) }) }, csrf);
        setSaved(fields(result)); setValue(fields(result)); setMessage("已保存并立即生效，重启后保留。公网 IP 更新后，可在域名页面重新检查解析。");
      } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
    }}>
      <div className="modal-body">
        {loading && <Loading />}
        {value && <fieldset disabled={busy}>
          <label htmlFor="server-public-url">管理地址<input id="server-public-url" type="url" value={value.public_url} onChange={e => update("public_url", e.target.value)} placeholder="https://nexo.example.com" autoCapitalize="none" spellCheck={false} aria-describedby="server-public-url-help" /></label>
          <p className="helper" id="server-public-url-help">可选，固定管理入口的来源；填写 HTTPS 地址后，API 只接受经可信代理转发的 HTTPS 请求。留空按当前访问地址校验。不自动创建反向代理或申请证书。</p>
          <label htmlFor="server-trusted-proxies">可信代理 IP<input id="server-trusted-proxies" value={value.trusted_proxies} onChange={e => update("trusted_proxies", e.target.value)} placeholder="127.0.0.1, ::1" autoCapitalize="none" spellCheck={false} aria-describedby="server-trusted-proxies-help" /></label>
          <p className="helper" id="server-trusted-proxies-help">填写直接连接 Server 的反向代理 IP，多个用逗号分隔，不支持 CIDR。留空不信任代理协议头；只填写由你控制的代理。</p>
          <label htmlFor="server-public-ips">公网 IP<input id="server-public-ips" value={value.public_ips} onChange={e => update("public_ips", e.target.value)} placeholder="203.0.113.10, 2001:db8::10" autoCapitalize="none" spellCheck={false} aria-describedby="server-public-ips-help" /></label>
          <p className="helper" id="server-public-ips-help">可选，用于核对域名 A/AAAA 解析结果，多个用逗号分隔。留空仅显示解析结果，不判断是否指向 Server；不会修改 DNS 或监听地址。</p>
          <details className="recovery-help"><summary>首次配置 HTTPS 或更换管理地址</summary><p>先配置 HTTPS 反向代理，保留原始 Host，并覆盖 X-Forwarded-Proto 为 https。在当前 HTTP 入口先保存可信代理 IP，管理地址留空；随后从 HTTPS 地址重新登录，再填写该管理地址并保存。</p><p>更换已有管理地址时，先从原入口清空管理地址并保存，再从新入口登录设置。保存时会检查当前连接，避免填写错误后无法继续管理。</p></details>
        </fieldset>}
        <Notice error={error} onRetry={!value && !loading ? () => setRetry(previous => previous + 1) : undefined} />
        {message && <p role="status" className="action-status">{message}</p>}
      </div>
      <footer className="modal-actions"><button className="primary-button" disabled={loading || busy || !value || !dirty}>{busy ? "保存中…" : "保存设置"}</button></footer>
    </form>
  </Modal>;
}
