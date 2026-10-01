import { useEffect, useRef, useState } from "react";
import { Globe } from "./icons";
import { Notice, errorText, useApi } from "./ui";
import type { Domain, DomainDnsPreview, DomainDnsResult } from "./ui";

/** 一次操作一次预览与确认；保存凭据或关闭窗口均不会触发解析写入。 */
export function DomainDnsRecords({ domain, csrf, busy, disabled, onBusyChange }: { domain: Domain; csrf?: string | null; busy: boolean; disabled: boolean; onBusyChange: (value: boolean) => void }) {
  const request = useApi(); const pending = useRef(false);
  const [preview, setPreview] = useState<DomainDnsPreview | null>(null);
  const [result, setResult] = useState<DomainDnsResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<"preview" | "write" | null>(null);
  const path = `/api/v1/public-domains/${encodeURIComponent(domain.id)}/dns-records`;
  const takeover = preview?.hosts.some(host => host.action === "takeover");
  // 开始更新凭据即作废本地预览；新凭据保存后必须重新读取记录。
  useEffect(() => { setPreview(null); setResult(null); setError(null); }, [disabled, domain.dns_provider]);
  async function perform(write = false) {
    if (busy || pending.current || disabled) return;
    pending.current = true; onBusyChange(true); setPhase(write ? "write" : "preview"); setError(null);
    try {
      if (write && preview) {
        const value = await request<DomainDnsResult>(path, { method: "POST", body: JSON.stringify({ preview, confirm_takeover: Boolean(takeover) }) }, csrf);
        setResult(value); setPreview(null);
      } else { setPreview(await request<DomainDnsPreview>(path)); setResult(null); }
    } catch (e) { setError(errorText(e)); setPreview(null); }
    finally { pending.current = false; setPhase(null); onBusyChange(false); }
  }
  return <section className="domain-dns-records" aria-label="DNS 解析">
    <div className="domain-dns-heading"><h3>DNS 解析</h3><button type="button" className="secondary-button" disabled={busy || disabled || !domain.credential_configured} onClick={() => void perform()}><Globe size={17} />{phase === "preview" ? "读取中…" : "配置解析"}</button></div>
    {!domain.credential_configured && <p className="helper">请先验证并保存 DNS 凭据。</p>}
    {disabled && domain.credential_configured && <p className="helper">请先保存或取消凭据更新，再配置解析。</p>}
    <Notice error={error} />
    {preview && <div className="domain-dns-preview" aria-label="解析预览">
      <p className="domain-dns-target">目标 IPv4 <code>{preview.ipv4}</code></p>
      <ul className="domain-dns-hosts">{preview.hosts.map(host => <li key={host.hostname}>
        <div className="domain-dns-host-heading"><strong>{host.hostname}</strong><span>{host.action === "create" ? "新增 A" : host.action === "reuse" ? "保持不变" : "接管解析"}</span></div>
        {host.existing.map(record => <p className="domain-dns-record" key={record.id}><span>{record.kind}</span><code>{record.value}</code>{record.proxied && <span>代理已开启</span>}</p>)}
        {host.action === "takeover" && <p className="helper">合并现有 A、替换 CNAME，使用直接解析。</p>}
        {host.existing.some(record => !["A", "CNAME"].includes(record.kind)) && <p className="helper">其他类型记录保留。</p>}
        {host.blocked && <Notice error={host.blocked} />}
      </li>)}</ul>
      {takeover && <p className="domain-dns-warning">接管会将以上主机名的访问解析改为目标 IPv4，可能改变原有网站入口。</p>}
      <div className="domain-dns-actions"><button type="button" className="secondary-button" disabled={busy} onClick={() => setPreview(null)}>取消</button><button type="button" className={takeover ? "danger-button" : "primary-button"} disabled={busy || disabled || preview.hosts.some(host => host.blocked)} onClick={() => void perform(true)}>{phase === "write" ? "写入中…" : takeover ? "确认接管" : "确认写入"}</button></div>
    </div>}
    {result && <div className="domain-dns-result" aria-label="解析结果"><ul className="domain-dns-hosts">{result.hosts.map(host => <li key={host.hostname}>
      <div className="domain-dns-host-heading"><strong>{host.hostname}</strong><span role="status">{host.status === "written" ? "已写入" : host.status === "unchanged" ? "记录一致" : "写入失败"}</span></div>
      <Notice error={host.error} />
    </li>)}</ul><p className="helper">DNS 传播及公网访问尚未验证。</p></div>}
  </section>;
}
