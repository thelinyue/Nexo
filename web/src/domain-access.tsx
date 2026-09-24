import { useState } from "react";
import { Loading, Modal, Notice, dateText, errorText, useApi, useResource } from "./ui";
import type { Domain, DomainAccessStatus } from "./ui";

function summary(result?: DomainAccessStatus | null) {
  if (!result?.checked_at || !result.records.length) return { label: "解析待检查", attention: false };
  if (result.records.some(record => record.status === "unresolved")) return { label: "解析异常", attention: true };
  if (result.records.some(record => record.matches_server === false)) return { label: "解析需核对", attention: true };
  if (result.records.some(record => record.status !== "resolved")) return { label: "解析待检查", attention: false };
  return { label: "DNS 已解析", attention: false };
}

/** DNS、内部运行和公网访问分别表述；没有外部探测时不会显示“公网可用”。 */
export function DomainAccess({ domain, active, csrf }: { domain: Domain; active: boolean; csrf?: string | null }) {
  const request = useApi();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const endpoint = `/api/v1/public-domains/${encodeURIComponent(domain.id)}/access`;
  // 弹层只读取后台快照，不触发 DNS 查询；查看详情时也更新结果，失败保留最后一次成功读取的数据。
  const resource = useResource(() => request<DomainAccessStatus>(endpoint), active && open, true, true);
  const result = open ? resource.data ?? domain.access : domain.access;
  const status = summary(result);
  return <><button className={`text-button domain-access-button${status.attention ? " danger-text" : ""}`} aria-label={`域名解析 ${domain.domain}：${status.label}`} aria-haspopup="dialog" onClick={() => setOpen(true)}>{status.label}</button>
    {open && active && <Modal title="域名解析" onClose={() => setOpen(false)}><div className="modal-body domain-access">
      <strong>{domain.domain}</strong>
      <Notice error={resource.error} onRetry={() => void resource.reload()} />{resource.busy && !resource.data && <Loading />}
      {result?.records.map(record => <section className="domain-certificate" key={record.hostname} aria-label={`DNS ${record.hostname}`}>
        <strong>{record.hostname}</strong><p>{record.status === "resolved" ? "DNS 已解析" : record.status === "unresolved" ? "DNS 未解析" : "DNS 待检查"}</p>
        {!!record.addresses.length && <code>{record.addresses.join(" · ")}</code>}
        {record.matches_server === true && <p className="helper">与 Server 地址一致。</p>}
        {record.matches_server === false && <p className="form-error">部分解析地址与 Server 不同。直连时请修正记录；使用 CDN 时请核对回源配置。</p>}
        {record.error && <p className="form-error">{record.error}</p>}
      </section>)}
      <Notice error={error} /><button className="text-button" disabled={busy} onClick={async () => { setBusy(true); setError(null); try { resource.setData(await request<DomainAccessStatus>(endpoint, { method: "POST" }, csrf)); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>{busy ? "检查中…" : "重新检查"}</button>
      {result?.checked_at && <p className="helper">最近检查：{dateText(result.checked_at)}</p>}
      {result?.next_retry_at ? <p className="helper">下次自动重试：{dateText(result.next_retry_at)}。剩余 {result.retries_remaining} 次。</p> : result?.checked_at && result.retries_remaining === 0 && result.records.some(record => record.status === "unresolved") ? <p className="helper">自动重试已结束。请核对 DNS 配置，修改后可点“重新检查”。</p> : null}
      <details className="recovery-help"><summary>检查说明</summary>
        <p>新增域名或服务域名变化时自动检查，解析成功后停止自动查询。未解析时每 5 分钟重试，最多 3 次。</p>
        <p>检查使用 Server 的 DNS 解析器。DNS 服务商侧的修改不会自动触发检查，修改后可点“重新检查”。检查结果不影响服务转发。</p>
      </details>
      <details className="recovery-help"><summary>如何配置解析</summary>
        <p>在 DNS 服务商添加 <strong>@</strong> 和 <strong>*</strong> 记录，分别覆盖 {domain.domain} 和服务子域名。已有单独的子域名记录时，也需要核对其指向。</p>
        <p>IPv4 使用 A 记录，IPv6 使用 AAAA 记录，指向 <strong>{result?.expected_addresses.length ? result.expected_addresses.join("、") : "Server 的公网 IP"}</strong>。没有可达的 IPv6 时不要添加 AAAA 记录。</p>
        <p className="helper">用户访问需要放行 80/443。Cloudflare 的 DNS 验证凭据只用于申请证书，不会自动创建访问解析；启用代理时还需核对回源地址与端口。</p>
      </details>
    </div></Modal>}
  </>;
}
