import { PageNavigationContext, useResourceDeletions } from "./navigation";
import { useContext, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { DeviceRecovery } from "./recovery";
import { AgentEnrollment } from "./agent-enrollment";
import { ServerSettings } from "./server-settings";
import { DomainSettings } from "./domain-settings";
import { ChevronRight, Settings, Trash2, Eye, EyeOff, KeyRound, Server, ShieldCheck, Users, X } from "lucide-react";
import { Confirm, CopyButton, EnrollmentDevice, CreateButton, DetailField, Empty, Loading, Modal, Notice, PageHeader, RowLink, Status, UserAvatar, dateText, errorText, request, useApi, useResource } from "./ui";
import type { Auth, Device, Domain, DomainEvent, Enrollment, IdentityCertificate, Session, TransportIdentity, Tunnel } from "./ui";

function identityCertificateLabel(certificate?: IdentityCertificate) {
  return ({ valid: "证书有效", expiring: "证书即将到期", retry_wait: "证书续签待重试", expired: "证书已过期", unknown: "尚无证书记录" } as Record<string,string>)[certificate?.status ?? "unknown"] ?? "证书状态待确认";
}
/** 证书提醒与在线状态分开；离线设备也能显示最后记录的到期时间。 */
function IdentityCertificateDetails({ certificate, offline = false, server = false }: { certificate?: IdentityCertificate; offline?: boolean; server?: boolean }) {
  const hint = server ? "到期前 30 天自动续签；失败会重试，现有连接继续运行。" : certificate?.status === "expired" ? "证书已过期，请联系管理员恢复设备身份。" : offline && ["expiring", "retry_wait"].includes(certificate?.status ?? "") ? "Agent 上线后会自动续签，请在证书到期前恢复连接。" : "到期前 30 天自动续签；失败会重试，设备与服务绑定保持不变。";
  return <><dl><DetailField label="证书状态">{identityCertificateLabel(certificate)}</DetailField><DetailField label="到期时间">{dateText(certificate?.expires_at)}</DetailField>{certificate?.renew_after && <DetailField label="提前续签">{dateText(certificate.renew_after)} 起</DetailField>}{certificate?.next_retry_at && <DetailField label="下次重试">{dateText(certificate.next_retry_at)}</DetailField>}</dl>{certificate?.error && <p className="form-error" role="status">{certificate.error}</p>}<p className="helper">{hint}</p></>;
}

function ServerIdentityCard({ active }: { active: boolean }) {
  const resource = useResource(() => request<TransportIdentity>("/api/v1/transport-identity"), active);
  const identity = resource.data;
  return <section className="panel detail-panel" aria-label="服务端内部证书"><details className="domain-diagnostics"><summary><span>服务端身份 · {identity ? identityCertificateLabel(identity.server) : resource.error ? "读取失败" : "读取中"}</span><ChevronRight size={17} /></summary><div className="domain-diagnostics-body"><Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} />{identity && <><IdentityCertificateDetails certificate={identity.server} server /><p className="helper">内部 CA 到期：{dateText(identity.ca_expires_at)}。公网域名证书由 Caddy 单独管理。</p></>}</div></details>{resource.error && <p className="form-error">无法读取内部证书状态，展开后重试。</p>}{identity && ["expiring", "retry_wait", "expired"].includes(identity.server.status) && <p className="form-error" role="status">服务端{identityCertificateLabel(identity.server)}，展开查看。</p>}{identity?.ca_needs_attention && <p className="form-error" role="status">内部 CA 需维护，请在到期前安排信任根更换。</p>}</section>;
}

export function AgentsPage({ route, active, csrf, back }: { route: string; active: boolean; csrf?: string | null; back: string }) {
  const navigation = useContext(PageNavigationContext);
  const request = useApi();
  const resource = useResource(async () => { const [devices, enrollments, tunnels] = await Promise.all([request<Device[]>("/api/v1/devices"), request<Enrollment[]>("/api/v1/enrollments"), request<Tunnel[]>("/api/v1/tunnels")]); return { devices, enrollments, tunnels }; }, active);
  useResourceDeletions(routes => { if (routes.some(route => route.startsWith("#/agents/"))) resource.setData(previous => previous && ({ ...previous, devices: previous.devices.filter(item => !routes.includes(`#/agents/${encodeURIComponent(item.id)}`)) })); });
  const [enrolling, setEnrolling] = useState(false); const [approveId, setApproveId] = useState<string | null>(null); const [deleting, setDeleting] = useState<Device | null>(null);
  const [recovering, setRecovering] = useState<Device | null>(null); const [cancelInvite, setCancelInvite] = useState<Enrollment | null>(null);
  const detailId = route.startsWith("#/agents/") ? route.slice("#/agents/".length) : null;
  const data = resource.data; const detail = data?.devices.find(item => encodeURIComponent(item.id) === detailId);
  const pending = data?.enrollments.filter(item => ["awaiting_agent", "awaiting_approval"].includes(item.status)) ?? [];
  const approval = data?.enrollments.find(item => item.id === approveId);
  const recoveryTarget = data?.devices.find(item => item.id === approval?.device_id);
  return <>
    <PageHeader title={detailId ? detail?.name ?? "设备详情" : "设备"} back={detailId ? back : undefined} action={!detailId && Boolean(data && (data.devices.length || pending.length)) && <CreateButton label="Agent" onClick={() => setEnrolling(true)} />} />
    <Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} />{!data && resource.busy && <Loading />}
    {data && (detailId ? detail ? <>
      <section className="panel detail-panel"><div className="detail-heading"><h2>{detail.name}</h2><Status kind="agent" value={detail.status} /></div>{detail.status !== "online" && <div className="notice"><p>Agent 离线，关联服务暂时无法转发。</p><p>最近连接：{dateText(detail.last_seen_at)} · {identityCertificateLabel(detail.certificate)}</p><p className="helper">请先检查主机上的 Agent 是否运行及能否连接 Server；身份过期或损坏时再恢复身份。</p></div>}</section>
      <h2 className="section-title">关联服务 · {detail.tunnel_count}</h2>
      <section className="panel agent-services">{data.tunnels.filter(item => item.device_id === detail.id).map(item => <RowLink key={item.id} href={`#/services/${encodeURIComponent(item.id)}`} title={item.name} detail={`${item.protocol.toUpperCase()} · ${item.public_address ?? "等待配置"}`} />)}{!data.tunnels.some(item => item.device_id === detail.id) && <p className="panel-note">暂无关联服务</p>}</section>
      <section className="panel detail-panel"><details className="domain-diagnostics" key={detail.id}><summary><span>设备信息</span><ChevronRight size={17} /></summary><div className="domain-diagnostics-body"><dl><DetailField label="设备识别码"><span className="device-id">{detail.id}</span><CopyButton value={detail.id} label="复制设备识别码" /></DetailField><DetailField label="系统">{detail.os ?? "未知系统"}{detail.architecture ? ` · ${detail.architecture}` : ""}</DetailField><DetailField label="Agent 版本">{detail.agent_version ?? "等待首次连接"}</DetailField><DetailField label="最近连接">{dateText(detail.last_seen_at)}</DetailField></dl></div></details></section>
      <section className="panel detail-panel" aria-label="设备内部证书"><details className="domain-diagnostics" key={`${detail.id}:${detail.certificate?.status}`} open={Boolean(detail.certificate?.error) || ["expiring", "retry_wait", "expired"].includes(detail.certificate?.status ?? "")}><summary><span>设备证书 · {identityCertificateLabel(detail.certificate)}</span><ChevronRight size={17} /></summary><div className="domain-diagnostics-body"><IdentityCertificateDetails certificate={detail.certificate} offline={detail.status !== "online"} /><button className="secondary-button" onClick={() => setRecovering(detail)}>恢复设备身份</button></div></details></section>
      <button className="danger-button danger-zone" onClick={() => setDeleting(detail)}>删除 Agent</button>
    </> : <Empty title="Agent 不存在" detail="该节点可能已被删除。"><a className="secondary-button" href="#/agents">返回 Agent 列表</a></Empty> : <>
      {pending.length > 0 && <section className="panel pending-panel"><h2 className="section-title">身份恢复申请 · {pending.length}</h2><p className="helper">等待连接 {pending.filter(item => item.status === "awaiting_agent").length} · 等待批准 {pending.filter(item => item.status === "awaiting_approval").length}</p>{pending.map(item => <div className="pending-row" key={item.id}><div><strong>{`恢复 ${data.devices.find(device => device.id === item.device_id)?.name ?? "原设备"} 的身份`}</strong>{item.status === "awaiting_approval" && <EnrollmentDevice item={item} />}<small>有效期至 {dateText(item.expires_at)}</small></div><div className="pending-actions">{item.status === "awaiting_approval" ? <button className="primary-button" onClick={() => setApproveId(item.id)}>批准</button> : <span className="helper">等待 Agent 提交</span>}<button className="text-button" aria-label={`撤销请求 ${item.id}`} onClick={() => setCancelInvite(item)}>撤销</button></div></div>)}</section>}
      {data.devices.length > 0 && <div className="list-caption"><span>{data.devices.length} 台 Agent</span><span>{data.devices.filter(item => item.status === "online").length} 台在线</span></div>}
      {!data.devices.length ? <Empty kind="agents" title={pending.length ? "等待 Agent 入网" : "还没有 Agent"} detail={pending.length ? "在目标设备启动 Agent，连接后在上方核对并批准。" : "部署 Agent，连接内网服务。"}>{!pending.length && <button className="primary-button" aria-label="添加 Agent" onClick={() => setEnrolling(true)}>添加 Agent</button>}</Empty> : <section className="panel agent-list">{data.devices.map(item => <a className="agent-row" key={item.id} href={`#/agents/${encodeURIComponent(item.id)}`}><span className="agent-avatar"><Server size={21} /></span><div className="agent-identity"><strong>{item.name}</strong><small>{item.tunnel_count} 个服务</small>{item.certificate && ["expiring", "retry_wait", "expired"].includes(item.certificate.status) && <small className="form-error">{identityCertificateLabel(item.certificate)}</small>}</div><Status kind="agent" value={item.status} /><ChevronRight size={18} /></a>)}</section>}
    </>)}
    {enrolling && active && <AgentEnrollment csrf={csrf} onClose={() => setEnrolling(false)} onCreated={() => resource.reload()} />}
    {recovering && active && <DeviceRecovery device={recovering} csrf={csrf} onClose={() => setRecovering(null)} onCreated={() => resource.reload()} />}
    {approveId && active && approval && <Confirm title={`批准恢复 ${recoveryTarget?.name ?? "原设备"} 的身份？`} description="原设备 ID、名称和服务绑定保留。批准后旧证书及旧连接立即失效，请确认申请来自你的 Agent。" label="批准恢复" onClose={() => setApproveId(null)} onConfirm={async () => { await request(`/api/v1/enrollments/${encodeURIComponent(approveId)}/approve`, { method: "POST", body: "{}" }, csrf); await resource.reload(); }} />}
    {cancelInvite && active && <Confirm title="撤销身份恢复请求？" description="凭证将立即失效。现有设备身份与服务不受影响。" label="撤销请求" onClose={() => setCancelInvite(null)} onConfirm={async () => { await request(`/api/v1/enrollments/${encodeURIComponent(cancelInvite.id)}`, { method: "DELETE" }, csrf); await resource.reload(); }} />}
    {deleting && active && <Confirm title={`删除 ${deleting.name}？`} description={`关联的 ${deleting.tunnel_count} 个服务将被停用，并解除 Agent 绑定。此操作无法撤销。`} label="删除 Agent" onClose={() => setDeleting(null)} onConfirm={async () => { await request(`/api/v1/devices/${encodeURIComponent(deleting.id)}`, { method: "DELETE" }, csrf); await resource.reload(); navigation?.removePages([`#/agents/${encodeURIComponent(deleting.id)}`], "#/agents"); }} />}
  </>;
}

/** 账号页只承载本人设置；管理员诊断仍使用本人的平台权限，不跟随代管空间。 */
export function ManagePage({ auth, active, onLogout, onExpired }: { auth: Auth; active: boolean; onLogout: () => Promise<void>; onExpired: () => void }) {
  const navigation = useContext(PageNavigationContext);
  const [serverSettings, setServerSettings] = useState(false);
  const [password, setPassword] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  return <div className="manage-page">
    <PageHeader title={navigation?.desktop ? "账号设置" : "我的"} />
    {auth.local_http_warning && <p className="notice" role="status">当前管理连接未使用 HTTPS，公网部署请通过 HTTPS 反向代理访问。</p>}
    <section className="panel account-summary"><UserAvatar role={auth.role} size={48} /><div><strong>{auth.username}</strong><small>{auth.role === "system_admin" ? "管理员" : "普通用户"}</small></div></section>
    <div className="management-sections"><section><h2 className="section-title">账号与安全</h2><section className="panel management-group"><button className="row-link" onClick={() => setPassword(true)}><KeyRound size={23} /><span><strong>修改密码</strong></span><ChevronRight size={19} /></button><RowLink href="#/settings/sessions" title="登录会话" icon={<ShieldCheck size={23} />} /></section>
    </section>{auth.role === "system_admin" && <section><h2 className="section-title">管理员功能</h2><section className="panel management-group"><RowLink href="#/users" title="用户管理" icon={<Users size={23} />} /><button className="row-link" onClick={() => setServerSettings(true)}><Server size={23} /><span><strong>服务器设置</strong></span><ChevronRight size={19} /></button></section><ServerIdentityCard active={active} /></section>}</div>
    <Notice error={error} /><button className="danger-button danger-zone" disabled={busy} onClick={async () => { setBusy(true); setError(null); try { await onLogout(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>{busy ? "退出中…" : "退出登录"}</button>
    {serverSettings && active && auth.role === "system_admin" && <ServerSettings csrf={auth.csrf_token} onClose={() => setServerSettings(false)} />}
    {password && active && <PasswordForm csrf={auth.csrf_token} onClose={() => setPassword(false)} onExpired={onExpired} />}
  </div>;
}

/** 浏览器先提示常见输入错误；服务端仍执行完整校验并负责最终规范化。 */
function normalizeDomain(value: string) {
  const raw = value.trim().replace(/\.$/, "");
  if (!raw || /[\s/:?#@%\\]/.test(raw)) return null;
  try {
    const domain = new URL(`https://${raw}`).hostname.toLowerCase();
    const labels = domain.split(".");
    if (domain.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1)!) || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
    return domain;
  } catch { return null; }
}

/** 粘贴网址时提供显式修正，不静默丢弃路径或端口，也不接受带账号信息的地址。 */
function domainFromUrl(value: string) {
  if (!/^https?:\/\//i.test(value.trim())) return null;
  try {
    const url = new URL(value.trim());
    return url.username || url.password ? null : normalizeDomain(url.hostname);
  } catch { return null; }
}

/** 单字段短表单：错误紧邻输入，底部保留提交按钮；清空和网址修正均不提交，失败保留原文。 */
function DomainForm({ onClose, onSave }: { onClose: () => void; onSave: (domain: string) => Promise<void> }) {
  const [value, setValue] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [invalid, setInvalid] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const normalized = normalizeDomain(value); const suggested = domainFromUrl(value);
  function updateValue(next: string) { setValue(next); setInvalid(false); setError(null); }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    const domain = normalizeDomain(value);
    if (!domain) { setError(value.trim() ? "请输入域名，不要包含网址前缀、端口或路径。" : "请输入域名。"); setInvalid(true); input.current?.focus(); return; }
    setBusy(true); setError(null); setInvalid(false);
    try { await onSave(domain); onClose(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <Modal title="添加域名" full dirty={Boolean(value.trim())} busy={busy} onClose={onClose}>{close =>
    <form className="modal-form domain-form" onSubmit={submit} noValidate>
      <div className="modal-body">
        <label className="sr-only" htmlFor="domain-input">域名</label>
        <div className="domain-input-control" data-invalid={invalid}>
          <input id="domain-input" name="domain" ref={input} value={value} onChange={e => updateValue(e.target.value)} placeholder="example.com" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} enterKeyHint="done" required disabled={busy} aria-invalid={invalid} aria-describedby={error ? "domain-input-error" : undefined} onKeyDown={e => { if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); e.currentTarget.blur(); } }} />
          {value && <button className="icon-button domain-clear" type="button" aria-label="清空域名" disabled={busy} onClick={() => { updateValue(""); input.current?.focus(); }}><X size={17} /></button>}
        </div>
        {error && <p className="form-error domain-input-error" id="domain-input-error" role="alert">{error}</p>}
        {suggested && <div className="domain-url-suggestion"><button type="button" className="text-button" disabled={busy} onClick={() => { updateValue(suggested); input.current?.focus(); }}><span>仅使用</span><code>{suggested}</code></button></div>}
        {normalized && normalized !== value.trim() && <p className="helper domain-normalized">将保存为 <code>{normalized}</code></p>}
      </div>
      <footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy}>{busy ? "添加中…" : "添加域名"}</button></footer>
    </form>}
  </Modal>;
}

/** 列表只概括证书与配置状态；续期失败不抹去仍然有效的证书日期。 */
function certificateSummary(item: Domain) {
  const runtime = item.runtime;
  const certificates = runtime?.certificates ?? [];
  const now = Date.now() / 1000;
  if (runtime?.config_status === "failed" || runtime?.config_error) return "配置失败";
  if (item.verification_status === "pending" || !item.https_enabled || runtime?.config_status === "disabled") return "待配置";
  if (certificates.some(cert => cert.status === "expired" || (cert.expires_at != null && cert.expires_at <= now))) return "已过期";
  const failed = certificates.filter(cert => cert.error || ["failed", "retry_wait"].includes(cert.status));
  if (failed.length) return failed.every(cert => cert.expires_at && cert.expires_at > now && cert.not_before != null && cert.not_before <= now) ? "续期失败" : "签发失败";
  if (!runtime || runtime.config_status !== "applied") return "待配置";
  if (!certificates.length || certificates.some(cert => !cert.expires_at || cert.not_before == null || cert.not_before > now)) return "签发中";
  return "证书有效";
}

function DomainCard({ item, onConfigure, onDelete, detail = false }: { item: Domain; onConfigure: () => void; onDelete: () => void; detail?: boolean }) {
  const runtime = item.runtime;
  const certificates = runtime?.certificates ?? [];
  const summary = certificateSummary(item);
  const tone = ["配置失败", "签发失败", "续期失败", "已过期"].includes(summary) ? "danger" : summary === "证书有效" ? "success" : "neutral";
  return <article className={`panel domain-row${detail ? " domain-detail" : " domain-compact"}`}>
    <div className="domain-heading"><h2>{detail ? item.domain : <a className="text-link" title={item.domain} href={`#/domains/${encodeURIComponent(item.id)}`}>{item.domain}</a>}</h2>{!detail && <span className={`domain-state ${tone}`}>{summary}</span>}<div className="domain-actions"><button className="icon-button" aria-label={`配置 ${item.domain}`} title="配置" onClick={onConfigure}><Settings size={19} aria-hidden="true" /></button><button className="icon-button danger-text" aria-label={`删除 ${item.domain}`} title="删除" onClick={onDelete}><Trash2 size={19} aria-hidden="true" /></button></div></div>
    {detail && <>
      <details className="domain-diagnostics" open>
        <summary><span className={`domain-state ${tone}`}>{summary}</span><ChevronRight size={17} /></summary>
        <div className="domain-diagnostics-body">
          {runtime?.config_error && <p className="domain-error">{runtime.config_error}</p>}
          {certificates.map(cert => <section className="domain-certificate" key={cert.hostname} aria-label={`证书 ${cert.hostname}`}>
            <div className="certificate-heading"><strong>{cert.hostname}</strong><Status kind="certificate" value={cert.status} /></div>
            {cert.expires_at != null && <dl><DetailField label="生效时间">{dateText(cert.not_before)}</DetailField><DetailField label="到期时间">{dateText(cert.expires_at)}</DetailField></dl>}
            {cert.error && <p className="domain-error">{cert.error}</p>}
            {cert.next_retry_at && <p className="helper">下次重试：{dateText(cert.next_retry_at)}</p>}
          </section>)}
        </div>
      </details>
    </>}
  </article>;
}

/** 日志仅在当前域名详情展开时读取；服务端先筛选域名，再限制条数。 */
function DomainEvents({ active, domainId }: { active: boolean; domainId: string }) {
  const request = useApi();
  const [open, setOpen] = useState(false);
  const events = useResource(() => request<{ events: DomainEvent[] }>(`/api/v1/public-domain-runtime-events?domain_id=${encodeURIComponent(domainId)}`), active && open);
  return <details className="panel domain-events" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>运行日志<ChevronRight size={17} /></summary>
    {open && <div className="domain-events-body"><Notice error={events.error} onRetry={() => void events.reload()} />{events.busy && !events.data && <Loading />}{events.data && (events.data.events.length ? <ol>{events.data.events.map(event => <li key={event.id}><time dateTime={new Date(event.occurred_at * 1000).toISOString()}>{dateText(event.occurred_at)}</time><p>{event.summary}</p></li>)}</ol> : <p className="helper">暂无日志</p>)}</div>}
  </details>;
}

export function DomainsPage({ active, csrf, route, back, initialConfiguration }: { active: boolean; csrf?: string | null; route: string; back: string; initialConfiguration?: Domain }) {
  const navigation = useContext(PageNavigationContext);
  const request = useApi();
  const resource = useResource(() => request<Domain[]>("/api/v1/public-domains"), active, true, false, initialConfiguration ? [initialConfiguration] : undefined);
  const [configuring, setConfiguring] = useState<Domain | null>(initialConfiguration ?? null);
  const [showDnsReminder, setShowDnsReminder] = useState(Boolean(initialConfiguration));
  const [adding, setAdding] = useState(false); const [deleting, setDeleting] = useState<Domain | null>(null); const [saved, setSaved] = useState<string | null>(initialConfiguration ? "已添加" : null);
  useResourceDeletions(routes => {
    if (!routes.some(route => route.startsWith("#/domains/"))) return;
    resource.setData(previous => previous?.filter(item => !routes.includes(`#/domains/${encodeURIComponent(item.id)}`)) ?? null);
    setSaved("已删除");
  });
  useEffect(() => { if (!active) setSaved(null); }, [active]);
  const detailId = route.startsWith("#/domains/") ? route.slice("#/domains/".length) : null;
  const detail = resource.data?.find(item => encodeURIComponent(item.id) === detailId);
  return <div className="domains-page">
    <PageHeader title={detailId ? detail?.domain ?? "域名详情" : "域名"} back={detailId ? back : undefined} action={!detailId && Boolean(resource.data?.length) && <CreateButton label="域名" onClick={() => setAdding(true)} />} />
    <Notice updatedAt={resource.updatedAt} error={resource.error ? `${saved ? "操作已完成，刷新失败：" : ""}${resource.error}` : null} onRetry={() => void resource.reload()} />{saved && !resource.error && <p className="helper domain-feedback" role="status">{saved}</p>}{!resource.data && resource.busy && <Loading />}
    {resource.data && (detailId ? detail ? <><DomainCard key={detail.id} item={detail} detail onConfigure={() => setConfiguring(detail)} onDelete={() => setDeleting(detail)} /><DomainEvents key={detail.id} active={active} domainId={detail.id} /></> : <Empty title="域名不存在" detail="域名可能已被删除，或不属于当前空间。"><a href="#/domains" className="secondary-button">返回域名列表</a></Empty> : !resource.data.length ? <Empty kind="domains" title="还没有域名" detail="用于网页访问和 HTTPS 证书。"><button className="primary-button" aria-label="添加 域名" onClick={() => setAdding(true)}>添加域名</button></Empty> : <>
      <div className="list-caption"><span>{resource.data.length} 个域名</span></div>
      <section className="domain-list" aria-label="域名列表">{resource.data.map(item => <DomainCard key={item.id} item={item} onConfigure={() => setConfiguring(item)} onDelete={() => setDeleting(item)} />)}</section>
    </>)}
    {adding && active && <DomainForm onClose={() => setAdding(false)} onSave={async domain => { const created = await request<Domain>("/api/v1/public-domains", { method: "POST", body: JSON.stringify({ domain, https_enabled: true }) }, csrf); resource.setData(previous => [...(previous ?? []).filter(item => item.id !== created.id), created].sort((a, b) => a.domain.localeCompare(b.domain))); setSaved("已添加"); setAdding(false); navigation?.openDomainConfiguration(created); }} />}
    {configuring && active && <DomainSettings domain={configuring} csrf={csrf} showDnsReminder={showDnsReminder} onDelete={() => setDeleting(configuring)} onClose={() => { setConfiguring(null); setShowDnsReminder(false); }} onSaved={value => { resource.setData(previous => (previous ?? []).map(item => item.id === configuring.id ? { ...item, ...value } : item)); }} />}
    {deleting && active && <Confirm title={`删除 ${deleting.domain}？`} description="删除后无法恢复。" label="删除" onClose={() => setDeleting(null)} onConfirm={async () => { await request(`/api/v1/public-domains/${encodeURIComponent(deleting.id)}`, { method: "DELETE" }, csrf); resource.setData(previous => (previous ?? []).filter(item => item.id !== deleting.id)); setSaved("已删除"); setConfiguring(null); navigation?.removePages([`#/domains/${encodeURIComponent(deleting.id)}`], "#/domains"); void resource.reload(); }} />}
  </div>;
}

/** 密码表单保留系统自动填充；键盘回车只切换字段，提交始终由明确的更新操作触发。 */
export function PasswordForm({ csrf, onClose, onExpired }: { csrf?: string | null; onClose: () => void; onExpired: () => void }) {
  const [current, setCurrent] = useState(""); const [next, setNext] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [visible, setVisible] = useState(false);
  const nextInput = useRef<HTMLInputElement>(null);
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(null); try { await request("/api/v1/auth/password", { method: "POST", body: JSON.stringify({ current_password: current, new_password: next }) }, csrf); onExpired(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }
  return <Modal title="修改密码" full dirty={Boolean(current || next)} busy={busy} onClose={onClose}>{close => <form onSubmit={submit} className="modal-form management-form"><div className="modal-body"><p className="helper">修改后所有会话将失效，需重新登录。</p><fieldset disabled={busy}><div className="management-fields"><label>当前密码<input type={visible ? "text" : "password"} autoComplete="current-password" autoCapitalize="none" spellCheck={false} enterKeyHint="next" value={current} onChange={e => setCurrent(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); nextInput.current?.focus(); } }} required /></label><label>新密码<input ref={nextInput} type={visible ? "text" : "password"} autoComplete="new-password" autoCapitalize="none" spellCheck={false} enterKeyHint="done" minLength={6} placeholder="至少 6 个字符" value={next} onChange={e => setNext(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); e.currentTarget.blur(); } }} required /></label></div><button className="text-button password-visibility" type="button" aria-pressed={visible} onClick={() => setVisible(!visible)}>{visible ? <EyeOff size={19} /> : <Eye size={19} />}{visible ? "隐藏密码" : "显示密码"}</button></fieldset></div><footer className="modal-actions"><Notice error={error} /><button type="button" className="secondary-button desktop-modal-cancel" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy}>{busy ? "更新中…" : "更新密码"}</button></footer></form>}</Modal>;
}

/** 会话页保持原链接，低频到期信息按需展开；结束当前会话仍交由认证流程处理。 */
export function SessionsPage({ active, auth, onExpired }: { active: boolean; auth: Auth; onExpired: () => void }) {
  const resource = useResource(async () => { const [sessions, current] = await Promise.all([request<Session[]>("/api/v1/auth/sessions"), request<Session>("/api/v1/auth/session")]); return { sessions, current }; }, active);
  const [revoke, setRevoke] = useState<Session | null>(null);
  return <><PageHeader title="登录会话" back="#/manage" />
    <Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} />{!resource.data && resource.busy && <Loading />}
    {resource.data && (resource.data.sessions.length ? <section className="panel session-list">{resource.data.sessions.map(session => <div className="session-row" data-current={session.id === resource.data?.current.id} key={session.id}><div><strong>{[session.browser, session.os].filter(Boolean).join(" · ") || "未知设备"}{session.id === resource.data?.current.id && <span> · <span>当前会话</span></span>}</strong><small>创建时间：{dateText(session.created_at)}</small><small>最近使用：{dateText(session.last_seen_at)}</small><details className="session-details"><summary>详情</summary><small>会话 {session.id.slice(0, 8)}</small><small>过期时间：{dateText(session.expires_at)}</small></details></div><button className="secondary-button" onClick={() => setRevoke(session)}>结束会话</button></div>)}</section> : <Empty kind="sessions" title="暂无登录会话" detail="登录设备的活动记录会显示在这里。" />)}
    {revoke && active && <Confirm title="结束登录会话？" description={revoke.id === resource.data?.current.id ? "这是当前会话，结束后需要重新登录。" : "该会话将立即失效，需要重新登录。"} label="结束会话" onClose={() => setRevoke(null)} onConfirm={async () => { await request(`/api/v1/auth/sessions/${encodeURIComponent(revoke.id)}`, { method: "POST" }, auth.csrf_token); if (revoke.id === resource.data?.current.id) onExpired(); else await resource.reload(); }} />}
  </>;
}
