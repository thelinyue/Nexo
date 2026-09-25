import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { DeviceRecovery } from "./recovery";
import { AgentEnrollment } from "./agent-enrollment";
import { DomainSettings } from "./domain-settings";
import { DomainAccess } from "./domain-access";
import { ChevronRight, Eye, EyeOff, Globe2, KeyRound, Plus, Server, ShieldCheck, Users, X } from "lucide-react";
import { Confirm, CreateButton, DetailField, Empty, Loading, Modal, Notice, PageHeader, Refresh, RowLink, Status, dateText, errorText, navigate, request, useApi, useResource } from "./ui";
import type { Auth, Device, Domain, DomainCertificate, DomainEvent, Enrollment, IdentityCertificate, Session, TransportIdentity, Tunnel } from "./ui";

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
  return <section className="panel detail-panel" aria-label="服务端内部证书"><details className="domain-diagnostics"><summary><span>服务端身份 · {identity ? identityCertificateLabel(identity.server) : resource.error ? "读取失败" : "读取中"}</span><ChevronRight size={17} /></summary><div className="domain-diagnostics-body"><Notice error={resource.error} onRetry={() => void resource.reload()} />{identity && <><IdentityCertificateDetails certificate={identity.server} server /><p className="helper">内部 CA 到期：{dateText(identity.ca_expires_at)}。公网域名证书由 Caddy 单独管理。</p></>}<Refresh label="内部证书" busy={resource.busy} onClick={() => void resource.reload()} /></div></details>{resource.error && <p className="form-error">无法读取内部证书状态，展开后重试。</p>}{identity && ["expiring", "retry_wait", "expired"].includes(identity.server.status) && <p className="form-error" role="status">服务端{identityCertificateLabel(identity.server)}，展开查看。</p>}{identity?.ca_needs_attention && <p className="form-error" role="status">内部 CA 需维护，请在到期前安排信任根更换。</p>}</section>;
}

/** 短表单集中处理请求状态，失败时保留输入；令牌只保存在当前组件内存。 */
function NameForm({ title, label, initial = "", onClose, onSave, children }: { title: string; label: string; initial?: string; onClose: () => void; onSave: (value: string) => Promise<void>; children?: ReactNode }) {
  const [value, setValue] = useState(initial); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  return <Modal title={title} dirty={value !== initial} busy={busy} onClose={onClose}><form className="modal-form" onSubmit={async e => { e.preventDefault(); if (!value.trim()) { setError(`${label}不能为空`); return; } setBusy(true); setError(null); try { await onSave(value.trim()); onClose(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}><div className="modal-body">{children}<label>{label}<input value={value} onChange={e => setValue(e.target.value)} required autoFocus enterKeyHint="done" autoCapitalize="none" spellCheck={false} disabled={busy} /></label><Notice error={error} /></div><footer className="modal-actions"><button className="primary-button" disabled={busy}>{busy ? "提交中…" : "确定"}</button></footer></form></Modal>;
}

export function AgentsPage({ route, active, csrf, back }: { route: string; active: boolean; csrf?: string | null; back: string }) {
  const request = useApi();
  const resource = useResource(async () => { const [devices, enrollments, tunnels] = await Promise.all([request<Device[]>("/api/v1/devices"), request<Enrollment[]>("/api/v1/enrollments"), request<Tunnel[]>("/api/v1/tunnels")]); return { devices, enrollments, tunnels }; }, active);
  const [enrolling, setEnrolling] = useState(false); const [approveId, setApproveId] = useState<string | null>(null); const [deleting, setDeleting] = useState<Device | null>(null);
  const [recovering, setRecovering] = useState<Device | null>(null); const [cancelInvite, setCancelInvite] = useState<Enrollment | null>(null);
  const detailId = route.startsWith("#/agents/") ? route.slice("#/agents/".length) : null;
  const data = resource.data; const detail = data?.devices.find(item => encodeURIComponent(item.id) === detailId);
  const pending = data?.enrollments.filter(item => ["awaiting_agent", "awaiting_approval"].includes(item.status)) ?? [];
  const approval = data?.enrollments.find(item => item.id === approveId);
  const recoveryTarget = data?.devices.find(item => item.id === approval?.device_id);
  return <>
    <PageHeader title={detailId ? "Agent 详情" : "Agent"} subtitle={detailId ? undefined : "连接本地服务的运行节点"} back={detailId ? back : "#/manage"} action={!detailId && <Refresh label="Agent" busy={resource.busy} onClick={() => void resource.reload()} />} />
    <Notice error={resource.error} onRetry={() => void resource.reload()} />{!data && resource.busy && <Loading />}
    {data && (detailId ? detail ? <>
      <section className="panel detail-panel"><div className="detail-heading"><h2>{detail.name}</h2><Status kind="agent" value={detail.status} /></div></section>
      <h2 className="section-title">关联服务 · {detail.tunnel_count}</h2>
      <section className="panel agent-services">{data.tunnels.filter(item => item.device_id === detail.id).map(item => <RowLink key={item.id} href={`#/services/${encodeURIComponent(item.id)}`} title={item.name} detail={`${item.protocol.toUpperCase()} · ${item.public_address ?? "等待配置"}`} />)}{!data.tunnels.some(item => item.device_id === detail.id) && <p className="panel-note">暂无关联服务</p>}</section>
      <section className="panel detail-panel"><details className="domain-diagnostics" key={detail.id}><summary><span>设备信息</span><ChevronRight size={17} /></summary><div className="domain-diagnostics-body"><dl><DetailField label="系统">{detail.os ?? "未知系统"}{detail.architecture ? ` · ${detail.architecture}` : ""}</DetailField><DetailField label="Agent 版本">{detail.agent_version ?? "等待首次连接"}</DetailField><DetailField label="最近连接">{dateText(detail.last_seen_at)}</DetailField></dl></div></details></section>
      <section className="panel detail-panel" aria-label="设备内部证书"><details className="domain-diagnostics" key={`${detail.id}:${detail.certificate?.status}`} open={Boolean(detail.certificate?.error) || ["expiring", "retry_wait", "expired"].includes(detail.certificate?.status ?? "")}><summary><span>设备证书 · {identityCertificateLabel(detail.certificate)}</span><ChevronRight size={17} /></summary><div className="domain-diagnostics-body"><IdentityCertificateDetails certificate={detail.certificate} offline={detail.status !== "online"} /><button className="secondary-button" onClick={() => setRecovering(detail)}>恢复设备身份</button></div></details></section>
      <button className="danger-button danger-zone" onClick={() => setDeleting(detail)}>删除 Agent</button>
    </> : <Empty title="Agent 不存在" detail="该节点可能已被删除。"><a className="secondary-button" href="#/agents">返回 Agent 列表</a></Empty> : <>
      {pending.length > 0 && <section className="panel pending-panel"><h2 className="section-title">等待批准 · {pending.length}</h2>{pending.map(item => <div className="pending-row" key={item.id}><div><strong>{item.kind === "recovery" ? `恢复 ${data.devices.find(device => device.id === item.device_id)?.name ?? "原设备"} 的身份` : "新的 Agent 入网请求"}</strong><small>有效期至 {dateText(item.expires_at)}</small></div><div className="pending-actions">{item.status === "awaiting_approval" ? <button className="primary-button" onClick={() => setApproveId(item.id)}>批准</button> : <span className="helper">等待 Agent 提交</span>}<button className="text-button" aria-label={`撤销请求 ${item.id}`} onClick={() => setCancelInvite(item)}>撤销</button></div></div>)}</section>}
      <div className="list-caption"><span>{data.devices.length} 台 Agent</span><span>{data.devices.filter(item => item.status === "online").length} 台在线</span></div>
      {!data.devices.length ? <Empty title="还没有 Agent" detail="添加一台 Agent，让它连接你的本地服务。" /> : <section className="panel agent-list">{data.devices.map(item => <a className="agent-row" key={item.id} href={`#/agents/${encodeURIComponent(item.id)}`}><span className="agent-avatar"><Server size={21} /></span><div className="agent-identity"><strong>{item.name}</strong><small>{item.tunnel_count} 个服务</small>{item.certificate && ["expiring", "retry_wait", "expired"].includes(item.certificate.status) && <small className="form-error">{identityCertificateLabel(item.certificate)}</small>}</div><Status kind="agent" value={item.status} /><ChevronRight size={18} /></a>)}</section>}
      <CreateButton label="Agent" onClick={() => setEnrolling(true)} />
    </>)}
    {enrolling && active && <AgentEnrollment csrf={csrf} onClose={() => setEnrolling(false)} onCreated={() => resource.reload()} />}
    {approveId && active && approval?.kind !== "recovery" && <NameForm title="批准 Agent 入网" label="Agent 名称" initial="我的 Agent" onClose={() => setApproveId(null)} onSave={async name => { await request(`/api/v1/enrollments/${encodeURIComponent(approveId)}/approve`, { method: "POST", body: JSON.stringify({ device_name: name }) }, csrf); await resource.reload(); }} />}
    {recovering && active && <DeviceRecovery device={recovering} csrf={csrf} onClose={() => setRecovering(null)} onCreated={() => void resource.reload()} />}
    {approveId && active && approval?.kind === "recovery" && <Confirm title={`批准恢复 ${recoveryTarget?.name ?? "原设备"} 的身份？`} description="原设备 ID、名称和服务绑定保留。批准后旧证书及旧连接立即失效，请确认申请来自你的 Agent。" label="批准恢复" onClose={() => setApproveId(null)} onConfirm={async () => { await request(`/api/v1/enrollments/${encodeURIComponent(approveId)}/approve`, { method: "POST", body: "{}" }, csrf); await resource.reload(); }} />}
    {cancelInvite && active && <Confirm title="撤销入网请求？" description="凭证将立即失效。现有设备身份与服务不受影响。" label="撤销请求" onClose={() => setCancelInvite(null)} onConfirm={async () => { await request(`/api/v1/enrollments/${encodeURIComponent(cancelInvite.id)}`, { method: "DELETE" }, csrf); await resource.reload(); }} />}
    {deleting && active && <Confirm title={`删除 ${deleting.name}？`} description={`关联的 ${deleting.tunnel_count} 个服务将被停用，并解除 Agent 绑定。此操作无法撤销。`} label="删除 Agent" onClose={() => setDeleting(null)} onConfirm={async () => { await request(`/api/v1/devices/${encodeURIComponent(deleting.id)}`, { method: "DELETE" }, csrf); await resource.reload(); navigate("#/agents", true); }} />}
  </>;
}

/** 管理页统一承载资源与本人账号操作；资源摘要绑定当前空间，账号与服务端身份始终使用本人权限。 */
export function ManagePage({ auth, active, onLogout, onExpired }: { auth: Auth; active: boolean; onLogout: () => Promise<void>; onExpired: () => void }) {
  const scopedRequest = useApi();
  const resource = useResource(async () => { const [devices, enrollments] = await Promise.all([scopedRequest<Device[]>("/api/v1/devices"), scopedRequest<Enrollment[]>("/api/v1/enrollments")]); return { devices, enrollments }; }, active);
  const [password, setPassword] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const devices = resource.data?.devices ?? [];
  const approvals = resource.data?.enrollments.filter(item => item.status === "awaiting_approval").length ?? 0;
  const offline = devices.filter(item => item.status !== "online").length;
  const certificates = devices.filter(item => item.certificate?.error || ["expiring", "retry_wait", "expired"].includes(item.certificate?.status ?? "")).length;
  const agentSummary = resource.data ? [`${devices.filter(item => item.status === "online").length} 台在线`, approvals ? `${approvals} 待批准` : "", offline ? `${offline} 台离线` : "", certificates ? `${certificates} 台证书需处理` : ""].filter(Boolean).join(" · ") : resource.error ? "摘要读取失败" : "读取中…";
  return <div className="manage-page">
    <PageHeader title="管理" />
    {auth.local_http_warning && <p className="notice" role="status">当前管理连接未使用 HTTPS，公网部署请通过 HTTPS 反向代理访问。</p>}
    <section className="panel account-summary"><span className="account-avatar">{(auth.username ?? "N").slice(0, 1).toUpperCase()}</span><div><strong>{auth.username}</strong><small>{auth.role === "system_admin" ? "管理员" : "普通用户"}</small></div></section>
    <h2 className="section-title">资源</h2><Notice error={resource.error} onRetry={() => void resource.reload()} />
    <section className="panel management-group"><RowLink href="#/agents" title="Agent" detail={agentSummary} icon={<Server size={23} />} /><RowLink href="#/domains" title="域名与证书" icon={<Globe2 size={23} />} />{auth.role === "system_admin" && <RowLink href="#/users" title="用户管理" icon={<Users size={23} />} />}</section>
    <h2 className="section-title">账号安全</h2><section className="panel management-group"><button className="row-link" onClick={() => setPassword(true)}><KeyRound size={23} /><span><strong>修改密码</strong></span><ChevronRight size={19} /></button><RowLink href="#/settings/sessions" title="登录会话" icon={<ShieldCheck size={23} />} /></section>
    {auth.role === "system_admin" && <><h2 className="section-title">系统</h2><ServerIdentityCard active={active} /></>}
    <Notice error={error} /><button className="danger-button danger-zone" disabled={busy} onClick={async () => { setBusy(true); setError(null); try { await onLogout(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>{busy ? "退出中…" : "退出登录"}</button>
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
    if (!domain) { setError(value.trim() ? "域名格式不正确，请填写 example.com，不要包含网址前缀、端口或路径。" : "请输入域名，例如 example.com。"); setInvalid(true); input.current?.focus(); return; }
    setBusy(true); setError(null); setInvalid(false);
    try { await onSave(domain); onClose(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <Modal title="添加域名" dirty={Boolean(value.trim())} busy={busy} onClose={onClose}>
    <form className="modal-form domain-form" onSubmit={submit} noValidate>
      <div className="modal-body">
        <label className="domain-input-label" htmlFor="domain-input">域名</label>
        <div className="domain-input-control" data-invalid={invalid}>
          <input id="domain-input" name="domain" ref={input} value={value} onChange={e => updateValue(e.target.value)} placeholder="example.com" inputMode="url" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} enterKeyHint="done" required disabled={busy} aria-invalid={invalid} aria-describedby={error ? "domain-input-error" : "domain-input-hint"} onKeyDown={e => { if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); e.currentTarget.blur(); } }} />
          {value && <button className="icon-button domain-clear" type="button" aria-label="清空域名" disabled={busy} onClick={() => { updateValue(""); input.current?.focus(); }}><X size={17} /></button>}
        </div>
        <p className="helper" id="domain-input-hint" hidden={Boolean(error)}>用于 HTTP / HTTPS 服务。</p>
        {error && <p className="form-error domain-input-error" id="domain-input-error" role="alert">{error}</p>}
        {suggested && <div className="domain-url-suggestion"><p className="helper">已输入完整网址，添加域名只需保留：</p><button type="button" className="text-button" disabled={busy} onClick={() => { updateValue(suggested); input.current?.focus(); }}><span>仅使用</span><code>{suggested}</code></button></div>}
        {normalized && normalized !== value.trim() && <p className="helper domain-normalized">将保存为 <code>{normalized}</code></p>}
        <p className="helper">添加后需验证归属，证书可自动签发与续期。</p>
      </div>
      <footer className="modal-actions"><button className="primary-button" disabled={busy}>{busy ? "添加中…" : "添加域名"}</button></footer>
    </form>
  </Modal>;
}

/** 证书文件的有效期与申请任务分开呈现：续期失败时，旧证书可能仍然有效。 */
function certificateSummary(certificates: DomainCertificate[]) {
  if (!certificates.length) return "等待证书状态";
  const now = Date.now() / 1000;
  if (certificates.some(cert => cert.expires_at && cert.expires_at <= now)) return "证书已过期";
  if (certificates.some(cert => cert.error || ["failed", "retry_wait"].includes(cert.status))) return "证书申请需关注";
  if (certificates.some(cert => cert.not_before && cert.not_before > now)) return "证书尚未生效";
  if (certificates.some(cert => cert.status === "renewing")) return "证书续期中";
  if (certificates.some(cert => !cert.expires_at || !cert.not_before)) return "等待证书签发";
  const expiry = Math.min(...certificates.map(cert => cert.expires_at!));
  return `证书有效 · ${new Date(expiry * 1000).toLocaleDateString()} 到期`;
}

function DomainCard({ item, onConfigure, active, csrf }: { item: Domain; onConfigure: () => void; active: boolean; csrf?: string | null }) {
  const runtime = item.runtime;
  const certificates = runtime?.certificates ?? [];
  return <article className="panel domain-row">
    <div className="domain-heading"><h2>{item.domain}</h2><button className="text-button" onClick={onConfigure}>{item.verification_status === "pending" ? "验证与配置" : "证书配置"}</button></div>
    <div className="domain-config"><DomainAccess domain={item} active={active} csrf={csrf} />{!item.https_enabled && <span>HTTPS 未开启</span>}{item.verification_status === "pending" ? <span className="status neutral">待验证归属</span> : runtime?.config_status !== "applied" && <Status kind="domain" value={runtime?.config_status ?? "unverified"} />}</div>
    <details className="domain-diagnostics">
      <summary><span>{!runtime ? "等待运行状态" : runtime.config_status === "disabled" ? "证书管理已暂停" : !item.https_enabled ? "未启用自动证书" : certificateSummary(certificates)}</span><ChevronRight size={17} /></summary>
      <div className="domain-diagnostics-body">
        <div className="domain-config"><span>HTTPS {item.https_enabled ? "已开启" : "未开启"}</span>{runtime?.config_status === "applied" && <Status kind="domain" value="applied" />}</div>
        {item.https_enabled && <p className="helper">{item.certificate_mode === "http01" ? "HTTP 验证按主机名签发证书，请开放公网 TCP 80、443。" : "子域名共用同级泛域名证书；公网申请与续期需要 Cloudflare DNS 验证凭据。"}</p>}
        {runtime?.config_error && <p className="domain-error"><strong>配置失败原因</strong>{runtime.config_error}</p>}
        {runtime?.service_warning && <p className="domain-error">{runtime.service_warning}</p>}
        {certificates.map(cert => <section className="domain-certificate" key={cert.hostname} aria-label={`证书 ${cert.hostname}`}>
          <div className="certificate-heading"><strong>{cert.hostname}</strong><Status kind="certificate" value={cert.status} /></div>
          {cert.expires_at ? <dl><DetailField label="生效时间">{dateText(cert.not_before)}</DetailField><DetailField label="到期时间">{dateText(cert.expires_at)}</DetailField></dl> : <p className="helper">尚未读取到已签发的证书</p>}
          {cert.error && <p className="domain-error"><strong>{cert.expires_at && cert.expires_at > Date.now() / 1000 ? "现有证书仍有效，续期遇到问题" : "申请失败原因"}</strong>{cert.error}</p>}
          {(cert.error || cert.status === "retry_wait") && <p className="helper">{cert.next_retry_at ? `Caddy 计划重试：${dateText(cert.next_retry_at)}` : "重试由 Caddy 安排，尚未提供下次时间。"}</p>}
        </section>)}
        <p className="helper">{runtime?.checked_at ? `最近检查：${dateText(runtime.checked_at)}` : "尚未完成运行检查"}</p>
      </div>
    </details>
    {runtime?.config_error && <p className="domain-alert">配置未成功加载，展开查看原因。</p>}
    {runtime?.service_warning && <p className="domain-alert">服务转发通道尚未就绪</p>}
  </article>;
}

function DomainEvents({ active, domains }: { active: boolean; domains: Domain[] }) {
  const request = useApi();
  const [open, setOpen] = useState(false);
  const events = useResource(() => request<{ events: DomainEvent[] }>("/api/v1/public-domain-runtime-events"), active && open);
  return <details className="panel domain-events" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>最近记录<ChevronRight size={17} /></summary>
    {open && <div className="domain-events-body"><div className="list-caption"><span>最近 100 条记录</span><Refresh label="运行记录" busy={events.busy} onClick={() => void events.reload()} /></div><Notice error={events.error} onRetry={() => void events.reload()} />{events.busy && !events.data && <Loading />}{events.data && (events.data.events.length ? <ol>{events.data.events.map(event => <li key={event.id}><strong>{domains.find(domain => domain.id === event.domain_id)?.domain ?? "已删除的域名"}</strong><time dateTime={new Date(event.occurred_at * 1000).toISOString()}>{dateText(event.occurred_at)}</time><p>{event.summary}</p></li>)}</ol> : <p className="helper">暂无运行记录</p>)}</div>}
  </details>;
}

export function DomainsPage({ active, csrf }: { active: boolean; csrf?: string | null }) {
  const request = useApi();
  const resource = useResource(() => request<Domain[]>("/api/v1/public-domains"), active);
  const [configuring, setConfiguring] = useState<Domain | null>(null);
  const [adding, setAdding] = useState(false); const [deleting, setDeleting] = useState<Domain | null>(null); const [saved, setSaved] = useState<string | null>(null);
  useEffect(() => { if (!active) setSaved(null); }, [active]);
  return <div className="domains-page">
    <PageHeader title="域名与证书" back="#/manage" action={<Refresh label="域名" busy={resource.busy} onClick={() => void resource.reload()} />} />
    <Notice error={resource.error ? `${saved ? "域名变更已保存，但列表刷新失败。可重试刷新，无需重复操作。" : ""}${resource.error}` : null} onRetry={() => void resource.reload()} />{saved && !resource.error && <p className="helper domain-feedback" role="status">{saved}</p>}{!resource.data && resource.busy && <Loading />}
    {resource.data && (!resource.data.length ? <Empty title="还没有域名" detail="添加域名后，可在 HTTP / HTTPS 服务中选择使用。" /> : <>
      <div className="list-caption"><span>{resource.data.length} 个域名</span></div>
      <section className="domain-list" aria-label="域名列表">{resource.data.map(item => <DomainCard key={item.id} item={item} onConfigure={() => setConfiguring(item)} active={active} csrf={csrf} />)}</section>
      <DomainEvents active={active} domains={resource.data} />
    </>)}
    <button className="secondary-button fab-create domain-create" aria-label="添加 域名" onClick={() => setAdding(true)}><Plus size={21} />添加域名</button>
    {adding && active && <DomainForm onClose={() => setAdding(false)} onSave={async domain => { const created = await request<Domain>("/api/v1/public-domains", { method: "POST", body: JSON.stringify({ domain, https_enabled: true }) }, csrf); resource.setData(previous => [...(previous ?? []).filter(item => item.id !== created.id), created].sort((a, b) => a.domain.localeCompare(b.domain))); setSaved(`已添加 ${created.domain}`); void resource.reload(); }} />}
    {configuring && active && <DomainSettings domain={configuring} csrf={csrf} onDelete={() => setDeleting(configuring)} onClose={() => setConfiguring(null)} onSaved={value => { resource.setData(previous => (previous ?? []).map(item => item.id === configuring.id ? { ...item, ...value } : item)); }} />}
    {deleting && active && <Confirm title={`删除 ${deleting.domain}？`} description="删除后无法再使用此域名配置服务。仍有关联服务时会阻止删除，请先修改或删除关联服务。" label="删除域名" onClose={() => setDeleting(null)} onConfirm={async () => { await request(`/api/v1/public-domains/${encodeURIComponent(deleting.id)}`, { method: "DELETE" }, csrf); resource.setData(previous => (previous ?? []).filter(item => item.id !== deleting.id)); setSaved(`已删除 ${deleting.domain}`); setConfiguring(null); void resource.reload(); }} />}
  </div>;
}

/** 密码表单保留系统自动填充；键盘回车只切换字段，提交始终由明确的更新操作触发。 */
export function PasswordForm({ csrf, onClose, onExpired }: { csrf?: string | null; onClose: () => void; onExpired: () => void }) {
  const [current, setCurrent] = useState(""); const [next, setNext] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [visible, setVisible] = useState(false);
  const nextInput = useRef<HTMLInputElement>(null);
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(null); try { await request("/api/v1/auth/password", { method: "POST", body: JSON.stringify({ current_password: current, new_password: next }) }, csrf); onExpired(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }
  return <Modal title="修改密码" full dirty={Boolean(current || next)} busy={busy} onClose={onClose}><form onSubmit={submit} className="modal-form management-form"><div className="modal-body"><p className="helper">修改后所有会话将失效，需要重新登录。</p><fieldset disabled={busy}><div className="management-fields"><label>当前密码<input type={visible ? "text" : "password"} autoComplete="current-password" autoCapitalize="none" spellCheck={false} enterKeyHint="next" value={current} onChange={e => setCurrent(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); nextInput.current?.focus(); } }} required /></label><label>新密码<input ref={nextInput} type={visible ? "text" : "password"} autoComplete="new-password" autoCapitalize="none" spellCheck={false} enterKeyHint="done" minLength={12} placeholder="至少 12 个字符" value={next} onChange={e => setNext(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); e.currentTarget.blur(); } }} required /></label></div><button className="text-button password-visibility" type="button" aria-pressed={visible} onClick={() => setVisible(!visible)}>{visible ? <EyeOff size={19} /> : <Eye size={19} />}{visible ? "隐藏密码" : "显示密码"}</button></fieldset></div><footer className="modal-actions"><Notice error={error} /><button className="primary-button" disabled={busy}>{busy ? "更新中…" : "更新密码"}</button></footer></form></Modal>;
}

/** 会话页保持原链接，低频到期信息按需展开；结束当前会话仍交由认证流程处理。 */
export function SessionsPage({ active, auth, onExpired }: { active: boolean; auth: Auth; onExpired: () => void }) {
  const resource = useResource(async () => { const [sessions, current] = await Promise.all([request<Session[]>("/api/v1/auth/sessions"), request<Session>("/api/v1/auth/session")]); return { sessions, current }; }, active);
  const [revoke, setRevoke] = useState<Session | null>(null);
  return <><PageHeader title="登录会话" back="#/manage" action={<Refresh label="会话" busy={resource.busy} onClick={() => void resource.reload()} />} />
    <Notice error={resource.error} onRetry={() => void resource.reload()} />{!resource.data && resource.busy && <Loading />}
    {resource.data && (resource.data.sessions.length ? <section className="panel session-list">{resource.data.sessions.map(session => <div className="session-row" data-current={session.id === resource.data?.current.id} key={session.id}><div><strong>{session.id === resource.data?.current.id ? "当前会话" : `会话 ${session.id.slice(0, 8)}`}</strong><small>最近使用：{dateText(session.last_seen_at)}</small><details className="session-details"><summary>详情</summary><small>过期时间：{dateText(session.expires_at)}</small></details></div><button className="secondary-button" onClick={() => setRevoke(session)}>结束会话</button></div>)}</section> : <Empty title="暂无登录会话" />)}
    {revoke && active && <Confirm title="结束登录会话？" description={revoke.id === resource.data?.current.id ? "这是当前会话，结束后需要重新登录。" : "该会话将立即失效，需要重新登录。"} label="结束会话" onClose={() => setRevoke(null)} onConfirm={async () => { await request(`/api/v1/auth/sessions/${encodeURIComponent(revoke.id)}`, { method: "POST" }, auth.csrf_token); if (revoke.id === resource.data?.current.id) onExpired(); else await resource.reload(); }} />}
  </>;
}
