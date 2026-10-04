import { Component, createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { InputHTMLAttributes, ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";
import { ArrowLeft, Check, ChevronRight, CircleAlert, CircleHelp, Clock, Copy, Pause, Plus, TriangleAlert, Users } from "./icons";
import { PageNavigationContext, rootRoutes } from "./navigation";

export type Auth = { initialized: boolean; authenticated: boolean; user_id?: string; username?: string; role?: "system_admin" | "tenant"; workspace_id?: string; csrf_token?: string | null; local_http_warning?: boolean };
export type NodeServiceStatus = { node_id: string; node_name?: string; healthy: boolean; checked_at?: number | null; error?: string | null; public_probe?: { kind: "tcp" | "http" | "https"; healthy: boolean; checked_at?: number | null; error?: string | null } };
export type Tunnel = { node_group_id?: string | null; node_ids?: string[]; node_statuses?: NodeServiceStatus[]; distribution_mode?: string; preferred_node_id?: string | null; node_selection?: { node_id: string; reason: string }; icon_id?: string | null; ipv6_direct_enabled?: boolean; direct_status?: { status: string; address?: string; error?: string; dns_error?: string; certificate_error?: string; certificate_expires_at?: number; public_reachability?: string; probe_error?: string }; https_port?: number; http_redirect_enabled?: boolean; protocol_statuses?: Record<string, { status: string; error_message?: string | null }>; access_mode?: "public" | "password"; service_mode?: "tunnel" | "reverse_proxy"; id: string; name: string; protocol: string; origin_protocol?: "http" | "https" | null; local_address: string; local_port: number; public_port?: number | null; public_address?: string | null; device_id?: string | null; device_name?: string | null; hostname?: string | null; enabled: boolean; apply_status: string; apply_error?: string | null; public_domain?: string | null; lan_redirect_enabled: boolean };
export type IdentityCertificate = { status: string; expires_at: number | null; renew_after: number | null; error: string | null; next_retry_at: number | null };
export type TransportIdentity = { server: IdentityCertificate; ca_expires_at: number | null; ca_needs_attention: boolean };
export type Device = { id: string; name: string; status: string; os?: string | null; architecture?: string | null; agent_version?: string | null; tunnel_count: number; enrolled_at?: number | null; last_seen_at?: number | null; certificate?: IdentityCertificate };
export type Enrollment = { id: string; kind: "recovery"; device_id?: string | null; status: string; expires_at: number; token?: string | null; device_name?: string | null; os?: string | null; architecture?: string | null; agent_version?: string | null };
export type DomainCertificate = { hostname: string; status: string; not_before: number | null; expires_at: number | null; error: string | null; next_retry_at: number | null };
export type DomainRuntime = { config_status: string; config_error: string | null; service_warning: string | null; checked_at: number | null; certificates: DomainCertificate[] };
export type Domain = { dns_provider?: "cloudflare" | "alidns" | "tencentcloud"; id: string; domain: string; is_primary: boolean; https_enabled: boolean; apply_status: string; runtime?: DomainRuntime; certificate_mode?: "cloudflare_dns"; verification_status?: "pending" | "verified"; verification_record?: { name: string; value: string } | null; credential_configured?: boolean; dns_resolvers?: string[]; dns_propagation_delay_seconds?: number | null; dns_propagation_timeout_seconds?: number | null };
export type DnsRecord = { id: string; name: string; kind: string; value: string; ttl: number; proxied: boolean };
export type DomainDnsPreview = { ipv4: string; provider: string; credential_revision: string; hosts: { hostname: string; existing: DnsRecord[]; action: "create" | "reuse" | "takeover"; blocked: string | null }[] };
export type DomainDnsResult = { hosts: { hostname: string; status: "written" | "unchanged" | "failed"; error: string | null }[] };
export type DomainEvent = { id: number; domain_id: string; summary: string; occurred_at: number };
export type Session = { created_at?: number; browser?: string | null; os?: string | null; id: string; last_seen_at: number; expires_at: number };

let sessionExpired = false;
// 刷新网页须等待写请求和响应处理结束，避免操作已提交但用户尚未收到结果。
let pendingWrites = 0;
export function hasPendingWrites() { return pendingWrites > 0; }
export function resumeSession() { sessionExpired = false; window.dispatchEvent(new Event("nexo:authenticated")); }
export async function request<T>(path: string, options: RequestInit = {}, csrf?: string | null, workspace?: string): Promise<T> {
  if (workspace && /^\/api\/v1\/(devices|nodes|node-groups|enrollments|agent-access-key|tunnels|public-domains|public-domain-runtime-events)(\/|$)/.test(path)) path = `/api/v1/admin/workspaces/${encodeURIComponent(workspace)}/${path.slice("/api/v1/".length)}`;
  const headers = new Headers(options.headers);
  headers.set("content-type", "application/json");
  if (csrf && options.method && options.method !== "GET") headers.set("x-nexo-csrf", csrf);
  const writing = !["GET", "HEAD"].includes((options.method ?? "GET").toUpperCase());
  if (writing) { pendingWrites++; window.dispatchEvent(new Event("nexo:writes-changed")); }
  try {
    let response: Response;
    try { response = await fetch(path, { ...options, headers, credentials: "same-origin" }); }
    catch { throw new Error("无法连接 Nexo，请检查网络后重试"); }
    const body = await response.json().catch(() => null);
    if (response.status === 401 && (body?.code === "session_expired" || !path.startsWith("/api/v1/auth/")) && !sessionExpired) {
      sessionExpired = true; window.dispatchEvent(new Event("nexo:session-expired"));
    }
    if (!response.ok) throw new Error(body?.error ?? "请求失败，请稍后重试");
    return body as T;
  } finally {
    if (writing) { pendingWrites--; window.dispatchEvent(new Event("nexo:writes-changed")); }
  }
}
/** 请求闭包绑定空间，旧请求和迟到回调不会随界面切换而访问另一个用户。 */
export const WorkspaceContext = createContext<string | undefined>(undefined);
export const WorkspaceLabelContext = createContext<string | undefined>(undefined);
export function useApi() {
  const workspace = useContext(WorkspaceContext);
  return useCallback(<T,>(path: string, options: RequestInit = {}, csrf?: string | null) => request<T>(path, options, csrf, workspace), [workspace]);
}
export const errorText = (error: unknown) => error instanceof Error ? error.message : "操作失败，请重试";
// Safari 的触摸点击不一定聚焦按钮，显式记住触发控件用于弹层关闭后的焦点恢复。
let interactionTarget: HTMLElement | null = null;
export function rememberInteraction(target: EventTarget | null) { interactionTarget = target instanceof Element ? target.closest<HTMLElement>("button,a,input,textarea,select") : null; }
// 网页服务展示真实内网协议，避免把公网 HTTPS 误认为内网也使用 HTTPS。
export const isPortProtocol = (protocol?: string) => ["tcp", "udp", "tcp_udp"].includes(protocol ?? "");
export const protocolLabel = (protocol: string) => protocol === "tcp_udp" ? "TCP+UDP" : protocol.toUpperCase();
export const localTarget = (item: Tunnel) => `${isPortProtocol(item.protocol) ? "" : `${item.origin_protocol ?? "http"}://`}${item.local_address.includes(":") ? `[${item.local_address.replace(/^\[|\]$/g, "")}]` : item.local_address}:${item.local_port}`;
export const dateText = (value?: number | null) => value ? new Date(value * 1000).toLocaleString("zh-CN", { year: "numeric", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }) : "暂无记录";

/** 密码显隐只改变当前输入的呈现，不改变自动填充语义或保存密码。 */
export function PasswordInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const [visible, setVisible] = useState(false);
  return <span className="password-input"><input {...props} type={visible ? "text" : "password"} /><button type="button" className="text-button" aria-label={visible ? "隐藏密码" : "显示密码"} aria-pressed={visible} onClick={() => setVisible(!visible)}>{visible ? "隐藏" : "显示"}</button></span>;
}

export function EnrollmentDevice({ item }: { item: Enrollment }) {
  return <div className="enrollment-device"><strong>{item.device_name || "尚未收到主机名"}</strong><p>{[item.os, item.architecture, item.agent_version && `设备 ${item.agent_version}`].filter(Boolean).join(" · ") || "等待设备信息"}</p><small>设备自报信息，请在批准前与目标主机核对。</small></div>;
}

export function Brand() { return <div className="brand"><img className="brand-icon" src="/brand/mole-head.webp" width="38" height="38" alt="" aria-hidden="true" /><span><strong>Nexo</strong><small>联巢 · 内网穿透</small></span></div>; }

/** 默认头像只由登录账号的真实角色决定，代管其他空间时不会改变管理员本人的身份。 */
export function UserAvatar({ role, size = 32 }: { role?: string; size?: 28 | 32 | 48 }) {
  const kind = role === "system_admin" ? "admin" : "user";
  return <img className="user-avatar" data-avatar-role={kind} src={`/brand/avatar-${kind}.webp`} width={size} height={size} alt="" aria-hidden="true" />;
}

/** 各资源分别解释状态，未知状态保留原值，避免把离线或未知情况误报为处理中。 */
export function Status({ value, kind = "service", badge = false }: { value: string; kind?: "service" | "agent" | "domain" | "certificate" | "reverse_proxy"; badge?: boolean }) {
  const labels: Record<string, string> = kind === "agent"
    ? { online: "在线", offline: "离线" }
    : kind === "domain" ? { applied: "配置已加载", pending: "等待加载", failed: "配置加载失败", disabled: "Caddy 已停用", unverified: "尚无运行状态" }
    : kind === "certificate" ? { pending: "等待签发", waiting_configuration: "申请中", presenting_dns: "提交 DNS 验证", waiting_dns: "等待 DNS 生效", validating: "验证中", issued: "已签发", active: "已签发", renewing: "续期中", retry_wait: "等待重试", failed: "申请失败", expired: "已过期", not_yet_valid: "尚未生效" }
    : kind === "reverse_proxy" ? { ready: "已生效", failed: "配置失败", error: "配置失败", disabled: "已停用", checking: "配置中", pending: "配置中", applying: "配置中" }
    : { partial: "部分可用", ready: "运行中", failed: "需处理", error: "需处理", disabled: "已关闭", checking: "检查中", pending: "待应用", applying: "应用中" };
  const tone = ["ready", "online", "applied", "issued", "active"].includes(value) ? "ready" : ["failed", "error", "expired"].includes(value) ? "failed" : ["partial", "pending", "checking", "applying", "waiting_configuration", "presenting_dns", "waiting_dns", "validating", "renewing", "retry_wait"].includes(value) ? "working" : "neutral";
  const label = labels[value] ?? (value === "waiting_address" ? "等待地址" : `未知状态：${value || "未返回"}`);
  // 应用角标复用完整状态文案，用形状区分异常、等待和关闭，读屏仍能获取原意。
  const Icon = value === "disabled" ? Pause : value === "partial" ? TriangleAlert : tone === "failed" ? CircleAlert : tone === "working" || value === "waiting_address" ? Clock : CircleHelp;
  return badge ? <span className={`status application-status ${tone}`} title={label}><Icon size={14} aria-hidden="true" /><span className="sr-only">{label}</span></span> : <span className={`status ${tone}`}><i />{label}</span>;
}

/** 底部容器只提供呈现位置；添加操作仍归属业务页面，保留表单状态、权限和触发焦点。 */
export const MobileCreateContext = createContext<HTMLElement | null>(null);
/** 顶部容器只决定首行位置；搜索、筛选和操作状态仍由原页面持有。 */
export const WorkspaceHeaderContext = createContext<HTMLElement | null>(null);

/** 手机主添加入口投递到底栏，缓存的非活动页不能投递；辅助操作和详情返回仍留在标题区。 */
export function PageHeader({ title, back, action, createAction, showTitle = false, topContent }: { title: string; back?: string; action?: ReactNode; createAction?: ReactNode; showTitle?: boolean; topContent?: ReactNode }) {
  const navigation = useContext(PageNavigationContext);
  const createTarget = useContext(MobileCreateContext);
  const headerTarget = useContext(WorkspaceHeaderContext);
  const topHeader = Boolean(navigation && (navigation.standalone || !navigation.desktop));
  const mobileCreate = Boolean(navigation && !navigation.desktop && rootRoutes.includes(navigation.route));
  const inlineAction = mobileCreate ? action : (action || createAction) && <>{action}{createAction}</>;
  const toolbarAction = !topHeader && navigation?.desktop && navigation.route !== "#/home";
  const showBack = back && !(navigation?.desktop && navigation.route === "#/users");
  const hideTitle = topHeader ? Boolean(topContent) : !showTitle && Boolean(navigation && (rootRoutes.includes(navigation.route) || navigation.route === "#/users"));
  const empty = hideTitle && !showBack && !(inlineAction && !toolbarAction);
  const header = <header className="page-header" data-title-hidden={hideTitle} data-empty={!topHeader && empty} data-has-action={Boolean(inlineAction && !toolbarAction)} data-has-back={Boolean(showBack)}>{showBack && <a className="icon-button page-back" href={back} aria-label="返回"><ArrowLeft size={21} /></a>}<div><h1 id={navigation ? `heading-${encodeURIComponent(navigation.route)}` : undefined} className="mobile-page-title" title={title} tabIndex={-1}>{title}</h1>{topHeader && topContent}</div>{inlineAction && !toolbarAction && <div className="page-actions">{inlineAction}</div>}</header>;
  return <>{topHeader ? navigation?.active && headerTarget && createPortal(header, headerTarget) : header}{inlineAction && toolbarAction && <div className="page-toolbar-actions">{inlineAction}</div>}{mobileCreate && navigation?.active && createTarget && createAction && createPortal(createAction, createTarget)}</>;
}
export function CreateButton({ label, onClick, disabled }: { label: string; onClick: () => void; disabled?: boolean }) {
  return <button className="primary-button page-create" data-resource={label} aria-label={label === "服务" ? "创建服务" : label === "设备" ? "添加设备" : `添加 ${label}`} title={label === "服务" ? "添加服务" : `添加${label}`} onClick={onClick} disabled={disabled}><Plus size={20} /><span>{label === "服务" ? "添加服务" : `添加${label}`}</span></button>;
}
/** 跨断点移动会重建按钮 DOM；关闭表单时只恢复同类资源的当前入口，不使用失效引用。 */
export function currentCreateButton(resource: string) {
  return Array.from(document.querySelectorAll<HTMLButtonElement>('.mobile-create-slot .page-create,.workspace-topbar .page-create,.page-slot:not([hidden]) .page-create')).find(button => button.dataset.resource === resource) ?? null;
}
export function Notice({ error, onRetry, updatedAt }: { error?: string | null; onRetry?: () => void; updatedAt?: number | null }) { return error ? <><div className="notice error" role="alert"><span>{error}</span>{onRetry && <button className="text-button" onClick={onRetry}>重试</button>}</div>{updatedAt && <p className="helper">保留上次数据 · 更新于 {dateText(updatedAt)}</p>}</> : null; }
/** 同一角色通过场景区分首次使用、搜索无结果和资源不存在；插画只作装饰，状态与操作由文字表达。 */
export function Empty({ title, detail, children, kind = "missing" }: { title: string; detail?: string; children?: ReactNode; kind?: "services" | "agents" | "domains" | "users" | "sessions" | "search" | "missing" }) {
  return <section className="empty" data-kind={kind}>{kind === "users" ? <div className="empty-symbol" aria-hidden="true"><Users size={34} /></div> : <img className="empty-illustration" src={`/illustrations/mole-${kind}.webp`} width="160" height="160" alt="" aria-hidden="true" />}<h2>{title}</h2>{detail && <p>{detail}</p>}{children && <div className="empty-actions">{children}</div>}</section>;
}
export function Loading() { return <div className="skeleton-list" role="status" aria-label="正在加载"><div /><div /><div /><span className="sr-only">正在加载</span></div>; }
export function RowLink({ href, title, detail, icon }: { href: string; title: string; detail?: string; icon?: ReactNode }) { return <a className="row-link" href={href}>{icon}<span><strong>{title}</strong>{detail && <small>{detail}</small>}</span><ChevronRight size={19} /></a>; }
export function DetailField({ label, children, className = "" }: { label: string; children: ReactNode; className?: string }) { return <div className={`detail-field ${className}`}><dt>{label}</dt><dd>{children}</dd></div>; }

/** HTTP 页面可能没有 Clipboard API；在点击回调内用同步选择复制，并恢复原焦点和选区。 */
export async function copyText(value: string, synchronous = false, trigger?: HTMLElement): Promise<void> {
  if (!synchronous && navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(value); return; } catch { /* 尝试浏览器的同步复制能力。 */ }
  }
  const focused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const textSelection = focused instanceof HTMLInputElement || focused instanceof HTMLTextAreaElement ? { start: focused.selectionStart, end: focused.selectionEnd, direction: focused.selectionDirection } : null;
  const selection = window.getSelection();
  const ranges = Array.from({ length: selection?.rangeCount ?? 0 }, (_, index) => selection!.getRangeAt(index).cloneRange());
  const input = document.createElement("textarea");
  input.value = value;
  input.readOnly = true;
  input.tabIndex = -1;
  input.setAttribute("aria-hidden", "true");
  input.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0";
  (trigger?.closest("dialog[open]") ?? focused?.closest("dialog[open]") ?? Array.from(document.querySelectorAll("dialog[open]")).at(-1) ?? document.body).append(input);
  try {
    input.focus({ preventScroll: true });
    input.select();
    if (!document.execCommand("copy")) throw new Error("浏览器不允许复制");
  } finally {
    input.remove();
    focused?.focus({ preventScroll: true });
    selection?.removeAllRanges();
    ranges.forEach(range => selection?.addRange(range));
    if (textSelection?.start != null && textSelection.end != null) (focused as HTMLInputElement | HTMLTextAreaElement).setSelectionRange(textSelection.start, textSelection.end, textSelection.direction ?? undefined);
  }
}

/** 异步权限失败后允许用新的点击直接同步复制；凭据仅保留在当前组件内存。 */
export function CopyButton({ value, label = "复制地址", compact = false, iconOnly = false, children }: { value: string; label?: string; compact?: boolean; iconOnly?: boolean; children?: ReactNode }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const manual = useRef<HTMLTextAreaElement>(null);
  useEffect(() => { setState("idle"); }, [value]);
  useEffect(() => { if (state !== "copied") return; const timer = window.setTimeout(() => setState("idle"), 2500); return () => clearTimeout(timer); }, [state]);
  useEffect(() => { if (state === "failed") manual.current?.scrollIntoView({ block: "nearest" }); }, [state]);
  return <div className={`copy-control ${compact ? "compact-copy" : ""}${iconOnly ? " icon-copy" : ""}`}>
    <button type="button" className={children ? "application-copy" : iconOnly ? "icon-button" : compact ? "address-button" : "secondary-button"} aria-label={state === "failed" ? "再次复制" : label} title={iconOnly || children ? label : undefined} onClick={async e => {
      try { await copyText(value, state === "failed", e.currentTarget); setState("copied"); } catch { setState("failed"); }
    }}>{children ?? <>{compact && <code>{value}</code>}{state === "copied" ? <Check size={17} /> : <Copy size={17} />}{!compact && !iconOnly && (state === "copied" ? "已复制" : state === "failed" ? "再次复制" : label)}</>}</button>
    {state !== "idle" && <span className={state === "failed" ? "form-error" : children ? "application-copy-feedback" : "sr-only"} role={state === "failed" ? "alert" : "status"}>{state === "copied" ? "已复制" : "无法复制，可再次复制，或选择下方完整文本手动复制"}</span>}
    {state === "failed" && <><textarea ref={manual} className="copy-fallback" aria-label="手动复制内容" readOnly value={value} onFocus={e => e.currentTarget.select()} /><button type="button" className="text-button" onClick={() => { manual.current?.focus(); manual.current?.select(); }}>选择全部</button></>}
  </div>;
}

/** 原生 dialog 提供焦点约束和背景隔离；长表单与短操作共享关闭和未保存保护。 */
export function Modal({ title, children, onClose, full = false, dirty = false, busy = false, dismissible = true, header, className = "", dialogRef, returnFocus }: { title: string; children: ReactNode | ((close: () => void) => ReactNode); onClose: () => void; full?: boolean; dirty?: boolean; busy?: boolean; dismissible?: boolean; header?: ReactNode; className?: string; dialogRef?: RefObject<HTMLDialogElement | null>; returnFocus?: () => HTMLElement | null }) {
  const workspaceLabel = useContext(WorkspaceLabelContext);
  const localRef = useRef<HTMLDialogElement>(null);
  const ref = dialogRef ?? localRef;
  const pendingNavigation = useRef<(() => void) | null>(null);
  const [discard, setDiscard] = useState(false);
  const close = () => { if (busy || !dismissible) return; if (dirty) setDiscard(true); else onClose(); };
  useEffect(() => {
    const dialog = ref.current!;
    const trigger = interactionTarget ?? document.activeElement as HTMLElement | null;
    interactionTarget = null;
    dialog.showModal();
    const resize = () => { dialog.style.setProperty("--visible-height", `${window.visualViewport?.height ?? window.innerHeight}px`); dialog.style.setProperty("--visual-top", `${window.visualViewport?.offsetTop ?? 0}px`); };
    resize(); window.visualViewport?.addEventListener("resize", resize); window.visualViewport?.addEventListener("scroll", resize);
    return () => { dialog.close(); window.visualViewport?.removeEventListener("resize", resize); window.visualViewport?.removeEventListener("scroll", resize); window.setTimeout(() => { const target = returnFocus ? returnFocus() : trigger?.isConnected ? trigger : trigger?.dataset.resource ? currentCreateButton(trigger.dataset.resource) : null; const top = Array.from(document.querySelectorAll("dialog[open]")).at(-1); if (target?.isConnected && !target.closest("[hidden]") && (!top || top.contains(target))) target.focus({ preventScroll: true }); }, 0); };
  }, []);
  // 使用独立监听读取最新 dirty，避免首次打开时的状态被闭包固定。
  useEffect(() => { if (!dirty) return; const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); }; window.addEventListener("beforeunload", handler); return () => window.removeEventListener("beforeunload", handler); }, [dirty]);
  useEffect(() => {
    // 完整表单在编辑期间阻止历史导航；主动关闭仍遵守草稿确认与提交保护。
    const handler = (event: Event) => {
      if (Array.from(document.querySelectorAll("dialog[open]")).at(-1) !== ref.current) return;
      event.preventDefault();
      if (full) return;
      if (busy || !dismissible) return;
      if (dirty) { pendingNavigation.current = (event as CustomEvent<{ resume: () => void }>).detail.resume; setDiscard(true); }
      else onClose();
    };
    window.addEventListener("nexo:route-change", handler);
    return () => window.removeEventListener("nexo:route-change", handler);
  }, [dirty, busy, dismissible, full, onClose]);
  return <><dialog ref={ref} data-navigation-lock={full} className={`modal ${full ? "full-form" : "short-modal"} ${className}`} aria-label={title} tabIndex={-1} onKeyDown={event => {
    if (event.key !== "Tab") return;
    const items = Array.from(ref.current!.querySelectorAll<HTMLElement>('button:not(:disabled),a[href],input:not(:disabled),textarea:not(:disabled),select:not(:disabled),summary,[tabindex="0"]')).filter(item => item.getClientRects().length > 0);
    const first = items[0]; const last = items[items.length - 1];
    if (!first) { event.preventDefault(); ref.current?.focus(); }
    else if (event.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }} onCancel={e => { e.preventDefault(); close(); }} onClick={e => { if (e.target === ref.current) { const box = ref.current.getBoundingClientRect(); if (e.clientX < box.left || e.clientX > box.right || e.clientY < box.top || e.clientY > box.bottom) close(); } }}><header className="modal-heading">{header ?? <h2>{title}</h2>}{dismissible && <><button type="button" className={`text-button modal-dismiss${full ? " form-cancel mobile-form-cancel" : ""}`} aria-label={full ? "取消" : "关闭"} onClick={close} disabled={busy}>{full ? "取消" : "关闭"}</button>{full && <button type="button" className="text-button modal-dismiss desktop-modal-close" aria-label="关闭" onClick={close} disabled={busy}>关闭</button>}</>}</header>{workspaceLabel && <p className="modal-workspace">操作空间：{workspaceLabel}</p>}{/* 自定义底部取消复用同一关闭入口，保留提交锁、草稿确认和焦点恢复。 */}{typeof children === "function" ? children(close) : children}</dialog>{discard && <Confirm title="放弃未保存的修改？" description="离开后，本次填写的内容将丢失。" label="放弃修改" onClose={() => { pendingNavigation.current = null; setDiscard(false); }} onConfirm={async () => { const resume = pendingNavigation.current; pendingNavigation.current = null; setDiscard(false); onClose(); if (resume) window.setTimeout(resume, 0); }} />}</>;
}
export function Confirm({ title, description, label, onClose, onConfirm, tone = "danger" }: { title: string; description: string; label: string; tone?: "danger" | "primary"; onClose: () => void; onConfirm: () => Promise<void> }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  return <Modal title={title} onClose={onClose} busy={busy}><div className="modal-body"><p>{description}</p><Notice error={error} /></div><footer className="modal-actions"><button className="secondary-button modal-dismiss" onClick={onClose} disabled={busy}>取消</button><button className={`${tone}-button`} disabled={busy} onClick={async () => { setBusy(true); try { await onConfirm(); onClose(); } catch (e) { setError(`${label}失败：${errorText(e)}`); } finally { setBusy(false); } }}>{busy ? "处理中…" : label}</button></footer></Modal>;
}

/** 前台每 5 秒更新，编辑/后台/登录过期时暂停；只读详情可显式允许弹层内更新，回到页面或网络恢复立即检查。 */
export function useResource<T>(load: () => Promise<T>, active: boolean, poll: boolean | number = true, pollInDialog = false, initialData?: T) {
  const loader = useRef(load); loader.current = load;
  const sequence = useRef(0); const inFlight = useRef(0);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [data, updateData] = useState<T | null>(initialData ?? null); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  async function reload(silent = false) {
    if (sessionExpired || inFlight.current) return;
    const seq = ++sequence.current; inFlight.current = seq;
    if (!silent) setBusy(true);
    try { const value = await loader.current(); if (seq === sequence.current) { updateData(value); setUpdatedAt(Date.now() / 1000); setError(null); } }
    catch (e) { if (seq === sequence.current) setError(errorText(e)); }
    finally { if (seq === sequence.current) { inFlight.current = 0; setBusy(false); } }
  }
  function setData(value: T | null | ((previous: T | null) => T | null)) {
    sequence.current++; inFlight.current = 0; setBusy(false); updateData(value);
  }
  useEffect(() => {
    if (!active) return;
    void reload();
    const refresh = () => { if (document.visibilityState === "visible" && (pollInDialog || !document.querySelector("dialog[open]"))) void reload(true); };
    const restored = () => { void reload(); };
    const timer = poll ? window.setInterval(refresh, poll === true ? 5000 : poll) : undefined;
    window.addEventListener("focus", refresh); window.addEventListener("online", refresh);
    document.addEventListener("visibilitychange", refresh); window.addEventListener("nexo:authenticated", restored);
    return () => {
      sequence.current++; inFlight.current = 0; window.clearInterval(timer);
      window.removeEventListener("focus", refresh); window.removeEventListener("online", refresh);
      document.removeEventListener("visibilitychange", refresh); window.removeEventListener("nexo:authenticated", restored);
    };
  }, [active, poll, pollInDialog]);
  return { updatedAt, data, setData, busy, error, reload };
}

/** 页面分包失败由局部边界呈现，已有页面和草稿保持挂载；重载由用户主动触发。 */
export class PageLoadBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <Notice error="页面加载失败，请检查网络后重新加载。" onRetry={() => window.location.reload()} /> : this.props.children;
  }
}
