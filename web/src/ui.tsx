import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { ArrowLeft, Check, ChevronRight, Copy, Plus, RefreshCw, X } from "lucide-react";

export type Auth = { initialized: boolean; authenticated: boolean; user_id?: string; username?: string; role?: "system_admin" | "tenant"; workspace_id?: string; csrf_token?: string | null; local_http_warning?: boolean };
export type Tunnel = { id: string; name: string; protocol: string; local_address: string; local_port: number; public_port?: number | null; public_address?: string | null; device_id?: string | null; device_name?: string | null; hostname?: string | null; enabled: boolean; apply_status: string; apply_error?: string | null; public_domain?: string | null };
export type IdentityCertificate = { status: string; expires_at: number | null; renew_after: number | null; error: string | null; next_retry_at: number | null };
export type TransportIdentity = { server: IdentityCertificate; ca_expires_at: number | null; ca_needs_attention: boolean };
export type Device = { id: string; name: string; status: string; os?: string | null; architecture?: string | null; agent_version?: string | null; tunnel_count: number; last_seen_at?: number | null; certificate?: IdentityCertificate };
export type Enrollment = { id: string; kind?: string; device_id?: string | null; status: string; expires_at: number; token?: string | null };
export type DomainCertificate = { hostname: string; status: string; not_before: number | null; expires_at: number | null; error: string | null; next_retry_at: number | null };
export type DomainRuntime = { config_status: string; config_error: string | null; service_warning: string | null; checked_at: number | null; certificates: DomainCertificate[] };
export type DomainAccessStatus = { expected_addresses: string[]; checked_at: number | null; next_retry_at?: number | null; retries_remaining?: number; public_access: string; records: { hostname: string; addresses: string[]; status: string; matches_server: boolean | null; error: string | null }[] };
export type Domain = { id: string; domain: string; is_primary: boolean; https_enabled: boolean; apply_status: string; runtime?: DomainRuntime; access?: DomainAccessStatus | null; certificate_mode?: "http01" | "cloudflare_dns"; verification_status?: "pending" | "verified"; verification_record?: { name: string; value: string } | null; credential_configured?: boolean; dns_resolvers?: string[]; dns_propagation_delay_seconds?: number | null; dns_propagation_timeout_seconds?: number | null };
export type DomainEvent = { id: number; domain_id: string; summary: string; occurred_at: number };
export type Session = { id: string; last_seen_at: number; expires_at: number };

let sessionExpired = false;
export function resumeSession() { sessionExpired = false; window.dispatchEvent(new Event("nexo:authenticated")); }
export async function request<T>(path: string, options: RequestInit = {}, csrf?: string | null, workspace?: string): Promise<T> {
  if (workspace && /^\/api\/v1\/(devices|enrollments|tunnels|public-domains|public-domain-runtime-events)(\/|$)/.test(path)) path = `/api/v1/admin/workspaces/${encodeURIComponent(workspace)}/${path.slice("/api/v1/".length)}`;
  const headers = new Headers(options.headers);
  headers.set("content-type", "application/json");
  if (csrf && options.method && options.method !== "GET") headers.set("x-nexo-csrf", csrf);
  let response: Response;
  try { response = await fetch(path, { ...options, headers, credentials: "same-origin" }); }
  catch { throw new Error("无法连接 Nexo，请检查网络后重试"); }
  const body = await response.json().catch(() => null);
  if (response.status === 401 && (body?.code === "session_expired" || !path.startsWith("/api/v1/auth/")) && !sessionExpired) {
    sessionExpired = true; window.dispatchEvent(new Event("nexo:session-expired"));
  }
  if (!response.ok) throw new Error(body?.error ?? "请求失败，请稍后重试");
  return body as T;
}
/** 请求闭包绑定空间，旧请求和迟到回调不会随界面切换而访问另一个用户。 */
export const WorkspaceContext = createContext<string | undefined>(undefined);
export function useApi() {
  const workspace = useContext(WorkspaceContext);
  return useCallback(<T,>(path: string, options: RequestInit = {}, csrf?: string | null) => request<T>(path, options, csrf, workspace), [workspace]);
}
export const errorText = (error: unknown) => error instanceof Error ? error.message : "操作失败，请重试";
// 前置配置跳转和成功提交后的返回由调用方明确放行，其余离开操作遵守弹层保护。
let allowedModalRoute: string | null = null;
export const navigate = (route: string, allowModalNavigation = false) => { allowedModalRoute = allowModalNavigation ? route : null; window.location.hash = route; };
export function consumeModalNavigation(route: string) { const retained = allowedModalRoute === route; allowedModalRoute = null; return retained; }
// Safari 的触摸点击不一定聚焦按钮，显式记住触发控件用于弹层关闭后的焦点恢复。
let interactionTarget: HTMLElement | null = null;
export function rememberInteraction(target: EventTarget | null) { interactionTarget = target instanceof Element ? target.closest<HTMLElement>("button,a,input,select") : null; }
export const localTarget = (item: Tunnel) => `${item.local_address.includes(":") ? `[${item.local_address.replace(/^\[|\]$/g, "")}]` : item.local_address}:${item.local_port}`;
export const dateText = (value?: number | null) => value ? new Date(value * 1000).toLocaleString("zh-CN", { year: "numeric", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false }) : "暂无记录";

export function Brand() { return <div className="brand"><span className="brand-icon">N</span><span><strong>Nexo</strong><small>联巢 · 内网穿透</small></span></div>; }

/** 各资源分别解释状态，未知状态保留原值，避免把离线或未知情况误报为处理中。 */
export function Status({ value, kind = "service" }: { value: string; kind?: "service" | "agent" | "domain" | "certificate" }) {
  const labels: Record<string, string> = kind === "agent"
    ? { online: "在线", offline: "离线" }
    : kind === "domain" ? { applied: "配置已加载", pending: "等待加载", failed: "配置加载失败", disabled: "Caddy 已停用", unverified: "尚无运行状态" }
    : kind === "certificate" ? { pending: "等待签发", waiting_configuration: "申请中", presenting_dns: "提交 DNS 验证", waiting_dns: "等待 DNS 生效", validating: "验证中", issued: "已签发", active: "已签发", renewing: "续期中", retry_wait: "等待重试", failed: "申请失败", expired: "已过期", not_yet_valid: "尚未生效" }
    : { ready: "转发就绪", failed: "需处理", error: "需处理", disabled: "已关闭", checking: "检查中", pending: "待应用", applying: "应用中" };
  const tone = ["ready", "online", "applied", "issued", "active"].includes(value) ? "ready" : ["failed", "error", "expired"].includes(value) ? "failed" : ["pending", "checking", "applying", "waiting_configuration", "presenting_dns", "waiting_dns", "validating", "renewing", "retry_wait"].includes(value) ? "working" : "neutral";
  return <span className={`status ${tone}`}><i />{labels[value] ?? `未知状态：${value || "未返回"}`}</span>;
}

export function PageHeader({ title, subtitle, back, action }: { title: string; subtitle?: string; back?: string; action?: ReactNode }) {
  return <header className="page-header">{back && <a className="icon-button page-back" href={back} aria-label="返回"><ArrowLeft size={21} /></a>}<div><h1 className="mobile-page-title" tabIndex={-1}>{title}</h1>{subtitle && <p className="subtitle">{subtitle}</p>}</div>{action && <div className="page-actions">{action}</div>}</header>;
}
export function CreateButton({ label, onClick, disabled }: { label: string; onClick: () => void; disabled?: boolean }) {
  return <button className={`primary-button fab-create${label === "服务" ? " fab-service" : ""}`} aria-label={label === "服务" ? "创建服务" : `添加 ${label}`} onClick={onClick} disabled={disabled}><Plus size={label === "服务" ? 26 : 20} strokeWidth={1.8} /><span>{label === "服务" ? "添加服务" : label}</span></button>;
}
export function Refresh({ onClick, busy, label }: { onClick: () => void; busy: boolean; label: string }) { return <button className="icon-button" aria-label={`刷新${label}`} onClick={onClick} disabled={busy}><RefreshCw size={18} className={busy ? "spin" : ""} /></button>; }
export function Notice({ error, onRetry }: { error?: string | null; onRetry?: () => void }) { return error ? <div className="notice error" role="alert"><span>{error}</span>{onRetry && <button className="text-button" onClick={onRetry}>重试</button>}</div> : null; }
export function Empty({ title, detail, children }: { title: string; detail?: string; children?: ReactNode }) { return <div className="empty"><span className="empty-symbol">N</span><h2>{title}</h2>{detail && <p>{detail}</p>}{children}</div>; }
export function Loading() { return <div className="skeleton-list" role="status" aria-label="正在加载"><div /><div /><div /><span className="sr-only">正在加载</span></div>; }
export function RowLink({ href, title, detail, icon }: { href: string; title: string; detail?: string; icon?: ReactNode }) { return <a className="row-link" href={href}>{icon}<span><strong>{title}</strong>{detail && <small>{detail}</small>}</span><ChevronRight size={19} /></a>; }
export function DetailField({ label, children }: { label: string; children: ReactNode }) { return <div className="detail-field"><dt>{label}</dt><dd>{children}</dd></div>; }

export function CopyButton({ value, label = "复制地址", compact = false }: { value: string; label?: string; compact?: boolean }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => { if (state === "idle") return; const timer = window.setTimeout(() => setState("idle"), 2500); return () => clearTimeout(timer); }, [state]);
  return <div className={`copy-control ${compact ? "compact-copy" : ""}`}><button className={compact ? "address-button" : "secondary-button"} aria-label={label} onClick={async () => { try { await navigator.clipboard.writeText(value); setState("copied"); } catch { setState("failed"); } }}>{compact && <code>{value}</code>}{state === "copied" ? <Check size={17} /> : <Copy size={17} />}{!compact && (state === "copied" ? "已复制" : "复制")}</button>{state !== "idle" && <span className={state === "failed" ? "form-error" : "copy-feedback"} role={state === "failed" ? "alert" : "status"}>{state === "copied" ? "已复制" : "无法复制，请在详情中长按文本手动复制"}</span>}</div>;
}

/** 原生 dialog 提供焦点约束和背景隔离；长表单与短操作共享关闭和未保存保护。 */
export function Modal({ title, children, onClose, full = false, dirty = false, busy = false, dismissible = true }: { title: string; children: ReactNode; onClose: () => void; full?: boolean; dirty?: boolean; busy?: boolean; dismissible?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
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
    return () => { dialog.close(); window.visualViewport?.removeEventListener("resize", resize); window.visualViewport?.removeEventListener("scroll", resize); window.setTimeout(() => { const top = Array.from(document.querySelectorAll("dialog[open]")).at(-1); if (trigger?.isConnected && !trigger.closest("[hidden]") && (!top || top.contains(trigger))) trigger.focus({ preventScroll: true }); }, 0); };
  }, []);
  // 使用独立监听读取最新 dirty，避免首次打开时的状态被闭包固定。
  useEffect(() => { if (!dirty) return; const handler = (e: BeforeUnloadEvent) => { e.preventDefault(); }; window.addEventListener("beforeunload", handler); return () => window.removeEventListener("beforeunload", handler); }, [dirty]);
  useEffect(() => {
    // 浏览器返回与界面关闭遵守同样的草稿保护；配置前置资源的跳转由调用方明确保留草稿。
    const handler = (event: Event) => {
      if (Array.from(document.querySelectorAll("dialog[open]")).at(-1) !== ref.current) return;
      event.preventDefault();
      if (busy || !dismissible) return;
      if (dirty) { pendingNavigation.current = (event as CustomEvent<{ resume: () => void }>).detail.resume; setDiscard(true); }
      else onClose();
    };
    window.addEventListener("nexo:route-change", handler);
    return () => window.removeEventListener("nexo:route-change", handler);
  }, [dirty, busy, dismissible, onClose]);
  return <><dialog ref={ref} className={`modal ${full ? "full-form" : "short-modal"}`} aria-label={title} tabIndex={-1} onKeyDown={event => {
    if (event.key !== "Tab") return;
    const items = Array.from(ref.current!.querySelectorAll<HTMLElement>('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),summary,[tabindex="0"]')).filter(item => item.getClientRects().length > 0);
    const first = items[0]; const last = items[items.length - 1];
    if (!first) { event.preventDefault(); ref.current?.focus(); }
    else if (event.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }} onCancel={e => { e.preventDefault(); close(); }} onClick={e => { if (e.target === ref.current) { const box = ref.current.getBoundingClientRect(); if (e.clientX < box.left || e.clientX > box.right || e.clientY < box.top || e.clientY > box.bottom) close(); } }}><header className="modal-heading"><h2>{title}</h2>{dismissible && <button className="icon-button" aria-label="关闭" onClick={close} disabled={busy}><X size={21} /></button>}</header>{children}</dialog>{discard && <Confirm title="放弃未保存的修改？" description="离开后，本次填写的内容将丢失。" label="放弃修改" onClose={() => { pendingNavigation.current = null; setDiscard(false); }} onConfirm={async () => { const resume = pendingNavigation.current; pendingNavigation.current = null; setDiscard(false); onClose(); if (resume) window.setTimeout(resume, 0); }} />}</>;
}
export function Confirm({ title, description, label, onClose, onConfirm }: { title: string; description: string; label: string; onClose: () => void; onConfirm: () => Promise<void> }) {
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  return <Modal title={title} onClose={onClose} busy={busy}><div className="modal-body"><p>{description}</p><Notice error={error} /></div><footer className="modal-actions"><button className="secondary-button" onClick={onClose} disabled={busy}>取消</button><button className="danger-button" disabled={busy} onClick={async () => { setBusy(true); try { await onConfirm(); onClose(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>{busy ? "处理中…" : label}</button></footer></Modal>;
}

/** 前台每 5 秒更新，编辑/后台/登录过期时暂停；只读详情可显式允许弹层内更新，回到页面或网络恢复立即检查。 */
export function useResource<T>(load: () => Promise<T>, active: boolean, poll = true, pollInDialog = false) {
  const loader = useRef(load); loader.current = load;
  const sequence = useRef(0); const inFlight = useRef(0);
  const [data, updateData] = useState<T | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  async function reload(silent = false) {
    if (sessionExpired || inFlight.current) return;
    const seq = ++sequence.current; inFlight.current = seq;
    if (!silent) setBusy(true);
    try { const value = await loader.current(); if (seq === sequence.current) { updateData(value); setError(null); } }
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
    const timer = poll ? window.setInterval(refresh, 5000) : undefined;
    window.addEventListener("focus", refresh); window.addEventListener("online", refresh);
    document.addEventListener("visibilitychange", refresh); window.addEventListener("nexo:authenticated", restored);
    return () => {
      sequence.current++; inFlight.current = 0; window.clearInterval(timer);
      window.removeEventListener("focus", refresh); window.removeEventListener("online", refresh);
      document.removeEventListener("visibilitychange", refresh); window.removeEventListener("nexo:authenticated", restored);
    };
  }, [active, poll, pollInDialog]);
  return { data, setData, busy, error, reload };
}
