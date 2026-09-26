import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Check, ChevronDown, ChevronRight, Search, Trash2 } from "lucide-react";
import { Confirm, CopyButton, CreateButton, DetailField, Empty, Loading, Modal, Notice, PageHeader, Status, errorText, localTarget, navigate, useApi, useResource } from "./ui";
import type { Device, Domain, Tunnel } from "./ui";
import { isLanRedirectAddress } from "./lan-redirect";

type ServiceData = { tunnels: Tunnel[]; devices: Device[]; domains: Domain[] };
const loadServices = async (request: ReturnType<typeof useApi>): Promise<ServiceData> => { const [tunnels, devices, domains] = await Promise.all([request<Tunnel[]>("/api/v1/tunnels"), request<Device[]>("/api/v1/devices"), request<Domain[]>("/api/v1/public-domains")]); return { tunnels, devices, domains: domains.filter(domain => domain.verification_status !== "pending") }; };

type ServiceSelectOption = { value: string; label: string; status?: "online" | "offline" };

/** 两个表单选择器共享原生顶层浮层，避免被 dialog 的滚动区裁切。焦点留在触发按钮，方向键仅移动候选项，确认后才修改草稿。 */
function ServiceSelect({ label, name, value, placeholder, options, disabled, compact = false, onChange, ...validation }: {
  label: string; name: string; value: string; placeholder: string; options: ServiceSelectOption[]; disabled?: boolean; compact?: boolean;
  onChange: (value: string) => void; "aria-invalid"?: boolean; "aria-describedby"?: string;
}) {
  const id = useId();
  const triggerRef = useRef<HTMLButtonElement>(null); const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false); const [highlighted, setHighlighted] = useState(0);
  const selected = options.find(option => option.value === value);
  function close(restoreFocus = false) {
    menuRef.current?.hidePopover(); setOpen(false);
    if (restoreFocus) triggerRef.current?.focus({ preventScroll: true });
  }
  function position() {
    const trigger = triggerRef.current; const menu = menuRef.current;
    if (!trigger || !menu?.matches(":popover-open")) return;
    const body = trigger.closest(".modal-body")!.getBoundingClientRect(); const row = trigger.getBoundingClientRect();
    const viewport = window.visualViewport;
    const top = Math.max(body.top, viewport?.offsetTop ?? 0) + 6;
    const bottom = Math.min(body.bottom, (viewport?.offsetTop ?? 0) + (viewport?.height ?? window.innerHeight)) - 6;
    const left = Math.max(body.left, viewport?.offsetLeft ?? 0) + 6;
    const right = Math.min(body.right, (viewport?.offsetLeft ?? 0) + (viewport?.width ?? window.innerWidth)) - 6;
    if (row.bottom <= top || row.top >= bottom) { close(); return; }
    // 紧凑域名触发器仍展开足够宽的列表，低高度视口下避免长域名撑高到无法完整选中。
    const width = Math.min(compact ? Math.max(row.width, 360) : row.width, right - left);
    menu.style.width = `${width}px`; menu.style.left = `${Math.max(left, Math.min(row.left, right - width))}px`;
    const desired = Math.min(menu.scrollHeight + 2, 300);
    const below = Math.max(0, bottom - row.bottom - 6); const above = Math.max(0, row.top - top - 6);
    const down = below >= desired || below >= above;
    const height = Math.min(desired, down ? below : above);
    menu.style.maxHeight = `${height}px`;
    menu.style.top = `${down ? row.bottom + 6 : row.top - 6 - height}px`;
  }
  function show() {
    if (disabled || !options.length) return;
    setHighlighted(Math.max(0, options.findIndex(option => option.value === value)));
    triggerRef.current?.scrollIntoView({ block: compact ? "end" : "nearest" });
    triggerRef.current?.focus({ preventScroll: true });
    menuRef.current?.showPopover(); position(); setOpen(true);
  }
  function choose(index: number) {
    if (options[index]) onChange(options[index].value);
    close(true);
  }
  useEffect(() => { if (disabled) close(); }, [disabled]);
  useEffect(() => {
    if (!open) return;
    // 定位以可见表单区为边界，软键盘、横竖屏和表单滚动时仍保留标题与保存栏。
    const body = triggerRef.current!.closest(".modal-body")!;
    const observer = new ResizeObserver(position); observer.observe(body); observer.observe(triggerRef.current!);
    body.addEventListener("scroll", position); window.addEventListener("resize", position);
    window.visualViewport?.addEventListener("resize", position); window.visualViewport?.addEventListener("scroll", position);
    return () => { observer.disconnect(); body.removeEventListener("scroll", position); window.removeEventListener("resize", position); window.visualViewport?.removeEventListener("resize", position); window.visualViewport?.removeEventListener("scroll", position); };
  }, [open]);
  useEffect(() => {
    const menu = menuRef.current; const option = menu?.children[highlighted] as HTMLElement | undefined;
    if (!open || !menu || !option) return;
    if (option.offsetTop < menu.scrollTop) menu.scrollTop = option.offsetTop;
    else if (option.offsetTop + option.offsetHeight > menu.scrollTop + menu.clientHeight) menu.scrollTop = option.offsetTop + option.offsetHeight - menu.clientHeight;
  }, [open, highlighted]);
  const status = (option: ServiceSelectOption) => option.status && <span className={`service-select-status ${option.status}`}><i aria-hidden="true" />{option.status === "online" ? "在线" : "离线"}</span>;
  return <div className={`service-field service-select-field${compact ? " service-select-compact" : ""}`}>
    <button ref={triggerRef} type="button" role="combobox" name={name} value={value} className="service-select-trigger" aria-label={label} aria-haspopup="listbox" aria-expanded={open} aria-controls={id} aria-activedescendant={open ? `${id}-${highlighted}` : undefined} aria-required="true" {...validation} disabled={disabled || !options.length} onClick={() => open ? close() : show()} onKeyDown={event => {
      if (event.nativeEvent.isComposing) return;
      if (event.key === "Tab") { close(); return; }
      if (event.key === "Escape" && open) { event.preventDefault(); event.stopPropagation(); close(true); return; }
      if (["Enter", " ", "ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
        event.preventDefault();
        if (!open) { show(); return; }
        if (event.key === "Enter" || event.key === " ") choose(highlighted);
        else setHighlighted(current => event.key === "Home" ? 0 : event.key === "End" ? options.length - 1 : Math.max(0, Math.min(options.length - 1, current + (event.key === "ArrowDown" ? 1 : -1))));
      }
    }}><span className={compact ? "sr-only" : "service-select-caption"}>{label}</span><span className={`service-select-value${selected ? "" : " placeholder"}`}><span className="service-select-name" title={selected?.label}>{selected?.label ?? placeholder}</span>{selected && status(selected)}</span><ChevronDown size={17} aria-hidden="true" /></button>
    <div ref={menuRef} id={id} popover="auto" role="listbox" aria-label={`${label}选项`} className="service-select-menu" onToggle={event => setOpen(event.currentTarget.matches(":popover-open"))} onMouseDown={event => event.preventDefault()}>
      {options.map((option, index) => <div key={option.value} id={`${id}-${index}`} role="option" aria-selected={option.value === value} data-active={highlighted === index} className="service-select-option" onPointerMove={event => { if (event.pointerType === "mouse") setHighlighted(index); }} onClick={() => choose(index)}><span className="service-select-option-name">{option.label}</span>{status(option)}<Check size={18} className="service-select-check" aria-hidden="true" /></div>)}
    </div>
  </div>;
}

/** 表单草稿只驻留内存；跳转配置 Agent / 域名时暂时隐藏，返回后继续填写。 */
function ServiceEditor({ tunnel, data, active, csrf, onClose, onSaved }: { tunnel?: Tunnel; data: ServiceData; active: boolean; csrf?: string | null; onClose: () => void; onSaved: (item: Tunnel) => void }) {
  const request = useApi();
  const initial = useMemo(() => ({ name: tunnel?.name ?? "", protocol: tunnel?.protocol ?? "https", origin_protocol: tunnel?.origin_protocol ?? "http", device_id: tunnel?.device_id ?? data.devices.find(item => item.status === "online")?.id ?? data.devices[0]?.id ?? "", local_address: tunnel?.local_address ?? "127.0.0.1", local_port: String(tunnel?.local_port ?? ""), public_port: String(tunnel?.public_port ?? ""), hostname: tunnel?.hostname ?? "", public_domain_id: tunnel ? data.domains.find(item => item.domain === tunnel.public_domain)?.id ?? "" : data.domains.length === 1 ? data.domains[0].id : "", lan_redirect_enabled: tunnel?.protocol !== "tcp" && (tunnel?.lan_redirect_enabled ?? false) }), []);
  const webProtocol = useRef(tunnel?.protocol !== "tcp" && tunnel?.protocol ? tunnel.protocol : "https");
  const [draft, setDraft] = useState(initial); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [invalidField, setInvalidField] = useState<keyof typeof initial | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const [advancedOpen, setAdvancedOpen] = useState(Boolean(tunnel?.public_port));
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const update = (field: keyof typeof draft, value: string | boolean) => {
    if (field === "protocol" && value !== "tcp") webProtocol.current = String(value);
    setDraft(current => {
      if (field === "protocol" && value === "tcp") return { ...current, protocol: value, lan_redirect_enabled: false };
      return { ...current, [field]: value };
    });
    if (field === invalidField || (invalidField === "local_address" && (field === "lan_redirect_enabled" || field === "protocol"))) { setInvalidField(null); setError(null); }
  };
  const devices = [...data.devices].sort((a, b) => Number(b.status === "online") - Number(a.status === "online"));
  const selectedDomain = data.domains.find(item => item.id === draft.public_domain_id);
  const finalAddress = draft.protocol === "tcp" ? `公网端口 ${draft.public_port || "自动分配"}` : `${draft.protocol}://${draft.hostname || "主机名"}.${selectedDomain?.domain || tunnel?.public_domain || "根域名"}`;
  // 从域名配置返回时，只有一个可用域名即可直接填入，多个域名仍由用户明确选择。
  useEffect(() => { if (!tunnel && data.domains.length === 1) setDraft(current => current.public_domain_id ? current : { ...current, public_domain_id: data.domains[0].id }); }, [data.domains, tunnel]);
  useEffect(() => {
    if (!active) return;
    // 键盘改变可见高度后，将正在编辑的字段留在滚动区内，避免落到固定保存栏下面。
    const reveal = () => requestAnimationFrame(() => { const input = document.activeElement; if (input instanceof HTMLInputElement && formRef.current?.contains(input)) input.scrollIntoView({ block: "nearest" }); });
    window.visualViewport?.addEventListener("resize", reveal);
    return () => window.visualViewport?.removeEventListener("resize", reveal);
  }, [active]);
  function fail(field: keyof typeof draft, message: string) {
    setError(message); setInvalidField(field);
    requestAnimationFrame(() => {
      const input = formRef.current?.elements.namedItem(field) as HTMLElement | null;
      const advanced = input?.closest("details"); if (advanced) advanced.open = true;
      input?.focus({ preventScroll: true }); input?.scrollIntoView({ block: "nearest" });
    });
  }
  const fieldProps = (field: keyof typeof draft) => ({ name: field, "aria-invalid": invalidField === field || undefined, "aria-describedby": invalidField === field ? "service-form-error" : undefined });
  async function save(event: FormEvent) {
    event.preventDefault(); setError(null); setInvalidField(null);
    if (!draft.name.trim()) { fail("name", "请填写服务名称"); return; }
    if (!devices.some(item => item.id === draft.device_id)) { fail("device_id", "请选择已入网的 Agent"); return; }
    if (!draft.local_address.trim()) { fail("local_address", "请填写内网地址"); return; }
    if (!/^\d+$/.test(draft.local_port) || Number(draft.local_port) < 1 || Number(draft.local_port) > 65535) { fail("local_port", "内网端口需要是 1–65535 之间的整数"); return; }
    if (draft.protocol === "tcp" && draft.public_port && (!/^\d+$/.test(draft.public_port) || Number(draft.public_port) < 20000 || Number(draft.public_port) > 29999)) { fail("public_port", "公网端口需要是 20000–29999 之间的整数，留空自动分配"); return; }
    if (draft.protocol !== "tcp" && !draft.hostname.trim()) { fail("hostname", "请填写主机名"); return; }
    if (draft.protocol !== "tcp" && !data.domains.some(item => item.id === draft.public_domain_id)) { fail("public_domain_id", "请选择根域名"); return; }
    if (draft.protocol !== "tcp" && draft.lan_redirect_enabled && !isLanRedirectAddress(draft.local_address)) { fail("local_address", "开启内网重定向时，内网地址必须是私有 IPv4 或 IPv6 ULA；回环地址和主机名不能供浏览器直连"); return; }
    setBusy(true);
    try {
      const body = { ...draft, origin_protocol: draft.protocol === "tcp" ? null : draft.origin_protocol, name: draft.name.trim(), local_address: draft.local_address.trim(), local_port: Number(draft.local_port), public_port: draft.protocol === "tcp" && draft.public_port ? Number(draft.public_port) : null, hostname: draft.protocol === "tcp" ? null : draft.hostname.trim(), public_domain_id: draft.protocol === "tcp" ? null : draft.public_domain_id, enabled: tunnel?.enabled ?? true, lan_redirect_enabled: draft.protocol !== "tcp" && draft.lan_redirect_enabled };
      onSaved(await request<Tunnel>(tunnel ? `/api/v1/tunnels/${encodeURIComponent(tunnel.id)}` : "/api/v1/tunnels", { method: tunnel ? "PUT" : "POST", body: JSON.stringify(body) }, csrf));
      onClose();
    } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  if (!active) return null;
  return <Modal title={tunnel ? "编辑服务" : "创建服务"} full dirty={dirty} busy={busy} onClose={onClose}>
    <form ref={formRef} onSubmit={save} noValidate className="modal-form service-form" onKeyDown={event => {
      // 软键盘的“下一项”只切换文本字段，最后一项收起键盘，避免误触 Enter 直接提交。
      if (event.key !== "Enter" || event.nativeEvent.isComposing || !(event.target instanceof HTMLInputElement) || event.target.type === "radio" || event.target.type === "checkbox") return;
      event.preventDefault();
      const inputs = Array.from(formRef.current!.querySelectorAll<HTMLInputElement>('input:not([type="radio"]):not([type="checkbox"]):not(:disabled)')).filter(input => !input.closest("details:not([open])") && input.getClientRects().length > 0);
      const next = inputs[inputs.indexOf(event.target) + 1];
      if (next) { next.focus(); next.scrollIntoView({ block: "nearest" }); } else event.target.blur();
    }}>
      <div className="modal-body"><fieldset disabled={busy}>
        <fieldset className="protocol-picker"><legend className="sr-only">服务类型</legend>{[["web", "网页服务"], ["tcp", "TCP 服务"]].map(([type, label]) => <label className="protocol-option" key={type}><input type="radio" name="service_type" value={type} checked={(draft.protocol === "tcp" ? "tcp" : "web") === type} disabled={Boolean(tunnel && !tunnel.public_domain && type === "web")} onChange={() => update("protocol", type === "tcp" ? "tcp" : webProtocol.current)} /><span>{label}</span></label>)}</fieldset>
        <section className="service-form-section"><div className="service-field-group">
          <label className="service-field"><span>服务名称</span><input {...fieldProps("name")} value={draft.name} onChange={e => update("name", e.target.value)} placeholder="例如：家庭 NAS" enterKeyHint="next" autoComplete="off" required /></label>
          <ServiceSelect {...fieldProps("device_id")} label="Agent" value={draft.device_id} placeholder="选择 Agent" options={devices.map(item => ({ value: item.id, label: item.name, status: item.status === "online" ? "online" : "offline" }))} disabled={busy} onChange={value => update("device_id", value)} />
        </div>{!devices.length && <div className="notice"><span>请先接入一台 Agent。</span><button type="button" className="text-button" onClick={() => navigate("#/agents", true)}>配置 Agent</button></div>}{devices.find(item => item.id === draft.device_id)?.status === "offline" && <p className="helper" role="status">Agent 当前离线，可保存配置，连接恢复后下发。</p>}</section>
        <section className="service-form-section"><h3>内网地址</h3><div className="service-field-group service-address-input" role="group" aria-label="内网连接">
          {draft.protocol === "tcp" ? <span className="service-fixed-protocol">TCP</span> : <select aria-label="内网协议" {...fieldProps("origin_protocol")} value={draft.origin_protocol} onChange={e => update("origin_protocol", e.target.value)}><option value="http">HTTP</option><option value="https">HTTPS</option></select>}
          <input aria-label="内网地址" {...fieldProps("local_address")} value={draft.local_address} onChange={e => update("local_address", e.target.value)} placeholder="IP 或主机名" inputMode="url" enterKeyHint="next" autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false} required />
          <span className="service-address-separator" aria-hidden="true">:</span>
          <input aria-label="内网端口" {...fieldProps("local_port")} value={draft.local_port} onChange={e => update("local_port", e.target.value)} placeholder="端口" type="text" inputMode="numeric" enterKeyHint={draft.protocol === "tcp" ? "done" : "next"} autoComplete="off" required />
        </div></section>
        {draft.protocol === "tcp" ? <details className="service-advanced" open={advancedOpen} onToggle={event => setAdvancedOpen(event.currentTarget.open)}><summary><span>公网端口</span><span>{draft.public_port || "自动分配"}</span><ChevronRight size={17} /></summary><label className="service-field"><span>指定端口</span><input {...fieldProps("public_port")} aria-label="公网端口" type="text" inputMode="numeric" enterKeyHint="done" autoComplete="off" value={draft.public_port} onChange={e => update("public_port", e.target.value)} placeholder="留空自动分配" /></label><p className="helper">可填写 20000–29999，通常无需修改。</p></details> : <section className="service-form-section"><h3 id="service-public-label">公网入口</h3><div className="service-field-group service-public-input" role="group" aria-labelledby="service-public-label">
          <select aria-label="公网协议" {...fieldProps("protocol")} value={draft.protocol} onChange={e => update("protocol", e.target.value)}><option value="https">HTTPS</option><option value="http">HTTP</option></select>
          <input aria-label="主机名" {...fieldProps("hostname")} value={draft.hostname} onChange={e => update("hostname", e.target.value)} placeholder="主机名" enterKeyHint="done" autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false} required />
          <span className="service-address-separator" aria-hidden="true">.</span>
          <ServiceSelect compact {...fieldProps("public_domain_id")} label="根域名" value={draft.public_domain_id} placeholder="选择域名" options={data.domains.map(item => ({ value: item.id, label: item.domain }))} disabled={busy || Boolean(tunnel)} onChange={value => update("public_domain_id", value)} />
        </div>{!data.domains.length && <div className="notice"><span>网页服务需要根域名。</span><button type="button" className="text-button" onClick={() => navigate("#/domains", true)}>添加域名</button></div>}{tunnel && <p className="helper">现有服务保留原根域名；更换根域名请创建新服务。</p>}</section>}
        {draft.protocol !== "tcp" && <section className="service-form-section"><div className="service-field-group">
          <label className="service-field service-toggle-field"><span>内网重定向</span><span className="service-switch"><input {...fieldProps("lan_redirect_enabled")} type="checkbox" role="switch" checked={draft.lan_redirect_enabled} onChange={e => update("lan_redirect_enabled", e.target.checked)} /><span className="service-switch-track" aria-hidden="true" /></span></label>
        </div>{draft.protocol === "http" && draft.lan_redirect_enabled && <p className="helper" role="status">部分浏览器访问 HTTP 域名时无法触发重定向，建议使用 HTTPS。</p>}</section>}
        {tunnel && !tunnel.public_domain && <p className="helper">此服务未绑定域名；需要网页访问时，请创建新服务。</p>}
      </fieldset></div>
      <footer className="modal-actions">{draft.protocol !== "tcp" && <div className="service-submit-preview"><span>访问地址</span><code>{finalAddress}</code></div>}{error && <p id="service-form-error" className="form-error" role="alert">{error}</p>}<button type="submit" className="primary-button" disabled={busy || !devices.length || (draft.protocol !== "tcp" && !data.domains.length)}>{busy ? "保存中…" : "保存服务"}</button></footer>
    </form>
  </Modal>;
}

/** 列表在二级详情和其他页之间保持挂载，保存筛选、选择和表单草稿。 */
export function ServicesPage({ route, active, csrf }: { route: string; active: boolean; csrf?: string | null }) {
  const request = useApi();
  const resource = useResource(() => loadServices(request), active);
  const [protocol, setProtocol] = useState("all"); const [agent, setAgent] = useState("all");
  const [query, setQuery] = useState(""); const [filter, setFilter] = useState("all"); const [selecting, setSelecting] = useState(false); const [selected, setSelected] = useState<string[]>([]);
  const [editor, setEditor] = useState<Tunnel | "new" | null>(null); const [busy, setBusy] = useState(false); const [actionError, setActionError] = useState<string | null>(null); const [message, setMessage] = useState<string | null>(null); const [deleting, setDeleting] = useState<Tunnel[] | null>(null);
  const data = resource.data;
  const tunnels = data?.tunnels ?? [];
  const detailId = route.startsWith("#/services/") ? route.slice("#/services/".length) : null;
  const detail = tunnels.find(item => encodeURIComponent(item.id) === detailId);
  const detailDomain = data?.domains.find(item => item.domain === detail?.public_domain);
  const matching = tunnels.filter(item => !query || `${item.name} ${item.device_name ?? ""} ${item.public_address ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  const matchesFilter = (item: Tunnel, value: string) => value === "all" || (value === "web" ? item.protocol !== "tcp" : value === "attention" ? ["failed", "error"].includes(item.apply_status) : value === "disabled" ? !item.enabled : item.enabled);
  const visible = matching.filter(item => matchesFilter(item, filter) && (protocol === "all" || (protocol === "web" ? item.protocol !== "tcp" : item.protocol === "tcp")) && (agent === "all" || item.device_id === agent));
  useEffect(() => { if (data) { setSelected(current => current.filter(id => data.tunnels.some(item => item.id === id))); if (!data.tunnels.length) setSelecting(false); } }, [data]);
  useEffect(() => { document.body.classList.toggle("selection-mode", active && selecting && !detailId); return () => document.body.classList.remove("selection-mode"); }, [active, selecting, detailId]);
  const merge = (updated: Tunnel) => resource.setData(current => current && ({ ...current, tunnels: current.tunnels.some(item => item.id === updated.id) ? current.tunnels.map(item => item.id === updated.id ? updated : item) : [updated, ...current.tunnels] }));
  async function toggle(items: Tunnel[], enabled: boolean) {
    setBusy(true); setActionError(null); setMessage(null);
    const failures: string[] = [];
    await Promise.all(items.map(async item => { try { merge(await request<Tunnel>(`/api/v1/tunnels/${encodeURIComponent(item.id)}/${enabled ? "enable" : "disable"}`, { method: "POST" }, csrf)); } catch (e) { failures.push(`${item.name}：${errorText(e)}`); } }));
    setActionError(failures.length ? failures.join("；") : null); setMessage(failures.length ? null : enabled ? "已启用，等待应用配置" : "已关闭服务"); setBusy(false);
  }
  async function remove(items: Tunnel[]) {
    const failures: string[] = [];
    await Promise.all(items.map(async item => { try { await request(`/api/v1/tunnels/${encodeURIComponent(item.id)}`, { method: "DELETE" }, csrf); resource.setData(current => current && ({ ...current, tunnels: current.tunnels.filter(value => value.id !== item.id) })); setSelected(current => current.filter(id => id !== item.id)); } catch (e) { failures.push(`${item.name}：${errorText(e)}`); } }));
    if (failures.length) { setActionError(failures.join("；")); } else { setMessage(`已删除 ${items.length} 个服务`); if (detailId) navigate("#/services", true); }
  }
  return <>
    <PageHeader title={detailId ? "服务详情" : "穿透服务"} subtitle={detailId ? undefined : "管理公网入口与内网服务"} back={detailId ? "#/services" : undefined} action={!detailId && !selecting && Boolean(tunnels.length) && <CreateButton label="服务" onClick={() => { setEditor("new"); setMessage(null); }} />} />
    <Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} /><Notice error={actionError} />{message && <p className="action-status" role="status">{message}</p>}
    {!data && resource.busy && <Loading />}
    {data && (detailId ? detail ? <>
      <section className="panel detail-panel service-detail">
        <div className="detail-heading"><h2 title={detail.name}>{detail.name}</h2><Status value={detail.enabled ? detail.apply_status : "disabled"} /></div>
        <dl>
          <DetailField label="公网地址"><div className="service-detail-address">{detail.public_address && detail.protocol !== "tcp" ? <a className="service-public-link" href={detail.public_address} target="_blank" rel="noopener noreferrer" title="在新标签页打开"><code>{detail.public_address}</code></a> : <code>{detail.public_address ?? "等待配置"}</code>}{detail.public_address && <CopyButton value={detail.public_address} label="复制公网地址" iconOnly />}</div></DetailField>
          <DetailField label="内网地址"><div className="service-detail-address"><code>{localTarget(detail)}</code><CopyButton value={localTarget(detail)} label="复制内网地址" iconOnly /></div></DetailField>
          {detail.protocol !== "tcp" && <DetailField label="内网重定向" className="service-detail-meta">{detail.lan_redirect_enabled ? "已开启" : "未开启"}</DetailField>}
          <DetailField label="服务类型" className="service-detail-meta">{detail.protocol === "tcp" ? "TCP 服务" : "网页服务"}</DetailField>
          <DetailField label="Agent" className="service-detail-meta">{detail.device_id ? <a className="text-link" href={`#/agents/${encodeURIComponent(detail.device_id)}`}>{detail.device_name ?? "查看 Agent"}</a> : "未分配 Agent"}</DetailField>
        </dl>
        {detail.apply_error && <div className="notice error"><strong>转发配置需处理</strong><p>当前服务可能无法访问。请核对 Agent 连接与内网地址；网页服务还需检查域名配置。</p><details><summary>技术详情</summary><p>{detail.apply_error}</p></details></div>}
        {((detail.enabled && detail.apply_status === "ready") || detail.protocol !== "tcp") && <div className="service-detail-note">{detail.enabled && detail.apply_status === "ready" && <span>Agent 已连接，内网地址连接检查已通过。请通过公网地址测试实际访问。</span>}{detail.protocol !== "tcp" && <a className="text-link" href={detailDomain ? `#/domains/${encodeURIComponent(detailDomain.id)}` : "#/domains"}>域名与 DNS</a>}</div>}
        <div className="service-detail-actions"><button className="primary-button" onClick={() => setEditor(detail)}>编辑服务</button><button className="secondary-button" disabled={busy} onClick={() => void toggle([detail], !detail.enabled)}>{busy ? "提交中…" : detail.enabled ? "关闭服务" : "启用服务"}</button><div className="service-detail-danger"><button className="danger-button" onClick={() => setDeleting([detail])}><Trash2 size={18} aria-hidden="true" />删除服务</button></div></div>
      </section>
    </> : <Empty title="服务不存在" detail="该服务可能已被删除。"><a href="#/services" className="secondary-button">返回服务列表</a></Empty> : <>
      {tunnels.length > 0 && <div className="toolbar"><label className="search"><Search size={19} /><input aria-label="搜索穿透服务" placeholder="搜索服务" value={query} onChange={e => setQuery(e.target.value)} /></label><div className="toolbar-row"><select aria-label="服务筛选" value={filter} onChange={e => setFilter(e.target.value)}>{[["all", "全部状态"], ["attention", "需处理"], ["enabled", "已启用"], ["disabled", "已关闭"]].map(([value, label]) => <option key={value} value={value}>{label} {matching.filter(item => matchesFilter(item, value)).length}</option>)}</select><select aria-label="类型筛选" value={protocol} onChange={e => setProtocol(e.target.value)}><option value="all">全部类型</option><option value="web">网页服务</option><option value="tcp">TCP 服务</option></select><select aria-label="Agent 筛选" value={agent} onChange={e => setAgent(e.target.value)}><option value="all">全部 Agent</option>{data.devices.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>{visible.length > 0 && (query || filter !== "all" || protocol !== "all" || agent !== "all") && <button className="text-button" onClick={() => { setQuery(""); setFilter("all"); setProtocol("all"); setAgent("all"); }}>清除筛选</button>}<button className="text-button" onClick={() => { setSelecting(value => !value); setSelected([]); }}>{selecting ? "完成" : "选择"}</button></div></div>}
      {!visible.length ? <Empty kind={tunnels.length ? "search" : "services"} title={tunnels.length ? "没有匹配的服务" : "还没有穿透服务"} detail={tunnels.length ? "试试其他关键词，或清除筛选条件。" : !data.devices.length ? "先接入一台 Agent，让内网应用随时可访问。" : !data.domains.length ? "TCP 服务可直接创建，网页服务需先配置域名。" : "连接 NAS、相册或其他内网应用，从公网轻松访问。"}>{tunnels.length ? <button className="secondary-button" onClick={() => { setQuery(""); setFilter("all"); setProtocol("all"); setAgent("all"); }}>清除筛选</button> : !data.devices.length ? <a href="#/agents" className="primary-button">接入 Agent</a> : <><button className="primary-button" onClick={() => setEditor("new")}>创建第一个服务</button>{!data.domains.length && <a href="#/domains" className="text-button">配置网页域名</a>}</>}</Empty> : <section className={`service-list ${selecting ? "selectable" : ""}`} aria-label="穿透服务列表">{visible.map(item => <article className="service-row" key={item.id}>{selecting && <label className="check"><input type="checkbox" aria-label={`选择${item.name}`} checked={selected.includes(item.id)} onChange={e => setSelected(current => e.target.checked ? [...current, item.id] : current.filter(id => id !== item.id))} /></label>}<div className="service-card-content"><div className="service-title"><a className="service-name" href={`#/services/${encodeURIComponent(item.id)}`}><strong title={item.name}>{item.name}</strong></a><Status value={item.enabled ? item.apply_status : "disabled"} /></div><p className="service-meta" title={`${item.protocol === "tcp" ? "TCP 服务" : "网页服务"} · ${item.device_name ?? "未分配 Agent"}`}>{item.protocol === "tcp" ? "TCP 服务" : "网页服务"} · {item.device_name ?? "未分配 Agent"}</p><div className="service-address"><span>公网</span>{item.public_address ? item.protocol === "tcp" ? <CopyButton value={item.public_address} compact label={`复制${item.name}公网地址`} /> : <><a className="public-address" href={item.public_address} target="_blank" rel="noopener noreferrer" title={item.public_address}>{item.public_address}</a><CopyButton value={item.public_address} iconOnly label={`复制${item.name}公网地址`} /></> : <span className="muted">等待配置</span>}</div><div className="service-origin"><span>内网</span><code title={localTarget(item)}>{localTarget(item)}</code><a className="icon-button" aria-label={`查看${item.name}详情`} href={`#/services/${encodeURIComponent(item.id)}`}><ChevronRight size={18} /></a></div>{item.apply_error && <a className="row-error" href={`#/services/${encodeURIComponent(item.id)}`}><span>{item.apply_error}</span>查看 <ChevronRight size={15} /></a>}</div></article>)}</section>}
      {selecting && <div className="batch-actions"><span aria-live="polite">已选择 {selected.length} 项</span><div><button className="secondary-button" disabled={!selected.length || busy} onClick={() => void toggle(tunnels.filter(item => selected.includes(item.id)), true)}>启用</button><button className="secondary-button" disabled={!selected.length || busy} onClick={() => void toggle(tunnels.filter(item => selected.includes(item.id)), false)}>关闭</button><button className="danger-button" disabled={!selected.length || busy} onClick={() => setDeleting(tunnels.filter(item => selected.includes(item.id)))}>删除</button></div></div>}
    </>)}
    {editor && data && <ServiceEditor active={active} tunnel={editor === "new" ? undefined : editor} data={data} csrf={csrf} onClose={() => setEditor(null)} onSaved={item => { merge(item); setMessage("配置已保存"); }} />}
    {deleting && active && <Confirm title={deleting.length === 1 ? `删除 ${deleting[0].name}？` : `删除 ${deleting.length} 个服务？`} description="删除后将立即停止新的连接，此操作无法撤销。" label="删除服务" onClose={() => setDeleting(null)} onConfirm={() => remove(deleting.filter(item => tunnels.some(current => current.id === item.id)))} />}
  </>;
}
