import type { NodeGroup } from "./node-groups";
import "./nodes.css";
import type { NodeList } from "./nodes";
import { ApplicationModal } from "./application-modal";
import { ServiceIcon, ServiceIconPicker } from "./service-icons";
import { PageNavigationContext, useResourceDeletions } from "./navigation";
import { useContext, useEffect, useId, useMemo, useRef, useState } from "react";
import type { FormEvent, MouseEvent as ReactMouseEvent, PointerEvent as ReactPointerEvent } from "react";
import { Check, CircleCheck, ChevronDown, ChevronRight, Globe, Power, PowerOff, Plus, Search, Server, Trash2 } from "./icons";
import { Confirm, CopyButton, CreateButton, currentCreateButton, DetailField, Empty, Loading, Modal, Notice, PageHeader, Status, errorText, isPortProtocol, protocolLabel, localTarget, useApi, useResource } from "./ui";
import type { Device, Domain, Tunnel } from "./ui";
import { isLanRedirectAddress } from "./lan-redirect";

type ServiceData = { tunnels: Tunnel[]; devices: Device[]; domains: Domain[] };
const loadServices = async (request: ReturnType<typeof useApi>): Promise<ServiceData> => { const [tunnels, devices, domains] = await Promise.all([request<Tunnel[]>("/api/v1/tunnels"), request<Device[]>("/api/v1/devices"), request<Domain[]>("/api/v1/public-domains")]); return { tunnels, devices, domains: domains.filter(domain => domain.verification_status !== "pending") }; };
const hasServiceDomain = (item: Tunnel) => ["http", "https", "tcp"].includes(item.protocol) && Boolean(item.public_domain && item.hostname);

type ServiceSelectOption = { value: string; label: string; status?: "online" | "offline"; disabled?: boolean };

/** 服务表单共享原生顶层浮层，避免被 dialog 的滚动区裁切。焦点留在触发按钮，键盘跳过禁用项，确认后才修改草稿。 */
function ServiceSelect({ label, name, value, placeholder, options, disabled, compact = false, menuMinWidth = compact ? 360 : 0, onChange, ...validation }: {
  label: string; name: string; value: string; placeholder: string; options: ServiceSelectOption[]; disabled?: boolean; compact?: boolean; menuMinWidth?: number;
  onChange: (value: string) => void; "aria-invalid"?: boolean; "aria-describedby"?: string;
}) {
  const id = useId();
  const triggerRef = useRef<HTMLButtonElement>(null); const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false); const [highlighted, setHighlighted] = useState(0);
  const selected = options.find(option => option.value === value);
  const enabledIndexes = options.flatMap((option, index) => option.disabled ? [] : [index]);
  const unavailable = disabled || !enabledIndexes.length;
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
    // 紧凑触发器按内容保留菜单最小宽度，协议无需占满地址行，长域名仍可完整阅读。
    const width = Math.min(Math.max(row.width, menuMinWidth), right - left);
    menu.style.width = `${width}px`; menu.style.left = `${Math.max(left, Math.min(row.left, right - width))}px`;
    const desired = Math.min(menu.scrollHeight + 2, 300);
    const below = Math.max(0, bottom - row.bottom - 6); const above = Math.max(0, row.top - top - 6);
    const down = below >= desired || below >= above;
    const height = Math.min(desired, down ? below : above);
    menu.style.maxHeight = `${height}px`;
    menu.style.top = `${down ? row.bottom + 6 : row.top - 6 - height}px`;
  }
  function show() {
    if (unavailable) return;
    const selectedIndex = options.findIndex(option => option.value === value && !option.disabled);
    setHighlighted(selectedIndex < 0 ? enabledIndexes[0] : selectedIndex);
    triggerRef.current?.scrollIntoView({ block: compact ? "end" : "nearest" });
    triggerRef.current?.focus({ preventScroll: true });
    menuRef.current?.showPopover(); position(); setOpen(true);
  }
  function choose(index: number) {
    if (unavailable || !options[index] || options[index].disabled) return;
    onChange(options[index].value);
    close(true);
  }
  useEffect(() => { if (unavailable) close(); }, [unavailable]);
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
    // 表单高度变化可能产生小数像素，保留菜单内边距，避免末项被裁掉半个像素。
    if (option.offsetTop < menu.scrollTop + 6) menu.scrollTop = option.offsetTop - 6;
    else if (option.offsetTop + option.offsetHeight > menu.scrollTop + menu.clientHeight - 6) menu.scrollTop = Math.ceil(option.offsetTop + option.offsetHeight - menu.clientHeight + 6);
  }, [open, highlighted]);
  const status = (option: ServiceSelectOption) => option.status && <span className={`service-select-status ${option.status}`}><i aria-hidden="true" />{option.status === "online" ? "在线" : "离线"}</span>;
  return <div className={`service-field service-select-field${compact ? " service-select-compact" : ""}`}>
    <button ref={triggerRef} type="button" role="combobox" name={name} value={value} className="service-select-trigger" aria-label={label} aria-haspopup="listbox" aria-expanded={open} aria-controls={id} aria-activedescendant={open ? `${id}-${highlighted}` : undefined} aria-required="true" {...validation} disabled={unavailable} onClick={() => open ? close() : show()} onKeyDown={event => {
      if (event.nativeEvent.isComposing) return;
      if (event.key === "Tab") { close(); return; }
      if (event.key === "Escape" && open) { event.preventDefault(); event.stopPropagation(); close(true); return; }
      if (["Enter", " ", "ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
        event.preventDefault();
        if (!open) { show(); return; }
        if (event.key === "Enter" || event.key === " ") choose(highlighted);
        else setHighlighted(current => {
          const next = event.key === "Home" ? 0 : event.key === "End" ? enabledIndexes.length - 1 : enabledIndexes.indexOf(current) + (event.key === "ArrowDown" ? 1 : -1);
          return enabledIndexes[Math.max(0, Math.min(enabledIndexes.length - 1, next))];
        });
      }
    }}><span className={compact ? "sr-only" : "service-select-caption"}>{label}</span><span className={`service-select-value${selected ? "" : " placeholder"}`}><span className="service-select-name" title={selected?.label}>{selected?.label ?? placeholder}</span>{selected && status(selected)}</span><ChevronDown size={17} aria-hidden="true" /></button>
    <div ref={menuRef} id={id} popover="auto" role="listbox" aria-label={`${label}选项`} className="service-select-menu" onToggle={event => setOpen(event.currentTarget.matches(":popover-open"))} onMouseDown={event => event.preventDefault()}>
      {options.map((option, index) => <div key={option.value} id={`${id}-${index}`} role="option" aria-selected={option.value === value} aria-disabled={option.disabled || undefined} data-active={!option.disabled && highlighted === index} className="service-select-option" onPointerMove={event => { if (event.pointerType === "mouse" && !option.disabled) setHighlighted(index); }} onClick={() => choose(index)}><span className="service-select-option-name">{option.label}</span>{status(option)}<Check size={18} className="service-select-check" aria-hidden="true" /></div>)}
    </div>
  </div>;
}

/** 表单草稿只驻留内存；跳转配置 Agent / 域名时暂时隐藏，返回后继续填写。 */
function ServiceEditor({ tunnel, mode, data, active, csrf, onClose, onSaved }: { tunnel?: Tunnel; mode: "tunnel" | "reverse_proxy"; data: ServiceData; active: boolean; csrf?: string | null; onClose: () => void; onSaved: (item: Tunnel) => void }) {
  const request = useApi();
  const initial = useMemo(() => ({ node_group_id: tunnel?.node_group_id ?? "", node_ids: tunnel?.node_ids ?? ["local"], distribution_mode: tunnel?.distribution_mode ?? "single", preferred_node_id: tunnel?.preferred_node_id ?? "", icon_id: tunnel?.icon_id ?? "", ipv6_direct_enabled: tunnel?.ipv6_direct_enabled ?? false, https_port: String(tunnel?.https_port ?? 443), http_redirect_enabled: tunnel ? tunnel.http_redirect_enabled ?? false : mode === "reverse_proxy", access_mode: tunnel?.access_mode ?? "public", access_password: "", service_mode: tunnel?.service_mode ?? mode, name: tunnel?.name ?? "", protocol: tunnel?.protocol ?? "https", origin_protocol: tunnel?.origin_protocol ?? "http", device_id: tunnel?.device_id ?? data.devices.find(item => item.status === "online")?.id ?? data.devices[0]?.id ?? "", local_address: tunnel?.local_address ?? "127.0.0.1", local_port: String(tunnel?.local_port ?? ""), public_port: String(tunnel?.public_port ?? ""), hostname: tunnel?.hostname ?? "", public_domain_id: tunnel ? data.domains.find(item => item.domain === tunnel.public_domain)?.id ?? "" : data.domains.length === 1 ? data.domains[0].id : "", lan_redirect_enabled: !isPortProtocol(tunnel?.protocol) && (tunnel?.lan_redirect_enabled ?? false) }), []);
  const webProtocol = useRef(!isPortProtocol(tunnel?.protocol) && tunnel?.protocol ? tunnel.protocol : "https");
  const [draft, setDraft] = useState(initial); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [invalidField, setInvalidField] = useState<keyof typeof initial | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const [advancedOpen, setAdvancedOpen] = useState(Boolean(tunnel?.public_port));
  const direct = draft.service_mode === "reverse_proxy";
  const nodeData = useResource(() => request<NodeList>("/api/v1/nodes"), active && !direct, false);
  const nodeGroups = useResource(() => request<NodeGroup[]>("/api/v1/node-groups"), active && !direct, false);
  const nodeSupported = !direct && ["http", "https", "tcp"].includes(draft.protocol);
  const remoteTcp = draft.protocol === "tcp" && draft.node_ids.some(id => id !== "local");
  const ipv6 = useResource(() => request<{ addresses: string[]; selected_address: string | null; supported: boolean }>(`/api/v1/devices/${encodeURIComponent(draft.device_id)}/ipv6`), active && !direct && draft.protocol === "https" && Boolean(draft.device_id), true, true);
  useEffect(() => { ipv6.setData(null); if (active && !direct && draft.protocol === "https" && draft.device_id) void ipv6.reload(); }, [draft.device_id]);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const metadataOnly = Boolean(tunnel) && (Object.keys(initial) as (keyof typeof initial)[]).every(field => field === "name" || field === "icon_id" || draft[field] === initial[field]);
  const update = (field: keyof typeof draft, value: string | boolean | string[]) => {
    if (field === "protocol" && !isPortProtocol(String(value))) webProtocol.current = String(value);
    setDraft(current => {
      if (field === "protocol" && typeof value === "string" && isPortProtocol(value)) return { ...current, protocol: value, ...(value !== "tcp" ? { node_group_id: "", node_ids: ["local"], distribution_mode: "single", preferred_node_id: "" } : {}), ipv6_direct_enabled: false, lan_redirect_enabled: false, access_mode: "public", access_password: "" };
      if (field === "protocol" && value === "http") return { ...current, protocol: "http", ipv6_direct_enabled: false };
      if (field === "access_mode" && value === "public") return { ...current, access_mode: "public", access_password: "" };
      return { ...current, [field]: value };
    });
    if (field === invalidField || (invalidField === "access_password" && (field === "access_mode" || (field === "protocol" && isPortProtocol(String(value))))) || (invalidField === "local_address" && (field === "lan_redirect_enabled" || field === "protocol"))) { setInvalidField(null); setError(null); }
  };
  const devices = [...data.devices].sort((a, b) => Number(b.status === "online") - Number(a.status === "online"));
  // 地址行统一选择内网协议；网页服务的公网协议独立保存，跨类型返回时恢复原选择。
  function updateOriginProtocol(value: string) {
    if (isPortProtocol(value)) update("protocol", value);
    else {
      if (isPortProtocol(draft.protocol)) update("protocol", webProtocol.current);
      update("origin_protocol", value);
    }
  }
  const selectedDomain = data.domains.find(item => item.id === draft.public_domain_id);
  const finalAddress = isPortProtocol(draft.protocol) ? `公网端口 ${draft.public_port || "自动分配"}` : `${draft.protocol}://${draft.hostname || "主机名"}.${selectedDomain?.domain || tunnel?.public_domain || "根域名"}${draft.protocol === "https" && draft.https_port !== "443" ? `:${draft.https_port}` : ""}`;
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
    if (!direct && !devices.some(item => item.id === draft.device_id)) { fail("device_id", "请选择已入网的设备"); return; }
    if (draft.ipv6_direct_enabled && (direct || draft.protocol !== "https" || draft.lan_redirect_enabled)) { fail("ipv6_direct_enabled", "直连需使用 HTTPS，并关闭内网重定向"); return; }
    if (!metadataOnly && draft.ipv6_direct_enabled && !ipv6.data?.supported) { fail("ipv6_direct_enabled", "请连接或升级设备"); return; }
    if (draft.protocol === "https" && (!/^\d+$/.test(draft.https_port) || Number(draft.https_port) < 1 || Number(draft.https_port) > 65535)) { fail("https_port", "请输入 1–65535 的整数端口"); return; }
    if (!draft.local_address.trim()) { fail("local_address", direct ? "请填写目标地址" : "请填写内网地址"); return; }
    if (!/^\d+$/.test(draft.local_port) || Number(draft.local_port) < 1 || Number(draft.local_port) > 65535) { fail("local_port", `${direct ? "目标" : "内网"}端口需要是 1–65535 之间的整数`); return; }
    if (isPortProtocol(draft.protocol) && draft.public_port && (!/^\d+$/.test(draft.public_port) || Number(draft.public_port) < 20000 || Number(draft.public_port) > 29999)) { fail("public_port", "公网端口需要是 20000–29999 之间的整数，留空自动分配"); return; }
    if (nodeSupported && (draft.node_ids.length === 0 || (draft.distribution_mode !== "single" && draft.node_ids.length < 2))) { fail("node_ids", "多节点至少选择两个授权节点，单节点需选择一个节点"); return; }
    if ((!isPortProtocol(draft.protocol) || remoteTcp) && !draft.hostname.trim()) { fail("hostname", "请填写主机名"); return; }
    if ((!isPortProtocol(draft.protocol) || remoteTcp) && !data.domains.some(item => item.id === draft.public_domain_id)) { fail("public_domain_id", "请选择根域名"); return; }
    if (!isPortProtocol(draft.protocol) && draft.lan_redirect_enabled && !isLanRedirectAddress(draft.local_address)) { fail("local_address", "开启内网重定向时，内网地址必须是私有 IPv4 或 IPv6 ULA；回环地址和主机名不能供浏览器直连"); return; }
    if (draft.access_mode === "password" && (draft.access_password || tunnel?.access_mode !== "password") && !/^[!-~]{4,16}$/.test(draft.access_password)) { fail("access_password", "请输入 4–16 位字母、数字或符号，不含空格"); return; }
    setBusy(true);
    try {
      const body = { ...draft, icon_id: draft.icon_id || null, https_port: Number(draft.https_port), access_password: draft.access_mode === "password" && draft.access_password ? draft.access_password : undefined, device_id: direct ? null : draft.device_id, origin_protocol: isPortProtocol(draft.protocol) ? null : draft.origin_protocol, name: draft.name.trim(), local_address: draft.local_address.trim(), local_port: Number(draft.local_port), public_port: isPortProtocol(draft.protocol) && draft.public_port ? Number(draft.public_port) : null, hostname: isPortProtocol(draft.protocol) && !remoteTcp ? null : draft.hostname.trim(), public_domain_id: isPortProtocol(draft.protocol) && !remoteTcp ? null : draft.public_domain_id, enabled: tunnel?.enabled ?? true, lan_redirect_enabled: !isPortProtocol(draft.protocol) && draft.lan_redirect_enabled };
      onSaved(await request<Tunnel>(tunnel ? `/api/v1/tunnels/${encodeURIComponent(tunnel.id)}` : "/api/v1/tunnels", { method: tunnel ? "PUT" : "POST", body: JSON.stringify(body) }, csrf));
      onClose();
    } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  if (!active) return null;
  return <Modal title={tunnel ? "编辑服务" : direct ? "添加反向代理" : "创建服务"} full dirty={dirty} busy={busy} onClose={onClose}>{close =>
    <form ref={formRef} onSubmit={save} noValidate className="modal-form service-form" onKeyDown={event => {
      // 软键盘的“下一项”只切换文本字段，最后一项收起键盘，避免误触 Enter 直接提交。
      if (event.key !== "Enter" || event.nativeEvent.isComposing || !(event.target instanceof HTMLInputElement) || event.target.type === "radio" || event.target.type === "checkbox") return;
      event.preventDefault();
      const inputs = Array.from(formRef.current!.querySelectorAll<HTMLInputElement>('input:not([type="radio"]):not([type="checkbox"]):not(:disabled)')).filter(input => !input.closest("details:not([open])") && input.getClientRects().length > 0);
      const next = inputs[inputs.indexOf(event.target) + 1];
      if (next) { next.focus(); next.scrollIntoView({ block: "nearest" }); } else event.target.blur();
    }}>
      <div className="modal-body"><fieldset disabled={busy}>
        {direct && <p className="helper">由 Nexo Server 直接访问目标，无需设备。仅管理员可管理，不计入穿透流量。</p>}
        <section className="service-form-section"><h3 className="desktop-form-label">基本信息</h3><div className="service-field-group">
          <div className="application-name-row"><ServiceIconPicker value={draft.icon_id} name={draft.name} protocol={draft.protocol} onChange={value => update("icon_id", value)} /><label className="service-field"><span>服务名称</span><input {...fieldProps("name")} value={draft.name} onChange={e => update("name", e.target.value)} placeholder="例如：家庭 NAS" enterKeyHint="next" autoComplete="off" required /></label></div>
          {!direct && <ServiceSelect {...fieldProps("device_id")} label="设备" value={draft.device_id} placeholder="选择设备" options={devices.map(item => ({ value: item.id, label: item.name, status: item.status === "online" ? "online" : "offline" }))} disabled={busy} onChange={value => update("device_id", value)} />}
        </div>{!direct && !devices.length && <div className="notice"><span>请关闭表单，到设备页添加设备。</span></div>}{!direct && devices.find(item => item.id === draft.device_id)?.status === "offline" && <p className="helper" role="status">设备当前离线，可保存配置，连接恢复后下发。</p>}</section>
        <section className="service-form-section"><h3>{direct ? "目标地址" : "内网地址"}</h3><div className="service-field-group service-address-input" role="group" aria-label={direct ? "目标连接" : "内网连接"}>
          <ServiceSelect compact menuMinWidth={160} label={direct ? "目标协议" : "内网协议"} {...fieldProps("origin_protocol")} value={isPortProtocol(draft.protocol) ? draft.protocol : draft.origin_protocol} placeholder="选择协议" disabled={busy} options={[{ value: "http", label: "HTTP", disabled: Boolean(!direct && tunnel && !tunnel.public_domain) }, { value: "https", label: "HTTPS", disabled: Boolean(!direct && tunnel && !tunnel.public_domain) }, ...(!direct ? [{ value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }, { value: "tcp_udp", label: "TCP+UDP" }] : [])]} onChange={updateOriginProtocol} />
          <input aria-label={direct ? "目标地址" : "内网地址"} {...fieldProps("local_address")} value={draft.local_address} onChange={e => update("local_address", e.target.value)} placeholder="IP 或主机名" inputMode="url" enterKeyHint="next" autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false} required />
          <span className="service-address-separator" aria-hidden="true">:</span>
          <input aria-label={direct ? "目标端口" : "内网端口"} {...fieldProps("local_port")} value={draft.local_port} onChange={e => update("local_port", e.target.value)} placeholder="端口" type="text" inputMode="numeric" enterKeyHint={isPortProtocol(draft.protocol) ? "done" : "next"} autoComplete="off" required />
        </div></section>
        {isPortProtocol(draft.protocol) ? <details className="service-advanced" open={advancedOpen} onToggle={event => setAdvancedOpen(event.currentTarget.open)}><summary><span>公网端口</span><span>{draft.public_port || "自动分配"}</span><ChevronRight size={17} /></summary><label className="service-field"><span>指定端口</span><input {...fieldProps("public_port")} aria-label="公网端口" type="text" inputMode="numeric" enterKeyHint="done" autoComplete="off" value={draft.public_port} onChange={e => update("public_port", e.target.value)} placeholder="留空自动分配" /></label><p className="helper">可用范围：20000–29999。</p></details> : <section className="service-form-section"><h3 id="service-public-label">公网入口</h3><div className="service-field-group service-public-input" role="group" aria-labelledby="service-public-label">
          <ServiceSelect compact menuMinWidth={160} label="公网协议" {...fieldProps("protocol")} value={draft.protocol} placeholder="选择协议" disabled={busy} options={[{ value: "https", label: "HTTPS" }, { value: "http", label: "HTTP" }]} onChange={value => update("protocol", value)} />
          <input aria-label="主机名" {...fieldProps("hostname")} value={draft.hostname} onChange={e => update("hostname", e.target.value)} placeholder="主机名" enterKeyHint="done" autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false} required />
          <span className="service-address-separator" aria-hidden="true">.</span>
          <ServiceSelect compact {...fieldProps("public_domain_id")} label="根域名" value={draft.public_domain_id} placeholder="选择域名" options={data.domains.map(item => ({ value: item.id, label: item.domain }))} disabled={busy} onChange={value => update("public_domain_id", value)} />
        </div>{draft.protocol === "https" && <div className="service-field-group"><label className="service-field"><span>HTTPS 端口</span><input {...fieldProps("https_port")} aria-label="HTTPS 端口" type="text" inputMode="numeric" value={draft.https_port} onChange={e => update("https_port", e.target.value)} placeholder="443" /></label></div>}{!data.domains.length && <div className="notice"><span>网页服务需要域名，请关闭表单后到域名页添加。</span></div>}</section>}
        {nodeSupported && <section className="service-form-section service-node-section"><h3>公网节点</h3><div className="service-field-group">
          <ServiceSelect {...fieldProps("node_group_id")} label="节点来源" value={draft.node_group_id} placeholder="选择来源" disabled={busy} options={[{ value: "", label: "手动选择" }, ...(nodeGroups.data ?? []).filter(group => group.selectable !== false).map(group => ({ value: group.id, label: `${group.name} · ${group.node_ids.length} 个节点` }))]} onChange={value => { const group = nodeGroups.data?.find(g => g.id === value); setDraft(current => ({ ...current, node_group_id: value, ...(group ? { node_ids: group.node_ids, distribution_mode: current.distribution_mode === "single" ? "latency" : current.distribution_mode, preferred_node_id: group.node_ids.includes(current.preferred_node_id) ? current.preferred_node_id : group.node_ids[0] } : {}) })); }} />
          <ServiceSelect {...fieldProps("distribution_mode")} label="选择策略" value={draft.distribution_mode} placeholder="选择策略" disabled={busy} options={[{ value: "single", label: "单节点", disabled: Boolean(draft.node_group_id) }, { value: "dns", label: "DNS 分流" }, { value: "latency", label: "回源延迟优先" }, { value: "manual", label: "主备切换" }]} onChange={value => setDraft(current => ({ ...current, distribution_mode: value, node_ids: value === "single" ? current.node_ids.slice(0, 1) : current.node_ids }))} />
        </div><Notice error={nodeGroups.error} /><Notice error={nodeData.error} onRetry={() => void nodeData.reload()} />
          {draft.node_group_id ? <div><span className="helper">组内节点</span><ul className="node-group-members" aria-label="组内节点">{draft.node_ids.map(id => { const node = nodeData.data?.nodes.find(item => item.id === id); return <li key={id}>{node?.name ?? id}{node && (node.status !== "online" || !node.enabled) && <span className="helper"> · 当前不可用</span>}</li>; })}</ul></div> : <fieldset><legend>可用节点</legend>{(nodeData.data?.nodes ?? []).filter(node => node.approved && node.enabled && node.selectable !== false).map(node => <label className="node-check" key={node.id}><input type={draft.distribution_mode === "single" ? "radio" : "checkbox"} name="node_ids" checked={draft.node_ids.includes(node.id)} onChange={e => setDraft(current => { const ids = current.distribution_mode === "single" ? [node.id] : e.target.checked ? [...current.node_ids, node.id] : current.node_ids.filter(id => id !== node.id); return { ...current, node_ids: ids, preferred_node_id: ids.includes(current.preferred_node_id) ? current.preferred_node_id : ids[0] ?? "" }; })} />{node.name}{node.status !== "online" && " · 当前不可用"}</label>)}</fieldset>}
          {draft.distribution_mode === "manual" && <div className="service-field-group"><ServiceSelect {...fieldProps("preferred_node_id")} label="首选节点" value={draft.preferred_node_id || draft.node_ids[0] || ""} placeholder="选择节点" disabled={busy} options={draft.node_ids.map(id => ({ value: id, label: nodeData.data?.nodes.find(n => n.id === id)?.name ?? id }))} onChange={value => update("preferred_node_id", value)} /></div>}
          {draft.distribution_mode === "latency" && <p className="helper">按设备到节点的实测延迟择优，避免频繁切换。</p>}
          {draft.distribution_mode === "manual" && <p className="helper">首选不可用时切换备用，恢复后自动切回。</p>}
          {draft.distribution_mode !== "single" && <p className="helper">共用同一域名；切换受 DNS 缓存与客户端重连影响，已有连接不会迁移。</p>}
          {remoteTcp && <><label className="service-field"><span>主机名</span><input {...fieldProps("hostname")} value={draft.hostname} onChange={e => update("hostname", e.target.value)} /></label><ServiceSelect {...fieldProps("public_domain_id")} label="根域名" value={draft.public_domain_id} placeholder="选择域名" options={data.domains.map(item => ({ value: item.id, label: item.domain }))} disabled={busy} onChange={value => update("public_domain_id", value)} /><p className="helper">TCP 多节点必须使用域名，直接访问 VPS IP 无法自动切换。</p></>}
        </section>}
        {direct && draft.protocol === "https" && <div className="service-field-group"><label className="service-field service-toggle-field"><span>强制 HTTPS</span><span className="service-switch"><input type="checkbox" role="switch" checked={draft.http_redirect_enabled} onChange={e => update("http_redirect_enabled", e.target.checked)} /><span className="service-switch-track" aria-hidden="true" /></span></label></div>}
        {!direct && draft.protocol === "https" && <section className="service-form-section"><div className="service-field-group"><label className="service-field service-toggle-field"><span>IPv6 直连</span><span className="service-switch"><input {...fieldProps("ipv6_direct_enabled")} type="checkbox" role="switch" checked={draft.ipv6_direct_enabled} disabled={busy || draft.lan_redirect_enabled} onChange={e => update("ipv6_direct_enabled", e.target.checked)} /><span className="service-switch-track" aria-hidden="true" /></span></label></div>{draft.ipv6_direct_enabled && <><Notice error={ipv6.error} onRetry={() => void ipv6.reload()} />{!ipv6.data?.supported ? <p className="helper">请连接或升级设备。</p> : <p className="helper" role="status">{ipv6.data.selected_address ? <>自动选择公网 IPv6：<code>{ipv6.data.selected_address}</code></> : "等待设备自动检测公网 IPv6。"}</p>}<p className="helper">IPv4 转发，IPv6 直连。需配置 DNS 验证，地址变化后自动更新解析，无需另设 DDNS。</p>{draft.access_mode === "password" && <p className="helper">直连仍需访问密码。Emby 客户端建议使用自身认证。</p>}</>}{draft.lan_redirect_enabled && <p className="helper">需先关闭内网重定向。</p>}</section>}
        {!isPortProtocol(draft.protocol) && <details className="service-advanced"><summary><span>高级设置</span><ChevronRight size={17} /></summary><div className="service-advanced-content">
          <section className="service-form-section"><h3>访问规则</h3>
            <fieldset className="protocol-picker"><legend className="sr-only">访问规则</legend>{[["public", "公开访问"], ["password", "认证访问"]].map(([mode, label]) => <label className="protocol-option" key={mode}><input type="radio" name="access_mode" value={mode} checked={draft.access_mode === mode} onChange={() => update("access_mode", mode)} /><span>{label}</span></label>)}</fieldset>
            {draft.access_mode === "password" && <><div className="service-field-group"><label className="service-field"><span>访问密码</span><input {...fieldProps("access_password")} type="password" autoComplete="new-password" value={draft.access_password} onChange={e => update("access_password", e.target.value)} placeholder={tunnel?.access_mode === "password" ? "留空保留原密码" : "4–16 位字母、数字或符号"} /></label></div>{draft.protocol === "http" && <p className="helper" role="status">HTTP 不加密，建议使用 HTTPS</p>}{draft.lan_redirect_enabled && <p className="helper" role="status">内网直达免认证，公网访问需密码</p>}</>}
          </section>
          {!direct && <section className="service-form-section"><div className="service-field-group">
              <label className="service-field service-toggle-field"><span>内网重定向</span><span className="service-switch"><input {...fieldProps("lan_redirect_enabled")} type="checkbox" role="switch" checked={draft.lan_redirect_enabled} disabled={draft.ipv6_direct_enabled} onChange={e => update("lan_redirect_enabled", e.target.checked)} /><span className="service-switch-track" aria-hidden="true" /></span></label>
          </div>{draft.protocol === "http" && draft.lan_redirect_enabled && <p className="helper" role="status">部分浏览器访问 HTTP 域名时无法触发重定向，建议使用 HTTPS。</p>}</section>}
        </div></details>}
        {tunnel && !tunnel.public_domain && <p className="helper">此服务未绑定域名；需要网页访问时，请创建新服务。</p>}
      </fieldset></div>
      <footer className="modal-actions">{!isPortProtocol(draft.protocol) && <div className="service-submit-preview"><span>访问地址</span><code>{finalAddress}</code></div>}{error && <p id="service-form-error" className="form-error" role="alert">{error}</p>}<button type="button" className="secondary-button desktop-modal-cancel modal-dismiss" onClick={close} disabled={busy}>取消</button><button type="submit" className="primary-button" disabled={busy || (!direct && !devices.length) || (!isPortProtocol(draft.protocol) && !data.domains.length)}>{busy ? "保存中…" : "保存服务"}</button></footer>
    </form>}
  </Modal>;
}

/** 批量换设备复用单项更新接口。提交前读取最新配置，逐项保留协议、域名、端口和启停状态；
 * 成功项立即更新并移出待办，失败项留在表单中重试，避免部分成功被误报为整体成功。
 */
function BatchAgentEditor({ items, devices, csrf, onSaved, onClose, onComplete }: { items: Tunnel[]; devices: Device[]; csrf?: string | null; onSaved: (item: Tunnel) => void; onClose: () => void; onComplete: () => void }) {
  const request = useApi();
  const [target, setTarget] = useState(""); const [pending, setPending] = useState(items);
  const [busy, setBusy] = useState(false); const [errors, setErrors] = useState<string[]>([]);
  const [completed, setCompleted] = useState(0);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  async function save(event: FormEvent) {
    event.preventDefault(); if (busy || !target) return;
    setBusy(true); setErrors([]);
    try {
      const latest = await loadServices(request);
      if (!latest.devices.some(item => item.id === target)) throw new Error("目标设备已不存在，请关闭表单并刷新设备列表");
      const failed: Tunnel[] = []; const failures: string[] = [];
      for (const original of pending) {
        if (!mounted.current) return;
        try {
          const item = latest.tunnels.find(item => item.id === original.id);
          if (!item) throw new Error("服务已不存在，请关闭表单并刷新列表");
          const domain = latest.domains.find(domain => domain.domain === item.public_domain);
          if (!isPortProtocol(item.protocol) && !domain) throw new Error("原域名不可用，请先检查该服务的域名配置");
          const updated = item.device_id === target ? item : await request<Tunnel>(`/api/v1/tunnels/${encodeURIComponent(item.id)}`, { method: "PUT", body: JSON.stringify({
            device_id: target, https_port: item.https_port ?? 443, ipv6_direct_enabled: item.ipv6_direct_enabled ?? false, name: item.name, protocol: item.protocol, origin_protocol: isPortProtocol(item.protocol) ? null : item.origin_protocol ?? "http",
            local_address: item.local_address, local_port: item.local_port, public_port: isPortProtocol(item.protocol) ? item.public_port : null,
            hostname: isPortProtocol(item.protocol) ? null : item.hostname, public_domain_id: isPortProtocol(item.protocol) ? null : domain!.id,
            enabled: item.enabled, lan_redirect_enabled: !isPortProtocol(item.protocol) && item.lan_redirect_enabled,
          }) }, csrf);
          if (!mounted.current) return;
          onSaved(updated); setCompleted(value => value + 1);
        } catch (error) { failed.push(original); failures.push(`${original.name}：${errorText(error)}`); }
      }
      if (!mounted.current) return;
      setPending(failed); setErrors(failures);
      if (!failed.length) { onComplete(); onClose(); }
    } catch (error) { if (mounted.current) setErrors([errorText(error)]); }
    finally { if (mounted.current) setBusy(false); }
  }
  return <Modal title="批量修改设备" full dirty={Boolean(target) && pending.length > 0} busy={busy} onClose={onClose}>{close =>
    <form className="modal-form batch-agent-form" onSubmit={save}><div className="modal-body">
      <details className="batch-agent-items"><summary><span>已选 {pending.length} 个服务</span><ChevronDown size={16} aria-hidden="true" /></summary><ul>{pending.map(item => <li key={item.id}>{item.name}</li>)}</ul></details>
      <fieldset className="batch-agent-options" disabled={busy}><legend>选择目标设备</legend>{devices.map(item => <label className="batch-agent-option" key={item.id}>
        <Server size={20} aria-hidden="true" /><span className="batch-agent-name" title={item.name}>{item.name}</span><Status kind="agent" value={item.status} />
        <input type="radio" name="batch-agent-target" aria-label={`${item.name} · ${item.status === "online" ? "在线" : "离线"}`} value={item.id} checked={target === item.id} required onChange={() => setTarget(item.id)} />
      </label>)}</fieldset>
      <p className="helper batch-agent-hint">目标设备需能访问现有内网地址。</p>
      {devices.find(item => item.id === target)?.status === "offline" && <p className="helper batch-agent-hint">设备当前离线，恢复连接后下发配置。</p>}
      {(busy || completed > 0) && <p role="status">已完成 {completed} / {items.length} 项</p>}
      {errors.length > 0 && <div className="notice error batch-agent-errors" role="alert"><p>以下服务未完成，可重试：</p><ul>{errors.map(error => <li key={error}>{error}</li>)}</ul></div>}
    </div><footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel modal-dismiss" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy || !target || !pending.length}>{busy ? "修改中…" : errors.length ? "重试未完成项" : "保存修改"}</button></footer></form>}
  </Modal>;
}

/** 批量换根域名只处理已绑定域名的服务。每次提交读取最新配置，省略图标、密码和节点字段，
 * 由现有接口保留这些配置；成功项退出待办，部分成功后固定目标域名，重试只处理失败项。
 */
function BatchDomainEditor({ items, domains, csrf, onSaved, onClose, onComplete }: { items: Tunnel[]; domains: Domain[]; csrf?: string | null; onSaved: (item: Tunnel) => void; onClose: () => void; onComplete: (completed: number, skipped: number) => void }) {
  const request = useApi();
  const [target, setTarget] = useState(""); const [pending, setPending] = useState(() => items.filter(hasServiceDomain));
  const [skipped, setSkipped] = useState(() => items.filter(item => !hasServiceDomain(item)).length);
  const [busy, setBusy] = useState(false); const [errors, setErrors] = useState<string[]>([]); const [completed, setCompleted] = useState(0);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const verified = domains.filter(domain => domain.verification_status === "verified");
  const selectedDomain = verified.find(domain => domain.id === target);
  function address(item: Tunnel, domain: string) {
    const host = `${item.hostname}.${domain}`;
    // 替换地址中的原主机，保留自定义 HTTP/HTTPS 端口与 TCP 公网端口。
    return item.public_address ? item.public_address.replace(`${item.hostname}.${item.public_domain}`, host) : isPortProtocol(item.protocol) ? `${host}:${item.public_port}` : `${item.protocol}://${host}${item.protocol === "https" && item.https_port && item.https_port !== 443 ? `:${item.https_port}` : ""}`;
  }
  async function save(event: FormEvent) {
    event.preventDefault(); if (busy || !target) return;
    setBusy(true); setErrors([]);
    try {
      const latest = await loadServices(request);
      const domain = latest.domains.find(domain => domain.id === target && domain.verification_status === "verified");
      if (!domain) throw new Error("目标域名已不存在或未完成验证，请关闭表单并刷新域名列表");
      const failed: Tunnel[] = []; const failures: string[] = []; let done = completed; let ignored = skipped;
      for (const original of pending) {
        if (!mounted.current) return;
        const item = latest.tunnels.find(item => item.id === original.id);
        try {
          if (!item) throw new Error("服务已不存在，请关闭表单并刷新列表");
          if (!hasServiceDomain(item)) { ignored++; setSkipped(ignored); continue; }
          const updated = item.public_domain === domain.domain ? item : await request<Tunnel>(`/api/v1/tunnels/${encodeURIComponent(item.id)}`, { method: "PUT", body: JSON.stringify({
            name: item.name, service_mode: item.service_mode ?? "tunnel", device_id: item.device_id ?? null,
            protocol: item.protocol, origin_protocol: isPortProtocol(item.protocol) ? null : item.origin_protocol ?? "http",
            local_address: item.local_address, local_port: item.local_port, public_port: isPortProtocol(item.protocol) ? item.public_port : null,
            hostname: item.hostname, public_domain_id: domain.id, https_port: item.https_port ?? 443,
            ipv6_direct_enabled: item.ipv6_direct_enabled ?? false, access_mode: item.access_mode,
            enabled: item.enabled, lan_redirect_enabled: !isPortProtocol(item.protocol) && item.lan_redirect_enabled,
            http_redirect_enabled: item.http_redirect_enabled ?? false,
          }) }, csrf);
          if (!mounted.current) return;
          onSaved(updated); setCompleted(++done);
        } catch (error) { failed.push(item ?? original); failures.push(`${item?.name ?? original.name}：${errorText(error)}`); }
      }
      if (!mounted.current) return;
      setPending(failed); setErrors(failures);
      if (!failed.length) { onComplete(done, ignored); onClose(); }
    } catch (error) { if (mounted.current) setErrors([errorText(error)]); }
    finally { if (mounted.current) setBusy(false); }
  }
  return <Modal title="批量修改域名" full dirty={Boolean(target) && pending.length > 0} busy={busy} onClose={onClose}>{close =>
    <form className="modal-form batch-domain-form" onSubmit={save}><div className="modal-body">
      <details className="batch-agent-items" open><summary><span>待修改 {pending.length} 个服务</span><ChevronDown size={16} aria-hidden="true" /></summary><ul className="batch-domain-preview">{pending.map(item => <li key={item.id}><strong>{item.name}</strong><code>{address(item, item.public_domain!)}</code>{selectedDomain && <code className="batch-domain-next">→ {address(item, selectedDomain.domain)}</code>}</li>)}</ul></details>
      {skipped > 0 && <p className="helper batch-agent-hint">已跳过 {skipped} 个无域名服务</p>}
      <fieldset className="batch-agent-options" disabled={busy || completed > 0}><legend>选择目标根域名</legend>{verified.map(domain => <label className="batch-agent-option" key={domain.id}><Globe size={20} aria-hidden="true" /><span className="batch-agent-name">{domain.domain}</span><input type="radio" name="batch-domain-target" aria-label={domain.domain} value={domain.id} checked={target === domain.id} required onChange={() => setTarget(domain.id)} /></label>)}</fieldset>
      {!verified.length && <p className="helper batch-agent-hint">请关闭表单后到域名页添加并验证根域名。</p>}
      <p className="helper batch-agent-hint">保留主机名，原访问地址将变更。新地址可用时间受 DNS 与证书更新影响。</p>
      {(busy || completed > 0) && <p role="status">已完成 {completed} / {items.length - skipped} 项</p>}
      {errors.length > 0 && <div className="notice error batch-agent-errors" role="alert"><p>以下服务未完成，可重试：</p><ul>{errors.map(error => <li key={error}>{error}</li>)}</ul></div>}
    </div><footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel modal-dismiss" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy || !selectedDomain || !pending.length}>{busy ? "修改中…" : errors.length ? "重试未完成项" : "保存修改"}</button></footer></form>}
  </Modal>;
}

/** 列表在二级详情和其他页之间保持挂载，保存筛选、选择和表单草稿。 */
export function ServicesPage({ route, active, admin = false, csrf }: { route: string; active: boolean; admin?: boolean; csrf?: string | null; back?: string }) {
  const request = useApi();
  const navigation = useContext(PageNavigationContext);
  const [protocol, setProtocol] = useState("all"); const [agent, setAgent] = useState("all");
  const [query, setQuery] = useState(""); const [filter, setFilter] = useState("all"); const [selecting, setSelecting] = useState(false); const [selected, setSelected] = useState<string[]>([]);
  const [pressing, setPressing] = useState<string | null>(null);
  const press = useRef<{ timer: number; pointer: number; x: number; y: number } | null>(null);
  const longPressed = useRef(false);
  const [editor, setEditor] = useState<Tunnel | "new" | "new-proxy" | null>(null); const [busy, setBusy] = useState(false); const [actionError, setActionError] = useState<string | null>(null); const [message, setMessage] = useState<string | null>(null); const [deleting, setDeleting] = useState<Tunnel[] | null>(null);
  const [changingAgent, setChangingAgent] = useState<Tunnel[] | null>(null);
  const [changingDomain, setChangingDomain] = useState<Tunnel[] | null>(null);
  const [creationMenu, setCreationMenu] = useState(false);
  const creationTrigger = useRef<HTMLButtonElement | null>(null);
  const [detailId, setDetailId] = useState<string | null>(() => route.startsWith("#/services/") ? route.slice("#/services/".length) : null);
  useEffect(() => { if (active && route.startsWith("#/services/")) setDetailId(route.slice("#/services/".length)); }, [active, route]);
  const pendingDetailRoute = useRef<string | null>(null);
  useEffect(() => {
    // 子弹窗的卸载清理先于此 effect，路由不会再被刚关闭的弹窗拦截。
    if (!detailId && pendingDetailRoute.current) { const next = pendingDetailRoute.current; pendingDetailRoute.current = null; window.location.hash = next; }
  }, [detailId]);
  const detailPresentation = useRef<{ origin: HTMLElement | null; trigger: HTMLElement | null; animate: boolean; scroll: number }>({ origin: null, trigger: null, animate: false, scroll: 0 });
  const seenDetail = useRef<string | null>(null);
  const resource = useResource(() => loadServices(request), active && !editor && !deleting && !changingAgent && !changingDomain, true, Boolean(detailId));
  useResourceDeletions(routes => { if (routes.some(route => route.startsWith("#/services/"))) resource.setData(previous => previous && ({ ...previous, tunnels: previous.tunnels.filter(item => !routes.includes(`#/services/${encodeURIComponent(item.id)}`)) })); });
  const data = resource.data;
  const tunnels = data?.tunnels ?? [];
  const detail = tunnels.find(item => encodeURIComponent(item.id) === detailId);
  if (detail) seenDetail.current = detailId;
  function detailFocus() {
    const trigger = detailPresentation.current.trigger;
    if (trigger?.isConnected && !trigger.closest("[hidden]")) return trigger;
    const page = document.querySelector('.page-slot:not([hidden])');
    return page?.querySelector<HTMLElement>('input[aria-label="搜索服务"],.empty .primary-button') ?? null;
  }
  function closeDetail(next?: string) {
    pendingDetailRoute.current = next ?? (route.startsWith("#/services/") ? "#/services" : null);
    setDetailId(null); setActionError(null);
  }
  function openDetail(event: ReactMouseEvent<HTMLAnchorElement>, item: Tunnel) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    detailPresentation.current = { origin: event.currentTarget.closest(".service-row")?.querySelector<HTMLElement>(".application-icon") ?? null, trigger: event.currentTarget, animate: true, scroll: 0 };
    setActionError(null); setMessage(null); setDetailId(encodeURIComponent(item.id));
  }
  const detailProxy = detail?.service_mode === "reverse_proxy";
  const readonlyDetail = detailProxy && !admin;
  const selectedProxy = tunnels.some(item => selected.includes(item.id) && item.service_mode === "reverse_proxy");
  const readonlySelection = selectedProxy && !admin;
  // 手机共用底部添加入口；选择后切换到独立表单，关闭表单时焦点回到加号。
  useEffect(() => { if (!active || navigation?.desktop || detailId || selecting || !admin) setCreationMenu(false); }, [active, navigation?.desktop, detailId, selecting, admin]);
  useEffect(() => {
    if (creationMenu || editor || !creationTrigger.current) return;
    if (active && !detailId && !selecting) (creationTrigger.current.isConnected ? creationTrigger.current : currentCreateButton("服务"))?.focus({ preventScroll: true });
    creationTrigger.current = null;
  }, [creationMenu, editor, active, detailId, selecting]);
  function create(mode: "new" | "new-proxy") { setCreationMenu(false); setEditor(mode); setMessage(null); }
  const detailDomain = data?.domains.find(item => item.domain === detail?.public_domain);
  const matching = tunnels.filter(item => !query || `${item.name} ${item.device_name ?? ""} ${item.public_address ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  const matchesFilter = (item: Tunnel, value: string) => value === "all" || (value === "web" ? !isPortProtocol(item.protocol) : value === "attention" ? ["failed", "error", "partial"].includes(item.apply_status) : value === "disabled" ? !item.enabled : item.enabled);
  const visible = matching.filter(item => matchesFilter(item, filter) && (protocol === "all" || (protocol === "web" ? !isPortProtocol(item.protocol) : item.protocol === protocol)) && (agent === "all" || item.device_id === agent));
  // 全选只作用于当前筛选结果，切换筛选后不把隐藏的服务带入批量操作。
  useEffect(() => { if (data) { setSelected(current => current.filter(id => visible.some(item => item.id === id))); if (!data.tunnels.length) setSelecting(false); } }, [data, query, filter, protocol, agent]);
  useEffect(() => { if (!active) return; document.body.classList.toggle("selection-mode", selecting && !detailId); return () => document.body.classList.remove("selection-mode"); }, [active, selecting, detailId]);
  function cancelPress() { if (press.current) window.clearTimeout(press.current.timer); press.current = null; setPressing(null); }
  function selectionTarget(target: EventTarget) { return target instanceof Element && !target.closest('input,textarea,label,select,code') && (!target.closest('button,a') || Boolean(target.closest('.service-name,.service-open,.application-copy,.application-unavailable'))); }
  function toggleSelected(id: string) { if (!busy) setSelected(current => current.includes(id) ? current.filter(value => value !== id) : [...current, id]); }
  /** 单元空白复用原生图标入口，网页打开新标签页，端口服务复制地址；名称与独立控件不触发访问。
   * 长按与多选已在捕获阶段消费点击，键盘用户仍通过现有链接访问，无需增加嵌套链接。
   */
  function openCard(event: ReactMouseEvent<HTMLElement>) {
    if (selecting || event.defaultPrevented || !(event.target instanceof Element)
      || event.target.closest("a,button,input,textarea,select,label")
      || window.getSelection()?.isCollapsed === false) return;
    event.currentTarget.querySelector<HTMLElement>(".service-open,.application-copy")?.click();
  }
  /** 长按只在手机布局启用；滑动、滚动和多指立即取消计时，不阻止浏览器原生滚动。
   * 成功后吞掉抬手产生的点击，避免进入详情或把刚选中的项再次取消。
   */
  function startPress(event: ReactPointerEvent, id: string) {
    cancelPress(); longPressed.current = false;
    if (!active || navigation?.desktop || selecting || event.button !== 0 || !event.isPrimary || !selectionTarget(event.target)) return;
    setPressing(id);
    press.current = { pointer: event.pointerId, x: event.clientX, y: event.clientY, timer: window.setTimeout(() => {
      longPressed.current = true; setPressing(null); setSelecting(true); setSelected([id]);
    }, 450) };
  }
  useEffect(() => {
    if (!active || navigation?.desktop || detailId) return;
    const scroll = () => cancelPress();
    const anotherPointer = (event: PointerEvent) => { if (press.current && event.pointerId !== press.current.pointer) cancelPress(); };
    window.addEventListener("scroll", scroll, true);
    window.addEventListener("pointerdown", anotherPointer);
    window.addEventListener("blur", scroll);
    return () => { cancelPress(); window.removeEventListener("scroll", scroll, true); window.removeEventListener("pointerdown", anotherPointer); window.removeEventListener("blur", scroll); };
  }, [active, navigation?.desktop, detailId, data, query, filter, protocol, agent]);
  const addProxyButton = admin && <button className="secondary-button service-add-proxy" onClick={() => create("new-proxy")}><Plus size={18} aria-hidden="true" /><span>添加反向代理</span></button>;
  const merge = (updated: Tunnel) => resource.setData(current => current && ({ ...current, tunnels: current.tunnels.some(item => item.id === updated.id) ? current.tunnels.map(item => item.id === updated.id ? updated : item) : [updated, ...current.tunnels] }));
  async function toggle(items: Tunnel[], enabled: boolean) {
    setBusy(true); setActionError(null); setMessage(null);
    try {
      const updated = items.length === 1
        ? [await request<Tunnel>(`/api/v1/tunnels/${encodeURIComponent(items[0].id)}/${enabled ? "enable" : "disable"}`, { method: "POST" }, csrf)]
        : await request<Tunnel[]>(`/api/v1/tunnels/batch/${enabled ? "enable" : "disable"}`, { method: "POST", body: JSON.stringify({ tunnel_ids: items.map(item => item.id) }) }, csrf);
      updated.forEach(merge); setMessage(enabled ? "已启用，等待应用配置" : "已关闭服务");
    } catch (e) { setActionError(errorText(e)); } finally { setBusy(false); }
  }
  async function remove(items: Tunnel[]) {
    if (items.length === 1) await request(`/api/v1/tunnels/${encodeURIComponent(items[0].id)}`, { method: "DELETE" }, csrf);
    else await request("/api/v1/tunnels/batch", { method: "DELETE", body: JSON.stringify({ tunnel_ids: items.map(item => item.id) }) }, csrf);
    const ids = new Set(items.map(item => item.id));
    resource.setData(current => current && ({ ...current, tunnels: current.tunnels.filter(item => !ids.has(item.id)) }));
    setSelected(current => current.filter(id => !ids.has(id)));
    navigation?.removePages(items.map(item => `#/services/${encodeURIComponent(item.id)}`), "#/services");
    setMessage(`已删除 ${items.length} 个服务`);
  }
  const topSearch = Boolean(navigation && (navigation.standalone || !navigation.desktop) && !detailId && tunnels.length);
  const searchRow = <div className="service-search-row"><label className="search"><Search size={19} /><input aria-label="搜索服务" placeholder="搜索服务" value={query} onChange={e => setQuery(e.target.value)} /></label><button className="text-button service-selection-toggle" data-selecting={selecting} disabled={busy} onClick={() => { setSelecting(value => !value); setSelected([]); }}><CircleCheck size={18} aria-hidden="true" /><span>{selecting ? "完成" : "选择"}</span></button></div>;
  return <>
    <PageHeader title={route.startsWith("#/services/") ? detail?.name ?? "服务详情" : "服务"} topContent={topSearch && searchRow} createAction={(navigation?.desktop || !detailId) && !selecting && Boolean(tunnels.length) && (admin && !navigation?.desktop
      ? <button className="primary-button page-create" data-resource="服务" aria-label="添加" aria-haspopup="dialog" aria-expanded={creationMenu} onClick={event => { creationTrigger.current = event.currentTarget; setCreationMenu(true); }}><Plus size={24} aria-hidden="true" /></button>
      : <>{addProxyButton}<CreateButton label="服务" onClick={() => create("new")} /></>)} />
    {!detailId && <><Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} /><Notice error={actionError} />{message && <p className="action-status" role="status">{message}</p>}</>}
    {!data && resource.busy && <Loading />}
    {data && <>
      {tunnels.length > 0 && <div className="toolbar service-toolbar">
        {!topSearch && searchRow}
        <div className="toolbar-row">
          <div className="service-filter-control" data-active={filter !== "all"}><select aria-label="服务筛选" value={filter} onChange={e => setFilter(e.target.value)}>{[["all", "全部状态"], ["attention", "需处理"], ["enabled", "已启用"], ["disabled", "已关闭"]].map(([value, label]) => <option key={value} value={value}>{label}{navigation?.desktop ? ` ${matching.filter(item => matchesFilter(item, value)).length}` : ""}</option>)}</select><ChevronDown size={14} aria-hidden="true" /></div>
          <div className="service-filter-control" data-active={protocol !== "all"}><select aria-label="类型筛选" value={protocol} onChange={e => setProtocol(e.target.value)}><option value="all">全部类型</option><option value="web">网页服务</option><option value="tcp">TCP 服务</option><option value="udp">UDP 服务</option><option value="tcp_udp">TCP+UDP</option></select><ChevronDown size={14} aria-hidden="true" /></div>
          <div className="service-filter-control" data-active={agent !== "all"}><select aria-label="设备筛选" title={agent === "all" ? "全部设备" : data.devices.find(item => item.id === agent)?.name} value={agent} onChange={e => setAgent(e.target.value)}><option value="all">{navigation?.desktop ? "全部设备" : "全部设备"}</option>{data.devices.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><ChevronDown size={14} aria-hidden="true" /></div>
          {visible.length > 0 && (query || filter !== "all" || protocol !== "all" || agent !== "all") && <div className="service-filter-result"><span role="status">找到 {visible.length} 个服务</span><button className="text-button" onClick={() => { setQuery(""); setFilter("all"); setProtocol("all"); setAgent("all"); }}>清除筛选</button></div>}
        </div>
      </div>}
      {!visible.length ? <Empty kind={tunnels.length ? "search" : "services"} title={tunnels.length ? "没有匹配的服务" : "还没有服务"} detail={tunnels.length ? "更换关键词或清除筛选。" : !admin && !data.devices.length ? "先接入设备，再创建服务。" : !data.domains.length ? "TCP/UDP 服务可直接创建，网页服务需先配置域名。" : "通过内网穿透或反向代理访问应用。"}>{tunnels.length ? <button className="secondary-button" onClick={() => { setQuery(""); setFilter("all"); setProtocol("all"); setAgent("all"); }}>清除筛选</button> : !admin && !data.devices.length ? <a href="#/agents" className="primary-button">接入设备</a> : <><button className="primary-button" onClick={() => setEditor("new")}>创建服务</button>{addProxyButton}{!data.domains.length && <a href="#/domains" className="text-button">配置网页域名</a>}</>}</Empty> : <section className={`service-list ${selecting ? "selectable" : ""}`} aria-label="服务列表">{visible.map(item => <article className="service-row" key={item.id} onClick={openCard} data-opens-application={!selecting && item.enabled && Boolean(item.public_address)} data-pressing={pressing === item.id} data-selected={selecting && selected.includes(item.id)} onPointerDown={event => startPress(event, item.id)} onPointerMove={event => { const current = press.current; if (current && (current.pointer !== event.pointerId || Math.hypot(event.clientX - current.x, event.clientY - current.y) > 10)) cancelPress(); }} onPointerUp={cancelPress} onPointerCancel={cancelPress} onPointerLeave={cancelPress} onContextMenu={event => { if (longPressed.current || press.current) event.preventDefault(); }} onClickCapture={event => { if (longPressed.current) { longPressed.current = false; event.preventDefault(); event.stopPropagation(); } else if (selecting && event.target instanceof Element && !event.target.closest("input,label")) { event.preventDefault(); event.stopPropagation(); toggleSelected(item.id); } }}><div className="application-launch">
        {selecting && <label className="check"><input type="checkbox" aria-label={`选择${item.name}`} checked={selected.includes(item.id)} disabled={busy} onChange={() => toggleSelected(item.id)} /></label>}
        {!item.enabled || !item.public_address ? <button type="button" className="application-unavailable" aria-disabled="true" aria-label={`${isPortProtocol(item.protocol) ? "复制" : "打开"}${item.name}`}><ServiceIcon id={item.icon_id} protocol={item.protocol} /></button> : isPortProtocol(item.protocol) ? <CopyButton value={item.public_address} label={`复制${item.name}地址`}><ServiceIcon id={item.icon_id} protocol={item.protocol} /></CopyButton> : <a className="service-open" href={item.public_address} target="_blank" rel="noopener noreferrer" aria-label={`打开${item.name}`}><ServiceIcon id={item.icon_id} protocol={item.protocol} /></a>}
        {(!item.enabled || item.apply_status !== "ready" || !item.public_address) && <Status badge kind={item.service_mode === "reverse_proxy" ? "reverse_proxy" : "service"} value={!item.enabled ? "disabled" : item.apply_status === "ready" && !item.public_address ? "waiting_address" : item.apply_status} />}
      </div>
      <a className="service-name" href={`#/services/${encodeURIComponent(item.id)}`} onClick={event => openDetail(event, item)} title={`${item.name} · 查看详情`}><strong>{item.name}</strong></a>
      </article>)}</section>}
      {selecting && selectedProxy && <p className="helper" role="status">选择中包含反向代理，不能修改设备。{readonlySelection && "反向代理仅允许管理员管理。"}</p>}
      {selecting && <div className="batch-actions"><div className="batch-selection"><span aria-live="polite">已选择 {selected.length} 项</span><button className="text-button" disabled={busy || !visible.length} onClick={() => setSelected(selected.length === visible.length ? [] : visible.map(item => item.id))}>{visible.length > 0 && selected.length === visible.length ? "取消全选" : "全选"}</button>{!navigation?.desktop && <button className="text-button" disabled={busy} onClick={() => { setSelecting(false); setSelected([]); }}>完成</button>}</div><div className="batch-commands"><button className="secondary-button" title={selectedProxy ? "反向代理不能修改设备，请仅选择内网穿透服务" : undefined} disabled={!selected.length || busy || !data.devices.length || selectedProxy} onClick={() => { setActionError(null); setMessage(null); setChangingAgent(tunnels.filter(item => selected.includes(item.id))); }}><Server size={20} aria-hidden="true" /><span>修改设备</span></button><button className="secondary-button" disabled={busy || readonlySelection || !tunnels.some(item => selected.includes(item.id) && hasServiceDomain(item))} onClick={() => { setActionError(null); setMessage(null); setChangingDomain(tunnels.filter(item => selected.includes(item.id))); }}><Globe size={20} aria-hidden="true" /><span>修改域名</span></button><button className="secondary-button" disabled={!selected.length || busy || readonlySelection} onClick={() => void toggle(tunnels.filter(item => selected.includes(item.id)), true)}><Power size={20} aria-hidden="true" /><span>启用</span></button><button className="secondary-button" disabled={!selected.length || busy || readonlySelection} onClick={() => void toggle(tunnels.filter(item => selected.includes(item.id)), false)}><PowerOff size={20} aria-hidden="true" /><span>关闭</span></button><button className="danger-button" disabled={!selected.length || busy || readonlySelection} onClick={() => setDeleting(tunnels.filter(item => selected.includes(item.id)))}><Trash2 size={20} aria-hidden="true" /><span>删除</span></button></div></div>}
    </>}
    {detailId && active && !editor && <ApplicationModal title={detail?.name ?? "服务详情"} header={detail ? <div className="application-summary"><ServiceIcon id={detail.icon_id} protocol={detail.protocol} /><div><h2>{detail.name}</h2><Status kind={detailProxy ? "reverse_proxy" : "service"} value={detail.enabled ? detail.apply_status : "disabled"} /></div></div> : undefined} origin={detailPresentation.current.origin} enterFromOrigin={detailPresentation.current.animate} returnFocus={detailFocus} busy={busy} dismissWhen={Boolean(data && !detail && seenDetail.current === detailId)} onClose={() => closeDetail()}>{leave => <div className="modal-body service-detail-body" ref={element => { if (element) element.scrollTop = detailPresentation.current.scroll; }} onScroll={event => { detailPresentation.current.scroll = event.currentTarget.scrollTop; }}>
      <Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} /><Notice error={actionError} />{message && <p className="action-status" role="status">{message}</p>}
      {!data ? <Loading /> : !detail ? <Empty title="服务不存在" detail="该服务可能已被删除。"><button className="secondary-button" onClick={() => leave()}>返回服务列表</button></Empty> : <>
        {detail.apply_error && detail.apply_status !== "partial" && <div className="notice error"><strong>{detail.apply_error === "暂无可用 IPv4 入口" ? detail.apply_error : "转发配置需处理"}</strong><p>{detail.apply_error === "暂无可用 IPv4 入口" ? "请检查下方节点状态。" : detailProxy ? "请检查目标地址与域名配置。" : "当前服务可能无法访问。请核对设备连接与内网地址；网页服务还需检查域名配置。"}</p>{detail.apply_error !== "暂无可用 IPv4 入口" && <details><summary>技术详情</summary><p>{detail.apply_error}</p></details>}</div>}
        {detail.apply_error && detail.apply_status === "partial" && <p className="service-detail-note">可用协议继续运行，请检查下方异常协议。</p>}
        <section className="service-detail-section service-detail-addresses"><dl>
          <DetailField label="公网地址"><div className="service-detail-address">{detail.public_address && !isPortProtocol(detail.protocol) ? <a className="service-public-link" href={detail.public_address} target="_blank" rel="noopener noreferrer" title="在新标签页打开"><code>{detail.public_address}</code></a> : <code>{detail.public_address ?? "等待配置"}</code>}{detail.public_address && <CopyButton value={detail.public_address} label="复制公网地址" iconOnly />}</div></DetailField>
          <DetailField label={detailProxy ? "目标地址" : "内网地址"}><div className="service-detail-address"><code>{localTarget(detail)}</code><CopyButton value={localTarget(detail)} label="复制内网地址" iconOnly /></div></DetailField>
        </dl></section>
        <section className="service-detail-section"><h3>服务配置</h3><dl>
          {!detailProxy && !isPortProtocol(detail.protocol) && <DetailField label="内网重定向" className="service-detail-meta">{detail.lan_redirect_enabled ? "已开启" : "未开启"}</DetailField>}
          {!isPortProtocol(detail.protocol) && <DetailField label="访问规则" className="service-detail-meta">{detail.access_mode === "password" ? "认证访问" : "公开访问"}</DetailField>}
          <DetailField label="服务类型" className="service-detail-meta">{detailProxy ? "反向代理" : isPortProtocol(detail.protocol) ? `${protocolLabel(detail.protocol)} 服务` : "网页服务"}</DetailField>
          {!detailProxy && <DetailField label="设备" className="service-detail-meta">{detail.device_id ? <a className="text-link" href={`#/agents/${encodeURIComponent(detail.device_id)}`} onClick={event => { if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return; event.preventDefault(); const href = event.currentTarget.hash; leave(() => closeDetail(href)); }}>{detail.device_name ?? "查看设备"}</a> : "未分配设备"}</DetailField>}
        {!isPortProtocol(detail.protocol) && <DetailField label="域名配置" className="service-detail-meta"><a className="text-link" href={detailDomain ? `#/domains/${encodeURIComponent(detailDomain.id)}` : "#/domains"} onClick={event => { if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return; event.preventDefault(); const href = event.currentTarget.hash; leave(() => closeDetail(href)); }}>域名与 DNS</a></DetailField>}
        </dl></section>
        {(detail.ipv6_direct_enabled || detail.node_ids?.some(id => id !== "local") || detail.node_statuses?.some(node => node.public_probe?.checked_at != null) || (isPortProtocol(detail.protocol) && Object.keys(detail.protocol_statuses ?? {}).length > 0)) && <section className="service-detail-section service-detail-connections"><h3>连接状态</h3><dl>
          {detail.node_statuses?.filter(node => node.node_id !== "local" || detail.node_ids?.some(id => id !== "local") || node.public_probe?.checked_at != null).map(node => {
            const probe = node.public_probe;
            const fresh = probe?.checked_at != null && Date.now() / 1000 - probe.checked_at < 45;
            const kind = probe?.kind.toUpperCase();
            return <DetailField key={node.node_id} label={node.node_name ?? (node.node_id === "local" ? "内置节点" : node.node_id)} className="service-detail-meta"><div className="service-node-state"><Status value={detail.enabled ? node.healthy ? "ready" : "checking" : "disabled"} /><span>{probe ? `${kind} 检查${probe.kind === "tcp" && !isPortProtocol(detail.protocol) ? "（兼容）" : ""}` : "待检查"}</span>{probe && <span className="helper">{probe.checked_at == null ? "待检查" : fresh ? probe.error ? "检查失败" : probe.healthy ? "健康" : "确认中" : "已过期"}</span>}{probe?.checked_at != null && <time className="helper" dateTime={new Date(probe.checked_at * 1000).toISOString()}>{new Date(probe.checked_at * 1000).toLocaleString()}</time>}{[node.error, probe?.error].filter((error, index, errors): error is string => !!error && errors.indexOf(error) === index).map(error => {
              const message = error.split(": ", 1)[0];
              return message === error ? <p className="form-error" key={error}>{message}</p> : <details className="service-node-error" key={error}><summary className="form-error">{message}</summary><p className="helper">{error}</p></details>;
            })}</div></DetailField>;
          })}
          {isPortProtocol(detail.protocol) && Object.entries(detail.protocol_statuses ?? {}).map(([protocol, state]) => <DetailField key={protocol} label={protocolLabel(protocol)} className="service-detail-meta"><div className="service-protocol-state"><Status value={state.status} />{state.error_message && <span className="helper">{state.error_message}</span>}</div></DetailField>)}
{detail.ipv6_direct_enabled && <DetailField label="IPv6 直连"><div><p>{detail.direct_status?.status === "configured" ? (detail.direct_status?.public_reachability === "verified" ? "已配置，探测通过" : "已配置，公网未验证") : detail.direct_status?.status === "disabled" ? "已停用" : detail.direct_status?.status === "offline" ? "设备未连接" : detail.direct_status?.status === "address_required" ? "等待公网 IPv6" : "配置中"}</p>{detail.direct_status?.address && <code>{detail.direct_status.address}</code>}{detail.direct_status?.certificate_expires_at && <p className="helper">证书到期：{new Date(detail.direct_status.certificate_expires_at * 1000).toLocaleString()}</p>}{[detail.direct_status?.error, detail.direct_status?.dns_error, detail.direct_status?.certificate_error].filter(Boolean).map((error, i) => <p className="form-error" key={i}>{error}</p>)}{detail.direct_status?.public_reachability === "verified" && <p className="helper">探测结果不代表当前连接路径。</p>}{detail.direct_status?.probe_error && <p className="helper">{detail.direct_status.probe_error}</p>}</div></DetailField>}
        </dl></section>}
        {detail.enabled && detail.apply_status === "ready" && <details className="service-state-explanation"><summary>状态说明</summary><span>{detailProxy ? "入口配置已生效，不代表目标服务健康。请通过公网地址测试实际访问；反代不计入穿透流量。" : ["udp", "tcp_udp"].includes(detail.protocol) ? "转发入口和数据通道已建立，不代表 UDP 目标应用已响应。请通过公网地址测试实际访问。" : detail.node_statuses?.some(node => node.public_probe?.checked_at != null) ? "入口和回源链路已就绪。应用与访问者网络需实际访问验证。" : "设备已连接，内网地址连接检查已通过。请通过公网地址测试实际访问。"}</span></details>}
        <div className="service-detail-actions"><button className="primary-button" disabled={busy || readonlyDetail} onClick={() => leave(() => { detailPresentation.current.animate = false; setEditor(detail); })}>编辑服务</button><button className="secondary-button" disabled={busy || readonlyDetail} onClick={() => void toggle([detail], !detail.enabled)}>{busy ? "提交中…" : detail.enabled ? "关闭服务" : "启用服务"}</button><div className="service-detail-danger"><button className="danger-button" disabled={busy || readonlyDetail} onClick={() => setDeleting([detail])}><Trash2 size={18} aria-hidden="true" />删除服务</button></div></div>
      </>}
    </div>}</ApplicationModal>}
    {creationMenu && active && <Modal title="添加" onClose={() => setCreationMenu(false)}><div className="modal-body service-create-options">
      <button aria-label="创建服务" onClick={() => create("new")}><Server size={22} aria-hidden="true" /><span>创建服务<small>通过设备访问内网服务</small></span><ChevronRight size={18} aria-hidden="true" /></button>
      <button aria-label="添加反向代理" onClick={() => create("new-proxy")}><Globe size={22} aria-hidden="true" /><span>添加反向代理<small>直接转发到目标地址</small></span><ChevronRight size={18} aria-hidden="true" /></button>
    </div></Modal>}
    {editor && data && <ServiceEditor key={typeof editor === "string" ? editor : editor.id} mode={editor === "new-proxy" ? "reverse_proxy" : "tunnel"} active={active} tunnel={typeof editor === "string" ? undefined : editor} data={data} csrf={csrf} onClose={() => setEditor(null)} onSaved={item => { merge(item); setMessage("配置已保存"); }} />}
    {changingAgent && active && data && <BatchAgentEditor items={changingAgent} devices={data.devices} csrf={csrf} onSaved={item => { merge(item); setSelected(current => current.filter(id => id !== item.id)); }} onComplete={() => setMessage(`已完成 ${changingAgent.length} 个服务的设备配置`)} onClose={() => setChangingAgent(null)} />}
    {changingDomain && active && data && <BatchDomainEditor items={changingDomain} domains={data.domains} csrf={csrf} onSaved={item => { merge(item); setSelected(current => current.filter(id => id !== item.id)); }} onComplete={(completed, skipped) => { setMessage(`已保存 ${completed} 个服务的域名配置${skipped ? `，跳过 ${skipped} 个无域名服务` : ""}`); setSelected(current => current.filter(id => !changingDomain.some(item => item.id === id))); }} onClose={() => setChangingDomain(null)} />}
    {deleting && active && <Confirm title={deleting.length === 1 ? `删除 ${deleting[0].name}？` : `删除 ${deleting.length} 个服务？`} description="删除后将立即停止新的连接，此操作无法撤销。" label="删除服务" onClose={() => setDeleting(null)} onConfirm={() => remove(deleting.filter(item => tunnels.some(current => current.id === item.id)))} />}
  </>;
}
