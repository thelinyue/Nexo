import { useContext, useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { ArrowDownLeft, ArrowUpRight, ChevronDown, ChevronRight, RotateCcw } from "./icons";
import type { ManagedWorkspace } from "./accounts";
import { WorkspaceContext, WorkspaceLabelContext, Confirm, Notice, Loading, PageHeader, dateText, request, useApi, useResource } from "./ui";
import type { Auth, Device, Domain, Tunnel } from "./ui";
import { PageNavigationContext, useResourceDeletions } from "./navigation";
import { bytes, QuotaSummary } from "./traffic-quota";
import "./home.css";

type User = { id: string; username: string; workspace_id: string; enabled: boolean };
type Rates = { to_origin: number; to_public: number };
type Realtime = { sampled_at: number | null; status: "collecting" | "ready" | "stale"; rates: Rates };
type Point = { at: number; seconds: number; covered_seconds: number; bytes: Rates; rates: Rates | null };
type History = { start: number; end: number; step: number; sampled_at: number | null; total: Rates; points: Point[] };
type Range = "1h" | "24h" | "7d";
type UsagePeriod = { start: number; total: Rates; partial: boolean };
type Usage = { timezone: string; sampled_at: number | null; started_at: number; reset_at: number | null; reset_users: number; today: UsagePeriod; week: UsagePeriod; month: UsagePeriod };
const ranges: [Range, string][] = [["1h", "1 小时"], ["24h", "24 小时"], ["7d", "7 天"]];

/** 页面实例保留时也停止不可见页面的初次请求；恢复后通过 useResource 重新读取。 */
function useVisible(active: boolean) {
  const [visible, setVisible] = useState(document.visibilityState === "visible");
  useEffect(() => { const update = () => setVisible(document.visibilityState === "visible"); document.addEventListener("visibilitychange", update); return () => document.removeEventListener("visibilitychange", update); }, []);
  return active && visible;
}

/** 图表按实际容器尺寸绘制，不缩放文字或压扁手机曲线。
 * 缺口及不完整采样拆成独立线段，渐变与折线使用同一分段，避免暗示未采集时段有流量。
 * 指针、点按与原生 range 共用选点状态；range 仅视觉隐藏，保留键盘和读屏语义。
 */
function TrafficChart({ history }: { history: History }) {
  const id = useId();
  const plot = useRef<HTMLDivElement>(null);
  const tooltip = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 600, height: 220 });
  const [tipWidth, setTipWidth] = useState(210);
  const [selected, setSelected] = useState<number | null>(null);
  const [showTip, setShowTip] = useState(false);
  useEffect(() => {
    const observer = new ResizeObserver(([entry]) => {
      if (entry.contentRect.width > 0) setSize({ width: entry.contentRect.width, height: entry.contentRect.height });
    });
    if (plot.current) observer.observe(plot.current);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    if (!showTip) return;
    const observer = new ResizeObserver(([entry]) => setTipWidth(entry.borderBoxSize?.[0]?.inlineSize ?? entry.contentRect.width));
    if (tooltip.current) observer.observe(tooltip.current);
    const dismiss = (event: PointerEvent) => { if (!plot.current?.contains(event.target as Node)) setShowTip(false); };
    document.addEventListener("pointerdown", dismiss);
    return () => { observer.disconnect(); document.removeEventListener("pointerdown", dismiss); };
  }, [showTip]);
  const points = history.points;
  const index = Math.max(0, Math.min(selected ?? points.length - 1, points.length - 1));
  const point = points[index];
  const peak = Math.max(0, ...points.flatMap(item => item.rates ? [item.rates.to_origin, item.rates.to_public] : []));
  const unitIndex = Math.min(4, Math.max(0, Math.floor(Math.log(Math.max(1, peak)) / Math.log(1024))));
  const unit = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"][unitIndex];
  const divisor = 1024 ** unitIndex;
  const max = peak ? Math.ceil(peak / divisor * 1.1) * divisor : 1;
  const left = 38, right = Math.max(left + 1, size.width - 8), top = 26, bottom = size.height - 28;
  const x = (at: number) => left + (at - history.start) / Math.max(1, history.end - history.start) * (right - left);
  const y = (value: number) => bottom - value / max * (bottom - top);
  const segments: number[][] = [];
  points.forEach((item, i) => {
    if (!item.rates) return;
    const previous = points[i - 1];
    const continuous = previous?.rates && previous.covered_seconds >= previous.seconds - 1 && item.covered_seconds >= item.seconds - 1 && item.at === previous.at + previous.seconds;
    if (continuous) segments[segments.length - 1].push(i);
    else segments.push([i]);
  });
  const line = (segment: number[], direction: keyof Rates) => segment.map((i, n) => `${n ? "L" : "M"}${x(points[i].at)},${y(points[i].rates![direction])}`).join(" ");
  const choose = (clientX: number) => {
    const box = plot.current!.getBoundingClientRect();
    const at = history.start + Math.max(0, Math.min(1, (clientX - box.left - left) / (right - left))) * (history.end - history.start);
    const nearest = points.reduce((best, item, i) => Math.abs(item.at - at) < Math.abs(points[best].at - at) ? i : best, 0);
    setSelected(nearest); setShowTip(true);
  };
  const tickCount = size.width < 540 ? 3 : 5;
  const crossesDay = new Date(history.start * 1000).toDateString() !== new Date(history.end * 1000).toDateString();
  const tickText = (at: number) => new Date(at * 1000).toLocaleString("zh-CN", crossesDay ? { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false } : { hour: "2-digit", minute: "2-digit", hour12: false });
  const reading = point ? `${dateText(point.at)} · ${point.rates ? `发往内网 ${bytes(point.rates.to_origin, true)} · 返回公网 ${bytes(point.rates.to_public, true)}${point.covered_seconds < point.seconds - 1 ? " · 部分时间未采集" : ""}` : "此时段未采集"}` : "尚无采集记录";
  const cursorX = point ? x(point.at) : left;
  const tipLeft = Math.max(4, Math.min(size.width - tipWidth - 4, cursorX + 14 + tipWidth <= size.width ? cursorX + 14 : cursorX - tipWidth - 14));
  return <div className="traffic-chart">
    <div className="traffic-legend"><span className="to-origin">发往内网</span><span className="to-public">返回公网</span></div>
    <div ref={plot} className="chart-plot" onPointerMove={event => { if (event.pointerType === "mouse" && points.length) choose(event.clientX); }} onPointerLeave={event => { if (event.pointerType === "mouse") setShowTip(false); }} onClick={event => { if (points.length) choose(event.clientX); }}>
      {points.some(item => item.covered_seconds > 0) ? <svg viewBox={`0 0 ${size.width} ${size.height}`} role="img" aria-label="双向速率趋势，点按图表或使用键盘选择时间点">
        <defs>{(["origin", "public"] as const).map(direction => <linearGradient key={direction} id={`${id}-${direction}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={direction === "origin" ? "var(--primary)" : "var(--chart-public)"} stopOpacity=".12" /><stop offset="100%" stopColor={direction === "origin" ? "var(--primary)" : "var(--chart-public)"} stopOpacity="0" /></linearGradient>)}</defs>
        <text x="0" y="13" className="chart-axis">{unit}</text>
        {[max, max / 2, 0].map(value => <g key={value}><line x1={left} x2={right} y1={y(value)} y2={y(value)} className="chart-grid" /><text x={left - 8} y={y(value) + 4} textAnchor="end" className="chart-axis">{(value / divisor).toLocaleString("zh-CN", { maximumFractionDigits: 1 })}</text></g>)}
        {(["to_origin", "to_public"] as const).map(direction => {
          const color = direction === "to_origin" ? "origin" : "public";
          return <g key={direction}>{segments.map((segment, n) => <g key={n}>
            {segment.length > 1 && <path className="chart-area" d={`${line(segment, direction)} L${x(points[segment[segment.length - 1]].at)},${bottom} L${x(points[segment[0]].at)},${bottom} Z`} fill={`url(#${id}-${color})`} />}
            <path d={line(segment, direction)} className={`chart-${color}`} />
            {segment.length === 1 && <circle cx={x(points[segment[0]].at)} cy={y(points[segment[0]].rates![direction])} r="2.5" className={`chart-${color}-dot`} />}
          </g>)}</g>;
        })}
        {Array.from({ length: tickCount }, (_, i) => {
          const at = history.start + (history.end - history.start) * i / (tickCount - 1);
          return <text key={i} x={x(at)} y={size.height - 5} textAnchor={i === 0 ? "start" : i === tickCount - 1 ? "end" : "middle"} className="chart-axis chart-time">{tickText(at)}</text>;
        })}
        {selected !== null && point && <g className="chart-selection"><line x1={cursorX} x2={cursorX} y1={top} y2={bottom} className="chart-cursor" />{point.rates && <><circle cx={cursorX} cy={y(point.rates.to_origin)} r="4" className="chart-origin-dot chart-selected-dot" /><circle cx={cursorX} cy={y(point.rates.to_public)} r="4" className="chart-public-dot chart-selected-dot" /></>}</g>}
      </svg> : <p className="traffic-empty">尚无采集记录，开始采集后会显示趋势。</p>}
      {point && <input className="chart-keyboard sr-only" type="range" min="0" max={points.length - 1} value={index} aria-label="查看流量时间点" aria-describedby={`${id}-hint`} aria-valuetext={reading} onFocus={() => { setSelected(index); setShowTip(true); }} onBlur={() => setShowTip(false)} onChange={event => { setSelected(Number(event.target.value)); setShowTip(true); }} onKeyDown={event => { if (event.key === "Escape") setShowTip(false); }} />}
      {showTip && point && <div ref={tooltip} className="chart-tooltip" style={{ left: tipLeft }} aria-hidden="true"><time>{dateText(point.at)}</time>{point.rates ? <><span>发往内网 <strong>{bytes(point.rates.to_origin, true)}</strong></span><span>返回公网 <strong>{bytes(point.rates.to_public, true)}</strong></span>{point.covered_seconds < point.seconds - 1 && <small>部分时间未采集</small>}</> : <span>此时段未采集</span>}</div>}
    </div>
    <p id={`${id}-hint`} className="chart-hint">点按图表查看，键盘可用方向键选择时间点</p>
    {selected !== null && point && <p className="chart-reading">{reading}</p>}
  </div>;
}

function TrafficReadings({ active, base, query, range, rangeControl }: { active: boolean; base: string; query: string; range: Range; rangeControl: ReactNode }) {
  const realtime = useResource(() => request<Realtime>(`${base}/realtime?${query}`), active);
  const history = useResource(() => request<History>(`${base}/history?${query}&range=${range}`), active, 60000);
  const live = realtime.data;
  const ready = live?.status === "ready";
  return <>
    <Notice error={realtime.error} updatedAt={realtime.updatedAt} onRetry={() => void realtime.reload()} />
    <div className="traffic-numbers">
      {([["to_origin", "发往内网", ArrowDownLeft], ["to_public", "返回公网", ArrowUpRight]] as const).map(([direction, label, Icon]) => <div key={direction}><span><Icon size={16} />{label}<small>实时</small></span><strong>{ready ? <>{bytes(live.rates[direction], true).split(" ")[0]} <small>{bytes(live.rates[direction], true).split(" ")[1]}</small></> : "—"}</strong></div>)}
    </div>
    {live && !ready && <p className="helper" role="status">{live.status === "collecting" ? "正在采集实时速率…" : "采集暂未更新，请稍后重试。"}</p>}
    <Notice error={history.error} updatedAt={history.updatedAt} onRetry={() => void history.reload()} />
    <div className="traffic-trend-heading"><h3>速率趋势</h3>{rangeControl}</div>
    {!history.data && history.busy && <Loading />}
    {history.data && <><TrafficChart history={history.data} /><div className="traffic-total"><span>时段累计</span><strong>{bytes(history.data.total.to_origin + history.data.total.to_public)}</strong><small>发往内网 {bytes(history.data.total.to_origin)} · 返回公网 {bytes(history.data.total.to_public)}</small></div></>}
    {live?.sampled_at && <p className="traffic-updated">速率更新于 {dateText(live.sampled_at)}</p>}
  </>;
}

/** 日历用量只按用户切换，图表筛选不能改变这三项数字的含义。 */
function TrafficUsage({ active, admin, user, csrf }: { active: boolean; admin: boolean; user?: User; csrf?: string | null }) {
  const base = admin ? "/api/v1/admin/traffic" : "/api/v1/traffic";
  const query = user ? `?user_id=${encodeURIComponent(user.id)}` : "";
  const usage = useResource(() => request<Usage>(`${base}/usage${query}`), active);
  const data = usage.data;
  const [confirm, setConfirm] = useState(false);
  const [notice, setNotice] = useState("");
  const calendarDate = (at: number) => new Date(at * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
  return <div className="traffic-usage-section">
    <Notice error={usage.error} updatedAt={usage.updatedAt} onRetry={() => void usage.reload()} />
    <div className="traffic-usage-heading"><h3>用量概览</h3>{admin && user && <button className="text-button traffic-reset" onClick={() => { setNotice(""); setConfirm(true); }}><RotateCcw size={15} aria-hidden="true" />重置统计</button>}</div>
    <div className="traffic-usage" aria-label="日历流量用量">{([["today", "今日已用"], ["week", "本周已用"], ["month", "本月已用"]] as const).map(([key, label]) => <div key={key}><span>{label}</span><strong>{data ? bytes(data[key].total.to_origin + data[key].total.to_public) : "—"}</strong>{data?.[key].partial && <small>部分时段未采集</small>}</div>)}</div>
    {data && [data.today, data.week, data.month].some(period => period.partial) && <p className="helper">未采集时段无法补回，用量仅包含已采集数据。</p>}
    {(!admin || user) && <QuotaSummary active={active} admin={admin} userId={user?.id} />}
    <details className="traffic-help"><summary>统计说明</summary>
      <p>北京时间 · 周一开始 · 全部隧道双向合计</p>
      {data && <p>自 {calendarDate(data.started_at)} 开始统计{data.reset_at ? `；最近重置于 ${calendarDate(data.reset_at)}` : data.reset_users ? `；所选时段内 ${data.reset_users} 个用户空间的用量已重置` : ""}。</p>}
      <p>按已采集时长计算平均速率；断点表示未采集，零值表示已采集但无流量。</p>
      <p>仅统计经过 Nexo 隧道的数据，包含应用协议数据，不含反向代理、加密传输开销、局域网直连及未进入隧道的响应。趋势保留 7 天，日用量汇总保留 90 天。日／周／月用量跟随用户选择，不受隧道和趋势时间筛选影响。正常写盘时，进程异常退出可能丢失最后约一分钟记录，不作为计费依据。</p>
    </details>
    {notice && <p className="helper" role="status">{notice}</p>}
    {confirm && user && <WorkspaceLabelContext.Provider value={undefined}><Confirm title={`重置 ${user.username} 的流量统计？`} description={`将该用户所属空间的今日、本周、本月用量归零，并从重置时刻继续累计。全部隧道均受影响；趋势历史和实时速率保留，其他用户空间不受影响。月额度消耗和剩余额度不变。此操作不可撤销。`} label="确认重置" onClose={() => setConfirm(false)} onConfirm={async () => {
      await request(`${base}/reset`, { method: "POST", body: JSON.stringify({ user_id: user.id }) }, csrf);
      usage.setData(null); // 丢弃重置前正在返回的旧请求，随后读取事务提交后的用量。
      setNotice(`${user.username} 的统计已重置，月额度消耗不变。`);
      await usage.reload();
    }} /></WorkspaceLabelContext.Provider>}
  </div>;
}

/** 用户筛选只作用于统计；跨用户接口仍以当前管理员会话鉴权，不改资源管理空间。 */
function TrafficPanel({ active, auth, managed, ownTunnels }: { active: boolean; auth: Auth; managed: ManagedWorkspace | null; ownTunnels: ReturnType<typeof useResource<Tunnel[]>> }) {
  const admin = auth.role === "system_admin";
  const users = useResource(() => request<User[]>("/api/v1/admin/users"), active && admin);
  const [choice, setChoice] = useState<string | null>(managed ? null : "");
  const [search, setSearch] = useState("");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const filterId = useId();
  const [notice, setNotice] = useState<string | null>(null);
  const selected = choice ?? users.data?.find(item => item.workspace_id === managed?.id)?.id;
  const selectedUser = users.data?.find(item => item.id === selected);
  const [range, setRange] = useState<Range>("24h");
  useEffect(() => {
    if (users.data && selected && !selectedUser) { setChoice(""); setNotice("所选用户已删除，已返回全部用户。"); }
    if (users.data && choice === null && !selectedUser) { setChoice(""); setNotice("该空间已无对应用户，已返回全部用户。"); }
  }, [users.data, selected, selectedUser, choice]);
  const scopeReady = !admin || selected === "" || Boolean(selectedUser);
  return <section className="panel home-traffic" aria-label="流量监控">
    <div className="home-section-heading"><h2>流量监控</h2><div className="traffic-filter-heading"><span>{admin ? selectedUser?.username ?? (selected === "" ? "全部用户" : "读取用户中…") : "我的流量"}</span><button className="text-button" aria-label="流量筛选" aria-expanded={filtersOpen} aria-controls={`${filterId}-users ${filterId}-tunnels`} onClick={() => setFiltersOpen(!filtersOpen)}>筛选<ChevronDown size={15} /></button></div></div>
    <div id={`${filterId}-users`} hidden={!filtersOpen}>{admin && <div className="traffic-user-filter"><label>搜索统计用户<input type="search" placeholder="输入用户名" value={search} onChange={event => setSearch(event.target.value)} /></label><label>统计用户<select aria-label="统计用户" value={selected ?? ""} disabled={!users.data} onChange={event => { setChoice(event.target.value); setNotice(null); }}><option value="">全部用户</option>{users.data?.filter(item => item.id === selected || item.username.toLowerCase().includes(search.trim().toLowerCase())).map(item => <option key={item.id} value={item.id}>{item.username}{item.id === auth.user_id ? "（我）" : ""}{!item.enabled ? "（已停用）" : ""}</option>)}</select></label></div>}</div>
    {admin && <Notice error={users.error} updatedAt={users.updatedAt} onRetry={() => void users.reload()} />}
    {notice && <p className="helper" role="status">{notice}</p>}
    {scopeReady && <TrafficScope key={admin ? selected : "own"} active={active} admin={admin} user={selectedUser} range={range} ownTunnels={ownTunnels} ownWorkspace={managed?.id ?? auth.workspace_id} filtersOpen={filtersOpen} filterId={`${filterId}-tunnels`} rangeControl={<div className="traffic-ranges" role="group" aria-label="流量时间范围">{ranges.map(([value, label]) => <button aria-label={label} key={value} aria-pressed={range === value} onClick={() => setRange(value)}>{label.replaceAll(" ", "")}</button>)}</div>} />}
    {scopeReady && <TrafficUsage key={`usage:${admin ? selected : "own"}`} active={active} admin={admin} user={selectedUser} csrf={auth.csrf_token} />}
  </section>;
}

function TrafficScope({ active, admin, user, range, ownTunnels, ownWorkspace, filtersOpen, filterId, rangeControl }: { active: boolean; admin: boolean; user?: User; range: Range; ownTunnels: ReturnType<typeof useResource<Tunnel[]>>; ownWorkspace?: string; filtersOpen: boolean; filterId: string; rangeControl: ReactNode }) {
  const [tunnel, setTunnel] = useState("");
  const canSelect = !admin || Boolean(user);
  // 当前展示空间复用概览请求；其他空间保持独立生命周期，避免跨空间迟到结果混入。
  const shared = !admin || Boolean(user && user.workspace_id === ownWorkspace);
  const otherTunnels = useResource(() => request<Tunnel[]>(`/api/v1/admin/workspaces/${encodeURIComponent(user!.workspace_id)}/tunnels`), active && canSelect && !shared);
  const tunnels = shared ? ownTunnels : otherTunnels;
  useEffect(() => { if (tunnel && tunnels.data && !tunnels.data.some(item => item.id === tunnel && item.service_mode !== "reverse_proxy")) setTunnel(""); }, [tunnels.data, tunnel]);
  const query = new URLSearchParams();
  if (user) query.set("user_id", user.id);
  if (tunnel) query.set("tunnel_id", tunnel);
  return <>
    {canSelect && <><p className="traffic-scope-label">统计隧道 · {tunnel ? tunnels.data?.find(item => item.id === tunnel)?.name : "全部隧道"}</p><Notice error={tunnels.error} updatedAt={tunnels.updatedAt} onRetry={() => void tunnels.reload()} /></>}
    <div id={filterId} hidden={!filtersOpen}>{canSelect && <label className="traffic-tunnel-filter">统计隧道<select aria-label="统计隧道" value={tunnel} onChange={event => setTunnel(event.target.value)}><option value="">全部隧道</option>{tunnels.data?.filter(item => item.service_mode !== "reverse_proxy").map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>}</div>
    <TrafficReadings key={`${tunnel}:${range}`} active={active} base={admin ? "/api/v1/admin/traffic" : "/api/v1/traffic"} query={query.toString()} range={range} rangeControl={rangeControl} />
  </>;
}

type Attention = { id: string; name: string; href: string; reasons: string[]; priority: number };
/** 首页保留资源自己的状态含义，不把 DNS 已解析或配置成功推断成公网可达。 */
function attentionItems(tunnels: Tunnel[], devices: Device[], domains: Domain[]): Attention[] {
  const items: Attention[] = [];
  for (const item of tunnels) if (item.enabled && (item.apply_status !== "ready" || item.apply_error)) items.push({ id: `t-${item.id}`, name: item.name, href: `#/services/${encodeURIComponent(item.id)}`, reasons: [item.apply_error || (item.service_mode === "reverse_proxy" ? "反代配置待生效" : "") || ({ partial: "部分协议不可用", failed: "服务配置需处理", error: "服务配置需处理", checking: "检查中", pending: "待应用", applying: "应用中" } as Record<string, string>)[item.apply_status] || `未知状态：${item.apply_status}`], priority: ["failed", "error"].includes(item.apply_status) ? 0 : 2 });
  for (const item of devices) if (item.status === "offline") items.push({ id: `a-${item.id}`, name: item.name, href: `#/agents/${encodeURIComponent(item.id)}`, reasons: ["设备离线"], priority: 0 });
  for (const item of domains) {
    const reasons: string[] = []; let priority = 2;
    if (item.credential_configured === false) reasons.push("待配置 DNS 凭据");
    else if (item.verification_status === "pending") reasons.push("待验证域名归属");
    if (item.runtime?.config_status === "failed") { reasons.push(item.runtime.config_error || "配置加载失败"); priority = 0; }
    else if (item.verification_status !== "pending" && (!item.runtime || item.runtime.config_status === "pending" || item.runtime.config_status === "unverified")) reasons.push("等待配置运行状态");
    if (item.https_enabled && item.runtime?.config_status === "disabled") { reasons.push("证书管理已暂停"); priority = Math.min(priority, 1); }
    if (item.https_enabled && !item.runtime?.certificates.length && item.verification_status !== "pending") reasons.push("等待证书状态");
    if (item.runtime?.service_warning) { reasons.push(item.runtime.service_warning); priority = Math.min(priority, 1); }
    if (item.https_enabled) for (const cert of item.runtime?.certificates ?? []) {
      const now = Date.now() / 1000;
      if (cert.status === "expired" || cert.expires_at && cert.expires_at <= now) { reasons.push("证书已过期"); priority = 0; }
      else if (cert.error || ["failed", "retry_wait"].includes(cert.status)) { reasons.push("证书申请或续期需关注"); priority = Math.min(priority, 1); }
      else if (cert.not_before && cert.not_before > now) { reasons.push("证书尚未生效"); }
      else if (!cert.expires_at || !cert.not_before) reasons.push("等待证书签发");
    }
    if (reasons.length) items.push({ id: `d-${item.id}`, name: item.domain, href: `#/domains/${encodeURIComponent(item.id)}`, reasons: [...new Set(reasons)], priority });
  }
  return items;
}

function AttentionGroup({ title, items }: { title: string; items: Attention[] }) {
  const [expanded, setExpanded] = useState(false);
  if (!items.length) return null;
  return <div className="home-attention-group"><h3>{title} <small>{items.length}</small></h3>{(expanded ? items : items.slice(0, 5)).map(item => <a key={item.id} className="home-attention-row" href={item.href}><span><strong>{item.name}</strong><small>{item.reasons.join(" · ")}</small></span><ChevronRight size={18} aria-hidden="true" /></a>)}{items.length > 5 && <button className="text-button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? "收起" : `展开全部 ${items.length} 项`}</button>}</div>;
}

/** 同一份待处理数据在手机折叠、桌面展开，避免重复链接和跨尺寸状态丢失。 */
function AttentionPanel({ items, complete, spaceLabel }: { items: Attention[]; complete: boolean; spaceLabel: string }) {
  const [expanded, setExpanded] = useState(false);
  const id = useId();
  const first = [...items].sort((a, b) => a.priority - b.priority)[0];
  return <section className="panel home-attention" aria-label="当前空间待处理">
    <div className="home-section-heading"><h2>当前空间待处理 <small>{items.length ? `${items.length} 项` : ""}</small></h2>{items.length > 0 && <button className="text-button attention-toggle" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded(!expanded)}>{expanded ? "收起" : "展开"}<ChevronDown size={15} /></button>}</div>
    <p className="attention-space">{spaceLabel}</p>
    {!complete && <p className="helper">部分资源状态尚未读取成功，以下仅展示已获取的结果。</p>}
    {complete && !items.length && <p className="helper">暂无待处理事项</p>}
    {first && !expanded && <p className="attention-preview">{first.name} · {first.reasons.join(" · ")}</p>}
    <div id={id} className="home-attention-items" data-expanded={expanded}>{["故障", "需核对", "等待处理"].map((title, priority) => <AttentionGroup key={title} title={title} items={items.filter(item => item.priority === priority)} />)}</div>
  </section>;
}

export function HomePage({ active, auth, managed }: { active: boolean; auth: Auth; managed: ManagedWorkspace | null }) {
  const navigation = useContext(PageNavigationContext);
  const topHeader = Boolean(navigation && (navigation.standalone || !navigation.desktop));
  const visible = useVisible(active);
  const api = useApi();
  const workspace = useContext(WorkspaceContext);
  const tunnels = useResource(() => api<Tunnel[]>("/api/v1/tunnels"), visible);
  const devices = useResource(() => api<Device[]>("/api/v1/devices"), visible);
  const domains = useResource(() => api<Domain[]>("/api/v1/public-domains"), visible);
  useResourceDeletions(routes => {
    tunnels.setData(previous => previous?.filter(item => !routes.includes(`#/services/${encodeURIComponent(item.id)}`)) ?? null);
    devices.setData(previous => previous?.filter(item => !routes.includes(`#/agents/${encodeURIComponent(item.id)}`)) ?? null);
    domains.setData(previous => previous?.filter(item => !routes.includes(`#/domains/${encodeURIComponent(item.id)}`)) ?? null);
  });
  const items = attentionItems(tunnels.data ?? [], devices.data ?? [], domains.data ?? []);
  const complete = Boolean(tunnels.data && devices.data && domains.data && !tunnels.error && !devices.error && !domains.error);
  const spaceLabel = managed?.name ?? `${auth.username}的工作空间`;
  return <div className="home-page">
    <PageHeader title="首页" topContent={<span className="home-workspace" title={spaceLabel}>{spaceLabel}</span>} />
    {!topHeader && <p className="home-workspace">当前空间：{spaceLabel}</p>}
    <div className="home-summaries">
      <a className="panel" href="#/services"><span>服务</span><strong>{tunnels.data?.length ?? "—"}</strong><small>{tunnels.data ? `穿透运行 ${tunnels.data.filter(item => item.service_mode !== "reverse_proxy" && item.enabled && item.apply_status === "ready").length} · 反代生效 ${tunnels.data.filter(item => item.service_mode === "reverse_proxy" && item.enabled && item.apply_status === "ready").length}` : "正在加载"}</small></a>
      <a className="panel" href="#/agents"><span>设备</span><strong>{devices.data ? `${devices.data.filter(item => item.status === "online").length} / ${devices.data.length}` : "—"}</strong><small>在线 / 总数</small></a>
      <a className="panel" href="#/domains"><span>域名</span><strong>{domains.data?.length ?? "—"}</strong><small>{domains.data ? `${items.filter(item => item.id.startsWith("d-")).length} 个需关注` : "总数"}</small></a>
    </div>
    <Notice error={tunnels.error} updatedAt={tunnels.updatedAt} onRetry={() => void tunnels.reload()} /><Notice error={devices.error} updatedAt={devices.updatedAt} onRetry={() => void devices.reload()} /><Notice error={domains.error} updatedAt={domains.updatedAt} onRetry={() => void domains.reload()} />
    {complete && !devices.data!.length && !tunnels.data!.length && auth.role !== "system_admin" ? <div className="panel home-onboarding"><div><strong>接入第一台设备</strong><p>安装客户端，将内网服务连接到 Nexo。</p></div><a className="primary-button" href="#/agents">接入设备</a></div> : complete && !tunnels.data!.length ? <div className="panel home-onboarding"><div><strong>创建第一个服务</strong><p>内网穿透需要设备；管理员也可直接反代 VPS 服务。网页访问需先配置域名。</p></div><a className="primary-button" href="#/services">创建服务</a></div> : null}
    <div className="home-overview">
      <AttentionPanel items={items} complete={complete} spaceLabel={spaceLabel} />
      <TrafficPanel key={workspace ?? "own"} active={visible} auth={auth} managed={managed} ownTunnels={tunnels} />
    </div>
  </div>;
}
