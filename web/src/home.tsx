import { useContext, useEffect, useState } from "react";
import { ArrowDownLeft, ArrowUpRight, ChevronRight, RefreshCw, RotateCcw } from "lucide-react";
import type { ManagedWorkspace } from "./accounts";
import { WorkspaceContext, WorkspaceLabelContext, Confirm, Notice, Loading, PageHeader, dateText, request, useApi, useResource } from "./ui";
import type { Auth, Device, Domain, Tunnel } from "./ui";
import { useResourceDeletions } from "./navigation";
import { bytes, QuotaSummary } from "./traffic-quota";

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

/** 不把未知时间画成零。指针与键盘共用同一个选中点，数值说明不依赖图形或颜色。 */
function TrafficChart({ history }: { history: History }) {
  const [selected, setSelected] = useState<number | null>(null);
  const points = history.points;
  const index = Math.min(selected ?? points.length - 1, points.length - 1);
  const point = points[index];
  const max = Math.max(1, ...points.flatMap(item => item.rates ? [item.rates.to_origin, item.rates.to_public] : []));
  const x = (i: number) => 12 + i / Math.max(1, points.length - 1) * 736;
  const y = (value: number) => 154 - value / max * 132;
  const line = (direction: keyof Rates) => points.reduce((result, item, i) => {
    if (!item.rates) return result;
    const continuous = i > 0 && points[i - 1].rates && points[i - 1].covered_seconds >= points[i - 1].seconds - 1 && item.covered_seconds >= item.seconds - 1;
    return `${result} ${continuous ? "L" : "M"}${x(i)},${y(item.rates[direction])}`;
  }, "");
  const hasCoverage = points.some(item => item.covered_seconds > 0);
  return <div className="traffic-chart">
    <div className="traffic-legend"><span className="to-origin">发往内网</span><span className="to-public">返回公网</span><small>最高 {bytes(max === 1 && !points.some(item => item.rates && (item.rates.to_origin || item.rates.to_public)) ? 0 : max, true)}</small></div>
    {!hasCoverage ? <p className="traffic-empty">尚无采集记录，开始采集后会显示趋势。</p> : <>
      <svg viewBox="0 0 760 180" role="img" aria-label="双向速率趋势，使用下方时间滑块查看具体数值" onPointerMove={event => { const box = event.currentTarget.getBoundingClientRect(); setSelected(Math.max(0, Math.min(points.length - 1, Math.round(((event.clientX - box.left) / box.width * 760 - 12) / 736 * (points.length - 1))))); }}>
        {[22, 88, 154].map(at => <line key={at} x1="12" x2="748" y1={at} y2={at} className="chart-grid" />)}
        <path d={line("to_origin")} className="chart-origin" /><path d={line("to_public")} className="chart-public" />
        {points.map((item, i) => item.rates && item.covered_seconds < item.seconds - 1 ? <g key={item.at}><circle cx={x(i)} cy={y(item.rates.to_origin)} r="2.5" className="chart-origin-dot" /><circle cx={x(i)} cy={y(item.rates.to_public)} r="2.5" className="chart-public-dot" /></g> : null)}
        <line x1={x(index)} x2={x(index)} y1="16" y2="160" className="chart-cursor" />
      </svg>
      <input type="range" min="0" max={points.length - 1} value={index} aria-label="查看流量时间点" aria-valuetext={`${dateText(point.at)}，${point.rates ? `发往内网 ${bytes(point.rates.to_origin, true)}，返回公网 ${bytes(point.rates.to_public, true)}` : "未采集"}`} onChange={event => setSelected(Number(event.target.value))} />
      <div className="chart-times"><time>{dateText(history.start)}</time><time>{dateText(history.end)}</time></div>
      <p className="chart-reading" aria-live="polite">{dateText(point.at)} · {point.rates ? <>发往内网 {bytes(point.rates.to_origin, true)} · 返回公网 {bytes(point.rates.to_public, true)}{point.covered_seconds < point.seconds - 1 && " · 部分时间未采集"}</> : "此时段未采集"}</p>
    </>}
    <p className="helper">按已采集时长计算平均速率；断点表示未采集，零值表示已采集但无流量。</p>
  </div>;
}

function TrafficReadings({ active, base, query, range, refresh }: { active: boolean; base: string; query: string; range: Range; refresh: number }) {
  const realtime = useResource(() => request<Realtime>(`${base}/realtime?${query}`), active);
  const history = useResource(() => request<History>(`${base}/history?${query}&range=${range}`), active, 60000);
  useEffect(() => { if (refresh && active) { void realtime.reload(); void history.reload(); } }, [refresh]);
  const live = realtime.data;
  const ready = live?.status === "ready";
  return <>
    <Notice error={realtime.error} updatedAt={realtime.updatedAt} onRetry={() => void realtime.reload()} />
    <div className="traffic-numbers">
      <div><span><ArrowDownLeft size={17} />发往内网</span><strong>{ready ? bytes(live.rates.to_origin, true) : "—"}</strong></div>
      <div><span><ArrowUpRight size={17} />返回公网</span><strong>{ready ? bytes(live.rates.to_public, true) : "—"}</strong></div>
    </div>
    {live && !ready && <p className="helper" role="status">{live.status === "collecting" ? "正在采集实时速率…" : "采集暂未更新，请稍后重试。"}</p>}
    <Notice error={history.error} updatedAt={history.updatedAt} onRetry={() => void history.reload()} />
    {!history.data && history.busy && <Loading />}
    {history.data && <><div className="traffic-total"><span>时段累计</span><strong>{bytes(history.data.total.to_origin + history.data.total.to_public)}</strong><small>发往内网 {bytes(history.data.total.to_origin)} · 返回公网 {bytes(history.data.total.to_public)}</small></div><TrafficChart history={history.data} /></>}
    {live?.sampled_at && <p className="helper">速率更新于 {dateText(live.sampled_at)}</p>}
  </>;
}

/** 日历用量只按用户切换，图表筛选不能改变这三项数字的含义。 */
function TrafficUsage({ active, admin, user, refresh, csrf }: { active: boolean; admin: boolean; user?: User; refresh: number; csrf?: string | null }) {
  const base = admin ? "/api/v1/admin/traffic" : "/api/v1/traffic";
  const query = user ? `?user_id=${encodeURIComponent(user.id)}` : "";
  const usage = useResource(() => request<Usage>(`${base}/usage${query}`), active);
  useEffect(() => { if (refresh && active) void usage.reload(); }, [refresh]);
  const data = usage.data;
  const [confirm, setConfirm] = useState(false);
  const [notice, setNotice] = useState("");
  const calendarDate = (at: number) => new Date(at * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
  return <div className="traffic-usage-section">
    <Notice error={usage.error} updatedAt={usage.updatedAt} onRetry={() => void usage.reload()} />
    <div className="traffic-usage-heading"><h3>用量概览</h3>{admin && user && <button className="text-button traffic-reset" onClick={() => { setNotice(""); setConfirm(true); }}><RotateCcw size={15} aria-hidden="true" />重置统计</button>}</div>
    <div className="traffic-usage" aria-label="日历流量用量">{([["today", "今日已用"], ["week", "本周已用"], ["month", "本月已用"]] as const).map(([key, label]) => <div key={key}><span>{label}</span><strong>{data ? bytes(data[key].total.to_origin + data[key].total.to_public) : "—"}</strong>{data?.[key].partial && <small>部分时段未采集</small>}</div>)}</div>
    <p className="helper">北京时间 · 周一开始 · 全部隧道双向合计</p>
    {data && <p className="helper">自 {calendarDate(data.started_at)} 开始统计{data.reset_at ? `；最近重置于 ${calendarDate(data.reset_at)}` : data.reset_users ? `；所选时段内 ${data.reset_users} 个用户空间的用量已重置` : ""}。{[data.today, data.week, data.month].some(period => period.partial) && "未采集时段无法补回，用量仅包含已采集数据。"}</p>}
    {(!admin || user) && <QuotaSummary active={active} admin={admin} userId={user?.id} refresh={refresh} />}
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
function TrafficPanel({ active, auth, managed, refresh }: { active: boolean; auth: Auth; managed: ManagedWorkspace | null; refresh: number }) {
  const admin = auth.role === "system_admin";
  const users = useResource(() => request<User[]>("/api/v1/admin/users"), active && admin);
  const [choice, setChoice] = useState<string | null>(managed ? null : "");
  const [search, setSearch] = useState("");
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
    <div className="home-section-heading"><h2>流量监控</h2><span>{admin ? selectedUser?.username ?? (selected === "" ? "全部用户" : "读取用户中…") : "我的流量"}</span></div>
    {admin && <><Notice error={users.error} updatedAt={users.updatedAt} onRetry={() => void users.reload()} /><div className="traffic-user-filter"><label>搜索统计用户<input type="search" placeholder="输入用户名" value={search} onChange={event => setSearch(event.target.value)} /></label><label>统计用户<select aria-label="统计用户" value={selected ?? ""} disabled={!users.data} onChange={event => { setChoice(event.target.value); setNotice(null); }}><option value="">全部用户</option>{users.data?.filter(item => item.id === selected || item.username.toLowerCase().includes(search.trim().toLowerCase())).map(item => <option key={item.id} value={item.id}>{item.username}{item.id === auth.user_id ? "（我）" : ""}{!item.enabled ? "（已停用）" : ""}</option>)}</select></label></div></>}
    {notice && <p className="helper" role="status">{notice}</p>}
    {scopeReady && <TrafficUsage key={`usage:${admin ? selected : "own"}`} active={active} admin={admin} user={selectedUser} refresh={refresh} csrf={auth.csrf_token} />}
    <div className="traffic-ranges" role="group" aria-label="流量时间范围">{ranges.map(([value, label]) => <button key={value} className="secondary-button" aria-pressed={range === value} onClick={() => setRange(value)}>{label}</button>)}</div>
    {scopeReady && <TrafficScope key={admin ? selected : "own"} active={active} admin={admin} user={selectedUser} range={range} refresh={refresh} />}
    <details className="traffic-help"><summary>统计口径</summary><p>仅统计经过 Nexo 隧道的数据，包含应用协议数据，不含加密传输开销、局域网直连及未进入隧道的响应。趋势保留 7 天，日用量汇总保留 90 天。日／周／月用量跟随用户选择，不受隧道和趋势时间筛选影响。正常写盘时，进程异常退出可能丢失最后约一分钟记录，不作为计费依据。</p></details>
  </section>;
}

function TrafficScope({ active, admin, user, range, refresh }: { active: boolean; admin: boolean; user?: User; range: Range; refresh: number }) {
  const [tunnel, setTunnel] = useState("");
  const canSelect = !admin || Boolean(user);
  const tunnels = useResource(() => request<Tunnel[]>(user ? `/api/v1/admin/workspaces/${encodeURIComponent(user.workspace_id)}/tunnels` : "/api/v1/tunnels"), active && canSelect);
  useEffect(() => { if (tunnel && tunnels.data && !tunnels.data.some(item => item.id === tunnel)) setTunnel(""); }, [tunnels.data, tunnel]);
  const query = new URLSearchParams();
  if (user) query.set("user_id", user.id);
  if (tunnel) query.set("tunnel_id", tunnel);
  return <>
    {canSelect && <><Notice error={tunnels.error} updatedAt={tunnels.updatedAt} onRetry={() => void tunnels.reload()} /><label className="traffic-tunnel-filter">统计隧道<select aria-label="统计隧道" value={tunnel} onChange={event => setTunnel(event.target.value)}><option value="">全部隧道</option>{tunnels.data?.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label></>}
    <TrafficReadings key={`${tunnel}:${range}`} active={active} base={admin ? "/api/v1/admin/traffic" : "/api/v1/traffic"} query={query.toString()} range={range} refresh={refresh} />
  </>;
}

type Attention = { id: string; name: string; href: string; reasons: string[]; priority: number };
/** 首页保留资源自己的状态含义，不把 DNS 已解析或配置成功推断成公网可达。 */
function attentionItems(tunnels: Tunnel[], devices: Device[], domains: Domain[]): Attention[] {
  const items: Attention[] = [];
  for (const item of tunnels) if (item.enabled && (item.apply_status !== "ready" || item.apply_error)) items.push({ id: `t-${item.id}`, name: item.name, href: `#/services/${encodeURIComponent(item.id)}`, reasons: [item.apply_error || ({ failed: "隧道运行失败", error: "隧道运行失败", checking: "检查中", pending: "待应用", applying: "应用中" } as Record<string, string>)[item.apply_status] || `未知状态：${item.apply_status}`], priority: ["failed", "error"].includes(item.apply_status) ? 0 : 2 });
  for (const item of devices) if (item.status === "offline") items.push({ id: `a-${item.id}`, name: item.name, href: `#/agents/${encodeURIComponent(item.id)}`, reasons: ["设备离线"], priority: 0 });
  for (const item of domains) {
    const reasons: string[] = []; let priority = 2;
    if (item.verification_status === "pending") reasons.push("待验证域名归属");
    if (item.runtime?.config_status === "failed") { reasons.push(item.runtime.config_error || "配置加载失败"); priority = 0; }
    else if (item.verification_status !== "pending" && (!item.runtime || item.runtime.config_status === "pending" || item.runtime.config_status === "unverified")) reasons.push("等待配置运行状态");
    if (item.https_enabled && item.runtime?.config_status === "disabled") { reasons.push("证书管理已暂停"); priority = Math.min(priority, 1); }
    if (item.https_enabled && !item.runtime?.certificates.length && item.verification_status !== "pending") reasons.push("等待证书状态");
    if (item.runtime?.service_warning) { reasons.push(item.runtime.service_warning); priority = Math.min(priority, 1); }
    if (item.access?.records.some(record => record.status === "unresolved")) { reasons.push("DNS 解析异常"); priority = 0; }
    else if (item.access?.records.some(record => record.matches_server === false)) { reasons.push("DNS 解析地址需核对"); priority = Math.min(priority, 1); }
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

export function HomePage({ active, auth, managed }: { active: boolean; auth: Auth; managed: ManagedWorkspace | null }) {
  const visible = useVisible(active);
  const api = useApi();
  const workspace = useContext(WorkspaceContext);
  const tunnels = useResource(() => api<Tunnel[]>("/api/v1/tunnels"), visible);
  const devices = useResource(() => api<Device[]>("/api/v1/devices"), visible);
  const domains = useResource(() => api<Domain[]>("/api/v1/public-domains"), visible);
  const [refresh, setRefresh] = useState(0);
  useResourceDeletions(routes => {
    tunnels.setData(previous => previous?.filter(item => !routes.includes(`#/services/${encodeURIComponent(item.id)}`)) ?? null);
    devices.setData(previous => previous?.filter(item => !routes.includes(`#/agents/${encodeURIComponent(item.id)}`)) ?? null);
    domains.setData(previous => previous?.filter(item => !routes.includes(`#/domains/${encodeURIComponent(item.id)}`)) ?? null);
  });
  const items = attentionItems(tunnels.data ?? [], devices.data ?? [], domains.data ?? []);
  const complete = Boolean(tunnels.data && devices.data && domains.data && !tunnels.error && !devices.error && !domains.error);
  const spaceLabel = managed?.name ?? `${auth.username}的工作空间`;
  return <div className="home-page">
    <PageHeader title="首页" action={<button className="icon-button" aria-label="刷新首页" onClick={() => { void tunnels.reload(); void devices.reload(); void domains.reload(); setRefresh(value => value + 1); }}><RefreshCw size={19} /></button>} />
    <p className="home-workspace">当前空间：{spaceLabel}</p>
    <div className="home-summaries">
      <a className="panel" href="#/services"><span>隧道</span><strong>{tunnels.data ? `${tunnels.data.filter(item => item.enabled && item.apply_status === "ready").length} / ${tunnels.data.length}` : "—"}</strong><small>运行中 / 总数</small></a>
      <a className="panel" href="#/agents"><span>设备</span><strong>{devices.data ? `${devices.data.filter(item => item.status === "online").length} / ${devices.data.length}` : "—"}</strong><small>在线 / 总数</small></a>
      <a className="panel" href="#/domains"><span>域名</span><strong>{domains.data?.length ?? "—"}</strong><small>{domains.data ? `${items.filter(item => item.id.startsWith("d-")).length} 个需关注` : "总数"}</small></a>
    </div>
    <Notice error={tunnels.error} updatedAt={tunnels.updatedAt} onRetry={() => void tunnels.reload()} /><Notice error={devices.error} updatedAt={devices.updatedAt} onRetry={() => void devices.reload()} /><Notice error={domains.error} updatedAt={domains.updatedAt} onRetry={() => void domains.reload()} />
    {complete && !devices.data!.length ? <div className="panel home-onboarding"><div><strong>接入第一台设备</strong><p>安装 Agent，将内网服务连接到 Nexo。</p></div><a className="primary-button" href="#/agents">接入设备</a></div> : complete && !tunnels.data!.length ? <div className="panel home-onboarding"><div><strong>创建第一条隧道</strong><p>TCP 可直接创建；HTTP / HTTPS 需先配置域名。</p></div><a className="primary-button" href="#/services">创建隧道</a></div> : null}
    <TrafficPanel key={workspace ?? "own"} active={visible} auth={auth} managed={managed} refresh={refresh} />
    <section className="panel home-attention" aria-label="当前空间待处理"><div className="home-section-heading"><h2>当前空间待处理</h2><span>{spaceLabel}</span></div>{!complete && <p className="helper">部分资源状态尚未读取成功，以下仅展示已获取的结果。</p>}{complete && !items.length && <p className="helper">暂无待处理事项</p>}{["故障", "需核对", "等待处理"].map((title, priority) => <AttentionGroup key={title} title={title} items={items.filter(item => item.priority === priority)} />)}</section>
  </div>;
}
