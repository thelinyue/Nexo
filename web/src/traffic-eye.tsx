import { useEffect, useId, useRef, useState } from "react";
import { Loading, Modal, Notice, dateText, request, useResource } from "./ui";
import { bytes } from "./traffic-quota";
import "./traffic-eye.css";

type Totals = { requests: number; errors: number; sessions: number; duration_ms: number; session_ms: number; to_origin: number; to_public: number; peak: number };
type Rank = { label: string; count: number };
type Summary = {
  sampled_at: number | null; started_at: number; uptime: number; status: "ready" | "collecting" | "stale";
  start: number; end: number; step: number; partial: boolean; dropped: number; lag_seconds?: number; coverage_percent?: number; geo_available: boolean;
  totals: Totals; qps: number; active: number; uv_daily_sum: number; p50_ms: number | null; p95_ms: number | null;
  series: { at: number; covered: boolean; partial: boolean; totals: Totals; p50_ms?: number | null; p95_ms?: number | null }[];
  services: { id: string; name: string; mode: string; requests: number; bytes: number; errors: number }[];
  protocols: Record<string, number>; breakdowns: Record<string, Rank[]>;
};
type Entry = { id: string; at: number; service: string; name: string; node: string; protocol: string; method: string; path: string; status: number; duration_ms: number; to_origin: number; to_public: number; source: string; country: string; browser: string; os: string; device: string; reason: string };
type Details = { items: Entry[]; next_cursor: string | null; retention_days: number };
type EyeRange = "live" | "1h" | "24h" | "7d" | "30d" | "90d";
const ranges: [EyeRange, string][] = [["live", "实时"], ["1h", "1小时"], ["24h", "24小时"], ["7d", "7天"], ["30d", "30天"], ["90d", "90天"]];
const number = (value?: number | null) => value == null ? "—" : value.toLocaleString("zh-CN", { maximumFractionDigits: 1 });
const milliseconds = (value?: number | null) => value == null ? "—" : `${number(value)} ms`;
const reasons: Record<string, string> = { closed: "正常结束", cancelled: "连接已中断", network_error: "网络错误", idle_timeout: "空闲超时", authorization_revoked: "授权已变更", quota_exhausted: "额度用尽" };
function useOnscreen(active: boolean) {
  const ref = useRef<HTMLDivElement>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const observer = new IntersectionObserver(entries => { if (entries.some(e => e.isIntersecting)) { setSeen(true); observer.disconnect(); } }, { rootMargin: "160px" });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return { ref, active: active && seen };
}

/** 排行始终显示真实计数；长标签可换行，颜色仅作辅助，读屏有完整标签。 */
function Ranking({ title, rows = [], help }: { title: string; rows?: Rank[]; help?: string }) {
  const max = Math.max(1, ...rows.map(row => row.count));
  return <section className="eye-card eye-ranking" aria-label={title}><header><h3>{title}</h3><small>TOP 10</small></header>{rows.length ? <ol>{rows.slice(0, 10).map((row, i) => <li key={row.label}><span className="eye-rank-index">{i + 1}</span><div><span title={row.label}>{row.label || "未知"}</span><span className="eye-bar" aria-hidden="true" style={{ width: `${Math.max(1, row.count / max * 100)}%` }} /></div><strong>{number(row.count)}</strong></li>)}</ol> : <p className="eye-empty">暂无采集记录</p>}{help && <p className="eye-caption">{help}</p>}</section>;
}

/** SVG 只负责视觉。原生滑块和读数共用选点，触屏与键盘均可查看，无采样点不补成零。 */
function Trend({ data, kind = "traffic", rate = false }: { data: Summary; kind?: "traffic" | "requests" | "sessions" | "latency"; rate?: boolean }) {
  const plot = useRef<HTMLDivElement>(null);
  const id = useId();
  const [width, setWidth] = useState(600);
  const [selected, setSelected] = useState<number | null>(null);
  useEffect(() => { const observer = new ResizeObserver(([entry]) => { if (entry.contentRect.width > 0) setWidth(entry.contentRect.width); }); if (plot.current) observer.observe(plot.current); return () => observer.disconnect(); }, []);
  const points = data.series;
  const values = (p: Summary["series"][number]) => { const t=p.totals; return kind === "traffic" ? [t.to_origin, t.to_public] : kind === "requests" ? [t.requests, t.errors] : kind === "latency" ? [p.p50_ms ?? 0, p.p95_ms ?? 0] : [t.sessions, t.peak]; };
  const labels = kind === "traffic" ? ["发往内网", "返回公网"] : kind === "requests" ? ["请求", "4xx / 5xx"] : kind === "latency" ? ["p50 上界", "p95 上界"] : ["已结束会话", "单服务峰值"];
  const max = Math.max(1, ...points.flatMap(p => values(p)));
  const x = (i: number) => 42 + i / Math.max(1, points.length - 1) * (width - 54);
  const y = (value: number) => 166 - value / max * 140;
  const choose = (clientX: number) => { const left = plot.current!.getBoundingClientRect().left; setSelected(Math.round(Math.max(0, Math.min(1, (clientX - left - 42) / Math.max(1, width - 54))) * (points.length - 1))); };
  const current = selected == null ? null : points[Math.min(selected, points.length - 1)];
  const fmt = (value: number) => kind === "traffic" ? bytes(rate ? value / data.step : value, rate) : kind === "latency" ? milliseconds(value) : number(value);
  const reading = (point: Summary["series"][number]) => !point.covered ? "此时段未采集" : labels.map((label, i) => `${label} ${kind === "latency" ? milliseconds(i ? point.p95_ms : point.p50_ms) : fmt(values(point)[i])}`).join(" · ");
  return <div className="eye-trend" ref={plot}>
    <div className="eye-legend"><span>{labels[0]}</span><span>{labels[1]}</span><small>{kind === "traffic" ? rate ? "完成数据平均速率" : "时段数据量" : kind === "latency" ? "毫秒" : "次数"}</small></div>
    <svg viewBox={`0 0 ${width} 204`} role="img" aria-label={`${labels.join("与")}趋势`} onPointerMove={e => { if (e.pointerType === "mouse" && points.length) choose(e.clientX); }} onClick={e => { if (points.length) choose(e.clientX); }}>
      <defs><linearGradient id={id} x1="0" y1="0" x2="0" y2="1"><stop stopColor="var(--primary)" stopOpacity=".18" /><stop offset="1" stopColor="var(--primary)" stopOpacity="0" /></linearGradient></defs>
      {[0, .5, 1].map(t => <g key={t}><line x1="42" x2={width - 12} y1={y(t * max)} y2={y(t * max)} className="eye-grid-line" /><text x="34" y={y(t * max) + 4} textAnchor="end">{fmt(t * max)}</text></g>)}
      {[0, 1].map(direction => {
        const segments: number[][] = [];
        points.forEach((p, i) => { if (!p.covered || (kind === "latency" && !p.totals.requests) || p.at + data.step <= data.started_at) return; const previous = points[i - 1]; if ((kind !== "latency" || Boolean(previous?.totals.requests)) && previous?.covered && previous.at + data.step > data.started_at && !previous.partial && !p.partial && segments.length) segments[segments.length - 1].push(i); else segments.push([i]); });
        return <g key={direction}>{segments.map((segment, n) => { const line = segment.map((i, j) => `${j ? "L" : "M"}${x(i)},${y(values(points[i])[direction])}`).join(" "); return <g key={n}>{!direction && segment.length > 1 && <path d={`${line} L${x(segment.at(-1)!)},166 L${x(segment[0])},166 Z`} fill={`url(#${id})`} />}<path d={line} className={`eye-line eye-line-${direction}`} />{segment.length === 1 && <circle cx={x(segment[0])} cy={y(values(points[segment[0]])[direction])} r="3" className={`eye-dot-${direction}`} />}</g>; })}</g>;
      })}
      {[0, .5, 1].map(t => { const i = Math.round(t * Math.max(0, points.length - 1)); return points[i] && <text key={t} x={x(i)} y="194" textAnchor={t === 0 ? "start" : t === 1 ? "end" : "middle"}>{new Date(points[i].at * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", ...(data.end - data.start > 86400 ? { month: "numeric", day: "numeric" } : { hour: "2-digit", minute: "2-digit", hour12: false }) })}</text>; })}
      {current && <line x1={x(selected!)} x2={x(selected!)} y1="20" y2="166" className="eye-crosshair" />}
    </svg>
    {points.length > 0 && <input className="eye-chart-selector" type="range" aria-label={`查看${labels[0]}趋势时间点`} min="0" max={points.length - 1} value={selected ?? points.length - 1} onChange={e => setSelected(Number(e.target.value))} aria-valuetext={current ? `${dateText(current.at)} ${reading(current)}` : "使用方向键查看"} />}
    {current && <p className="eye-caption">{dateText(current.at)} · {reading(current)}{current.partial && current.covered ? " · 部分时段未采集" : ""}</p>}
  </div>;
}

function Distribution({ data }: { data: Summary | null }) {
  const rows = data?.breakdowns.status ?? [];
  const groups = [1, 2, 3, 4, 5].map(group => ({ label: `${group}xx`, count: rows.filter(row => Number(row.label) >= group * 100 && Number(row.label) < (group + 1) * 100).reduce((sum, row) => sum + row.count, 0) }));
  const total = groups.reduce((sum, row) => sum + row.count, 0);
  let start = 0;
  const stops = groups.map((row, i) => { const end = start + row.count / Math.max(1, total) * 100; const stop = `var(--eye-status-${i + 1}) ${start}% ${end}%`; start = end; return stop; }).join(",");
  return <section className="eye-card eye-status"><header><h3>状态码分布</h3><small>HTTP 请求</small></header><div className="eye-status-body"><div className="eye-donut" role="img" aria-label={`请求状态分布：${groups.map(row => `${row.label} ${row.count}`).join("，")}`} style={{ background: total ? `conic-gradient(${stops})` : "var(--surface-raised)" }}><div><strong>{number(data?.totals.requests)}</strong><small>总请求</small></div></div><dl>{groups.map((row, i) => <div key={row.label}><dt><i style={{ background: `var(--eye-status-${i + 1})` }} />{row.label}</dt><dd>{number(row.count)} <small>{total ? (row.count / total * 100).toFixed(1) : "0"}%</small></dd></div>)}</dl></div><footer><span>HTTP 非错误响应 <b>{total ? `${((total - groups[3].count - groups[4].count) / total * 100).toFixed(1)}%` : "—"}</b></span><span>4xx <b>{number(groups[3].count)}</b></span><span>5xx <b>{number(groups[4].count)}</b></span></footer></section>;
}

type StreamProps = { active: boolean; base: string; query: string; sessions?: boolean; onService: (id: string, name: string) => void };

function RequestStream({ active, sessions = false, ...props }: StreamProps) {
  const visibility = useOnscreen(active);
  const [cursor, setCursor] = useState<string | null>(null);
  // 每页独立请求生命周期，连续翻页仍会加载，并丢弃上一页的迟到响应和暂停快照。
  return <section ref={visibility.ref} className={`eye-card ${sessions ? "eye-sessions" : "eye-stream"}`} aria-label={sessions ? "会话明细" : "实时请求流"}><RequestStreamPage key={cursor ?? "latest"} {...props} active={visibility.active} sessions={sessions} cursor={cursor} onPage={setCursor} /></section>;
}

function RequestStreamPage({ active, base, query, sessions, onService, cursor, onPage }: StreamProps & { cursor: string | null; onPage: (cursor: string | null) => void }) {
  const page = useResource(() => request<Details>(`${base}/${sessions ? "sessions" : "requests"}?${query}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`), active, cursor ? false : 5000);
  const [paused, setPaused] = useState(false);
  const retained = useRef<Details | null>(null);
  if (!paused && page.data) retained.current = page.data;
  const data = paused ? retained.current : page.data;
  return <><header><h3>{sessions ? "会话明细" : "实时请求流"}</h3><div className="eye-inline-actions"><small>明细保留 7 天</small><button className="text-button" aria-pressed={paused} onClick={() => setPaused(!paused)}>{paused ? "恢复显示" : "暂停显示"}</button></div></header><Notice error={page.error} updatedAt={page.updatedAt} onRetry={() => void page.reload()} />
    <div className="eye-stream-list" tabIndex={0} aria-label={sessions ? "最近会话" : "最近请求"}>{!data?.items.length ? <p className="eye-empty">{page.busy ? "正在读取…" : "暂无采集记录"}</p> : data.items.map(row => <article key={row.id} className="eye-request"><time>{new Date(row.at * 1000).toLocaleTimeString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })}</time><span className="eye-method">{sessions ? row.protocol.toUpperCase() : row.method}</span><button className="text-button eye-service-link" title={row.name} onClick={() => onService(row.service, row.name)}>{row.name}</button><span className="eye-request-path" title={row.path}>{sessions ? reasons[row.reason] ?? "连接已中断" : row.path}</span><strong className="eye-status-code" data-error={row.status >= 400}>{sessions ? "结束" : row.status}</strong><span>{milliseconds(row.duration_ms)}</span><span>{bytes(row.to_origin + row.to_public)}</span><small>{row.source || "—"} · {row.country || "未知"} · {row.browser || row.protocol} · {row.node === "local" ? "内置节点" : row.node}</small></article>)}</div>
    <footer><button className="text-button" disabled={!cursor} onClick={() => onPage(null)}>返回最新</button><button className="text-button" disabled={!data?.next_cursor} onClick={() => onPage(data!.next_cursor)}>下一页</button></footer>
  </>;
}

/** 首页按 HP-Lite 的空间关系组织：五项 KPI、实时大图、分布/画像、排行/请求流。
 * 统计范围与配额保持独立；每次切换用 key 隔离在途结果，避免跨用户或服务串数。
 */
export function TrafficEye({ active, base, query }: { active: boolean; base: string; query: string }) {
  const initial = new URLSearchParams(location.search);
  const [range, setRange] = useState<EyeRange>(ranges.some(([r]) => r === initial.get("eye_range")) ? initial.get("eye_range") as EyeRange : "24h");
  const [protocol, setProtocol] = useState(["http","https","websocket","tcp","udp"].includes(initial.get("eye_protocol") ?? "") ? initial.get("eye_protocol")! : "");
  const [mode, setMode] = useState(initial.get("eye_mode") === "reverse_proxy" ? "reverse_proxy" : "tunnel");
  const [status, setStatus] = useState(["1","2","3","4","5"].includes(initial.get("eye_status") ?? "") ? initial.get("eye_status")! : "");
  const [detail, setDetail] = useState<{ id: string; name: string } | null>(null);
  const params = new URLSearchParams(query); params.set("range", range); if (protocol) params.set("protocol", protocol); if (mode) params.set("mode", mode); if (status) params.set("status_class", status);
  const filters = params.toString();
  useEffect(() => {
    const url = new URL(location.href);
    url.searchParams.set("eye_range", range);
    url.searchParams.set("eye_mode", mode);
    if (status) url.searchParams.set("eye_status", status); else url.searchParams.delete("eye_status");
    if (protocol) url.searchParams.set("eye_protocol", protocol); else url.searchParams.delete("eye_protocol");
    history.replaceState(history.state, "", url);
  }, [range, protocol, mode, status]);
  return <><div className="eye-controls"><div><span className="eye-eyebrow">NEXO · TRAFFIC INSIGHTS</span><h2>流量天眼</h2></div><div className="eye-scope-controls"><label>服务类型<select aria-label="统计服务类型" value={mode} onChange={e => setMode(e.target.value)}><option value="tunnel">穿透服务</option><option value="reverse_proxy">反向代理</option></select></label><label>协议<select aria-label="统计协议" value={protocol} onChange={e => setProtocol(e.target.value)}><option value="">全部协议</option>{["http", "https", "websocket", "tcp", "udp"].map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}</select></label><div className="eye-status-filters" role="group" aria-label="请求状态筛选">{[["", "全部"], ["2", "2xx"], ["4", "4xx"], ["5", "5xx"]].map(([value, label]) => <button key={value} aria-pressed={status === value} onClick={() => setStatus(value)}>{label}</button>)}</div><div className="eye-ranges" role="group" aria-label="天眼时间范围">{ranges.map(([value, label]) => <button key={value} aria-pressed={range === value} onClick={() => setRange(value)}>{label}</button>)}</div>{document.fullscreenEnabled && <button className="text-button eye-fullscreen" onClick={e => { const target=e.currentTarget.closest(".home-traffic") as HTMLElement | null; void (document.fullscreenElement ? document.exitFullscreen() : target?.requestFullscreen())?.catch(() => {}); }}>全屏</button>}</div></div>
    <EyeData key={`${query}:${filters}`} active={active} base={`${base}/analytics`} query={filters} range={range} onService={(id, name) => setDetail({ id, name })} />
    {detail && <Modal title={`${detail.name} · 统计`} className="eye-detail" onClose={() => setDetail(null)}><div className="modal-body"><EyeData key={detail.id} active={active} base={`${base}/analytics`} query={`${new URLSearchParams({ ...Object.fromEntries(params), tunnel_id: detail.id })}`} range={range} compact onService={(id, name) => setDetail({ id, name })} /></div></Modal>}
  </>;
}

function EyeData({ active, base, query, range, compact = false, onService }: { active: boolean; base: string; query: string; range: EyeRange; compact?: boolean; onService: (id: string, name: string) => void }) {
  const summary = useResource(() => request<Summary>(`${base}/summary?${query}`), active, 5000, compact);
  const liveQuery = new URLSearchParams(query); liveQuery.set("range", "live");
  const live = useResource(() => request<Summary>(`${base}/summary?${liveQuery}`), active && range !== "live", 5000, compact);
  const data = summary.data;
  const total = data?.totals;
  const avg = total?.requests ? total.duration_ms / total.requests : null;
  const errorRate = total?.requests ? total.errors / total.requests * 100 : null;
  const cards = compact ? [
    ["发往内网", total ? bytes(total.to_origin) : "—", "所选时段"], ["返回公网", total ? bytes(total.to_public) : "—", "所选时段"],
    ["PV · HTTP 请求", number(total?.requests), "已完成请求"], ["UV · 日去重之和", number(data?.uv_daily_sum), "同一访客跨日分别计数"], ["平均耗时", milliseconds(avg), `p95 ≤ ${milliseconds(data?.p95_ms)}`],
  ] : [
    ["实时 QPS", number(data?.qps), "最近 60 秒完成请求 / 秒"], ["累计请求", number(total?.requests), "所选时段 · HTTP / HTTPS / WS"],
    ["总流量", total ? bytes(total.to_origin + total.to_public) : "—", total ? `↑ ${bytes(total.to_origin)}  ↓ ${bytes(total.to_public)}` : "双向数据量"],
    ["平均耗时", milliseconds(avg), `p95 ≤ ${milliseconds(data?.p95_ms)}`], ["运行时长", data ? `${Math.floor(data.uptime / 3600)}:${String(Math.floor(data.uptime / 60) % 60).padStart(2, "0")}:${String(data.uptime % 60).padStart(2, "0")}` : "—", `${number(data?.active)} 个 TCP/UDP 会话 · 错误率 ${errorRate == null ? "—" : `${number(errorRate)}%`}`],
  ];
  return <div className="eye-dashboard" aria-label={compact ? "单服务统计" : "流量天眼驾驶舱"}><Notice error={summary.error} updatedAt={summary.updatedAt} onRetry={() => void summary.reload()} />
    <div className="eye-health"><span className={`eye-live eye-live-${data?.status ?? "collecting"}`}>{data?.status === "ready" ? "采集运行中" : data?.status === "stale" ? "采集暂未更新" : "正在建立采集"}</span><span>{data?.sampled_at ? `更新于 ${dateText(data.sampled_at)}` : "等待首批记录"}</span><span>北京时间</span>{data?.coverage_percent != null && <span>采集覆盖 {number(data.coverage_percent)}%</span>}{Boolean(data?.lag_seconds && data.lag_seconds > 15) && <span>采集延迟 {number(data?.lag_seconds)} 秒</span>}</div>
    <div className="eye-kpis">{cards.map(([label, value, help]) => <section key={label} className="eye-card eye-kpi"><span>{label}</span><strong>{value}</strong><small>{help}</small></section>)}</div>
    {!data && summary.busy && <Loading />}
    <div className="eye-main-grid"><section className="eye-card eye-throughput"><header><h3>实时吞吐</h3><small>60 秒窗口 · 完成数据</small></header>{range !== "live" && <Notice error={live.error} updatedAt={live.updatedAt} onRetry={() => void live.reload()} />}{(range === "live" ? data : live.data) ? <Trend data={(range === "live" ? data : live.data)!} rate /> : <p className="eye-empty">等待采集数据</p>}<p className="eye-caption">HTTP 按请求完成统计数据量，TCP/UDP 按成功写入统计。</p></section><Distribution data={data} /><section className="eye-card eye-profile"><header><h3>访客画像</h3><small>HTTP 请求</small></header><div className="eye-profile-grid">{[["device", "设备"], ["os", "系统"], ["browser", "浏览器"], ["operator", "运营商 / ASN"]].map(([key, title]) => <div key={key}><h4>{title}</h4>{data?.breakdowns[key]?.slice(0, 3).map(row => <p key={row.label}><span>{row.label}</span><strong>{number(row.count)}</strong></p>) ?? <p>暂无采集记录</p>}</div>)}</div><footer><span>UV · 日去重之和 <b>{number(data?.uv_daily_sum)}</b></span></footer></section><Ranking title="TOP 来源国家 / 地区" rows={data?.breakdowns.country} help={data?.geo_available ? "本地 GeoIP 数据" : "未配置本地 GeoIP，地域显示未知"} /></div>
    <div className="eye-bottom-grid"><section className="eye-card eye-services"><header><h3>TOP 服务</h3><small>按流量</small></header>{data?.services.length ? <ol>{data.services.map((service, i) => <li key={service.id}><span>{i + 1}</span><button className="text-button" onClick={() => onService(service.id, service.name)}>{service.name}</button><strong>{bytes(service.bytes)}</strong><small>{number(service.requests)} 请求 · {number(service.errors)} 非成功响应</small></li>)}</ol> : <p className="eye-empty">暂无采集记录</p>}</section><RequestStream key={`requests:${query}`} active={active} base={base} query={query} onService={onService} /><Ranking title="TOP 来源网段" rows={data?.breakdowns.source} help="IPv4 /24 · IPv6 /48 脱敏" /><Ranking title="TOP 路径" rows={data?.breakdowns.path} help="查询参数不进入统计" /></div>
    <div className="eye-secondary-grid"><section className="eye-card"><header><h3>历史流量趋势</h3><small>所选时段</small></header>{data && <Trend data={data} />}</section><Ranking title="TOP 域名" rows={data?.breakdowns.domain} /><section className="eye-card"><header><h3>延迟趋势</h3><small>HTTP 请求</small></header>{data && <Trend data={data} kind="latency" />}<dl className="eye-latencies"><div><dt>平均耗时</dt><dd>{milliseconds(avg)}</dd></div><div><dt>p50 上界</dt><dd>{milliseconds(data?.p50_ms)}</dd></div><div><dt>p95 上界</dt><dd>{milliseconds(data?.p95_ms)}</dd></div></dl><p className="eye-caption">按完整响应时长统计；分位数使用延迟桶的上界。</p></section><section className="eye-card"><header><h3>访问趋势</h3><small>请求 / 错误</small></header>{data && <Trend data={data} kind="requests" />}</section><section className="eye-card"><header><h3>协议分布</h3><small>请求 / 会话</small></header><Ranking title="协议" rows={Object.entries(data?.protocols ?? {}).map(([label, count]) => ({ label: label.toUpperCase(), count }))} /></section><section className="eye-card"><header><h3>TCP / UDP 会话趋势</h3><small>会话 / 峰值</small></header>{data && <Trend data={data} kind="sessions" />}</section></div>
    <details className="eye-session-details"><summary>TCP / UDP 会话明细与结束原因</summary><div className="eye-session-grid"><RequestStream key={`sessions:${query}`} active={active} base={base} query={query} sessions onService={onService} /><Ranking title="结束原因" rows={data?.breakdowns.reason?.map(row => ({ ...row, label: reasons[row.label] ?? row.label }))} /></div></details>
    <details className="eye-statistics-help"><summary>统计口径与采集范围</summary><p>HTTP 请求耗时包含完整响应传输；WebSocket 在升级连接结束后记录，不能当作首字节延迟。TCP/UDP 只统计真实会话。时段累计与用户流量额度分别计算。</p><p>访客按入口、自然日、来源地址摘要与浏览器类别近似去重，跨日相加；共享出口可能低估，跨入口访问可能高估。来源仅保留网段，不保存原始 IP、请求体、查询参数。</p><p>明细保留 7 天，聚合保留 90 天。小时聚合用于长周期，未采集时段无法补回。{data && `本实例自 ${dateText(data.started_at)} 开始采集。`}{data?.partial ? "当前范围包含未采集或不完整时段。" : ""}{data?.dropped ? `已丢弃 ${number(data.dropped)} 条采集事件。` : ""}</p></details>
  </div>;
}
