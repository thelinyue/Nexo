import { NodeGroupsDialog, WorkspaceChoices } from "./node-groups";
import type { NodeGroup } from "./node-groups";
import { NodeEnrollmentPanel, NodeSetupStatus } from "./node-enrollment";
import type { NodeEnrollment } from "./node-enrollment";
import { useState } from "react";
import { Clock, CircleAlert, Server, Check, Pause, ChevronRight, ArrowUpRight, Search } from "./icons";
import { CopyButton, CreateButton, Loading, Modal, Notice, PageHeader, dateText, errorText, useApi, useResource } from "./ui";
import "./nodes.css";

export type NodeLatency = { device_id: string; device_name: string; rtt_ms: number; checked_at: number; samples: number; fresh: boolean };
export type RelayNode = { id: string; name: string; public_ipv4: string; control_port: number; status: string; approved: boolean; enabled: boolean; registered: boolean; can_enroll?: boolean; assigned?: boolean; selectable?: boolean; enrollment_expires_at?: number; os?: string; architecture?: string; version?: string; last_seen?: number; connections: number; services: { id: string; name: string; enabled?: boolean; alternatives?: { id: string; name: string }[] }[]; workspace_ids?: string[]; latencies: NodeLatency[]; error?: string; update?: { stage: string; target_version: string; error?: string }; events?: { message: string; occurred_at: number }[] };
type NodeRelease = { version: string; architectures: string[] };
type UpdateJob = { id: string; target_version: string; status: string; items: { node_id: string; stage: string; error?: string }[] };
export type NodeList = { nodes: RelayNode[]; server_version: string };
const statuses: Record<string, string> = { online: "在线", offline: "离线", unregistered: "待安装", expired: "凭证已过期", pending: "待审批", disabled: "已停用", maintenance: "维护中" };
const stages: Record<string, string> = { queued: "等待执行", downloading: "下载并校验", withdrawing: "撤出 DNS，等待缓存过期", draining: "等待连接结束", installing: "安装重启", verifying: "验证服务", restoring: "恢复 DNS", failed: "更新失败", rolled_back: "已回退", rollback_failed: "回退失败", unknown: "结果待确认" };
const newer = (current: string | undefined, target: string) => !!current && /^\d+\.\d+\.\d+$/.test(current) && target.split(".").map(Number).some((v, i, all) => v > Number(current.split(".")[i]) && all.slice(0, i).every((p, j) => p === Number(current.split(".")[j])));

/** 只汇总新鲜样本；历史样本独立标注，不用 0 ms 表示待测速或离线。 */
export function NodeLatencyView({ node, compact = false, onDetails }: { node: RelayNode; compact?: boolean; onDetails?: () => void }) {
  const fresh = node.latencies.filter(sample => node.status === "online" && sample.fresh && Date.now() / 1000 - sample.checked_at < 45);
  const samples = fresh.length ? fresh : node.latencies;
  const values = samples.map(sample => sample.rtt_ms);
  const low = Math.min(...values), high = Math.max(...values);
  const label = values.length ? `${low === high ? low : `${low}–${high}`} ms` : "待测速";
  if (compact) return <button className="node-latency-summary" data-fresh={!!fresh.length} onClick={onDetails} aria-label={`查看 ${node.name} 逐设备延迟`}>
    <span className="node-latency-caption"><span>延迟</span>{!fresh.length && !!samples.length && <small>已过期</small>}</span>
    <span className="node-latency-reading"><strong className={values.length ? "" : "node-measurement-pending"}>{values.length ? <>{low === high ? low : `${low}–${high}`}<small> ms</small></> : "待测速"}</strong><ChevronRight size={14} aria-hidden="true" /></span>
  </button>;
  return <div className="node-latency" aria-label="延迟"><strong>{label}</strong>{!fresh.length && !!samples.length && <small>上次测量 · 已过期</small>}
    {!!node.latencies.length && <details><summary>逐设备延迟（{node.latencies.length}）</summary><ul>{node.latencies.map(sample => <li key={sample.device_id}><span>{sample.device_name}</span><strong>{sample.rtt_ms} ms</strong><small>{!fresh.includes(sample) && "上次测量 "}{dateText(sample.checked_at)}</small></li>)}</ul></details>}
  </div>;
}

export function NodesPage({ admin, active, csrf }: { admin: boolean; active: boolean; csrf?: string | null }) {
  const api = useApi();
  const resource = useResource(() => api<NodeList>("/api/v1/nodes"), active, 10000);
  const releases = useResource(() => api<NodeRelease[]>("/api/v1/node-releases"), active && admin, false);
  const jobs = useResource(() => api<UpdateJob[]>("/api/v1/node-update-jobs"), active && admin, 10000);
  const [forceJob, setForceJob] = useState<string | null>(null);
  const groups = useResource(() => api<NodeGroup[]>("/api/v1/node-groups"), active, 10000);
  const [groupFilter, setGroupFilter] = useState(""); const [groupDialog, setGroupDialog] = useState(false);
  const [search, setSearch] = useState(""); const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<string[]>([]); const [creating, setCreating] = useState(false);
  const [detail, setDetail] = useState<RelayNode | null>(null); const [update, setUpdate] = useState<RelayNode[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const data = resource.data;
  const available = (n: RelayNode) => n.id !== "local" && n.status === "online" && !n.update && !!releases.data?.some(release => release.architectures.includes(n.architecture ?? "") && newer(n.version, release.version));
  const nodes = (data?.nodes ?? []).filter(n => (!groupFilter || groups.data?.find(group => group.id === groupFilter)?.node_ids.includes(n.id)) && `${n.name} ${n.public_ipv4}`.toLowerCase().includes(search.trim().toLowerCase()) && (!filter || (filter === "updates" ? available(n) : n.status === filter)));
  async function open(node: RelayNode) { try { setError(null); setDetail(await api<RelayNode>(`/api/v1/nodes/${encodeURIComponent(node.id)}`)); } catch (e) { setError(errorText(e)); } }
  return <>
    <PageHeader title="节点" action={<CreateButton label="节点" onClick={() => setCreating(true)} />} />
    <p className="helper node-page-caption">管理公网入口，查看节点状态与设备延迟。</p>
    <div className="node-filters"><label className="node-search"><Search size={18} aria-hidden="true" /><input type="search" aria-label="搜索节点名称或 IP" placeholder="搜索名称或 IP" value={search} onChange={e => setSearch(e.target.value)} /></label><select aria-label="筛选节点" value={filter} onChange={e => setFilter(e.target.value)}><option value="">全部状态</option>{Object.entries(statuses).map(([key, label]) => <option key={key} value={key}>{label}</option>)}<option value="updates">可更新</option></select><select aria-label="筛选节点组" value={groupFilter} onChange={e => setGroupFilter(e.target.value)}><option value="">全部节点组</option>{groups.data?.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select>{admin && <button className="secondary-button" disabled={!groups.data} onClick={() => setGroupDialog(true)}>节点组</button>}{admin && <button className="secondary-button" disabled={!data?.nodes.some(n => selected.includes(n.id) && available(n))} onClick={() => setUpdate(data!.nodes.filter(n => selected.includes(n.id) && available(n)))}>批量更新{selected.length ? `（${selected.length}）` : ""}</button>}</div>
    <Notice error={resource.error ?? groups.error ?? releases.error ?? jobs.error ?? error} onRetry={() => void resource.reload()} updatedAt={resource.updatedAt} />
    {admin && jobs.data?.filter(job => ["queued", "running", "paused"].includes(job.status)).map(job => <section className="panel node-job" key={job.id} aria-label="节点维护任务"><strong>顺序更新 · v{job.target_version} · {job.status === "paused" ? "已暂停" : "进行中"}</strong><ol>{job.items.map(item => <li key={item.node_id}>{data?.nodes.find(n => n.id === item.node_id)?.name ?? item.node_id} · {stages[item.stage] ?? item.stage}{item.error && <p className="form-error">{item.error}</p>}</li>)}</ol>{["queued", "paused"].includes(job.status) && <div className="node-dialog-actions">{(job.items.some(item => item.stage === "draining") ? [["wait", "继续等待"], ["force", "中断连接后更新"], ["cancel", "取消任务"]] : [["retry", "重试"], ["skip", "跳过当前节点"], ["cancel", "取消余下任务"]]).map(([action, label]) => <button className="text-button" key={action} onClick={async () => { if (action === "force" && forceJob !== job.id) { setForceJob(job.id); return; } try { await api(`/api/v1/node-update-jobs/${job.id}`, { method: "POST", body: JSON.stringify({ action }) }, csrf); setForceJob(null); void jobs.reload(); void resource.reload(); } catch (e) { setError(errorText(e)); } }}>{action === "force" && forceJob === job.id ? "确认中断连接并更新" : label}</button>)}</div>}</section>)}
    {!data && resource.busy ? <Loading /> : <div className="node-grid">{nodes.map(node => {
      const Icon = node.error || node.update?.error ? CircleAlert : node.status === "online" ? Check : node.status === "disabled" ? Pause : Clock;
      return <article className="node-card" key={node.id} aria-label={node.name} data-selected={selected.includes(node.id)}>
        <header className="node-card-heading"><span className="node-symbol" aria-hidden="true"><Server size={23} /></span><div><h2>{node.name}</h2><p className="node-platform">{[node.os, node.architecture === "aarch64" ? "ARM64" : node.architecture].filter(Boolean).join(" · ") || "等待系统信息"}</p></div>{admin && node.id !== "local" && <label className="node-selection"><input type="checkbox" aria-label={`选择 ${node.name}`} checked={selected.includes(node.id)} disabled={!available(node)} onChange={e => setSelected(e.target.checked ? [...selected, node.id] : selected.filter(id => id !== node.id))} /></label>}</header>
        <div className="node-address-row"><div className="node-address"><span>{node.public_ipv4 || "管理 Server"}</span>{node.public_ipv4 && <CopyButton iconOnly value={node.public_ipv4} label={`复制 ${node.name} IP`} />}</div><span className={`node-status ${node.status === "online" ? "online" : node.update?.error || node.error ? "failed" : ""}`}><Icon size={14} aria-hidden="true" />{statuses[node.status] ?? node.status}</span></div>
        <div className="node-metrics"><NodeLatencyView node={node} compact onDetails={() => void open(node)} /><dl><div><dd>{node.services.length}</dd><dt>服务</dt></div><div><dd>{node.connections}</dd><dt>{node.status === "online" ? "连接" : "上次连接"}</dt></div></dl></div>
        {node.approved && node.assigned === false && <p className="node-context">等待管理员分配工作空间</p>}
        {node.status === "offline" && <p className="node-context">最近在线 {dateText(node.last_seen)}</p>}
        {node.update && <p className="node-context" role="status">{stages[node.update.stage] ?? node.update.stage} · v{node.update.target_version}</p>}
        <Notice error={node.update?.error ?? node.error} />
        <footer><span className="node-version" title="当前版本">{node.version ? `v${node.version}` : "版本待上报"}</span><div>{admin && available(node) && <button className="node-update-button" onClick={() => setUpdate([node])}>更新版本<ArrowUpRight size={14} aria-hidden="true" /></button>}<button className="node-manage-button" onClick={() => void open(node)}>{admin && node.id !== "local" ? "管理" : "详情"}<ChevronRight size={15} aria-hidden="true" /></button></div></footer>
      </article>;
    })}</div>}
    {data && !nodes.length && <p className="helper">{data.nodes.length ? "没有符合筛选条件的节点" : "尚未接入 VPS，添加节点以生成安装命令。"}</p>}
    {groupDialog && <NodeGroupsDialog groups={groups.data ?? []} nodes={data?.nodes ?? []} csrf={csrf} onClose={() => { setGroupDialog(false); void groups.reload(); void resource.reload(); }} />}
    {creating && <NodeCreate csrf={csrf} onClose={() => { setCreating(false); void resource.reload(); }} />}
    {detail && <NodeDetail node={detail} admin={admin} csrf={csrf} onClose={() => { setDetail(null); void resource.reload(); }} />}
    {update && data && <NodeUpdate nodes={update} releases={releases.data ?? []} version={data.server_version} csrf={csrf} onClose={() => { setUpdate(null); setSelected([]); void resource.reload(); }} />}
  </>;
}

function NodeCreate({ csrf, onClose }: { csrf?: string | null; onClose: () => void }) {
  const api = useApi(); const [name, setName] = useState(""); const [ip, setIp] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<NodeEnrollment | null>(null);
  return <Modal title="添加节点" onClose={onClose} busy={busy} dirty={!!name && !enrollment}>
    {enrollment ? <>
      <div className="modal-body"><NodeEnrollmentPanel initial={enrollment} nodeId={enrollment.id} csrf={csrf} /></div>
      <footer className="modal-actions"><button className="primary-button" onClick={onClose}>返回列表</button></footer>
    </> : <form className="modal-form" onSubmit={async e => { e.preventDefault(); setBusy(true); setError(null); try { setEnrollment(await api("/api/v1/nodes", { method: "POST", body: JSON.stringify({ name, public_ipv4: ip }) }, csrf)); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>
      <div className="modal-body">
        <label>名称<input required maxLength={80} value={name} onChange={e => setName(e.target.value)} /></label>
        <label>公网 IPv4<input required value={ip} onChange={e => setIp(e.target.value)} placeholder="203.0.113.10" /></label>
        <p className="helper">Debian 12/13、Ubuntu 22.04/24.04 · x86_64 / ARM64</p><Notice error={error} />
      </div>
      <footer className="modal-actions"><button className="primary-button" disabled={busy}>{busy ? "正在创建…" : "继续"}</button></footer>
    </form>}
  </Modal>;
}

/** 所有写操作仍由服务端鉴权；普通用户详情只呈现其可见服务和设备延迟。 */
function NodeDetail({ node, admin, csrf, onClose }: { node: RelayNode; admin: boolean; csrf?: string | null; onClose: () => void }) {
  const api = useApi(); const [name, setName] = useState(node.name); const [ip, setIp] = useState(node.public_ipv4); const [port, setPort] = useState(node.control_port); const [grants, setGrants] = useState(node.workspace_ids ?? []); const [enabled, setEnabled] = useState(node.enabled);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [confirm, setConfirm] = useState(false); const [restart, setRestart] = useState(false); const [interruption, setInterruption] = useState(false);
  async function perform(path: string, method: string, body?: unknown) { setBusy(true); setError(null); try { await api(path, { method, body: body === undefined ? undefined : JSON.stringify(body) }, csrf); onClose(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }
  const path = `/api/v1/nodes/${encodeURIComponent(node.id)}`;
  const live = useResource(() => api<RelayNode>(path), true, 3000, true);
  async function approve() {
    setBusy(true); setError(null);
    try {
      await api(path, { method: "PUT", body: JSON.stringify({ name, public_ipv4: ip, control_port: port, enabled, workspace_ids: grants }) }, csrf);
      await api(`${path}/approve`, { method: "POST" }, csrf);
      onClose();
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }
  return <Modal title={node.name} onClose={onClose} busy={busy}><div className="modal-body">
    {(live.data ?? node).can_enroll ? <NodeEnrollmentPanel nodeId={node.id} csrf={csrf} /> : <NodeSetupStatus node={live.data ?? node} />}
    <NodeLatencyView node={node} />
    <h3>关联服务</h3><ul>{node.services.map(service => <li key={service.id}><a href={`#/services/${encodeURIComponent(service.id)}`} onClick={onClose}>{service.name}</a></li>)}</ul>{!node.services.length && <p className="helper">尚无关联服务</p>}
    {admin && node.id !== "local" && <><form onSubmit={e => { e.preventDefault(); void perform(path, "PUT", { name, public_ipv4: ip, control_port: port, enabled, workspace_ids: grants }); }}><label>节点名称<input value={name} onChange={e => setName(e.target.value)} required maxLength={80} /></label><label>公网 IPv4<input required value={ip} onChange={e => setIp(e.target.value)} /></label><label>数据端口<input type="number" min={1} max={65535} value={port} onChange={e => setPort(Number(e.target.value))} /></label><WorkspaceChoices value={grants} onChange={setGrants} /><label className="node-check"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />启用节点</label><button className="primary-button" disabled={busy || !!node.update}>保存配置</button></form>
      {!node.approved && <button className="secondary-button" disabled={busy || !(live.data ?? node).registered} onClick={() => void approve()}>批准并保存配置</button>}
      <button className="secondary-button" disabled={busy || !!node.update || node.status !== "online"} onClick={() => setRestart(true)}>重启节点服务</button>
      {restart && <section><p>仅重启 Nexo 节点服务，先撤出 DNS 并排空连接。影响 {node.services.filter(service => service.enabled !== false).length} 个服务。</p><NodeImpact node={node} /><label className="node-check"><input type="checkbox" checked={interruption} onChange={e => setInterruption(e.target.checked)} />没有其他健康 IPv4 入口时，我接受服务中断</label><button className="primary-button" disabled={busy || (!interruption && needsInterruption(node))} onClick={() => void perform("/api/v1/node-update-jobs", "POST", { operation: "restart", node_ids: [node.id], target_version: node.version, accept_interruption: interruption })}>确认重启 Nexo 服务</button><button className="text-button" onClick={() => setRestart(false)}>取消</button></section>}
      <button className="secondary-button" disabled={busy || !!node.update} onClick={() => setConfirm(true)}>移除节点</button>
      {confirm && <div role="alert"><p>移除将撤销身份并关闭服务连接，VPS 上的数据保留。</p><button className="danger-button" disabled={busy} onClick={() => void perform(path, "DELETE")}>确认移除</button><button className="secondary-button" onClick={() => setConfirm(false)}>取消</button></div>}
    </>}
    <Notice error={error ?? live.error} />
    {!!node.events?.length && <><h3>操作记录</h3><ul>{node.events.map((event, i) => <li key={i}>{event.message}<small> · {dateText(event.occurred_at)}</small></li>)}</ul></>}
  </div></Modal>;
}

const needsInterruption = (node: RelayNode) => node.services.some(service => service.enabled !== false && !service.alternatives?.length);

/** 按服务展示已通过公网检查的 IPv4 备用入口；实际执行前服务端再次核对。 */
function NodeImpact({ node }: { node: RelayNode }) {
  const services = node.services.filter(service => service.enabled !== false);
  if (!services.length) return <p className="helper">没有启用中的关联服务</p>;
  return <ul>{services.map(service => <li key={service.id}>{service.name}<p className="helper">{service.alternatives?.length ? `健康备用入口：${service.alternatives.map(node => node.name).join("、")}` : "暂无已确认的健康 IPv4 备用入口"}</p></li>)}</ul>;
}

function NodeUpdate({ nodes, version, releases, csrf, onClose }: { nodes: RelayNode[]; version: string; releases: NodeRelease[]; csrf?: string | null; onClose: () => void }) {
  const api = useApi(); const [accepted, setAccepted] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const compatible = releases.filter(release => nodes.every(node => release.architectures.includes(node.architecture ?? "") && newer(node.version, release.version)));
  const [target, setTarget] = useState(compatible.find(release => release.version === version)?.version ?? compatible[0]?.version ?? "");
  return <Modal title="顺序更新节点" busy={busy} onClose={onClose}><label>目标版本<select value={target} onChange={e => setTarget(e.target.value)}>{compatible.map(release => <option key={release.version} value={release.version}>v{release.version}</option>)}</select></label><p>按下列顺序逐台更新，每台恢复健康后才继续。</p><ol>{nodes.map(node => <li key={node.id}>{node.name} · 影响 {node.services.filter(service => service.enabled !== false).length} 个服务<NodeImpact node={node} /></li>)}</ol><p>先校验安装包，再撤出 DNS 并等待连接结束。长连接超过 5 分钟时暂停，需管理员处理。</p><label className="node-check"><input type="checkbox" checked={accepted} onChange={e => setAccepted(e.target.checked)} />若没有其他健康 IPv4 入口，我接受服务中断</label><Notice error={error} /><button className="primary-button" disabled={busy || !target || (!accepted && nodes.some(needsInterruption))} onClick={async () => { setBusy(true); setError(null); try { await api("/api/v1/node-update-jobs", { method: "POST", body: JSON.stringify({ node_ids: nodes.map(n => n.id), target_version: target, accept_interruption: accepted }) }, csrf); onClose(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>开始更新</button></Modal>;
}
