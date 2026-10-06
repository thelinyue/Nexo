import { useEffect, useState } from "react";
import { Loading, Modal, Notice, errorText, useApi, useResource } from "./ui";
import { bytes } from "./traffic-quota";

export type NodeQuota = { monthly_limit_bytes: number | null; used_bytes: number; reserved_bytes: number; remaining_bytes: number | null; period_start: number; period_end: number; started_at: number | null; supported: boolean; exhausted: boolean; revision: number };
const date = (at: number) => new Date(at * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });

/** 节点在线与业务停流独立呈现；预留不算实际用量。 */
export function NodeQuotaSummary({ quota, onEdit }: { quota: NodeQuota; onEdit?: () => void }) {
  return <section className="node-section node-quota" aria-label="节点本月流量">
    <div className="node-quota-heading"><h3>本月流量</h3>{onEdit && <button className="text-button" onClick={onEdit}>设置流量限制</button>}</div>
    {!quota.supported ? <p className="helper" role="status">升级节点后可计量流量{quota.monthly_limit_bytes !== null && "，升级前转发暂停"}。</p> : <>
      <p>已用 {bytes(quota.used_bytes)} / {quota.monthly_limit_bytes === null ? "不限制" : bytes(quota.monthly_limit_bytes)}</p>
      {quota.monthly_limit_bytes !== null && <><progress aria-label="节点月额度占用比例" value={Math.min(quota.used_bytes + quota.reserved_bytes, quota.monthly_limit_bytes)} max={quota.monthly_limit_bytes} /><p className="helper">剩余 {bytes(quota.remaining_bytes ?? 0)} · {date(quota.period_end)} 重置</p></>}
      {quota.reserved_bytes > 0 && <p className="helper">待结算占用 {bytes(quota.reserved_bytes)}</p>}
      {quota.exhausted && <p className="quota-warning" role="status">本月额度已用尽，转发暂停。提高额度、取消限制或下月重置后，请重新连接。</p>}
    </>}
    <p className="helper">穿透与反向代理 · 所有用户上传下载合计</p>
    <details><summary>计量说明</summary><p className="helper">升级后开始计量，不追溯历史流量。每月 1 日北京时间 00:00 重置，重置用户统计不影响节点额度。待结算占用包含转发预留和失联未结算额度。计量包含 HTTP 头和 HTTPS 回源 TLS 字节，不含节点管理流量，可能与运营商账单不同。</p></details>
  </section>;
}

/** 草稿只初始化一次；实时刷新不覆盖输入，停流保存前再次读取占用。 */
export function NodeQuotaForm({ node, csrf, onClose, onSaved }: { node: { id: string; name: string }; csrf?: string | null; onClose: () => void; onSaved: () => void }) {
  const api = useApi(); const path = `/api/v1/nodes/${encodeURIComponent(node.id)}/traffic/quota`;
  const resource = useResource(() => api<NodeQuota>(path), true, 3000, true);
  const [mode, setMode] = useState<"unlimited" | "limited" | null>(null);
  const [amount, setAmount] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (resource.data && mode === null) { setMode(resource.data.monthly_limit_bytes === null ? "unlimited" : "limited"); setAmount(resource.data.monthly_limit_bytes === null ? "" : String(resource.data.monthly_limit_bytes / 1024 ** 3)); } }, [resource.data, mode]);
  const limit = mode === "unlimited" ? null : Number(amount) * 1024 ** 3;
  const valid = mode !== null && (mode === "unlimited" || (resource.data?.supported && /^[1-9]\d*$/.test(amount) && Number.isSafeInteger(limit)));
  const dirty = Boolean(resource.data && limit !== resource.data.monthly_limit_bytes);
  const stopping = Boolean(limit !== null && resource.data && limit <= resource.data.used_bytes + resource.data.reserved_bytes);
  return <Modal className="node-modal" title={`流量限制 · ${node.name}`} dirty={dirty} busy={busy} onClose={onClose}><form className="modal-form" onSubmit={async e => {
    e.preventDefault(); if (busy || !valid || !dirty) return; setBusy(true); setError(null);
    try {
      const latest = await api<NodeQuota>(path); resource.setData(latest);
      if (limit !== null && limit <= latest.used_bytes + latest.reserved_bytes && !stopping) { setError("当前占用已达新额度，请确认后再次保存。"); return; }
      await api(path, { method: "PUT", body: JSON.stringify({ monthly_limit_bytes: limit }) }, csrf); onSaved();
    } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }}><div className="modal-body node-form-fields">
    <Notice error={resource.error} onRetry={() => void resource.reload()} />
    {!resource.data ? !resource.error && <Loading /> : <>
      <p>本月已用 {bytes(resource.data.used_bytes)} · 待结算 {bytes(resource.data.reserved_bytes)}</p>
      <fieldset disabled={busy || mode === null}><label>限制方式<select value={mode ?? "unlimited"} onChange={e => setMode(e.target.value as "unlimited" | "limited")}><option value="unlimited">不限制</option><option value="limited" disabled={!resource.data.supported}>设置月额度</option></select></label>
        {mode === "limited" && <label>月额度（GiB）<input type="number" min={1} max={8388607} step={1} inputMode="numeric" value={amount} onChange={e => setAmount(e.target.value)} required disabled={!resource.data.supported} /></label>}
      </fieldset>
      {!resource.data.supported && <p className="helper">升级节点后可设置流量限制。</p>}
      <p className="helper">所有用户上传下载合计，每月 1 日北京时间 00:00 重置。修改限制会断开现有连接，需重新连接。</p>
      {stopping && <p className="quota-warning" role="alert">当前占用已达新额度。保存后暂停转发；有可用备用节点的穿透服务自动切换。</p>}
    </>}<Notice error={error} />
  </div><footer className="modal-actions"><button type="button" className="secondary-button modal-dismiss" disabled={busy} onClick={onClose}>取消</button><button className={stopping ? "danger-button" : "primary-button"} disabled={busy || !valid || !dirty || !resource.data}>{busy ? "保存中…" : stopping ? "保存并断开连接" : "保存"}</button></footer></form></Modal>;
}
