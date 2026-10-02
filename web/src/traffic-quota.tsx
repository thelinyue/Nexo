import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Loading, Modal, Notice, WorkspaceLabelContext, errorText, request, useResource } from "./ui";

export type Quota = { monthly_limit_bytes: number | null; used_bytes: number; remaining_bytes: number | null; period_start: number; period_end: number; started_at: number; exhausted: boolean };
export function bytes(value: number, rate = false) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = value > 0 ? Math.max(0, Math.min(4, Math.floor(Math.log(value) / Math.log(1024)))) : 0;
  return `${(value / 1024 ** index).toLocaleString("zh-CN", { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}${rate ? "/s" : ""}`;
}
const calendarDate = (at: number) => new Date(at * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", year: "numeric", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });

/** 额度独立于可重置统计，单用户组件随筛选重新挂载，迟到结果不能串用。 */
export function QuotaSummary({ active, admin, userId }: { active: boolean; admin: boolean; userId?: string }) {
  const resource = useResource(() => request<Quota>(admin ? `/api/v1/admin/traffic/quota?user_id=${encodeURIComponent(userId!)}` : "/api/v1/traffic/quota"), active);
  const data = resource.data;
  return <section className="traffic-quota" aria-label="本月流量额度" data-exhausted={data?.exhausted}>
    <div className="quota-heading"><h3>本月流量额度</h3>{data && <span>{data.monthly_limit_bytes === null ? "未设置限制" : `已用 ${bytes(data.used_bytes)} / ${bytes(data.monthly_limit_bytes)}`}</span>}</div>
    <Notice error={resource.error} updatedAt={resource.updatedAt} onRetry={() => void resource.reload()} />
    {!data && <p className="helper">{resource.error ? "暂时无法获取额度" : "正在获取额度…"}</p>}
    {data && <>{data.monthly_limit_bytes !== null ? <><progress aria-label="本月额度使用比例" value={Math.min(data.used_bytes, data.monthly_limit_bytes)} max={data.monthly_limit_bytes} /><div className="quota-details"><span>剩余 {bytes(data.remaining_bytes!)}</span><span>{calendarDate(data.period_end)} 恢复</span></div></> : <p className="helper">本月额度消耗 {bytes(data.used_bytes)}</p>}
      {data.exhausted && <p className="quota-warning" role="status">本月额度已用尽，隧道转发已暂停。提高或取消限制，或等待下月恢复后可重新连接。</p>}
      <p className="helper">仅内网穿透，不含反向代理 · 北京时间 · 双向合计 · 自 {calendarDate(data.started_at)} 独立计量。重置统计不会恢复额度。</p></>}
  </section>;
}

/** 仅管理员修改额度；草稿与轮询状态分离，失败保留输入，停流操作在提交前明确说明。 */
export function QuotaForm({ user, csrf, onClose, onSaved }: { user: { id: string; username: string }; csrf?: string | null; onClose: () => void; onSaved: () => void }) {
  const path = `/api/v1/admin/traffic/quota?user_id=${encodeURIComponent(user.id)}`;
  const resource = useResource(() => request<Quota>(path), true, true, true);
  const [mode, setMode] = useState<"unlimited" | "limited" | null>(null);
  const [amount, setAmount] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (resource.data && mode === null) { setMode(resource.data.monthly_limit_bytes === null ? "unlimited" : "limited"); setAmount(resource.data.monthly_limit_bytes === null ? "" : String(resource.data.monthly_limit_bytes / 1024 ** 3)); } }, [resource.data, mode]);
  const limit = mode === "unlimited" ? null : Number(amount) * 1024 ** 3;
  const valid = mode !== null && (mode === "unlimited" || (/^[1-9]\d*$/.test(amount) && Number.isSafeInteger(limit)));
  const dirty = Boolean(resource.data && limit !== resource.data.monthly_limit_bytes);
  const stopping = valid && limit !== null && Boolean(resource.data && limit <= resource.data.used_bytes);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (busy || !valid || !dirty) return;
    setBusy(true); setError(null);
    try {
      const latest = await request<Quota>(path);
      resource.setData(latest);
      if (limit !== null && limit <= latest.used_bytes && !stopping) { setError("用量已增加，请确认停止全部转发后再次保存。"); return; }
      await request<Quota>(path, { method: "PUT", body: JSON.stringify({ monthly_limit_bytes: limit }) }, csrf);
      onSaved();
    } catch (error) { setError(errorText(error)); } finally { setBusy(false); }
  }
  return <WorkspaceLabelContext.Provider value={undefined}><Modal title={`流量限制 · ${user.username}`} dirty={dirty} busy={busy} onClose={onClose}><form className="modal-form quota-form" onSubmit={submit}>
    <div className="modal-body"><Notice error={resource.error} updatedAt={resource.updatedAt} onRetry={() => void resource.reload()} />
      {!resource.data ? !resource.error && <Loading /> : <><div className="quota-heading"><span>本月额度消耗</span><strong>{bytes(resource.data.used_bytes)}</strong></div>
        <fieldset disabled={busy || mode === null}><label>限制方式<select value={mode ?? "unlimited"} onChange={event => setMode(event.target.value as "unlimited" | "limited")}><option value="unlimited">不限制</option><option value="limited">设置月额度</option></select></label>
          {mode === "limited" && <label>月额度（GiB）<input type="number" min="1" max="8388607" step="1" inputMode="numeric" required value={amount} onChange={event => setAmount(event.target.value)} /></label>}
        </fieldset><p className="helper">每月 1 日北京时间零点恢复；全部隧道双向合计。重置统计不会恢复额度。</p>
        {stopping && <p className="quota-warning" role="alert">保存后将停止该用户全部隧道转发，包括现有连接。账号和设备保持在线。</p>}
      </>}<Notice error={error} /></div>
    <footer className="modal-actions"><button type="button" className="secondary-button modal-dismiss" disabled={busy} onClick={onClose}>取消</button><button className={stopping ? "danger-button" : "primary-button"} disabled={busy || !valid || !dirty || !resource.data}>{busy ? "保存中…" : stopping ? "保存并停止转发" : "保存"}</button></footer>
  </form></Modal></WorkspaceLabelContext.Provider>;
}
