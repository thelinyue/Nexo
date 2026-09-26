import { useState } from "react";
import { Confirm, EnrollmentDevice, Notice, dateText, useApi, useResource } from "./ui";
import type { Device, Enrollment } from "./ui";

/** 只读进度允许在弹窗内刷新；审批由用户明确提交，设备名称草稿不随轮询覆盖。 */
export function EnrollmentProgress({ invite, csrf, onApproved }: { invite: Enrollment; csrf?: string | null; onApproved: () => Promise<void> | void }) {
  const request = useApi();
  const resource = useResource(async () => {
    const enrollment = await request<Enrollment>(`/api/v1/enrollments/${encodeURIComponent(invite.id)}`);
    const devices = enrollment.status === "approved" ? await request<Device[]>("/api/v1/devices") : [];
    return { enrollment, device: devices.find(item => item.id === enrollment.device_id) };
  }, true, true, true);
  const [name, setName] = useState(""); const [approving, setApproving] = useState(false);
  const item = resource.data?.enrollment ?? invite;
  const recovery = item.kind === "recovery";
  return <section className="enrollment-progress" aria-label="入网进度">
    <h3>{recovery ? "恢复进度" : "入网进度"}</h3>
    <p aria-live="polite">{resource.data?.device?.status === "online" ? "Agent 已上线，服务配置将自动下发。" : ({ awaiting_agent: "等待 Agent 连接", awaiting_approval: "设备已连接，等待批准", approved: "已批准，等待 Agent 上线", expired: "申请已过期，请重新生成凭证", revoked: "申请已撤销" } as Record<string, string>)[item.status] ?? item.status}</p>
    <Notice error={resource.error} onRetry={() => void resource.reload()} />
    {item.status === "awaiting_approval" && <><EnrollmentDevice item={item} /><p className="helper">有效期至 {dateText(item.expires_at)}</p>{!recovery && <label>Agent 名称<input value={name} placeholder={item.device_name || "我的 Agent"} onChange={e => setName(e.target.value)} /></label>}<button className="primary-button" onClick={() => setApproving(true)}>{recovery ? "批准恢复" : "批准入网"}</button></>}
    {item.status === "approved" && recovery && <p className="helper">恢复命令成功退出后，用原配置启动 Agent，保留原数据目录。</p>}
    {approving && <Confirm title={recovery ? "批准恢复设备身份？" : "批准 Agent 入网？"} tone={recovery ? "danger" : "primary"} description={recovery ? "原设备与服务绑定保留。批准后旧证书及旧连接立即失效，请确认申请来自你的 Agent。" : `请确认 ${item.device_name || "此设备"} 是你刚刚部署的主机。`} label={recovery ? "批准恢复" : "批准入网"} onClose={() => setApproving(false)} onConfirm={async () => {
      await request(`/api/v1/enrollments/${encodeURIComponent(item.id)}/approve`, { method: "POST", body: JSON.stringify(recovery ? {} : { device_name: name.trim() || item.device_name || "我的 Agent" }) }, csrf);
      await resource.reload(); await onApproved();
    }} />}
  </section>;
}
