import { useState } from "react";
import { CopyButton, Modal, Notice, dateText, errorText, useApi } from "./ui";
import type { Device, Enrollment } from "./ui";

/** 生成邀请只授权新的申请；真正替换证书需在 Agent 列表再次批准，避免误触造成断线。 */
export function DeviceRecovery({ device, csrf, onClose, onCreated }: { device: Device; csrf?: string | null; onClose: () => void; onCreated: () => void }) {
  const request = useApi();
  const [invite, setInvite] = useState<Enrollment | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  async function create() {
    setBusy(true); setError(null);
    try { setInvite(await request<Enrollment>(`/api/v1/devices/${encodeURIComponent(device.id)}/recovery`, { method: "POST" }, csrf)); onCreated(); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <Modal title={`恢复 ${device.name} 的身份`} onClose={onClose} busy={busy}><div className="modal-body">
    <p>用于设备证书已过期、私钥丢失或身份文件损坏。原设备 ID 和 {device.tunnel_count} 个服务绑定会保留。</p>
    <ol className="steps">
      <li><strong>生成恢复凭证</strong><p>有效期 1 小时，仅本次显示，请在关闭前保存。重新生成会撤销此前的恢复凭证。</p>{!invite ? <button className="primary-button" onClick={() => void create()} disabled={busy}>{busy ? "生成中…" : "生成恢复凭证"}</button> : <><code className="token">{invite.token}</code>{invite.token && <CopyButton value={invite.token} label="复制恢复凭证" />}<small>有效期至 {dateText(invite.expires_at)}</small></>}</li>
      <li><strong>在原 Agent 主机提交恢复申请</strong><p>先停止原 Agent，保留数据目录。使用恢复凭证运行一次恢复命令：</p><code className="command-block">docker compose -f compose.agent.yml run --rm -e NEXO_ENROLLMENT_TOKEN=恢复凭证 nexo-agent --recover-identity</code><details className="recovery-help"><summary>使用二进制部署</summary><p className="helper">直接运行二进制时，设置 NEXO_ENROLLMENT_TOKEN 后执行 nexo-agent --recover-identity，保持原 NEXO_STATE_DIR 和 Server 地址。</p></details></li>
      <li><strong>返回列表批准恢复</strong><p>关闭此窗口，在 Agent 列表核对原设备后批准。批准时旧证书和旧连接立即失效。</p></li>
      <li><strong>正常启动 Agent</strong><p>恢复命令成功退出后，用原配置启动 Agent。服务会自动重新下发，无需重新绑定。</p></li>
    </ol><Notice error={error} />
  </div></Modal>;
}
