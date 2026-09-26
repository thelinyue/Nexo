import { EnrollmentProgress } from "./enrollment-progress";
import { useState } from "react";
import { CopyButton, Modal, Notice, dateText, errorText, useApi } from "./ui";
import type { Device, Enrollment } from "./ui";

/** 生成邀请只授权新的申请；真正替换证书需核对申请后再次批准，避免误触造成断线。 */
export function DeviceRecovery({ device, csrf, onClose, onCreated }: { device: Device; csrf?: string | null; onClose: () => void; onCreated: () => Promise<void> }) {
  const request = useApi();
  const [composeFile, setComposeFile] = useState("compose.yml");
  const shellLiteral = (value: string) => "'" + value.replace(/'/g, "'\"'\"'") + "'";
  const [invite, setInvite] = useState<Enrollment | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  async function create() {
    setBusy(true); setError(null);
    try { setInvite(await request<Enrollment>(`/api/v1/devices/${encodeURIComponent(device.id)}/recovery`, { method: "POST" }, csrf)); onCreated(); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  const command = invite?.token && composeFile.trim() ? `docker compose -f ${shellLiteral(composeFile.trim())} run --rm -e ${shellLiteral(`NEXO_ENROLLMENT_TOKEN=${invite.token}`)} nexo-agent --recover-identity` : "";
  const binaryCommand = invite?.token ? `NEXO_ENROLLMENT_TOKEN=${shellLiteral(invite.token)} nexo-agent --recover-identity` : "";
  return <Modal title={`恢复 ${device.name} 的身份`} onClose={onClose} busy={busy}><div className="modal-body">
    <p>用于设备证书已过期、私钥丢失或身份文件损坏。原设备 ID 和 {device.tunnel_count} 个服务绑定会保留。</p>
    <ol className="steps">
      <li><strong>生成恢复凭证</strong><p>有效期 1 小时，仅本次显示，请在关闭前保存。重新生成会撤销此前的恢复凭证。</p>{!invite ? <button className="primary-button" onClick={() => void create()} disabled={busy}>{busy ? "生成中…" : "生成恢复凭证"}</button> : <><code className="token">{invite.token}</code>{invite.token && <CopyButton value={invite.token} label="复制恢复凭证" />}<small>有效期至 {dateText(invite.expires_at)}</small></>}</li>
      <li><strong>在原 Agent 主机提交恢复申请</strong><p>先停止原 Agent，在原 Compose 项目目录执行以下命令，保留原数据目录。</p><p className="helper">使用原配置文件，旧部署可能为 compose.agent.yml。</p>{invite && <label>原 Compose 文件<input value={composeFile} onChange={e => setComposeFile(e.target.value)} autoCapitalize="none" spellCheck={false} /></label>}{command && <><pre className="command-block" tabIndex={0}><code>{command}</code></pre><CopyButton value={command} label="复制恢复命令" /></>}<details className="recovery-help"><summary>使用二进制部署</summary><p className="helper">保持原 NEXO_STATE_DIR 和 Server 地址，执行以下命令。</p>{binaryCommand && <><pre className="command-block" tabIndex={0}><code>{binaryCommand}</code></pre><CopyButton value={binaryCommand} label="复制二进制恢复命令" /></>}</details></li>
      <li>{invite ? <EnrollmentProgress key={invite.id} invite={invite} csrf={csrf} onApproved={onCreated} /> : <><strong>核对并批准恢复</strong><p>提交申请后在此核对原设备。批准时旧证书和旧连接立即失效。</p></>}</li>
      <li><strong>正常启动 Agent</strong><p>恢复命令成功退出后，用原配置启动 Agent。服务会自动重新下发，无需重新绑定。</p></li>
    </ol><Notice error={error} />
  </div></Modal>;
}
