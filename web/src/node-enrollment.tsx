import { useState } from "react";
import type { RelayNode } from "./nodes";
import { CopyButton, Loading, Notice, dateText, errorText, useApi, useResource } from "./ui";

export type NodeEnrollment = { id: string; token: string; expires_at: number; version: string; server_url: string; http_port: number; data_port: number };
type Release = { version: string; architectures: string[] };

/** 用文字说明接入的下一步；在线只表示管理通道正常，不代替工作空间授权。 */
export function NodeSetupStatus({ node }: { node: RelayNode }) {
  const text = !node.registered && node.id !== "local" ? node.status === "expired" ? "凭证已过期，请重新生成。" : "等待安装。"
    : !node.approved ? "已注册，等待管理员审批与分配。"
    : node.assigned === false ? "已审批，等待分配工作空间。"
    : node.status === "online" ? node.selectable === false ? "已接入，当前工作空间未获授权。" : null
    : "节点未连接，请检查节点服务和网络。";
  return text ? <p className="helper" role="status">{text}</p> : null;
}

/** 凭证只存在弹窗内存；关闭后通过轮换恢复安装，不回显历史凭证。 */
export function NodeEnrollmentPanel({ initial, nodeId, csrf }: { initial?: NodeEnrollment; nodeId: string; csrf?: string | null }) {
  const api = useApi();
  const [enrollment, setEnrollment] = useState(initial);
  const [httpsPort, setHttpsPort] = useState("443");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const node = useResource(() => api<RelayNode>(`/api/v1/nodes/${encodeURIComponent(nodeId)}`), true, 3000, true);
  const releases = useResource(() => api<Release[]>("/api/v1/node-releases"), !node.data?.registered, false);
  const selected = releases.data?.find(item => item.version === (version || enrollment?.version)) ?? (!version ? releases.data?.[0] : undefined);
  const expired = !!enrollment && enrollment.expires_at <= Date.now() / 1000;
  const port = Number(httpsPort);
  const validPort = /^\d+$/.test(httpsPort) && port > 0 && port <= 65535 && ![8282, 8290, enrollment?.http_port, enrollment?.data_port].includes(port);
  const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
  // 带引号的 here-document 不展开凭证；凭证只进入标准输入，不放入进程参数。
  const command = enrollment && selected && validPort && !expired ? `(nexo_installer=$(mktemp) || exit; trap 'rm -f -- "$nexo_installer"' EXIT; curl --proto '=https' --proto-redir '=https' -fsSL ${quote(`${enrollment.server_url}/api/v1/node/install.sh`)} -o "$nexo_installer" && { nexo_sudo=; if [ "$(id -u)" -ne 0 ]; then nexo_sudo=sudo; fi; $nexo_sudo bash "$nexo_installer" --server ${quote(enrollment.server_url)} --version ${quote(selected.version)} --http-port ${enrollment.http_port} --https-port ${port} --data-port ${enrollment.data_port} <<'NEXO_ENROLLMENT'\n${enrollment.token}\nNEXO_ENROLLMENT\n})` : "";
  async function renew() {
    setBusy(true); setError(null);
    try { setEnrollment(await api<NodeEnrollment>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/enrollment`, { method: "POST" }, csrf)); void node.reload(); }
    catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }
  return <div className="node-enrollment">
    <Notice error={node.error} onRetry={() => void node.reload()} />
    {node.data?.registered && <NodeSetupStatus node={node.data} />}
    {node.data?.registered ? null : <>
      <Notice error={releases.error} onRetry={() => void releases.reload()} />
      {!releases.data && releases.busy && <Loading />}
      {releases.data?.length === 0 && <div className="notice" role="status"><span>暂无正式安装包，发布后可继续。</span><button className="text-button" onClick={() => void releases.reload()}>刷新</button></div>}
      {(!enrollment || expired) && <>
        <p className="helper">{expired || node.data?.status === "expired" ? "凭证已过期，请重新生成。" : "请生成新凭证以继续安装。"}旧凭证将失效。</p>
        {node.data?.can_enroll && <button className="secondary-button" disabled={busy} onClick={() => void renew()}>{busy ? "正在生成…" : "生成新凭证"}</button>}
      </>}
      {!!releases.data?.length && enrollment && !expired && <>
        <details className="node-install-options">
          <summary>安装选项 · HTTPS {httpsPort || "未填写"}</summary>
          <div className="node-install-fields">
            {releases.data.length > 1 ? <label>版本<select value={selected?.version ?? ""} onChange={e => setVersion(e.target.value)}>{releases.data.map(item => <option key={item.version} value={item.version}>v{item.version} · {item.architectures.map(arch => arch === "aarch64" ? "ARM64" : arch).join(" / ")}</option>)}</select></label> : <p className="helper">v{selected?.version} · {selected?.architectures.map(arch => arch === "aarch64" ? "ARM64" : arch).join(" / ")}</p>}
            <label>HTTPS 端口<input type="number" min={1} max={65535} value={httpsPort} onChange={e => setHttpsPort(e.target.value)} aria-invalid={!validPort} aria-describedby="node-port-help" /></label>
            <p className="helper" id="node-port-help">用于安装检查，需与服务端口一致。443 被占用时可改为 8443。</p>
            <p className="helper">HTTP {enrollment.http_port} · 数据端口 {enrollment.data_port}</p>
            {node.data?.can_enroll && <div><p className="helper">重新生成后，旧凭证立即失效。</p><button className="text-button" disabled={busy} onClick={() => void renew()}>{busy ? "正在生成…" : "重新生成凭证"}</button></div>}
          </div>
        </details>
        {!validPort && <p className="form-error" role="alert">请输入 1–65535 的 HTTPS 端口，避免与其他端口冲突。</p>}
        {command && <>
          <section className="node-install-step" aria-label="执行安装命令"><h3>在 VPS 执行即可接入</h3><CopyButton value={command} label="复制命令" /><p className="helper">已包含接入凭证，有效至 {dateText(enrollment.expires_at)}。请勿分享命令。</p><details><summary>查看命令</summary><pre className="node-command">{command}</pre></details></section>
        </>}
      </>}
    </>}
    <Notice error={error} />
  </div>;
}
