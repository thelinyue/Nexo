import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { useCallback, useEffect, useState } from "react";
import "./styles.css";

type Overview = {
  devices: number;
  running_tunnels: number;
  mesh_devices: number;
  current_connections: number;
};

type GatewayReport = {
  subnet_gateway: "ready" | "unavailable";
  site_gateway: "ready" | "unavailable";
};

type Device = {
  id: string;
  name: string;
  os: string | null;
  architecture: string | null;
  agent_version: string | null;
  status: string;
  gateway_report: GatewayReport | null;
};

const emptyOverview: Overview = {
  devices: 0,
  running_tunnels: 0,
  mesh_devices: 0,
  current_connections: 0,
};

function App() {
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [devices, setDevices] = useState<Device[]>([]);
  const [token, setToken] = useState(() => sessionStorage.getItem("nexo-admin-token") ?? "");
  const [activeToken, setActiveToken] = useState(() => sessionStorage.getItem("nexo-admin-token") ?? "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshOverview = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const headers: HeadersInit = activeToken.trim()
        ? { "x-nexo-admin-token": activeToken.trim() }
        : {};
      const [overviewResponse, devicesResponse] = await Promise.all([
        fetch("/api/v1/overview", { headers }),
        fetch("/api/v1/devices", { headers }),
      ]);
      if (!overviewResponse.ok) {
        const body = (await overviewResponse.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? "暂时无法读取概览");
      }
      setOverview((await overviewResponse.json()) as Overview);
      if (!devicesResponse.ok) {
        const body = (await devicesResponse.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? "暂时无法读取设备");
      }
      setDevices((await devicesResponse.json()) as Device[]);
      if (activeToken.trim()) {
        sessionStorage.setItem("nexo-admin-token", activeToken.trim());
      } else {
        sessionStorage.removeItem("nexo-admin-token");
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法读取概览");
    } finally {
      setLoading(false);
    }
  }, [activeToken]);

  useEffect(() => {
    void refreshOverview();
  }, [refreshOverview]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark" aria-label="Nexo 联巢">
          <span className="brand-icon">N</span>
          <span>
            <strong>Nexo</strong>
            <small>联巢</small>
          </span>
        </div>
        <nav aria-label="主导航">
          <a className="nav-item active" href="#overview">概览</a>
          <a className="nav-item" href="#devices">设备</a>
          <a className="nav-item" href="#networks">组网</a>
          <a className="nav-item" href="#settings">设置</a>
        </nav>
        <div className="sidebar-footer">where your networks come together.</div>
      </aside>

      <main className="content" id="overview">
        <header className="page-header">
          <div>
            <p className="eyebrow">网络的家</p>
            <h1>概览</h1>
            <p className="subtitle">设备、隧道与异地组网，都在这里汇聚。</p>
          </div>
          <button className="refresh-button" type="button" onClick={() => void refreshOverview()} disabled={loading}>
            {loading ? "读取中…" : "刷新状态"}
          </button>
        </header>

        <section className="metric-grid" aria-label="系统概览">
          <Metric label="客户端 / 设备" value={overview.devices} hint="已加入 Nexo 的设备" />
          <Metric label="运行中的隧道" value={overview.running_tunnels} hint="当前已生效" />
          <Metric label="异地组网设备" value={overview.mesh_devices} hint="正在参与组网" />
          <Metric label="当前连接" value={overview.current_connections} hint="最近在线的设备" />
        </section>

        {error && (
          <div className="notice error" role="alert">
            <strong>概览暂时不可用</strong>
            <span>{error}</span>
          </div>
        )}

        <section className="workspace-grid">
          <article className="panel panel-wide" id="devices">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">设备状态</p>
                <h2>一眼看到谁在线</h2>
              </div>
              <span className="status-pill"><i />实时汇总</span>
            </div>
            {devices.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">⌁</div>
                <strong>还没有加入设备</strong>
                <span>设备加入后，在线状态与网关能力会显示在这里。</span>
              </div>
            ) : (
              <div className="device-list">
                {devices.slice(0, 5).map((device) => <DeviceRow key={device.id} device={device} />)}
              </div>
            )}
          </article>

          <article className="panel" id="networks">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">站点互联</p>
                <h2>让网络归于一处</h2>
              </div>
            </div>
            <div className="guide-card">
              <span className="guide-dot" />
              <div>
                <strong>静态路由引导</strong>
                <p>建立站点互联后，Nexo 会给出目标网段与下一跳。路由器由你掌控，Nexo 不会自动修改。</p>
              </div>
            </div>
            <button className="secondary-button" type="button" disabled>查看组网</button>
          </article>
        </section>

        <section className="token-bar" id="settings">
          <div>
            <strong>管理凭证</strong>
            <span>仅用于当前浏览器请求，不会显示在页面上。</span>
          </div>
          <form onSubmit={(event) => { event.preventDefault(); setActiveToken(token); }}>
            <input
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="输入 X-Nexo-Admin-Token"
              aria-label="Nexo 管理凭证"
            />
            <button className="secondary-button" type="submit">连接</button>
          </form>
        </section>
      </main>
    </div>
  );
}

function Metric({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <article className="metric-card">
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
      <span className="metric-hint">{hint}</span>
    </article>
  );
}

function DeviceRow({ device }: { device: Device }) {
  const online = device.status === "online";
  const subnetReady = device.gateway_report?.subnet_gateway === "ready";
  const siteReady = device.gateway_report?.site_gateway === "ready";
  return (
    <div className="device-row">
      <span className={`device-avatar ${online ? "online" : ""}`}>{device.name.slice(0, 1).toUpperCase()}</span>
      <div className="device-identity">
        <strong>{device.name}</strong>
        <span>{[device.os, device.architecture, device.agent_version].filter(Boolean).join(" · ") || "设备信息待上报"}</span>
      </div>
      <div className="device-capabilities">
        <span className={`device-status ${online ? "online" : "offline"}`}><i />{online ? "在线" : "离线"}</span>
        {device.gateway_report && (
          <span className={`capability ${subnetReady ? "ready" : ""}`}>共享网络 {subnetReady ? "可用" : "待检查"}</span>
        )}
        {device.gateway_report && (
          <span className={`capability ${siteReady ? "ready" : ""}`}>站点互联 {siteReady ? "可用" : "待检查"}</span>
        )}
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
