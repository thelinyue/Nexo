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
  local_networks?: LocalNetwork[];
};

type LocalNetwork = {
  interface_id: string;
  prefix: string;
  gateway_address: string | null;
};

type Site = {
  id: string;
  tenant_id: string;
  name: string;
};

type Device = {
  id: string;
  tenant_id: string;
  site_id: string | null;
  name: string;
  os: string | null;
  architecture: string | null;
  agent_version: string | null;
  status: string;
  gateway_report: GatewayReport | null;
  mesh_status?: "joining" | "connected" | "mesh_offline" | "needs_recovery" | "failed" | "disabled" | "not_joined";
  mesh_address?: string | null;
};

type Enrollment = {
  enrollment_id: string;
  status: "pending" | "awaiting_approval" | "approved" | "consumed" | "expired" | "revoked";
  tenant_id: string;
  site_id: string | null;
  device_name: string | null;
  os: string | null;
  architecture: string | null;
  agent_version: string | null;
  expires_at: number;
  device_id: string | null;
};

type MeshStatus = {
  status: "normal" | "starting" | "abnormal" | "version_incompatible";
  message: string;
};

type StaticRouteGuide = {
  router_site_id: string;
  destination_site_id: string;
  router_site_name: string;
  destination_site_name: string;
  destination_prefix: string;
  next_hop: string | null;
  router_confirmed?: boolean;
};

type SiteLink = {
  id: string;
  left_site_name: string;
  right_site_name: string;
  left_network_prefix: string;
  right_network_prefix: string;
  static_routes: StaticRouteGuide[];
  enabled: boolean;
  apply_status: "disabled" | "checking" | "applying" | "ready" | "retrying" | "failed";
  apply_error: string | null;
  health_status: "ready" | "degraded" | "failed" | "disabled";
  health_error: string | null;
  route_confirmations?: { site_id: string; confirmed_at: string }[];
};

type SiteNetwork = {
  id: string;
  tenant_id: string;
  site_id: string;
  site_name: string;
  name: string;
  publisher_device_name: string;
  publisher_device_id: string;
  interface_id: string;
  gateway_address: string | null;
  desired_prefix: string;
  applied_prefix: string | null;
  enabled: boolean;
  apply_status: SiteLink["apply_status"];
  apply_error: string | null;
  health_status: SiteLink["health_status"];
  health_error: string | null;
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
  const [sites, setSites] = useState<Site[]>([]);
  const [siteNetworks, setSiteNetworks] = useState<SiteNetwork[]>([]);
  const [siteLinks, setSiteLinks] = useState<SiteLink[]>([]);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [meshStatus, setMeshStatus] = useState<MeshStatus | null>(null);
  const [token, setToken] = useState(() => sessionStorage.getItem("nexo-admin-token") ?? "");
  const [activeToken, setActiveToken] = useState(() => sessionStorage.getItem("nexo-admin-token") ?? "");
  const [loading, setLoading] = useState(false);
  const [actionLinkId, setActionLinkId] = useState<string | null>(null);
  const [actionNetworkId, setActionNetworkId] = useState<string | null>(null);
  const [showNetworkForm, setShowNetworkForm] = useState(false);
  const [showLinkForm, setShowLinkForm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshOverview = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const headers: HeadersInit = activeToken.trim()
        ? { "x-nexo-admin-token": activeToken.trim() }
        : {};
      const [overviewResponse, devicesResponse, sitesResponse] = await Promise.all([
        fetch("/api/v1/overview", { headers }),
        fetch("/api/v1/devices", { headers }),
        fetch("/api/v1/sites", { headers }),
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
      if (!sitesResponse.ok) {
        const body = (await sitesResponse.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? "暂时无法读取站点");
      }
      setSites((await sitesResponse.json()) as Site[]);
      const [enrollmentResponse, meshResponse] = await Promise.all([
        fetch("/api/v1/enrollments", { headers }),
        fetch("/api/v1/mesh/status", { headers }),
      ]);
      if (enrollmentResponse.ok) {
        setEnrollments((await enrollmentResponse.json()) as Enrollment[]);
      }
      if (meshResponse.ok) {
        setMeshStatus((await meshResponse.json()) as MeshStatus);
      }
      const [siteNetworksResponse, siteLinksResponse] = await Promise.all([
        fetch("/api/v1/site-networks", { headers }),
        fetch("/api/v1/site-links", { headers }),
      ]);
      if (!siteNetworksResponse.ok) {
        const body = (await siteNetworksResponse.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? "暂时无法读取共享网络");
      }
      setSiteNetworks((await siteNetworksResponse.json()) as SiteNetwork[]);
      if (!siteLinksResponse.ok) {
        const body = (await siteLinksResponse.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? "暂时无法读取站点互联");
      }
      setSiteLinks((await siteLinksResponse.json()) as SiteLink[]);
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

  const approveEnrollment = useCallback(async (enrollment: Enrollment) => {
    setError(null);
    try {
      const response = await fetch(`/api/v1/enrollments/${encodeURIComponent(enrollment.enrollment_id)}/approve`, {
        method: "POST",
        headers: activeToken.trim() ? { "x-nexo-admin-token": activeToken.trim() } : {},
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(readApiError(body, "暂时无法批准设备"));
      }
      await refreshOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法批准设备");
    }
  }, [activeToken, refreshOverview]);

  const recheckSiteLink = useCallback(async (link: SiteLink) => {
    setError(null);
    try {
      const response = await fetch(`/api/v1/site-links/${encodeURIComponent(link.id)}/recheck`, {
        method: "POST",
        headers: activeToken.trim() ? { "x-nexo-admin-token": activeToken.trim() } : {},
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法重新检测站点互联"));
      await refreshOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法重新检测站点互联");
    }
  }, [activeToken, refreshOverview]);

  const confirmRoute = useCallback(async (link: SiteLink, siteId: string) => {
    setError(null);
    try {
      const response = await fetch(`/api/v1/site-links/${encodeURIComponent(link.id)}/router-confirmations/${encodeURIComponent(siteId)}`, {
        method: "POST",
        headers: activeToken.trim() ? { "x-nexo-admin-token": activeToken.trim() } : {},
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法保存路由确认"));
      await refreshOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法保存路由确认");
    }
  }, [activeToken, refreshOverview]);

  /** 共享网络开关复用服务端 Desired State，避免 UI 本地状态与 Agent 脱节。 */
  const toggleSiteNetwork = useCallback(async (network: SiteNetwork) => {
    if (network.enabled && !window.confirm(`确定停止共享“${network.name}”吗？`)) {
      return;
    }
    setActionNetworkId(network.id);
    setError(null);
    try {
      const headers: HeadersInit = activeToken.trim()
        ? { "x-nexo-admin-token": activeToken.trim() }
        : {};
      const response = await fetch(`/api/v1/site-networks/${encodeURIComponent(network.id)}/${network.enabled ? "disable" : "enable"}`, {
        method: "POST",
        headers,
      });
      const body = (await response.json().catch(() => null)) as { error?: string } | SiteNetwork | null;
      if (!response.ok) {
        throw new Error(body && "error" in body ? body.error ?? "暂时无法更新共享网络" : "暂时无法更新共享网络");
      }
      await refreshOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法更新共享网络");
    } finally {
      setActionNetworkId(null);
    }
  }, [activeToken, refreshOverview]);

  /** 站点互联开关沿用服务端 Desired State，成功后重新读取两侧应用状态。 */
  const toggleSiteLink = useCallback(async (link: SiteLink) => {
    if (link.enabled && !window.confirm(`确定关闭“${link.left_site_name} ↔ ${link.right_site_name}”吗？`)) {
      return;
    }
    setActionLinkId(link.id);
    setError(null);
    try {
      const headers: HeadersInit = {
        ...(activeToken.trim() ? { "x-nexo-admin-token": activeToken.trim() } : {}),
      };
      const response = await fetch(`/api/v1/site-links/${encodeURIComponent(link.id)}/${link.enabled ? "disable" : "enable"}`, {
        method: "POST",
        headers,
      });
      const body = (await response.json().catch(() => null)) as { error?: string } | SiteLink | null;
      if (!response.ok) {
        throw new Error(body && "error" in body ? body.error ?? "暂时无法更新站点互联" : "暂时无法更新站点互联");
      }
      await refreshOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法更新站点互联");
    } finally {
      setActionLinkId(null);
    }
  }, [activeToken, refreshOverview]);

  useEffect(() => {
    void refreshOverview();
  }, [refreshOverview]);

  /**
   * 网关状态由 Agent ACK 最终收敛；只在存在待应用 revision 时轮询，避免常驻后台请求。
   * 失败状态不会自动重置，用户仍能看到明确错误并决定是否重新启用。
   */
  const hasPendingGatewayChanges = [...siteNetworks, ...siteLinks].some((item) =>
    item.apply_status === "checking" || item.apply_status === "applying" || item.apply_status === "retrying",
  );
  useEffect(() => {
    if (!hasPendingGatewayChanges) {
      return;
    }
    const timer = window.setInterval(() => {
      void refreshOverview();
    }, 4000);
    return () => window.clearInterval(timer);
  }, [hasPendingGatewayChanges, refreshOverview]);

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
          <a className="nav-item" href="#enrollments">入网请求</a>
          <a className="nav-item" href="#devices">设备</a>
          <a className="nav-item" href="#shared-networks">共享网络</a>
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

        <section className="panel enrollment-panel" id="enrollments">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">添加设备</p>
              <h2>批准后自动加入组网</h2>
            </div>
            <span className={`status-pill ${meshStatus?.status === "normal" ? "ready" : ""}`}><i />{meshStatus?.message ?? "组网状态检查中"}</span>
          </div>
          {enrollments.filter((item) => item.status === "awaiting_approval").length === 0 ? (
            <div className="empty-state compact-empty">
              <div className="empty-icon">＋</div>
              <strong>没有待批准设备</strong>
              <span>Agent 提交入网请求后，会在这里等待你的确认。</span>
            </div>
          ) : (
            <div className="enrollment-list">
              {enrollments.filter((item) => item.status === "awaiting_approval").map((item) => (
                <div className="enrollment-row" key={item.enrollment_id}>
                  <div>
                    <strong>{item.device_name ?? "未命名设备"}</strong>
                    <span>{[item.os, item.architecture, item.agent_version].filter(Boolean).join(" · ") || "设备信息待上报"}</span>
                  </div>
                  <button className="primary-button" type="button" onClick={() => void approveEnrollment(item)}>批准设备</button>
                </div>
              ))}
            </div>
          )}
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
              <button className="secondary-button panel-action" type="button" onClick={() => setShowLinkForm((visible) => !visible)}>
                {showLinkForm ? "收起" : "新建互联"}
              </button>
            </div>
            {showLinkForm && (
              <CreateSiteLinkForm
                sites={sites}
                siteNetworks={siteNetworks}
                token={activeToken}
                onCreated={async () => { setShowLinkForm(false); await refreshOverview(); }}
              />
            )}
            {siteLinks.length === 0 ? (
              <div className="empty-state compact-empty">
                <div className="empty-icon">↔</div>
                <strong>还没有站点互联</strong>
                <span>建立互联后，两侧路由器的配置引导会显示在这里。</span>
              </div>
            ) : (
              <div className="link-list">
                {siteLinks.slice(0, 3).map((link) => (
                  <SiteLinkCard
                    key={link.id}
                    link={link}
                    actionPending={actionLinkId === link.id}
                    onToggle={() => void toggleSiteLink(link)}
                    onRecheck={() => void recheckSiteLink(link)}
                    onConfirmRoute={(siteId) => void confirmRoute(link, siteId)}
                  />
                ))}
              </div>
            )}
          </article>
        </section>

        <section className="panel shared-network-panel" id="shared-networks">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">共享本地网络</p>
              <h2>让家庭或办公室网络可达</h2>
            </div>
            <button className="secondary-button panel-action" type="button" onClick={() => setShowNetworkForm((visible) => !visible)}>
              {showNetworkForm ? "收起" : "新建共享网络"}
            </button>
          </div>
          {showNetworkForm && (
            <CreateSiteNetworkForm
              sites={sites}
              devices={devices}
              token={activeToken}
              onCreated={async () => { setShowNetworkForm(false); await refreshOverview(); }}
            />
          )}
          {siteNetworks.length === 0 ? (
            <div className="empty-state compact-empty">
              <div className="empty-icon">⌂</div>
              <strong>还没有共享网络</strong>
              <span>选择设备的本地网络后，远端设备才能访问对应网段。</span>
            </div>
          ) : (
            <div className="network-list">
              {siteNetworks.slice(0, 5).map((network) => (
                <SiteNetworkRow
                  key={network.id}
                  network={network}
                  actionPending={actionNetworkId === network.id}
                  onToggle={() => void toggleSiteNetwork(network)}
                />
              ))}
            </div>
          )}
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
        <span className={`capability ${device.mesh_status === "connected" ? "ready" : ""}`}>异地组网：{meshStatusLabel(device.mesh_status)}</span>
        {device.mesh_address && <span className="capability">{device.mesh_address}</span>}
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

/**
 * 共享网络创建表单：只呈现站点、设备和 Agent 已探测到的本地网段。
 * 表单提交后由服务端再次校验能力和网段，避免浏览器状态成为配置真源。
 */
function CreateSiteNetworkForm({
  sites,
  devices,
  token,
  onCreated,
}: {
  sites: Site[];
  devices: Device[];
  token: string;
  onCreated: () => Promise<void>;
}) {
  const [siteId, setSiteId] = useState(sites[0]?.id ?? "");
  const [deviceId, setDeviceId] = useState("");
  const [networkKey, setNetworkKey] = useState("");
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selectedSite = sites.find((site) => site.id === siteId);
  const eligibleDevices = devices.filter(
    (device) => device.site_id === siteId && device.gateway_report?.subnet_gateway === "ready",
  );
  const selectedDevice = eligibleDevices.find((device) => device.id === deviceId);
  const localNetworks = selectedDevice?.gateway_report?.local_networks ?? [];
  const selectedNetwork = localNetworks.find((network) => `${network.interface_id}|${network.prefix}` === networkKey);

  /**
   * 页面会定时重新读取 Agent 能力；如果站点、设备或网段在此期间变化，
   * 及时清空失效选择，避免表单提交一个已经不存在的设备状态。
   */
  useEffect(() => {
    if (!siteId && sites.length > 0) {
      setSiteId(sites[0].id);
      return;
    }
    if (siteId && !sites.some((site) => site.id === siteId)) {
      setSiteId(sites[0]?.id ?? "");
      setDeviceId("");
      setNetworkKey("");
    }
  }, [siteId, sites]);

  useEffect(() => {
    if (deviceId && !eligibleDevices.some((device) => device.id === deviceId)) {
      setDeviceId("");
      setNetworkKey("");
    }
  }, [deviceId, eligibleDevices]);

  useEffect(() => {
    if (networkKey && !localNetworks.some((network) => `${network.interface_id}|${network.prefix}` === networkKey)) {
      setNetworkKey("");
    }
  }, [localNetworks, networkKey]);

  return (
    <form
      className="inline-form"
      onSubmit={async (event) => {
        event.preventDefault();
        if (!selectedSite || !selectedDevice || !selectedNetwork || !name.trim()) {
          setError("请先选择站点、可用设备和本地网络，并填写名称");
          return;
        }
        setSubmitting(true);
        setError(null);
        try {
          const response = await fetch("/api/v1/site-networks", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              ...(token.trim() ? { "x-nexo-admin-token": token.trim() } : {}),
            },
            body: JSON.stringify({
              tenant_id: selectedSite.tenant_id,
              site_id: selectedSite.id,
              name: name.trim(),
              publisher_device_id: selectedDevice.id,
              interface_id: selectedNetwork.interface_id,
              prefix: selectedNetwork.prefix,
            }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) {
            throw new Error(readApiError(body, "暂时无法创建共享网络"));
          }
          setName("");
          setNetworkKey("");
          await onCreated();
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法创建共享网络");
        } finally {
          setSubmitting(false);
        }
      }}
    >
      <div className="form-grid">
        <label>
          <span>名称</span>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="家庭网络" required />
        </label>
        <label>
          <span>站点</span>
          <select
            value={siteId}
            onChange={(event) => { setSiteId(event.target.value); setDeviceId(""); setNetworkKey(""); }}
            required
          >
            <option value="">选择站点</option>
            {sites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label>
          <span>设备</span>
          <select
            value={deviceId}
            onChange={(event) => { setDeviceId(event.target.value); setNetworkKey(""); }}
            required
            disabled={!siteId || eligibleDevices.length === 0}
          >
            <option value="">{siteId ? "选择可用设备" : "先选择站点"}</option>
            {eligibleDevices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
          </select>
        </label>
        <label>
          <span>本地网络</span>
          <select
            value={networkKey}
            onChange={(event) => setNetworkKey(event.target.value)}
            required
            disabled={!deviceId || localNetworks.length === 0}
          >
            <option value="">{deviceId ? "选择已探测网段" : "先选择设备"}</option>
            {localNetworks.map((network) => {
              const value = `${network.interface_id}|${network.prefix}`;
              return <option key={value} value={value}>{network.prefix} · {network.interface_id}</option>;
            })}
          </select>
        </label>
      </div>
      <div className="form-footer">
        <span className="form-hint">
          {sites.length === 0 ? "还没有可用站点。" : eligibleDevices.length === 0 ? "该站点暂无已确认共享网络能力的设备。" : "仅显示 Agent 最近探测到的网段。"}
        </span>
        <button className="primary-button" type="submit" disabled={submitting || !selectedSite || !selectedDevice || !selectedNetwork}>
          {submitting ? "创建中…" : "创建共享网络"}
        </button>
      </div>
      {error && <p className="form-error" role="alert">{error}</p>}
    </form>
  );
}

/** 站点互联创建表单：两侧只允许选择已启用的共享网络，冲突由服务端最终裁决。 */
function CreateSiteLinkForm({
  sites,
  siteNetworks,
  token,
  onCreated,
}: {
  sites: Site[];
  siteNetworks: SiteNetwork[];
  token: string;
  onCreated: () => Promise<void>;
}) {
  const availableNetworks = siteNetworks.filter((network) => network.enabled);
  const availableSites = sites.filter((site) => availableNetworks.some((network) => network.site_id === site.id));
  const [leftSiteId, setLeftSiteId] = useState(availableSites[0]?.id ?? "");
  const [rightSiteId, setRightSiteId] = useState(availableSites[1]?.id ?? availableSites[0]?.id ?? "");
  const [leftNetworkId, setLeftNetworkId] = useState("");
  const [rightNetworkId, setRightNetworkId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const leftNetworks = availableNetworks.filter((network) => network.site_id === leftSiteId);
  const rightNetworks = availableNetworks.filter((network) => network.site_id === rightSiteId);
  const leftSite = sites.find((site) => site.id === leftSiteId);
  const rightSite = sites.find((site) => site.id === rightSiteId);

  /**
   * 轮询期间共享网络可能被关闭或删除；站点选择失效时同步回到当前可用站点，
   * 并清理对应网络，避免把旧站点 ID 继续带入提交请求。
   */
  useEffect(() => {
    if (!leftSiteId && availableSites.length > 0) {
      setLeftSiteId(availableSites[0].id);
      setLeftNetworkId("");
    }
    if (!rightSiteId && availableSites.length > 0) {
      setRightSiteId(availableSites[1]?.id ?? availableSites[0].id);
      setRightNetworkId("");
    }
    if (leftSiteId && !availableSites.some((site) => site.id === leftSiteId)) {
      setLeftSiteId(availableSites[0]?.id ?? "");
      setLeftNetworkId("");
    }
    if (rightSiteId && !availableSites.some((site) => site.id === rightSiteId)) {
      setRightSiteId(availableSites[1]?.id ?? availableSites[0]?.id ?? "");
      setRightNetworkId("");
    }
  }, [availableSites, leftSiteId, rightSiteId]);

  useEffect(() => {
    if (leftNetworkId && !leftNetworks.some((network) => network.id === leftNetworkId)) {
      setLeftNetworkId("");
    }
    if (rightNetworkId && !rightNetworks.some((network) => network.id === rightNetworkId)) {
      setRightNetworkId("");
    }
  }, [leftNetworkId, leftNetworks, rightNetworkId, rightNetworks]);

  return (
    <form
      className="inline-form"
      onSubmit={async (event) => {
        event.preventDefault();
        if (!leftSite || !rightSite || !leftNetworkId || !rightNetworkId) {
          setError("请先选择两侧站点和共享网络");
          return;
        }
        if (leftSite.id === rightSite.id) {
          setError("站点互联需要选择两个不同站点");
          return;
        }
        if (leftSite.tenant_id !== rightSite.tenant_id) {
          setError("暂不支持跨租户建立站点互联");
          return;
        }
        setSubmitting(true);
        setError(null);
        try {
          const response = await fetch("/api/v1/site-links", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              ...(token.trim() ? { "x-nexo-admin-token": token.trim() } : {}),
            },
            body: JSON.stringify({
              tenant_id: leftSite.tenant_id,
              left_site_id: leftSite.id,
              left_network_id: leftNetworkId,
              right_site_id: rightSite.id,
              right_network_id: rightNetworkId,
            }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) {
            throw new Error(readApiError(body, "暂时无法创建站点互联"));
          }
          setLeftNetworkId("");
          setRightNetworkId("");
          await onCreated();
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法创建站点互联");
        } finally {
          setSubmitting(false);
        }
      }}
    >
      <div className="form-grid form-grid-link">
        <label>
          <span>一侧站点</span>
          <select value={leftSiteId} onChange={(event) => { setLeftSiteId(event.target.value); setLeftNetworkId(""); }} required>
            <option value="">选择站点</option>
            {availableSites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label>
          <span>一侧网络</span>
          <select value={leftNetworkId} onChange={(event) => setLeftNetworkId(event.target.value)} required disabled={!leftSiteId}>
            <option value="">选择共享网络</option>
            {leftNetworks.map((network) => <option key={network.id} value={network.id}>{network.name} · {network.desired_prefix}</option>)}
          </select>
        </label>
        <label>
          <span>另一侧站点</span>
          <select value={rightSiteId} onChange={(event) => { setRightSiteId(event.target.value); setRightNetworkId(""); }} required>
            <option value="">选择站点</option>
            {availableSites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label>
          <span>另一侧网络</span>
          <select value={rightNetworkId} onChange={(event) => setRightNetworkId(event.target.value)} required disabled={!rightSiteId}>
            <option value="">选择共享网络</option>
            {rightNetworks.map((network) => <option key={network.id} value={network.id}>{network.name} · {network.desired_prefix}</option>)}
          </select>
        </label>
      </div>
      <div className="form-footer">
        <span className="form-hint">相同或重叠网段会被服务端阻止，并显示冲突原因。</span>
        <button className="primary-button" type="submit" disabled={submitting || !leftNetworkId || !rightNetworkId}>
          {submitting ? "创建中…" : "建立站点互联"}
        </button>
      </div>
      {error && <p className="form-error" role="alert">{error}</p>}
    </form>
  );
}

function readApiError(body: unknown, fallback: string): string {
  if (typeof body === "object" && body !== null && "error" in body) {
    const error = (body as { error?: unknown }).error;
    if (typeof error === "string" && error.trim()) {
      return error;
    }
  }
  return fallback;
}

/** 站点互联摘要卡片：只显示用户需要的站点、网段、下一跳和应用状态。 */
function SiteLinkCard({
  link,
  actionPending,
  onToggle,
  onRecheck,
  onConfirmRoute,
}: {
  link: SiteLink;
  actionPending: boolean;
  onToggle: () => void;
  onRecheck: () => void;
  onConfirmRoute: (siteId: string) => void;
}) {
  const status = siteLinkStatus(link.apply_status);
  const health = gatewayHealthStatus(link.health_status);
  return (
    <div className="site-link-card">
      <div className="site-link-heading">
        <div className="site-link-title">
          <strong>{link.left_site_name}</strong>
          <span>↔</span>
          <strong>{link.right_site_name}</strong>
        </div>
        <div className="site-link-actions">
          <span className={`link-status ${status.kind}`}><i />{status.label}</span>
          <span className={`link-status ${health.kind}`}><i />{health.label}</span>
          <button
            className="link-action"
            type="button"
            onClick={onToggle}
            disabled={actionPending}
            aria-label={link.enabled ? "关闭站点互联" : "重新启用站点互联"}
          >
            {actionPending ? "处理中…" : link.enabled ? "关闭" : "启用"}
          </button>
          <button className="link-action" type="button" onClick={onRecheck} disabled={actionPending}>重新检测</button>
        </div>
      </div>
      {link.apply_error && <p className="link-error">{link.apply_error}</p>}
      {link.health_error && link.health_error !== link.apply_error && <p className="link-health-error">健康提示：{link.health_error}</p>}
      <div className="route-guide-list">
        {link.static_routes.map((route) => (
          <div className="route-guide" key={`${route.router_site_id}-${route.destination_site_id}`}>
            <span className="route-site">{route.router_site_name}</span>
            <span className="route-arrow">→</span>
            <span className="route-destination">{route.destination_site_name} · {route.destination_prefix}</span>
            <span className="route-via">下一跳：{route.next_hop ?? "等待设备地址"}</span>
            {route.router_confirmed ? (
              <span className="route-confirmed">已确认</span>
            ) : (
              <button className="route-confirm-button" type="button" onClick={() => onConfirmRoute(route.router_site_id)}>
                我已完成配置
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/** 共享网络行：用已确认网段和应用阶段替代底层路由术语。 */
function SiteNetworkRow({
  network,
  actionPending,
  onToggle,
}: {
  network: SiteNetwork;
  actionPending: boolean;
  onToggle: () => void;
}) {
  const status = siteLinkStatus(network.apply_status);
  const health = gatewayHealthStatus(network.health_status);
  return (
    <div className="network-row">
      <div className="network-identity">
        <strong>{network.name}</strong>
        <span>{network.site_name} · {network.publisher_device_name}</span>
      </div>
      <div className="network-prefix">
        <span>期望共享网段</span>
        <code>{network.desired_prefix}</code>
        <small className="network-applied">
          {network.applied_prefix
            ? `已确认生效：${network.applied_prefix}`
            : network.enabled
              ? "实际状态：等待设备确认"
              : "已确认生效：未共享"}
        </small>
        <small>下一跳：{network.gateway_address ?? "等待设备地址"}</small>
      </div>
      {network.apply_error && <p className="network-error">{network.apply_error}</p>}
      <div className="network-actions">
        <span className={`link-status ${status.kind}`}><i />{status.label}</span>
        <span className={`link-status ${health.kind}`}><i />{health.label}</span>
        <button
          className="link-action"
          type="button"
          onClick={onToggle}
          disabled={actionPending}
          aria-label={network.enabled ? "停止共享本地网络" : "重新共享本地网络"}
        >
          {actionPending ? "处理中…" : network.enabled ? "停止共享" : "重新启用"}
        </button>
      </div>
      {network.health_error && network.health_error !== network.apply_error && <p className="network-health-error">健康提示：{network.health_error}</p>}
    </div>
  );
}

/** 网关健康状态翻译；与 Desired / Applied 状态并列，避免把设备在线当成路由可用。 */
function gatewayHealthStatus(status: SiteLink["health_status"]): { label: string; kind: string } {
  switch (status) {
    case "ready":
      return { label: "网关正常", kind: "ready" };
    case "degraded":
      return { label: "状态受限", kind: "working" };
    case "failed":
      return { label: "网关异常", kind: "failed" };
    case "disabled":
      return { label: "未启用", kind: "disabled" };
    default:
      return { label: "状态检查中", kind: "working" };
  }
}

function meshStatusLabel(status: Device["mesh_status"]): string {
  switch (status) {
    case "joining":
      return "加入中";
    case "connected":
      return "已连接";
    case "mesh_offline":
      return "暂时离线";
    case "needs_recovery":
      return "需要恢复";
    case "failed":
      return "异常";
    case "disabled":
      return "未启用";
    default:
      return "未加入";
  }
}

function siteLinkStatus(status: SiteLink["apply_status"]): { label: string; kind: string } {
  switch (status) {
    case "ready":
      return { label: "已生效", kind: "ready" };
    case "checking":
      return { label: "等待设备确认", kind: "working" };
    case "applying":
      return { label: "正在应用", kind: "working" };
    case "retrying":
      return { label: "自动重试中", kind: "working" };
    case "failed":
      return { label: "需要处理", kind: "failed" };
    case "disabled":
      return { label: "已关闭", kind: "disabled" };
    default:
      return { label: "正在应用", kind: "working" };
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
