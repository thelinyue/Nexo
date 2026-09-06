import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Building2,
  CheckCircle2,
  CircleAlert,
  Globe2,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  MonitorSmartphone,
  Network,
  Plus,
  RefreshCw,
  Server,
  Settings,
  Share2,
  ShieldCheck,
  UserPlus,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import "./styles.css";

type AppRoute =
  | "#/overview"
  | "#/devices/list"
  | "#/devices/enrollments"
  | "#/public-access"
  | "#/networks/sites"
  | "#/networks/shared"
  | "#/networks/links"
  | "#/settings";

type PrimaryRoute = "overview" | "devices" | "public-access" | "networks" | "settings";

type NavigationItem = {
  id: PrimaryRoute;
  label: string;
  href: AppRoute;
  icon: LucideIcon;
};

const navigationItems: NavigationItem[] = [
  { id: "overview", label: "概览", href: "#/overview", icon: LayoutDashboard },
  { id: "devices", label: "设备", href: "#/devices/list", icon: MonitorSmartphone },
  { id: "public-access", label: "公网访问", href: "#/public-access", icon: Globe2 },
  { id: "networks", label: "网络互联", href: "#/networks/sites", icon: Network },
  { id: "settings", label: "设置", href: "#/settings", icon: Settings },
];

const validRoutes = new Set<AppRoute>([
  "#/overview",
  "#/devices/list",
  "#/devices/enrollments",
  "#/public-access",
  "#/networks/sites",
  "#/networks/shared",
  "#/networks/links",
  "#/settings",
]);

/** Hash 路由避免改变服务端静态托管，同时让每个管理页面可以刷新和前进后退。 */
function readRoute(): AppRoute {
  const hash = window.location.hash as AppRoute;
  if (validRoutes.has(hash)) return hash;
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/overview`);
  return "#/overview";
}

function primaryRoute(route: AppRoute): PrimaryRoute {
  if (route.startsWith("#/devices/")) return "devices";
  if (route === "#/public-access") return "public-access";
  if (route.startsWith("#/networks/")) return "networks";
  if (route === "#/settings") return "settings";
  return "overview";
}

type Overview = {
  devices: number;
  running_tunnels: number;
  mesh_devices: number;
  current_connections: number;
};

type AuthStatus = {
  initialized: boolean;
  authenticated: boolean;
  username: string | null;
  channel: string | null;
  csrf_token: string | null;
  local_http_warning: boolean;
};

type SessionInfo = {
  id: string;
  channel: string;
  created_at: number;
  last_seen_at: number;
  expires_at: number;
};

type ApiRequest = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

type Tunnel = {
  id: string;
  tenant_id: string;
  device_id: string;
  device_name: string;
  name: string;
  protocol: "tcp" | "http" | "https";
  local_address: string;
  local_port: number;
  public_port: number | null;
  hostname: string | null;
  origin_protocol: "http" | "https" | null;
  origin_tls_server_name: string | null;
  origin_tls_verification: string;
  service_name: string | null;
  enabled: boolean;
  apply_status: string;
  apply_error: string | null;
  desired_revision: number;
  applied_revision: number;
  public_address: string | null;
};

type PublicEntry = {
  base_domain: string | null;
  https_enabled: boolean;
  certificate_mode: string;
  acme_environment: string;
  apply_status: string;
  apply_error: string | null;
  certificate_not_before: number | null;
  certificate_not_after: number | null;
  certificate_subjects: string[];
  dns_check: {
    resolved?: string[];
    error?: string;
    root?: { hostname?: string; resolved?: string[]; error?: string };
    wildcard?: { hostname?: string; resolved?: string[]; error?: string };
  };
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

type CreatedEnrollment = {
  enrollment_id: string;
  token: string;
  expires_at: number;
};

type MeshStatus = {
  status: "normal" | "starting" | "abnormal" | "restricted" | "version_incompatible";
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

function Dashboard({
  request,
  auth,
  onLogout,
  onSessionEnded,
}: {
  request: ApiRequest;
  auth: AuthStatus;
  onLogout: () => Promise<void>;
  onSessionEnded: (message: string) => void;
}) {
  const [route, setRoute] = useState<AppRoute>(() => readRoute());
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [devices, setDevices] = useState<Device[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [siteNetworks, setSiteNetworks] = useState<SiteNetwork[]>([]);
  const [siteLinks, setSiteLinks] = useState<SiteLink[]>([]);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [meshStatus, setMeshStatus] = useState<MeshStatus | null>(null);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [publicEntry, setPublicEntry] = useState<PublicEntry | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLinkId, setActionLinkId] = useState<string | null>(null);
  const [actionNetworkId, setActionNetworkId] = useState<string | null>(null);
  const [showNetworkForm, setShowNetworkForm] = useState(false);
  const [showLinkForm, setShowLinkForm] = useState(false);
  const [showTunnelForm, setShowTunnelForm] = useState(false);
  const [showSiteForm, setShowSiteForm] = useState(false);
  const [editingTunnel, setEditingTunnel] = useState<Tunnel | null>(null);
  const [editTrigger, setEditTrigger] = useState<HTMLButtonElement | null>(null);
  const [showEnrollmentForm, setShowEnrollmentForm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const updateRoute = () => setRoute(readRoute());
    window.addEventListener("hashchange", updateRoute);
    return () => window.removeEventListener("hashchange", updateRoute);
  }, []);

  useEffect(() => {
    const title = navigationItems.find((item) => item.id === primaryRoute(route))?.label ?? "概览";
    document.title = `${title} - Nexo`;
    setMobileNavigationOpen(false);
    window.requestAnimationFrame(() => document.querySelector<HTMLElement>("#main-content h1")?.focus());
  }, [route]);

  /** 每个一级页面只读取自身所需资源，避免侧栏切换继续触发旧概览的全量请求。 */
  const refreshCurrentPage = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const read = async <T,>(path: string, fallback: string): Promise<T> => {
        const response = await request(path);
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, fallback));
        return body as T;
      };
      const page = primaryRoute(route);
      if (page === "overview") {
        const [nextOverview, nextEnrollments, nextTunnels, nextNetworks, nextLinks] = await Promise.all([
          read<Overview>("/api/v1/overview", "暂时无法读取概览"),
          read<Enrollment[]>("/api/v1/enrollments", "暂时无法读取入网请求"),
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取公网访问"),
          read<SiteNetwork[]>("/api/v1/site-networks", "暂时无法读取共享网络"),
          read<SiteLink[]>("/api/v1/site-links", "暂时无法读取站点互联"),
        ]);
        setOverview(nextOverview); setEnrollments(nextEnrollments); setTunnels(nextTunnels);
        setSiteNetworks(nextNetworks); setSiteLinks(nextLinks);
      } else if (page === "devices") {
        const [nextDevices, nextSites, nextEnrollments, nextMeshStatus] = await Promise.all([
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
          read<Site[]>("/api/v1/sites", "暂时无法读取站点"),
          read<Enrollment[]>("/api/v1/enrollments", "暂时无法读取入网请求"),
          read<MeshStatus>("/api/v1/mesh/status", "暂时无法读取设备互联状态"),
        ]);
        setDevices(nextDevices); setSites(nextSites); setEnrollments(nextEnrollments); setMeshStatus(nextMeshStatus);
      } else if (page === "public-access") {
        const [nextEntry, nextTunnels, nextDevices] = await Promise.all([
          read<PublicEntry>("/api/v1/settings/public-entry", "暂时无法读取公网入口"),
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取公网访问"),
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
        ]);
        setPublicEntry(nextEntry); setTunnels(nextTunnels); setDevices(nextDevices);
      } else if (page === "networks") {
        const [nextSites, nextDevices, nextNetworks, nextLinks] = await Promise.all([
          read<Site[]>("/api/v1/sites", "暂时无法读取站点"),
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
          read<SiteNetwork[]>("/api/v1/site-networks", "暂时无法读取共享网络"),
          read<SiteLink[]>("/api/v1/site-links", "暂时无法读取站点互联"),
        ]);
        setSites(nextSites); setDevices(nextDevices); setSiteNetworks(nextNetworks); setSiteLinks(nextLinks);
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法读取页面数据");
    } finally {
      setLoading(false);
    }
  }, [request, route]);

  const approveEnrollment = useCallback(async (enrollment: Enrollment) => {
    setError(null);
    try {
      const response = await request(`/api/v1/enrollments/${encodeURIComponent(enrollment.enrollment_id)}/approve`, {
        method: "POST",
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(readApiError(body, "暂时无法批准设备"));
      }
      await refreshCurrentPage();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法批准设备");
    }
  }, [request, refreshCurrentPage]);

  const recheckSiteLink = useCallback(async (link: SiteLink) => {
    setError(null);
    try {
      const response = await request(`/api/v1/site-links/${encodeURIComponent(link.id)}/recheck`, {
        method: "POST",
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法重新检测站点互联"));
      await refreshCurrentPage();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法重新检测站点互联");
    }
  }, [request, refreshCurrentPage]);

  const confirmRoute = useCallback(async (link: SiteLink, siteId: string) => {
    setError(null);
    try {
      const response = await request(`/api/v1/site-links/${encodeURIComponent(link.id)}/router-confirmations/${encodeURIComponent(siteId)}`, {
        method: "POST",
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法保存路由确认"));
      await refreshCurrentPage();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法保存路由确认");
    }
  }, [request, refreshCurrentPage]);

  /** 共享网络开关复用服务端 Desired State，避免 UI 本地状态与 Agent 脱节。 */
  const toggleSiteNetwork = useCallback(async (network: SiteNetwork) => {
    if (network.enabled && !window.confirm(`确定停止共享“${network.name}”吗？`)) {
      return;
    }
    setActionNetworkId(network.id);
    setError(null);
    try {
      const response = await request(`/api/v1/site-networks/${encodeURIComponent(network.id)}/${network.enabled ? "disable" : "enable"}`, {
        method: "POST",
      });
      const body = (await response.json().catch(() => null)) as { error?: string } | SiteNetwork | null;
      if (!response.ok) {
        throw new Error(body && "error" in body ? body.error ?? "暂时无法更新共享网络" : "暂时无法更新共享网络");
      }
      await refreshCurrentPage();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法更新共享网络");
    } finally {
      setActionNetworkId(null);
    }
  }, [request, refreshCurrentPage]);

  /** 站点互联开关沿用服务端 Desired State，成功后重新读取两侧应用状态。 */
  const toggleSiteLink = useCallback(async (link: SiteLink) => {
    if (link.enabled && !window.confirm(`确定关闭“${link.left_site_name} ↔ ${link.right_site_name}”吗？`)) {
      return;
    }
    setActionLinkId(link.id);
    setError(null);
    try {
      const response = await request(`/api/v1/site-links/${encodeURIComponent(link.id)}/${link.enabled ? "disable" : "enable"}`, {
        method: "POST",
      });
      const body = (await response.json().catch(() => null)) as { error?: string } | SiteLink | null;
      if (!response.ok) {
        throw new Error(body && "error" in body ? body.error ?? "暂时无法更新站点互联" : "暂时无法更新站点互联");
      }
      await refreshCurrentPage();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法更新站点互联");
    } finally {
      setActionLinkId(null);
    }
  }, [request, refreshCurrentPage]);

  useEffect(() => {
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  /**
   * 网关状态由 Agent ACK 最终收敛；只在存在待应用 revision 时轮询，避免常驻后台请求。
   * 失败状态不会自动重置，用户仍能看到明确错误并决定是否重新启用。
   */
  const hasPendingGatewayChanges = [...siteNetworks, ...siteLinks].some((item) =>
    item.apply_status === "checking" || item.apply_status === "applying" || item.apply_status === "retrying",
  );
  useEffect(() => {
    if (!hasPendingGatewayChanges || !route.startsWith("#/networks/")) {
      return;
    }
    const timer = window.setInterval(() => {
      void refreshCurrentPage();
    }, 4000);
    return () => window.clearInterval(timer);
  }, [hasPendingGatewayChanges, refreshCurrentPage, route]);

  const applyTunnelUpdate = useCallback((updated: Tunnel) => {
    setTunnels((current) => current.map((tunnel) => tunnel.id === updated.id ? updated : tunnel));
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <Sidebar route={route} />
      <MobileHeader onOpen={() => setMobileNavigationOpen(true)} />
      {mobileNavigationOpen && <MobileNavigation route={route} onClose={() => setMobileNavigationOpen(false)} />}

      <main className="content" id="main-content">
        <div className="page-transition" key={route}>
          {route === "#/overview" && (
            <OverviewPage
              auth={auth}
              overview={overview}
              enrollments={enrollments}
              tunnels={tunnels}
              siteNetworks={siteNetworks}
              siteLinks={siteLinks}
              loading={loading}
              error={error}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route.startsWith("#/devices/") && (
            <DevicesPage
              route={route}
              devices={devices}
              sites={sites}
              enrollments={enrollments}
              meshStatus={meshStatus}
              loading={loading}
              error={error}
              showEnrollmentForm={showEnrollmentForm}
              onToggleEnrollmentForm={() => setShowEnrollmentForm((visible) => !visible)}
              onCloseEnrollmentForm={() => setShowEnrollmentForm(false)}
              onApprove={approveEnrollment}
              request={request}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route === "#/public-access" && (
            <PublicAccessPage
              publicEntry={publicEntry}
              tunnels={tunnels}
              devices={devices}
              loading={loading}
              error={error}
              request={request}
              showCreate={showTunnelForm}
              onOpenCreate={() => setShowTunnelForm(true)}
              onCloseCreate={() => setShowTunnelForm(false)}
              onRefresh={refreshCurrentPage}
              onTunnelChanged={applyTunnelUpdate}
              onEdit={(tunnel, trigger) => { setEditingTunnel(tunnel); setEditTrigger(trigger); }}
            />
          )}
          {route.startsWith("#/networks/") && (
            <NetworksPage
              route={route}
              sites={sites}
              devices={devices}
              siteNetworks={siteNetworks}
              siteLinks={siteLinks}
              loading={loading}
              error={error}
              request={request}
              showSiteForm={showSiteForm}
              showNetworkForm={showNetworkForm}
              showLinkForm={showLinkForm}
              onToggleSiteForm={() => setShowSiteForm((visible) => !visible)}
              onOpenNetworkForm={() => setShowNetworkForm(true)}
              onCloseNetworkForm={() => setShowNetworkForm(false)}
              onOpenLinkForm={() => setShowLinkForm(true)}
              onCloseLinkForm={() => setShowLinkForm(false)}
              onToggleNetwork={toggleSiteNetwork}
              onToggleLink={toggleSiteLink}
              onRecheckLink={recheckSiteLink}
              onConfirmRoute={confirmRoute}
              actionNetworkId={actionNetworkId}
              actionLinkId={actionLinkId}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route === "#/settings" && (
            <SettingsPage auth={auth} request={request} onLogout={onLogout} onSessionEnded={onSessionEnded} />
          )}
        </div>
      </main>

      {editingTunnel && (
        <EditTunnelDialog
          tunnel={editingTunnel}
          devices={devices}
          request={request}
          returnFocus={editTrigger}
          onUpdated={applyTunnelUpdate}
          onClose={() => { setEditingTunnel(null); setEditTrigger(null); }}
        />
      )}
    </div>
  );
}

function BrandMark() {
  return (
    <div className="brand-mark" aria-label="Nexo 联巢">
      <span className="brand-icon">N</span>
      <span><strong>Nexo</strong><small>联巢</small></span>
    </div>
  );
}

function NavigationLinks({ route, onNavigate }: { route: AppRoute; onNavigate?: () => void }) {
  const active = primaryRoute(route);
  return (
    <nav className="primary-navigation" aria-label="主导航">
      {navigationItems.map((item) => {
        const Icon = item.icon;
        return (
          <a
            className={`nav-item ${active === item.id ? "active" : ""}`}
            href={item.href}
            aria-current={active === item.id ? "page" : undefined}
            onClick={onNavigate}
            key={item.id}
          >
            <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
            <span>{item.label}</span>
          </a>
        );
      })}
    </nav>
  );
}

function Sidebar({ route }: { route: AppRoute }) {
  return (
    <aside className="sidebar">
      <BrandMark />
      <NavigationLinks route={route} />
      <p className="sidebar-footer">设备、服务与网络，都有清晰的归处。</p>
    </aside>
  );
}

function MobileHeader({ onOpen }: { onOpen: () => void }) {
  return (
    <header className="mobile-header">
      <button className="icon-button" type="button" aria-label="打开导航" onClick={onOpen}>
        <Menu size={21} aria-hidden="true" />
      </button>
      <BrandMark />
      <span className="mobile-header-spacer" aria-hidden="true" />
    </header>
  );
}

/** 移动导航使用原生 dialog 获得焦点约束，并从左侧沿同一路径进入和离开。 */
function MobileNavigation({ route, onClose }: { route: AppRoute; onClose: () => void }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => { if (dialog?.open) dialog.close(); };
  }, []);
  return (
    <dialog
      ref={dialogRef}
      className="mobile-nav-dialog"
      aria-label="移动导航"
      onCancel={(event) => { event.preventDefault(); onClose(); }}
      onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      <div className="mobile-nav-sheet" onClick={(event) => event.stopPropagation()}>
        <div className="mobile-nav-heading">
          <BrandMark />
          <button className="icon-button" type="button" aria-label="关闭导航" onClick={onClose}>
            <X size={20} aria-hidden="true" />
          </button>
        </div>
        <NavigationLinks route={route} onNavigate={onClose} />
      </div>
    </dialog>
  );
}

function PageHeader({
  eyebrow,
  title,
  subtitle,
  loading,
  onRefresh,
  action,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  loading?: boolean;
  onRefresh?: () => Promise<void>;
  action?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1 tabIndex={-1}>{title}</h1>
        <p className="subtitle">{subtitle}</p>
      </div>
      <div className="page-actions">
        {onRefresh && (
          <button className="secondary-button" type="button" onClick={() => void onRefresh()} disabled={loading}>
            <RefreshCw size={16} className={loading ? "spin" : ""} aria-hidden="true" />
            {loading ? "读取中" : "刷新"}
          </button>
        )}
        {action}
      </div>
    </header>
  );
}

function SectionTabs({ items, route, label }: { items: { href: AppRoute; label: string; icon: LucideIcon }[]; route: AppRoute; label: string }) {
  return (
    <nav className="section-tabs" aria-label={label}>
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <a key={item.href} href={item.href} aria-current={route === item.href ? "page" : undefined}>
            <Icon size={16} aria-hidden="true" />
            {item.label}
          </a>
        );
      })}
    </nav>
  );
}

function EmptyState({ icon: Icon, title, detail }: { icon: LucideIcon; title: string; detail: string }) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon size={21} aria-hidden="true" /></span>
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function PageError({ error, onRetry }: { error: string | null; onRetry: () => Promise<void> }) {
  if (!error) return null;
  return (
    <div className="notice error" role="alert">
      <CircleAlert size={18} aria-hidden="true" />
      <div><strong>页面数据暂时不可用</strong><span>{error}</span></div>
      <button className="notice-action" type="button" onClick={() => void onRetry()}>重试</button>
    </div>
  );
}

function OverviewPage({
  auth,
  overview,
  enrollments,
  tunnels,
  siteNetworks,
  siteLinks,
  loading,
  error,
  onRefresh,
}: {
  auth: AuthStatus;
  overview: Overview;
  enrollments: Enrollment[];
  tunnels: Tunnel[];
  siteNetworks: SiteNetwork[];
  siteLinks: SiteLink[];
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
}) {
  const pendingEnrollments = enrollments.filter((item) => item.status === "awaiting_approval").length;
  const failedTunnels = tunnels.filter((item) => item.apply_status === "failed").length;
  const failedNetworks = siteNetworks.filter((item) => item.apply_status === "failed").length;
  const failedLinks = siteLinks.filter((item) => item.apply_status === "failed").length;
  const failedResources = failedTunnels + failedNetworks + failedLinks;
  const applyingTunnels = tunnels.filter((item) => ["checking", "applying", "retrying"].includes(item.apply_status)).length;
  const applyingNetworks = siteNetworks.filter((item) => ["checking", "applying", "retrying"].includes(item.apply_status)).length;
  const applyingLinks = siteLinks.filter((item) => ["checking", "applying", "retrying"].includes(item.apply_status)).length;
  const applyingResources = applyingTunnels + applyingNetworks + applyingLinks;
  const failedHref: AppRoute = failedTunnels ? "#/public-access" : failedNetworks ? "#/networks/shared" : failedLinks ? "#/networks/links" : "#/overview";
  const applyingHref: AppRoute = applyingTunnels ? "#/public-access" : applyingNetworks ? "#/networks/shared" : "#/networks/links";
  return (
    <>
      <PageHeader eyebrow="运行状态" title="概览" subtitle="先处理异常，再进入具体页面完成配置。" loading={loading} onRefresh={onRefresh} />
      <section className="metric-grid" aria-label="系统概览">
        <Metric label="设备" value={overview.devices} hint="已加入 Nexo" />
        <Metric label="已生效公网访问" value={overview.running_tunnels} hint="公网入口可用" />
        <Metric label="互联设备" value={overview.mesh_devices} hint="已加入网络互联" />
        <Metric label="在线设备" value={overview.current_connections} hint="当前与服务端连接" />
      </section>
      <PageError error={error} onRetry={onRefresh} />
      {auth.local_http_warning && (
        <div className="notice warning" role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div><strong>当前为未加密 HTTP</strong><span>仅在可信局域网使用；需要远程管理时，请先配置公网 HTTPS。</span></div>
          <a className="notice-action" href="#/public-access">前往配置</a>
        </div>
      )}
      <section className="overview-grid">
        <article className="panel attention-panel">
          <div className="panel-heading"><div><p className="eyebrow">待处理</p><h2>需要你关注</h2></div></div>
          <div className="attention-list">
            <AttentionRow icon={UserPlus} label="待批准设备" count={pendingEnrollments} href="#/devices/enrollments" />
            <AttentionRow icon={CircleAlert} label="配置生效失败" count={failedResources} href={failedHref} />
            <AttentionRow icon={RefreshCw} label="配置生效中" count={applyingResources} href={applyingHref} />
          </div>
        </article>
        <article className="panel quick-panel">
          <div className="panel-heading"><div><p className="eyebrow">快速前往</p><h2>继续管理</h2></div></div>
          <div className="quick-links">
            <QuickLink icon={MonitorSmartphone} title="设备与入网" detail="查看在线状态或添加设备" href="#/devices/list" />
            <QuickLink icon={Globe2} title="公网访问" detail="管理 Web 服务与 TCP 端口" href="#/public-access" />
            <QuickLink icon={Network} title="网络互联" detail="配置站点、共享网络与互联" href="#/networks/sites" />
          </div>
        </article>
      </section>
    </>
  );
}

function AttentionRow({ icon: Icon, label, count, href }: { icon: LucideIcon; label: string; count: number; href: AppRoute }) {
  return (
    <a className="attention-row" href={href}>
      <Icon size={17} aria-hidden="true" />
      <span>{label}</span>
      <strong>{count}</strong>
      <ArrowRight size={16} aria-hidden="true" />
    </a>
  );
}

function QuickLink({ icon: Icon, title, detail, href }: { icon: LucideIcon; title: string; detail: string; href: AppRoute }) {
  return (
    <a className="quick-link" href={href}>
      <span className="quick-link-icon"><Icon size={18} aria-hidden="true" /></span>
      <span><strong>{title}</strong><small>{detail}</small></span>
      <ArrowRight size={16} aria-hidden="true" />
    </a>
  );
}

function DevicesPage({
  route,
  devices,
  sites,
  enrollments,
  meshStatus,
  loading,
  error,
  showEnrollmentForm,
  onToggleEnrollmentForm,
  onCloseEnrollmentForm,
  onApprove,
  request,
  onRefresh,
}: {
  route: AppRoute;
  devices: Device[];
  sites: Site[];
  enrollments: Enrollment[];
  meshStatus: MeshStatus | null;
  loading: boolean;
  error: string | null;
  showEnrollmentForm: boolean;
  onToggleEnrollmentForm: () => void;
  onCloseEnrollmentForm: () => void;
  onApprove: (enrollment: Enrollment) => Promise<void>;
  request: ApiRequest;
  onRefresh: () => Promise<void>;
}) {
  const pending = enrollments.filter((item) => item.status === "awaiting_approval");
  const enrollmentView = route === "#/devices/enrollments";
  return (
    <>
      <PageHeader
        eyebrow="设备管理"
        title={enrollmentView ? "入网请求" : "设备"}
        subtitle={enrollmentView ? "生成一次性配置，并批准可信设备加入。" : "查看设备在线状态、地址与网关能力。"}
        loading={loading}
        onRefresh={onRefresh}
        action={enrollmentView ? (
          <button className="primary-button" type="button" onClick={onToggleEnrollmentForm} aria-expanded={showEnrollmentForm}>
            <Plus size={16} aria-hidden="true" />添加设备
          </button>
        ) : undefined}
      />
      <SectionTabs label="设备页面" route={route} items={[
        { href: "#/devices/list", label: "设备列表", icon: MonitorSmartphone },
        { href: "#/devices/enrollments", label: `入网请求${pending.length ? ` (${pending.length})` : ""}`, icon: UserPlus },
      ]} />
      <PageError error={error} onRetry={onRefresh} />
      {enrollmentView ? (
        <section className="panel page-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">设备互联状态</p><h2>{meshStatus?.message ?? "正在检查"}</h2></div>
            <span className={`status-pill ${meshStatus?.status === "normal" ? "ready" : "working"}`}><i />{pending.length} 个待批准</span>
          </div>
          {showEnrollmentForm && <CreateEnrollmentForm sites={sites} request={request} onCreated={onRefresh} onDone={onCloseEnrollmentForm} />}
          {pending.length === 0 ? (
            <EmptyState icon={ShieldCheck} title="没有待批准设备" detail="设备发起的入网请求会显示在这里。" />
          ) : (
            <div className="enrollment-list">
              {pending.map((item) => (
                <div className="enrollment-row" key={item.enrollment_id}>
                  <div><strong>{item.device_name ?? "未命名设备"}</strong><span>{[item.os, item.architecture, item.agent_version].filter(Boolean).join(" · ") || "设备信息待上报"}</span></div>
                  <button className="primary-button" type="button" onClick={() => void onApprove(item)}><CheckCircle2 size={16} aria-hidden="true" />批准设备</button>
                </div>
              ))}
            </div>
          )}
        </section>
      ) : (
        <section className="panel page-panel">
          <div className="panel-heading"><div><p className="eyebrow">设备状态</p><h2>{devices.length} 台设备</h2></div><span className="status-pill ready"><i />当前状态</span></div>
          {devices.length === 0 ? <EmptyState icon={Server} title="还没有加入设备" detail="请从入网请求页面添加第一台设备。" /> : <div className="device-list">{devices.map((device) => <DeviceRow key={device.id} device={device} />)}</div>}
        </section>
      )}
    </>
  );
}

function PublicAccessPage({
  publicEntry,
  tunnels,
  devices,
  loading,
  error,
  request,
  showCreate,
  onOpenCreate,
  onCloseCreate,
  onRefresh,
  onTunnelChanged,
  onEdit,
}: {
  publicEntry: PublicEntry | null;
  tunnels: Tunnel[];
  devices: Device[];
  loading: boolean;
  error: string | null;
  request: ApiRequest;
  showCreate: boolean;
  onOpenCreate: () => void;
  onCloseCreate: () => void;
  onRefresh: () => Promise<void>;
  onTunnelChanged: (updated: Tunnel) => void;
  onEdit: (tunnel: Tunnel, trigger: HTMLButtonElement) => void;
}) {
  return (
    <>
      <PageHeader
        eyebrow="公网入口"
        title="公网访问"
        subtitle="为设备上的 Web 服务或 TCP 端口建立受控入口。"
        loading={loading}
        onRefresh={onRefresh}
        action={<button className="primary-button" type="button" onClick={onOpenCreate}><Plus size={16} aria-hidden="true" />新建公网访问</button>}
      />
      <PageError error={error} onRetry={onRefresh} />
      <section className="panel page-panel public-entry-panel">
        <div className="panel-heading">
          <div><p className="eyebrow">入口设置</p><h2>域名与 HTTPS</h2></div>
          <span className={`status-pill ${publicEntry?.apply_status === "ready" ? "ready" : "working"}`}><i />{publicEntryLabel(publicEntry)}</span>
        </div>
        {publicEntry?.base_domain && <p className="panel-note">入口域名：{publicEntry.base_domain} · {publicEntry.https_enabled ? "HTTPS 已开启" : "仅 HTTP"}</p>}
        <PublicEntrySettings entry={publicEntry} request={request} onChanged={onRefresh} />
      </section>
      <section className="panel page-panel">
        <div className="panel-heading"><div><p className="eyebrow">内网穿透</p><h2>{tunnels.length} 个公网入口</h2></div></div>
        {tunnels.length === 0 ? (
          <EmptyState icon={Globe2} title="还没有公网访问" detail="新建 Web 服务或 TCP 端口后，配置生效状态会显示在这里。" />
        ) : (
          <div className="tunnel-list">
            {tunnels.map((tunnel) => (
              <TunnelRow
                key={tunnel.id}
                tunnel={tunnel}
                request={request}
                onChanged={onTunnelChanged}
                onEdit={(trigger) => onEdit(tunnel, trigger)}
              />
            ))}
          </div>
        )}
      </section>
      {showCreate && (
        <FormDialog eyebrow="公网访问" title="新建公网访问" description="选择设备和本地服务，Nexo 会创建对应的公网入口。" onClose={onCloseCreate}>
          <CreateTunnelForm devices={devices} request={request} onCancel={onCloseCreate} onCreated={async () => { onCloseCreate(); await onRefresh(); }} />
        </FormDialog>
      )}
    </>
  );
}

function NetworksPage({
  route,
  sites,
  devices,
  siteNetworks,
  siteLinks,
  loading,
  error,
  request,
  showSiteForm,
  showNetworkForm,
  showLinkForm,
  onToggleSiteForm,
  onOpenNetworkForm,
  onCloseNetworkForm,
  onOpenLinkForm,
  onCloseLinkForm,
  onToggleNetwork,
  onToggleLink,
  onRecheckLink,
  onConfirmRoute,
  actionNetworkId,
  actionLinkId,
  onRefresh,
}: {
  route: AppRoute;
  sites: Site[];
  devices: Device[];
  siteNetworks: SiteNetwork[];
  siteLinks: SiteLink[];
  loading: boolean;
  error: string | null;
  request: ApiRequest;
  showSiteForm: boolean;
  showNetworkForm: boolean;
  showLinkForm: boolean;
  onToggleSiteForm: () => void;
  onOpenNetworkForm: () => void;
  onCloseNetworkForm: () => void;
  onOpenLinkForm: () => void;
  onCloseLinkForm: () => void;
  onToggleNetwork: (network: SiteNetwork) => Promise<void>;
  onToggleLink: (link: SiteLink) => Promise<void>;
  onRecheckLink: (link: SiteLink) => Promise<void>;
  onConfirmRoute: (link: SiteLink, siteId: string) => Promise<void>;
  actionNetworkId: string | null;
  actionLinkId: string | null;
  onRefresh: () => Promise<void>;
}) {
  const sitesView = route === "#/networks/sites";
  const sharedView = route === "#/networks/shared";
  const title = sitesView ? "站点" : sharedView ? "共享网络" : "站点互联";
  const subtitle = sitesView ? "用站点表示家庭、办公室等独立局域网。" : sharedView ? "将设备已探测到的本地网段共享给其他站点。" : "连接两个站点的共享网络，并完成两侧静态路由。";
  const action = sitesView ? (
    <button className="primary-button" type="button" onClick={onToggleSiteForm} aria-expanded={showSiteForm}><Plus size={16} aria-hidden="true" />新建站点</button>
  ) : sharedView ? (
    <button className="primary-button" type="button" onClick={onOpenNetworkForm}><Plus size={16} aria-hidden="true" />新建共享网络</button>
  ) : (
    <button className="primary-button" type="button" onClick={onOpenLinkForm}><Plus size={16} aria-hidden="true" />新建站点互联</button>
  );
  return (
    <>
      <PageHeader eyebrow="局域网互联" title={title} subtitle={subtitle} loading={loading} onRefresh={onRefresh} action={action} />
      <SectionTabs label="网络互联页面" route={route} items={[
        { href: "#/networks/sites", label: `站点 (${sites.length})`, icon: Building2 },
        { href: "#/networks/shared", label: `共享网络 (${siteNetworks.length})`, icon: Share2 },
        { href: "#/networks/links", label: `站点互联 (${siteLinks.length})`, icon: Network },
      ]} />
      <PageError error={error} onRetry={onRefresh} />
      {sitesView && (
        <section className="panel page-panel">
          {showSiteForm && <CreateSiteForm request={request} onCreated={onRefresh} onDone={onToggleSiteForm} />}
          {sites.length === 0 ? <EmptyState icon={Building2} title="还没有站点" detail="创建家庭、办公室等站点后，才能配置共享网络。" /> : (
            <div className="site-list">{sites.map((site) => <div className="site-row" key={site.id}><span className="site-icon"><Building2 size={18} aria-hidden="true" /></span><div><strong>{site.name}</strong><span>{devices.filter((device) => device.site_id === site.id).length} 台设备</span></div></div>)}</div>
          )}
        </section>
      )}
      {sharedView && (
        <section className="panel page-panel">
          {siteNetworks.length === 0 ? <EmptyState icon={Share2} title="还没有共享网络" detail="选择站点内的网关设备及其已探测网段。" /> : (
            <div className="network-list">{siteNetworks.map((network) => <SiteNetworkRow key={network.id} network={network} actionPending={actionNetworkId === network.id} onToggle={() => void onToggleNetwork(network)} />)}</div>
          )}
        </section>
      )}
      {!sitesView && !sharedView && (
        <section className="panel page-panel">
          {siteLinks.length === 0 ? <EmptyState icon={Network} title="还没有站点互联" detail="先在两侧创建共享网络，再建立双向互联。" /> : (
            <div className="link-list">{siteLinks.map((link) => <SiteLinkCard key={link.id} link={link} actionPending={actionLinkId === link.id} onToggle={() => void onToggleLink(link)} onRecheck={() => void onRecheckLink(link)} onConfirmRoute={(siteId) => void onConfirmRoute(link, siteId)} />)}</div>
          )}
        </section>
      )}
      {showNetworkForm && (
        <FormDialog eyebrow="共享网络" title="新建共享网络" description="选择站点、网关设备及其最近探测到的本地网段。" onClose={onCloseNetworkForm}>
          <CreateSiteNetworkForm sites={sites} devices={devices} request={request} onCancel={onCloseNetworkForm} onCreated={async () => { onCloseNetworkForm(); await onRefresh(); }} />
        </FormDialog>
      )}
      {showLinkForm && (
        <FormDialog eyebrow="站点互联" title="新建站点互联" description="选择两个不同站点的共享网络，建立仅限这两个站点的双向连接。" onClose={onCloseLinkForm}>
          <CreateSiteLinkForm sites={sites} siteNetworks={siteNetworks} request={request} onCancel={onCloseLinkForm} onCreated={async () => { onCloseLinkForm(); await onRefresh(); }} />
        </FormDialog>
      )}
    </>
  );
}

/**
 * 网络创建流程共用的模态外壳。原生 dialog 负责焦点约束；关闭时把焦点
 * 送回触发按钮，提交中的表单则拒绝 Esc 和遮罩关闭，避免请求状态丢失。
 */
function FormDialog({
  eyebrow,
  title,
  description,
  onClose,
  children,
  returnFocus: explicitReturnFocus,
}: {
  eyebrow: string;
  title: string;
  description: string;
  onClose: () => void;
  children: ReactNode;
  returnFocus?: HTMLElement | null;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const returnFocus = useRef<HTMLElement | null>(explicitReturnFocus ?? document.activeElement as HTMLElement | null);
  const titleId = useRef(`dialog-${Math.random().toString(36).slice(2)}`);
  const submitting = () => dialogRef.current?.querySelector('[aria-busy="true"]') !== null;
  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => {
      if (dialog?.open) dialog.close();
      returnFocus.current?.focus();
    };
  }, []);
  return (
    <dialog
      ref={dialogRef}
      className="form-dialog"
      aria-labelledby={titleId.current}
      onCancel={(event) => { event.preventDefault(); if (!submitting()) onClose(); }}
      onClick={(event) => { if (event.target === event.currentTarget && !submitting()) onClose(); }}
    >
      <div className="form-dialog-surface" onClick={(event) => event.stopPropagation()}>
        <header className="form-dialog-header">
          <div><p className="eyebrow">{eyebrow}</p><h2 id={titleId.current}>{title}</h2><p>{description}</p></div>
          <button className="icon-button" type="button" aria-label={`关闭${title}窗口`} onClick={() => { if (!submitting()) onClose(); }}>
            <X size={20} aria-hidden="true" />
          </button>
        </header>
        <div className="form-dialog-body">{children}</div>
      </div>
    </dialog>
  );
}

function CreateSiteForm({ request, onCreated, onDone }: { request: ApiRequest; onCreated: () => Promise<void>; onDone: () => void }) {
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <form className="site-create-form" aria-busy={submitting} onSubmit={async (event) => {
      event.preventDefault();
      if (!name.trim()) { setError("请输入站点名称"); return; }
      setSubmitting(true); setError(null);
      try {
        const response = await request("/api/v1/sites", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tenant_id: "default", name: name.trim() }),
        });
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, "暂时无法创建站点"));
        setName("");
        await onCreated();
        onDone();
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "暂时无法创建站点");
      } finally { setSubmitting(false); }
    }}>
      <label><span>站点名称</span><input autoFocus value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：家庭" required /></label>
      <button className="primary-button" type="submit" disabled={submitting}><Plus size={16} aria-hidden="true" />{submitting ? "创建中" : "创建站点"}</button>
      <button className="secondary-button" type="button" onClick={onDone} disabled={submitting}>取消</button>
      {error && <p className="form-error" role="alert">{error}</p>}
    </form>
  );
}

function SettingsPage({
  auth,
  request,
  onLogout,
  onSessionEnded,
}: {
  auth: AuthStatus;
  request: ApiRequest;
  onLogout: () => Promise<void>;
  onSessionEnded: (message: string) => void;
}) {
  const [currentSession, setCurrentSession] = useState<SessionInfo | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [changingPassword, setChangingPassword] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const loadSessions = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [currentResponse, sessionsResponse] = await Promise.all([
        request("/api/v1/auth/session"),
        request("/api/v1/auth/sessions"),
      ]);
      const currentBody: unknown = await currentResponse.json().catch(() => null);
      const sessionsBody: unknown = await sessionsResponse.json().catch(() => null);
      if (!currentResponse.ok) throw new Error(readApiError(currentBody, "暂时无法读取当前登录会话"));
      if (!sessionsResponse.ok) throw new Error(readApiError(sessionsBody, "暂时无法读取登录会话"));
      setCurrentSession(currentBody as SessionInfo);
      setSessions(sessionsBody as SessionInfo[]);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法读取登录会话");
    } finally { setLoading(false); }
  }, [request]);

  useEffect(() => { void loadSessions(); }, [loadSessions]);

  return (
    <>
      <PageHeader eyebrow="系统管理" title="设置" subtitle="修改管理员密码并管理仍有效的登录会话。" loading={loading} onRefresh={loadSessions} />
      <PageError error={error} onRetry={loadSessions} />
      {auth.local_http_warning && (
        <div className="notice warning" role="status"><AlertTriangle size={18} aria-hidden="true" /><div><strong>当前通过局域网 HTTP 登录</strong><span>这个入口只应在可信网络内使用。</span></div></div>
      )}
      <div className="settings-layout">
        <section className="panel settings-section">
          <div className="settings-heading"><span className="settings-icon"><KeyRound size={19} aria-hidden="true" /></span><div><h2>修改密码</h2><p>更新后，所有登录会话都会失效。</p></div></div>
          <form className="settings-form" aria-busy={changingPassword} onSubmit={async (event) => {
            event.preventDefault();
            if (newPassword.length < 12) { setPasswordError("新密码至少需要 12 个字符"); return; }
            if (newPassword !== confirmPassword) { setPasswordError("两次输入的新密码不一致"); return; }
            setChangingPassword(true); setPasswordError(null);
            try {
              const response = await request("/api/v1/auth/password", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
              });
              const body = await response.json().catch(() => null) as { message?: string; error?: string } | null;
              if (!response.ok) throw new Error(body?.error ?? "暂时无法修改密码");
              onSessionEnded(body?.message ?? "密码已更新，请重新登录");
            } catch (requestError) {
              setPasswordError(requestError instanceof Error ? requestError.message : "暂时无法修改密码");
            } finally { setChangingPassword(false); }
          }}>
            <label><span>当前密码</span><input type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required /></label>
            <label><span>新密码</span><input type="password" autoComplete="new-password" minLength={12} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required /></label>
            <label><span>确认新密码</span><input type="password" autoComplete="new-password" minLength={12} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required /></label>
            {passwordError && <p className="form-error" role="alert">{passwordError}</p>}
            <div className="settings-actions"><button className="primary-button" type="submit" disabled={changingPassword}>{changingPassword ? "更新中" : "更新密码"}</button></div>
          </form>
        </section>

        <section className="panel settings-section">
          <div className="settings-heading"><span className="settings-icon"><ShieldCheck size={19} aria-hidden="true" /></span><div><h2>登录会话</h2><p>查看并撤销不再使用的登录会话。</p></div></div>
          <div className="session-list">
            {sessions.map((session) => {
              const current = session.id === currentSession?.id;
              return (
                <div className="session-row" key={session.id}>
                  <span className="session-channel"><Server size={17} aria-hidden="true" /></span>
                  <div><strong>{session.channel === "public_https" ? "公网 HTTPS 会话" : "局域网 HTTP 会话"}{current && <em>当前会话</em>}</strong><span>最近使用：{formatSessionTime(session.last_seen_at)} · 到期：{formatSessionTime(session.expires_at)}</span></div>
                  <button className="secondary-button compact-button" type="button" disabled={current || revokingId === session.id} onClick={async () => {
                    setRevokingId(session.id); setError(null);
                    try {
                      const response = await request(`/api/v1/auth/sessions/${encodeURIComponent(session.id)}`, { method: "POST" });
                      const body: unknown = await response.json().catch(() => null);
                      if (!response.ok) throw new Error(readApiError(body, "暂时无法撤销登录会话"));
                      await loadSessions();
                    } catch (requestError) {
                      setError(requestError instanceof Error ? requestError.message : "暂时无法撤销登录会话");
                    } finally { setRevokingId(null); }
                  }}>{current ? "当前会话" : revokingId === session.id ? "撤销中" : "撤销会话"}</button>
                </div>
              );
            })}
          </div>
        </section>

        <section className="settings-danger">
          <div><strong>{auth.username ?? "管理员"}</strong><span>退出当前设备上的管理会话。</span></div>
          <button className="danger-button" type="button" onClick={() => void onLogout()}><LogOut size={16} aria-hidden="true" />退出登录</button>
        </section>
      </div>
    </>
  );
}

function formatSessionTime(timestamp: number): string {
  return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(timestamp * 1000));
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
        <span className={`capability ${device.mesh_status === "connected" ? "ready" : ""}`}>网络互联：{meshStatusLabel(device.mesh_status)}</span>
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
  request,
  onCancel,
  onCreated,
}: {
  sites: Site[];
  devices: Device[];
  request: ApiRequest;
  onCancel: () => void;
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
      className="inline-form network-form-table"
      aria-busy={submitting}
      onSubmit={async (event) => {
        event.preventDefault();
        if (!selectedSite || !selectedDevice || !selectedNetwork || !name.trim()) {
          setError("请填写显示名称，并选择站点、网关设备和本地网络");
          return;
        }
        setSubmitting(true);
        setError(null);
        try {
          const response = await request("/api/v1/site-networks", {
            method: "POST",
            headers: {
              "content-type": "application/json",
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
      <fieldset className="form-grid" disabled={submitting}>
        <legend className="sr-only">共享网络信息</legend>
        <label>
          <span>显示名称</span>
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
          <span>网关设备</span>
          <select
            value={deviceId}
            onChange={(event) => { setDeviceId(event.target.value); setNetworkKey(""); }}
            required
            disabled={!siteId || eligibleDevices.length === 0}
          >
            <option value="">{siteId ? "选择网关设备" : "先选择站点"}</option>
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
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-footer">
        <span className="form-hint">
          {sites.length === 0 ? "还没有可用站点。" : eligibleDevices.length === 0 ? "该站点暂无可用于共享网络的设备。" : "仅显示设备最近探测到的网段。"}
        </span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting || !selectedSite || !selectedDevice || !selectedNetwork}>
            {submitting ? "创建中…" : "创建共享网络"}
          </button>
        </div>
      </div>
    </form>
  );
}

/** 站点互联创建表单：两侧只允许选择已启用的共享网络，冲突由服务端最终裁决。 */
function CreateSiteLinkForm({
  sites,
  siteNetworks,
  request,
  onCancel,
  onCreated,
}: {
  sites: Site[];
  siteNetworks: SiteNetwork[];
  request: ApiRequest;
  onCancel: () => void;
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
      className="inline-form network-form-table"
      aria-busy={submitting}
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
          const response = await request("/api/v1/site-links", {
            method: "POST",
            headers: {
              "content-type": "application/json",
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
      <fieldset className="form-grid form-grid-link" disabled={submitting}>
        <legend className="sr-only">站点互联信息</legend>
        <label>
          <span>站点 A</span>
          <select value={leftSiteId} onChange={(event) => { setLeftSiteId(event.target.value); setLeftNetworkId(""); }} required>
            <option value="">选择站点</option>
            {availableSites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label>
          <span>网络 A</span>
          <select value={leftNetworkId} onChange={(event) => setLeftNetworkId(event.target.value)} required disabled={!leftSiteId}>
            <option value="">选择共享网络</option>
            {leftNetworks.map((network) => <option key={network.id} value={network.id}>{network.name} · {network.desired_prefix}</option>)}
          </select>
        </label>
        <label>
          <span>站点 B</span>
          <select value={rightSiteId} onChange={(event) => { setRightSiteId(event.target.value); setRightNetworkId(""); }} required>
            <option value="">选择站点</option>
            {availableSites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label>
          <span>网络 B</span>
          <select value={rightNetworkId} onChange={(event) => setRightNetworkId(event.target.value)} required disabled={!rightSiteId}>
            <option value="">选择共享网络</option>
            {rightNetworks.map((network) => <option key={network.id} value={network.id}>{network.name} · {network.desired_prefix}</option>)}
          </select>
        </label>
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-footer">
        <span className="form-hint">相同或重叠网段会被服务端阻止，并显示冲突原因。</span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting || !leftNetworkId || !rightNetworkId}>
            {submitting ? "创建中…" : "建立站点互联"}
          </button>
        </div>
      </div>
    </form>
  );
}

const RELEASE_AGENT_IMAGE = "ghcr.io/thelinyue/nexo-agent:0.1.2";

function buildAgentCompose(serverUrl: string, token: string): string {
  return `name: nexo-agent

services:
  nexo-agent:
    image: ${RELEASE_AGENT_IMAGE}
    container_name: nexo-agent
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
    environment:
      NEXO_SERVER_URL: ${JSON.stringify(serverUrl)}
      NEXO_ENROLLMENT_TOKEN: ${JSON.stringify(token)}
    volumes:
      - ./data/nexo-agent:/data/nexo-agent
    restart: unless-stopped
`;
}

/**
 * 设备加入向导只收集无法自动获知的信息，并立即生成可运行的 Compose。
 * 一次性 Token 不写入浏览器存储；用户离开当前结果后只能重新生成。
 */
function CreateEnrollmentForm({
  sites,
  request,
  onCreated,
  onDone,
}: {
  sites: Site[];
  request: ApiRequest;
  onCreated: () => Promise<void>;
  onDone: () => void;
}) {
  const [deviceName, setDeviceName] = useState("");
  const [siteId, setSiteId] = useState("");
  const [serverUrl, setServerUrl] = useState(() => window.location.origin);
  const [created, setCreated] = useState<CreatedEnrollment | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [error, setError] = useState<string | null>(null);

  const normalizedServerUrl = serverUrl.trim().replace(/\/+$/, "");
  const compose = created ? buildAgentCompose(normalizedServerUrl, created.token) : "";

  if (created) {
    return (
      <div className="enrollment-setup" aria-live="polite">
        <div className="enrollment-result-heading">
          <div>
            <strong>Docker Compose 配置已生成</strong>
            <span>凭证将在 {new Date(created.expires_at * 1000).toLocaleTimeString()} 前有效，且只能使用一次。</span>
          </div>
          <span className="entry-state ready"><i />等待设备连接</span>
        </div>
        <textarea className="enrollment-compose" aria-label="Docker Compose 配置" value={compose} readOnly spellCheck={false} />
        <div className="form-footer enrollment-result-actions">
          <span className="form-hint">复制到设备后运行 <code>docker compose up -d</code>。设备领取身份后可以删除 Token。</span>
          <div className="panel-heading-actions">
            <button className="secondary-button" type="button" onClick={onDone}>完成</button>
            <button
              className="primary-button"
              type="button"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(compose);
                  setCopyState("copied");
                } catch {
                  setCopyState("failed");
                }
              }}
            >
              {copyState === "copied" ? "已复制" : "复制 Compose 配置"}
            </button>
          </div>
        </div>
        {copyState === "failed" && <p className="form-error" role="alert">浏览器无法访问剪贴板，请手动选择上方内容。</p>}
      </div>
    );
  }

  return (
    <form
      className="enrollment-setup"
      onSubmit={async (event) => {
        event.preventDefault();
        setError(null);
        let parsed: URL;
        try {
          parsed = new URL(normalizedServerUrl);
        } catch {
          setError("Nexo 服务地址格式无效");
          return;
        }
        if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
          setError("Nexo 服务地址必须使用 http:// 或 https://");
          return;
        }
        if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
          setError("Nexo 服务地址不能包含路径、查询参数或锚点");
          return;
        }
        const selectedSite = sites.find((site) => site.id === siteId);
        setSubmitting(true);
        try {
          const response = await request("/api/v1/enrollments", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              tenant_id: selectedSite?.tenant_id ?? sites[0]?.tenant_id ?? "default",
              site_id: siteId || null,
              ttl_seconds: 900,
              device_name: deviceName.trim(),
            }),
          });
          const body = await response.json().catch(() => null) as CreatedEnrollment | { error?: string } | null;
          if (!response.ok) throw new Error(readApiError(body, "暂时无法创建设备入网凭证"));
          setCreated(body as CreatedEnrollment);
          await onCreated();
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法创建设备入网凭证");
        } finally {
          setSubmitting(false);
        }
      }}
    >
      <div className="form-grid enrollment-form-grid">
        <label>
          <span>设备名称</span>
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} placeholder="家庭 NAS" required autoFocus />
        </label>
        <label>
          <span>所属站点（可选）</span>
          <select value={siteId} onChange={(event) => setSiteId(event.target.value)}>
            <option value="">暂不指定</option>
            {sites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        <label>
          <span>Nexo 服务地址</span>
          <input value={serverUrl} onChange={(event) => setServerUrl(event.target.value)} inputMode="url" placeholder="http://192.168.1.10:8280" required />
        </label>
      </div>
      <div className="form-footer">
        <span className="form-hint">系统会自动使用同一主机的 9890 和 9891 端口，不需要分别配置。</span>
        <button className="primary-button" type="submit" disabled={submitting || !deviceName.trim() || !serverUrl.trim()}>
          {submitting ? "正在生成…" : "生成设备配置"}
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

function publicEntryLabel(entry: PublicEntry | null): string {
  if (!entry) return "入口状态检查中";
  switch (entry.apply_status.toLowerCase()) {
    case "ready": return "公网入口正常";
    case "configuring": return "公网入口配置中";
    case "error": return "公网入口配置失败";
    default: return "公网入口尚未配置";
  }
}

/**
 * 公网入口设置：把域名、HTTPS 和证书材料放在同一个可校验的流程里。
 * 文件内容只在提交瞬间读取，服务端成功写入 0600 Secret 后浏览器不再保留正文。
 */
function PublicEntrySettings({
  entry,
  request,
  onChanged,
}: {
  entry: PublicEntry | null;
  request: ApiRequest;
  onChanged: () => Promise<void>;
}) {
  const [domain, setDomain] = useState("");
  const [httpsEnabled, setHttpsEnabled] = useState(false);
  const [certificateMode, setCertificateMode] = useState("none");
  const [acmeEnvironment, setAcmeEnvironment] = useState("production");
  const [certificateFile, setCertificateFile] = useState<File | null>(null);
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null);
  const [cloudflareTokenFile, setCloudflareTokenFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!entry) return;
    setDomain(entry.base_domain ?? "");
    setHttpsEnabled(entry.https_enabled);
    setCertificateMode(entry.certificate_mode);
    setAcmeEnvironment(entry.acme_environment);
  }, [entry]);

  const save = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedDomain = domain.trim().replace(/\.+$/, "").toLowerCase();
    if (httpsEnabled && !trimmedDomain) {
      setError("启用 HTTPS 前请填写根域名");
      return;
    }
    if (trimmedDomain && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(trimmedDomain)) {
      setError("根域名格式无效，请填写例如 example.com");
      return;
    }
    if (certificateMode === "manual" && Boolean(certificateFile) !== Boolean(privateKeyFile)) {
      setError("手动证书需要同时选择证书和私钥文件");
      return;
    }
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const response = await request("/api/v1/settings/public-entry", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          base_domain: trimmedDomain || null,
          https_enabled: httpsEnabled,
          certificate_mode: httpsEnabled ? certificateMode : "none",
          acme_environment: acmeEnvironment,
        }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法保存公网入口设置"));

      const secrets: Record<string, string> = {};
      if (certificateFile && privateKeyFile) {
        secrets.certificate_pem = await certificateFile.text();
        secrets.private_key_pem = await privateKeyFile.text();
      }
      if (cloudflareTokenFile) {
        secrets.cloudflare_token = (await cloudflareTokenFile.text()).trim();
      }
      if (Object.keys(secrets).length > 0) {
        const secretResponse = await request("/api/v1/settings/public-entry/certificate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(secrets),
        });
        const secretBody: unknown = await secretResponse.json().catch(() => null);
        if (!secretResponse.ok) throw new Error(readApiError(secretBody, "证书或访问凭据上传失败"));
        setCertificateFile(null);
        setPrivateKeyFile(null);
        setCloudflareTokenFile(null);
      }
      setMessage("公网入口设置已保存，正在检查配置生效状态");
      await onChanged();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法保存公网入口设置");
    } finally {
      setBusy(false);
    }
  };

  const recheck = async () => {
    setChecking(true);
    setError(null);
    setMessage(null);
    try {
      const response = await request("/api/v1/settings/public-entry/recheck", { method: "POST" });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法重新检测公网入口"));
      await onChanged();
      setMessage("公网入口检测已完成");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法重新检测公网入口");
    } finally {
      setChecking(false);
    }
  };

  if (!entry) {
    return <div className="public-entry-settings"><span className="form-hint">正在读取公网入口设置…</span></div>;
  }
  const resolved = entry.dns_check?.resolved ?? [];
  const rootDns = entry.dns_check?.root;
  const wildcardDns = entry.dns_check?.wildcard;
  const dnsValue = (value?: { resolved?: string[]; error?: string }) =>
    value?.resolved?.length ? value.resolved.join("、") : value?.error ?? "未解析";
  return (
    <div className="public-entry-settings">
      <div className="public-entry-heading">
        <div>
          <strong>公网入口</strong>
          <span>为 Web 服务配置入口域名和 HTTPS。</span>
        </div>
        <span className={`entry-state ${entry.apply_status.toLowerCase()}`}><i />{publicEntryLabel(entry)}</span>
      </div>
      <form className="inline-form public-entry-form" onSubmit={save}>
        <div className="form-grid public-entry-form-grid">
          <label>
            <span>根域名</span>
            <input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.com" inputMode="url" />
          </label>
          <label>
            <span>HTTPS</span>
            <select value={httpsEnabled ? "https" : "http"} onChange={(event) => { const enabled = event.target.value === "https"; setHttpsEnabled(enabled); if (!enabled) setCertificateMode("none"); else if (certificateMode === "none") setCertificateMode("cloudflare"); }}>
              <option value="http">关闭（仅 HTTP）</option>
              <option value="https">开启</option>
            </select>
          </label>
          <label>
            <span>证书来源</span>
            <select value={httpsEnabled ? certificateMode : "none"} onChange={(event) => setCertificateMode(event.target.value)} disabled={!httpsEnabled}>
              <option value="none">未配置</option>
              <option value="cloudflare">自动申请</option>
              <option value="manual">手动证书</option>
            </select>
          </label>
          <label>
            <span>证书环境</span>
            <select value={acmeEnvironment} onChange={(event) => setAcmeEnvironment(event.target.value)} disabled={!httpsEnabled || certificateMode !== "cloudflare"}>
              <option value="production">正式环境</option>
              <option value="staging">测试环境</option>
            </select>
          </label>
        </div>
        {httpsEnabled && certificateMode === "manual" && (
          <div className="secret-picker-grid">
            <label><span>证书文件</span><input type="file" accept=".pem,.crt,text/plain" onChange={(event) => setCertificateFile(event.currentTarget.files?.[0] ?? null)} /></label>
            <label><span>私钥文件</span><input type="file" accept=".pem,.key,text/plain" onChange={(event) => setPrivateKeyFile(event.currentTarget.files?.[0] ?? null)} /></label>
          </div>
        )}
        {httpsEnabled && certificateMode === "cloudflare" && (
          <label className="secret-picker"><span>Cloudflare API Token 文件</span><input type="file" accept="text/plain,.txt" onChange={(event) => setCloudflareTokenFile(event.currentTarget.files?.[0] ?? null)} /><small>API Token 只会写入服务端受限文件，不会显示在页面或日志中。</small></label>
        )}
        <div className="form-footer">
          <span className="form-hint">HTTP 使用 80 端口，HTTPS 使用 443 端口；子域名前缀 nexo 和 mesh 已由系统保留。</span>
          <button className="primary-button" type="submit" disabled={busy}>{busy ? "保存中…" : "保存设置"}</button>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        {message && <p className="form-success" role="status">{message}</p>}
      </form>
      <div className="public-entry-meta">
        <span>DNS 根域名：{rootDns ? dnsValue(rootDns) : resolved.length > 0 ? resolved.join("、") : entry.dns_check?.error ?? "尚未检测"}</span>
        <span>DNS 泛域名：{wildcardDns ? dnsValue(wildcardDns) : "尚未检测"}</span>
        <span>{entry.certificate_not_after ? `证书有效期至 ${new Date(entry.certificate_not_after * 1000).toLocaleDateString()}` : "尚无证书信息"}</span>
        <button className="link-action" type="button" onClick={() => void recheck()} disabled={checking}>{checking ? "检测中…" : "重新检测"}</button>
      </div>
      {entry.apply_error && <p className="network-error">{entry.apply_error}</p>}
    </div>
  );
}

function validateTunnelPorts(localPortValue: string, publicPortValue: string) {
  const localPort = Number(localPortValue);
  const publicPort = publicPortValue.trim() ? Number(publicPortValue) : null;
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
    return { error: "本地端口必须在 1-65535 范围内" } as const;
  }
  if (publicPort !== null && (!Number.isInteger(publicPort) || publicPort < 20000 || publicPort > 29999)) {
    return { error: "公网 TCP 端口必须在 20000-29999 范围内" } as const;
  }
  return { localPort, publicPort } as const;
}

/** 公网访问创建表单：仅展示设备、本地服务和用户可理解的访问模式。 */
function CreateTunnelForm({
  devices,
  request,
  onCancel,
  onCreated,
}: {
  devices: Device[];
  request: ApiRequest;
  onCancel: () => void;
  onCreated: () => Promise<void>;
}) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id ?? "");
  const [name, setName] = useState("");
  const [protocol, setProtocol] = useState<Tunnel["protocol"]>("http");
  const [localAddress, setLocalAddress] = useState("127.0.0.1");
  const [localPort, setLocalPort] = useState("8800");
  const [hostname, setHostname] = useState("");
  const [publicPort, setPublicPort] = useState("");
  const [originProtocol, setOriginProtocol] = useState<"http" | "https">("http");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ field: "device" | "localPort" | "publicPort"; message: string } | null>(null);
  const device = devices.find((item) => item.id === deviceId);
  useEffect(() => {
    if (!deviceId || !devices.some((item) => item.id === deviceId)) setDeviceId(devices[0]?.id ?? "");
  }, [deviceId, devices]);
  return (
    <form className="inline-form network-form-table" aria-busy={submitting} onSubmit={async (event) => {
      event.preventDefault();
      if (!device) { setValidation({ field: "device", message: "请先选择设备" }); return; }
      const ports = validateTunnelPorts(localPort, publicPort);
      if ("error" in ports) {
        setValidation({ field: ports.error.startsWith("本地") ? "localPort" : "publicPort", message: ports.error });
        return;
      }
      setSubmitting(true); setError(null); setValidation(null);
      try {
        const response = await request("/api/v1/tunnels", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            tenant_id: device.tenant_id,
            device_id: device.id,
            name: name.trim() || (protocol === "tcp" ? "TCP 端口" : "Web 服务"),
            protocol,
            local_address: localAddress.trim(),
            local_port: ports.localPort,
            public_port: protocol === "tcp" ? ports.publicPort : null,
            hostname: protocol === "tcp" ? null : hostname.trim(),
            origin_protocol: protocol === "tcp" ? null : originProtocol,
          }),
        });
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, "暂时无法创建公网访问"));
        setName(""); setHostname(""); setPublicPort(""); await onCreated();
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "暂时无法创建公网访问");
      } finally { setSubmitting(false); }
    }}>
      <fieldset className="form-grid tunnel-form-grid" disabled={submitting}>
        <legend className="sr-only">公网访问信息</legend>
        <label><span>显示名称（可选）</span><input value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：家庭媒体库" /></label>
        <label><span>设备</span><select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required><option value="">选择设备</option>{devices.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>{validation?.field === "device" && <small className="field-error" role="alert">{validation.message}</small>}</label>
        <label><span>公网协议</span><select value={protocol} onChange={(event) => { const value = event.target.value as Tunnel["protocol"]; setProtocol(value); if (value === "https") setOriginProtocol("https"); }}><option value="http">HTTP</option><option value="https">HTTPS</option><option value="tcp">TCP</option></select></label>
        {protocol === "tcp" ? (
          <label><span>本地地址</span><input value={localAddress} onChange={(event) => setLocalAddress(event.target.value)} required /></label>
        ) : (
          <label>
            <span>本地服务</span>
            <div className="local-service-control">
              <select aria-label="本地服务协议" value={originProtocol} onChange={(event) => setOriginProtocol(event.target.value as "http" | "https")}><option value="http">HTTP</option><option value="https">HTTPS</option></select>
              <input aria-label="本地地址" value={localAddress} onChange={(event) => setLocalAddress(event.target.value)} required />
            </div>
          </label>
        )}
        <label><span>本地端口</span><input inputMode="numeric" value={localPort} onChange={(event) => setLocalPort(event.target.value)} required />{validation?.field === "localPort" && <small className="field-error" role="alert">{validation.message}</small>}</label>
        {protocol === "tcp" ? <label><span>公网端口（可选）</span><input inputMode="numeric" value={publicPort} onChange={(event) => setPublicPort(event.target.value)} placeholder="自动分配" />{validation?.field === "publicPort" && <small className="field-error" role="alert">{validation.message}</small>}</label> : <label><span>子域名前缀</span><input value={hostname} onChange={(event) => setHostname(event.target.value)} placeholder="例如：media" required /></label>}
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-footer">
        <span className="form-hint">{protocol === "tcp" ? "公网端口范围：20000-29999。" : "子域名前缀会与入口域名组合为完整访问地址。"}</span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting || !device}>{submitting ? "创建中…" : "创建公网访问"}</button>
        </div>
      </div>
    </form>
  );
}

/** 公网访问编辑弹窗：基础字段可修改，未展示的 TLS 元数据按适用性原样保留。 */
function EditTunnelDialog({
  tunnel,
  devices,
  request,
  returnFocus,
  onUpdated,
  onClose,
}: {
  tunnel: Tunnel;
  devices: Device[];
  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onUpdated: (updated: Tunnel) => void;
  onClose: () => void;
}) {
  const [deviceId, setDeviceId] = useState(tunnel.device_id);
  const [name, setName] = useState(tunnel.name);
  const [protocol, setProtocol] = useState<Tunnel["protocol"]>(tunnel.protocol);
  const [localAddress, setLocalAddress] = useState(tunnel.local_address);
  const [localPort, setLocalPort] = useState(String(tunnel.local_port));
  const [hostname, setHostname] = useState(tunnel.hostname ?? "");
  const [publicPort, setPublicPort] = useState(tunnel.public_port === null ? "" : String(tunnel.public_port));
  const [originProtocol, setOriginProtocol] = useState<"http" | "https">(tunnel.origin_protocol ?? "http");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ field: "device" | "name" | "address" | "hostname" | "localPort" | "publicPort"; message: string } | null>(null);

  return (
    <FormDialog
      eyebrow="公网访问"
      title="编辑公网访问"
      description="修改公网入口与设备本地服务之间的连接信息。"
      onClose={onClose}
      returnFocus={returnFocus}
    >
      <form className="inline-form network-form-table" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        const device = devices.find((item) => item.id === deviceId);
        if (!device) { setValidation({ field: "device", message: "请选择有效设备" }); return; }
        if (!name.trim()) { setValidation({ field: "name", message: "显示名称不能为空" }); return; }
        if (!localAddress.trim()) { setValidation({ field: "address", message: "本地地址不能为空" }); return; }
        if (protocol !== "tcp" && !hostname.trim()) { setValidation({ field: "hostname", message: "子域名前缀不能为空" }); return; }
        const ports = validateTunnelPorts(localPort, publicPort);
        if ("error" in ports) {
          setValidation({ field: ports.error.startsWith("本地") ? "localPort" : "publicPort", message: ports.error });
          return;
        }
        const keepsTlsSettings = protocol !== "tcp" && originProtocol === "https";
        setSubmitting(true);
        setError(null); setValidation(null);
        try {
          const response = await request(`/api/v1/tunnels/${encodeURIComponent(tunnel.id)}`, {
            method: "PUT",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              tenant_id: tunnel.tenant_id,
              device_id: device.id,
              name: name.trim(),
              protocol,
              local_address: localAddress.trim(),
              local_port: ports.localPort,
              public_port: protocol === "tcp" ? ports.publicPort : null,
              hostname: protocol === "tcp" ? null : hostname.trim(),
              origin_protocol: protocol === "tcp" ? null : originProtocol,
              origin_tls_server_name: keepsTlsSettings ? tunnel.origin_tls_server_name : null,
              origin_tls_verification: keepsTlsSettings ? tunnel.origin_tls_verification : "system",
              service_name: protocol === "tcp" ? null : (tunnel.service_name ?? hostname.trim()),
            }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法保存公网访问"));
          onUpdated(body as Tunnel);
          onClose();
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法保存公网访问");
        } finally {
          setSubmitting(false);
        }
      }}>
        <fieldset className="form-grid tunnel-edit-grid" disabled={submitting}>
          <legend className="sr-only">公网访问编辑信息</legend>
          <label><span>显示名称</span><input autoFocus value={name} onChange={(event) => setName(event.target.value)} required />{validation?.field === "name" && <small className="field-error" role="alert">{validation.message}</small>}</label>
          <label><span>设备</span><select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required>{devices.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>{validation?.field === "device" && <small className="field-error" role="alert">{validation.message}</small>}</label>
          <label><span>公网协议</span><select value={protocol} onChange={(event) => { const value = event.target.value as Tunnel["protocol"]; setProtocol(value); if (value === "https") setOriginProtocol("https"); }}><option value="http">HTTP</option><option value="https">HTTPS</option><option value="tcp">TCP</option></select></label>
          {protocol === "tcp" ? (
            <label><span>本地地址</span><input value={localAddress} onChange={(event) => setLocalAddress(event.target.value)} required />{validation?.field === "address" && <small className="field-error" role="alert">{validation.message}</small>}</label>
          ) : (
            <label>
              <span>本地服务</span>
              <div className="local-service-control">
                <select aria-label="本地服务协议" value={originProtocol} onChange={(event) => setOriginProtocol(event.target.value as "http" | "https")}><option value="http">HTTP</option><option value="https">HTTPS</option></select>
                <input aria-label="本地地址" value={localAddress} onChange={(event) => setLocalAddress(event.target.value)} required />
              </div>
              {validation?.field === "address" && <small className="field-error" role="alert">{validation.message}</small>}
            </label>
          )}
          <label><span>本地端口</span><input inputMode="numeric" value={localPort} onChange={(event) => setLocalPort(event.target.value)} required />{validation?.field === "localPort" && <small className="field-error" role="alert">{validation.message}</small>}</label>
          {protocol === "tcp" ? <label><span>公网端口（可选）</span><input inputMode="numeric" value={publicPort} onChange={(event) => setPublicPort(event.target.value)} placeholder="自动分配" />{validation?.field === "publicPort" && <small className="field-error" role="alert">{validation.message}</small>}</label> : <label><span>子域名前缀</span><input value={hostname} onChange={(event) => setHostname(event.target.value)} required />{validation?.field === "hostname" && <small className="field-error" role="alert">{validation.message}</small>}</label>}
        </fieldset>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <button className="secondary-button" type="button" disabled={submitting} onClick={onClose}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting}>{submitting ? "保存中…" : "保存修改"}</button>
        </div>
      </form>
    </FormDialog>
  );
}

function TunnelRow({
  tunnel,
  request,
  onChanged,
  onEdit,
}: {
  tunnel: Tunnel;
  request: ApiRequest;
  onChanged: (updated: Tunnel) => void;
  onEdit: (trigger: HTMLButtonElement) => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const statusKind = !tunnel.enabled ? "disabled" : tunnel.apply_status === "ready" ? "ready" : tunnel.apply_status === "failed" ? "failed" : "working";
  return (
    <div className="tunnel-row">
      <div className="tunnel-identity"><strong>{tunnel.name}</strong><span>{tunnel.device_name} · {tunnel.local_address}:{tunnel.local_port}</span></div>
      <div className="tunnel-address"><span>{tunnel.protocol.toUpperCase()}</span><code>{tunnel.public_address ?? "等待配置生效"}</code></div>
      <div className="network-actions">
        <span className={`link-status ${statusKind}`}><i />{tunnel.enabled ? (tunnel.apply_status === "ready" ? "已生效" : tunnel.apply_status === "failed" ? "配置失败" : "配置生效中") : "已关闭"}</span>
        <button className="link-action" type="button" disabled={pending} onClick={(event) => onEdit(event.currentTarget)}>编辑</button>
        <button className="link-action" type="button" disabled={pending} onClick={async () => {
          setPending(true);
          setError(null);
          try {
            const response = await request(`/api/v1/tunnels/${encodeURIComponent(tunnel.id)}/${tunnel.enabled ? "disable" : "enable"}`, { method: "POST" });
            const body: unknown = await response.json().catch(() => null);
            if (!response.ok) throw new Error(readApiError(body, tunnel.enabled ? "暂时无法关闭公网访问" : "暂时无法启用公网访问"));
            onChanged(body as Tunnel);
          } catch (requestError) {
            setError(requestError instanceof Error ? requestError.message : "暂时无法更新公网访问");
          } finally {
            setPending(false);
          }
        }}>{pending ? "处理中…" : tunnel.enabled ? "关闭" : "启用"}</button>
      </div>
      {error && <p className="network-error" role="alert">{error}</p>}
      {tunnel.apply_error && <p className="network-error">{tunnel.apply_error}</p>}
    </div>
  );
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
      {link.health_error && link.health_error !== link.apply_error && <p className="link-health-error">网关状态：{link.health_error}</p>}
      <div className="route-guide-list">
        {link.static_routes.map((route) => (
          <div className="route-guide" key={`${route.router_site_id}-${route.destination_site_id}`}>
            <span className="route-site">{route.router_site_name}</span>
            <span className="route-arrow">→</span>
            <span className="route-destination">{route.destination_site_name} · {route.destination_prefix}</span>
            <span className="route-via">下一跳：{route.next_hop ?? "等待设备地址"}</span>
            {route.router_confirmed ? (
              <span className="route-confirmed">路由已配置</span>
            ) : (
              <button className="route-confirm-button" type="button" onClick={() => onConfirmRoute(route.router_site_id)}>
                确认路由已配置
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
        <span>共享网段</span>
        <code>{network.desired_prefix}</code>
        <small className="network-applied">
          {network.applied_prefix
            ? `设备已应用：${network.applied_prefix}`
            : network.enabled
              ? "设备应用状态：等待确认"
              : "当前未共享"}
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
      {network.health_error && network.health_error !== network.apply_error && <p className="network-health-error">网关状态：{network.health_error}</p>}
    </div>
  );
}

/** 网关健康状态翻译；与 Desired / Applied 状态并列，避免把设备在线当成路由可用。 */
function gatewayHealthStatus(status: SiteLink["health_status"]): { label: string; kind: string } {
  switch (status) {
    case "ready":
      return { label: "网关正常", kind: "ready" };
    case "degraded":
      return { label: "部分可用", kind: "working" };
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
      return { label: "配置生效中", kind: "working" };
    case "retrying":
      return { label: "自动重试中", kind: "working" };
    case "failed":
      return { label: "配置失败", kind: "failed" };
    case "disabled":
      return { label: "已关闭", kind: "disabled" };
    default:
      return { label: "配置生效中", kind: "working" };
  }
}

function AuthShell({ children }: { children: ReactNode }) {
  return <main className="auth-shell"><div className="auth-panel"><div className="brand-mark auth-brand"><span className="brand-icon">N</span><span><strong>Nexo</strong><small>联巢</small></span></div>{children}</div></main>;
}

function InitializeScreen({ onDone }: { onDone: (body: AuthStatus & { csrf_token?: string | null }) => void }) {
  const [bootstrapCode, setBootstrapCode] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return <AuthShell><p className="eyebrow">首次设置</p><h1>创建管理员</h1><p className="auth-copy">输入本机生成的一次性初始化口令，开始管理你的设备与网络。</p><form className="auth-form" onSubmit={async (event) => { event.preventDefault(); setBusy(true); setError(null); try { const response = await fetch("/api/v1/auth/initialize", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ bootstrap_code: bootstrapCode, username, password }) }); const body = await response.json().catch(() => null) as { csrf_token?: string | null; error?: string }; if (!response.ok) throw new Error(body.error ?? "初始化失败"); onDone({ initialized: true, authenticated: true, username, channel: "local_http", csrf_token: body.csrf_token ?? null, local_http_warning: true }); } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "初始化失败"); } finally { setBusy(false); } }}><label><span>初始化口令</span><input value={bootstrapCode} onChange={(event) => setBootstrapCode(event.target.value)} type="password" autoComplete="one-time-code" required /></label><label><span>管理员用户名</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label><span>管理员密码</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="new-password" minLength={12} required /></label><button className="primary-button" type="submit" disabled={busy}>{busy ? "正在创建…" : "完成初始化"}</button>{error && <p className="form-error" role="alert">{error}</p>}</form></AuthShell>;
}

function LoginScreen({ onDone, notice }: { onDone: (body: AuthStatus & { csrf_token?: string | null }) => void; notice?: string | null }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recovery, setRecovery] = useState(false);
  if (recovery) return <RecoveryScreen onBack={() => setRecovery(false)} />;
  return <AuthShell><p className="eyebrow">安全登录</p><h1>欢迎回来</h1><p className="auth-copy">登录后管理公网访问、设备和网络互联。</p>{notice && <p className="form-success login-notice" role="status">{notice}</p>}<form className="auth-form" onSubmit={async (event) => { event.preventDefault(); setBusy(true); setError(null); try { const response = await fetch("/api/v1/auth/login", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) }); const body = await response.json().catch(() => null) as { csrf_token?: string | null; error?: string; channel?: string }; if (!response.ok) throw new Error(body.error ?? "用户名或密码错误"); onDone({ initialized: true, authenticated: true, username, channel: body.channel ?? "local_http", csrf_token: body.csrf_token ?? null, local_http_warning: body.channel !== "public_https" }); } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "登录失败"); } finally { setBusy(false); } }}><label><span>用户名</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label><span>密码</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" required /></label><button className="primary-button" type="submit" disabled={busy}>{busy ? "正在登录…" : "登录"}</button>{error && <p className="form-error" role="alert">{error}</p>}</form><button className="text-button" type="button" onClick={() => setRecovery(true)}>使用恢复码</button></AuthShell>;
}

function RecoveryScreen({ onBack }: { onBack: () => void }) {
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return <AuthShell><p className="eyebrow">账户恢复</p><h1>重设密码</h1><p className="auth-copy">恢复码只能使用一次，并在 10 分钟后失效。</p><form className="auth-form" onSubmit={async (event) => { event.preventDefault(); setBusy(true); setError(null); try { const response = await fetch("/api/v1/auth/recover", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ recovery_code: code, new_password: password }) }); const body = await response.json().catch(() => null) as { message?: string; error?: string }; if (!response.ok) throw new Error(body.error ?? "恢复失败"); setMessage(body.message ?? "密码已更新"); } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "恢复失败"); } finally { setBusy(false); } }}><label><span>恢复码</span><input value={code} onChange={(event) => setCode(event.target.value)} type="password" autoComplete="one-time-code" required /></label><label><span>新密码</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="new-password" minLength={12} required /></label><button className="primary-button" type="submit" disabled={busy}>{busy ? "正在恢复…" : "更新密码"}</button>{message && <p className="form-success" role="status">{message}</p>}{error && <p className="form-error" role="alert">{error}</p>}</form><button className="text-button" type="button" onClick={onBack}>返回登录</button></AuthShell>;
}

function App() {
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const [loginNotice, setLoginNotice] = useState<string | null>(null);
  useEffect(() => { void fetch("/api/v1/auth/status", { credentials: "same-origin" }).then(async (response) => { const body = await response.json() as AuthStatus; setAuth(body); setCsrfToken(body.csrf_token); }).catch(() => setAuth({ initialized: false, authenticated: false, username: null, channel: null, csrf_token: null, local_http_warning: true })).finally(() => setChecking(false)); }, []);
  const request = useCallback<ApiRequest>(async (input, init = {}) => {
    const headers = new Headers(init.headers);
    const method = (init.method ?? "GET").toString().toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) headers.set("x-nexo-csrf", csrfToken);
    const response = await fetch(input, { ...init, headers, credentials: "same-origin" });
    if (response.status === 401) setAuth((current) => current ? { ...current, authenticated: false, csrf_token: null } : current);
    return response;
  }, [csrfToken]);
  const onAuthenticated = useCallback((next: AuthStatus & { csrf_token?: string | null }) => { setAuth(next); setCsrfToken(next.csrf_token ?? null); setLoginNotice(null); }, []);
  const onLogout = useCallback(async () => { await request("/api/v1/auth/logout", { method: "POST" }); setCsrfToken(null); setAuth((current) => current ? { ...current, authenticated: false, csrf_token: null } : current); }, [request]);
  const onSessionEnded = useCallback((message: string) => { setLoginNotice(message); setCsrfToken(null); setAuth((current) => current ? { ...current, authenticated: false, csrf_token: null } : current); }, []);
  if (checking || !auth) return <AuthShell><p className="auth-copy">正在检查登录会话…</p></AuthShell>;
  if (!auth.initialized) return <InitializeScreen onDone={onAuthenticated} />;
  if (!auth.authenticated) return <LoginScreen onDone={onAuthenticated} notice={loginNotice} />;
  return <Dashboard request={request} auth={auth} onLogout={onLogout} onSessionEnded={onSessionEnded} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
