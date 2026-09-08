import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Building2,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  Copy,
  Download,
  Eye,
  EyeOff,
  Globe2,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  MoreHorizontal,
  MonitorSmartphone,
  Network,
  Pencil,
  Plus,
  Power,
  PowerOff,
  RefreshCw,
  ScrollText,
  Search,
  Server,
  Settings,
  Share2,
  ShieldCheck,
  Trash2,
  UserPlus,
  WifiOff,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { registerSW } from "virtual:pwa-register";
import "./styles.css";

type AppRoute =
  | "#/overview"
  | "#/network/devices"
  | "#/network/private"
  | "#/network/public"
  | "#/network/access"
  | "#/network/settings/domains"
  | "#/network/settings/keys"
  | "#/network/settings/service"
  | "#/settings";

type PrimaryRoute = "overview" | "network" | "settings";

type NavigationItem = {
  id: PrimaryRoute;
  label: string;
  href: AppRoute;
  icon: LucideIcon;
  systemOnly?: boolean;
};

const navigationItems: NavigationItem[] = [
  { id: "overview", label: "概览", href: "#/overview", icon: LayoutDashboard },
  { id: "settings", label: "设置", href: "#/settings", icon: Settings },
];

const networkNavigationItems: Omit<NavigationItem, "id">[] = [
  { label: "设备", href: "#/network/devices", icon: MonitorSmartphone },
  { label: "私网访问", href: "#/network/private", icon: Network },
  { label: "公网服务", href: "#/network/public", icon: Globe2 },
  { label: "访问策略", href: "#/network/access", icon: ShieldCheck },
  { label: "网络设置", href: "#/network/settings/service", icon: Settings },
];

const validRoutes = new Set<AppRoute>([
  "#/overview",
  "#/network/devices",
  "#/network/private",
  "#/network/public",
  "#/network/access",
  "#/network/settings/domains",
  "#/network/settings/keys",
  "#/network/settings/service",
  "#/settings",
]);

/** Hash 路由避免改变服务端静态托管，同时让每个管理页面可以刷新和前进后退。 */
function readRoute(): AppRoute {
  const hash = window.location.hash;
  const route = hash as AppRoute;
  if (validRoutes.has(route)) return route;
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/overview`);
  return "#/overview";
}

function primaryRoute(route: AppRoute): PrimaryRoute {
  if (route.startsWith("#/network/")) return "network";
  if (route === "#/settings") return "settings";
  return "overview";
}

/** 子页面标题直接描述当前位置，一级导航只负责标识所属能力。 */
function routeTitle(route: AppRoute): string {
  if (route === "#/network/devices") return "设备";
  if (route === "#/network/private") return "私网访问";
  if (route === "#/network/public") return "公网服务";
  if (route === "#/network/access") return "访问策略";
  if (route === "#/network/settings/domains") return "域名与 HTTPS";
  if (route === "#/network/settings/keys") return "客户端密钥";
  if (route === "#/network/settings/service") return "组网服务";
  if (route === "#/settings") return "设置";
  return "概览";
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
  user_id: string | null;
  username: string | null;
  role: "system_admin" | "tenant" | string | null;
  workspace_id: string | null;
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
  device_id: string | null;
  device_name: string | null;
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
  deletion_pending: boolean;
  public_address: string | null;
  public_domain_id: string | null;
  public_domain: string | null;
};

type DeleteResponse = {
  deleted: boolean;
  pending: boolean;
  id: string;
  message: string;
};

type BatchSkippedItem = {
  id: string;
  reason: string;
};

type BatchTunnelResponse = {
  updated: Tunnel[];
  affected_count: number;
  skipped: BatchSkippedItem[];
  message: string;
};

type BatchTunnelDeleteResponse = {
  deleted_ids: string[];
  affected_count: number;
  message: string;
};

type CertificateStatus = {
  status: string;
  not_before: number | null;
  not_after: number | null;
  renewal_at: number | null;
  subjects: string[];
  progress: CertificateProgress;
};

type CertificateProgress = {
  stage: "waiting_configuration" | "presenting_dns" | "waiting_dns" | "validating" | "issued" | "active" | "retry_wait" | "failed" | string;
  attempt_count: number;
  last_event_at: number | null;
  next_retry_at: number | null;
  error_code: string | null;
  error_message: string | null;
};

type DnsManagement = {
  enabled: boolean;
  target_ipv4: string | null;
  target_ipv6: string | null;
  status: string;
  error: string | null;
  version: number;
};

type PublicDomain = {
  id: string;
  tenant_id: string;
  domain: string;
  is_primary: boolean;
  https_enabled: boolean;
  certificate_mode: "manual" | "cloudflare" | string;
  acme_environment: "staging" | "production" | string;
  apply_status: string;
  apply_error: string | null;
  error_code: string | null;
  dns_check: {
    root?: { hostname?: string; resolved?: string[]; error?: string };
    wildcard?: { hostname?: string; resolved?: string[]; error?: string };
    [key: string]: unknown;
  };
  root_certificate: CertificateStatus;
  wildcard_certificate: CertificateStatus;
  usage_count: number;
  desired_revision: number;
  applied_revision: number;
  retry_after: number | null;
  attempt_count: number;
  next_retry_at: number | null;
  dns_management: DnsManagement;
  management_entry?: string | null;
  mesh_entry?: string | null;
  readiness_summary?: {
    status: string;
    root_dns: string;
    wildcard_dns: string;
    https: string;
    management_entry: string;
    mesh_entry: string;
  };
};

type ManagedDnsChange = {
  action: "adopt" | "create" | "replace" | string;
  record_type: string;
  name: string;
  desired_content: string;
  current_content: string | null;
  record_id: string | null;
};

type ManagedDnsPreview = {
  domain_id: string;
  zone_name: string;
  changes: ManagedDnsChange[];
  has_conflicts: boolean;
};

type PublicDomainMigration = {
  id: string;
  from_domain_id: string;
  to_domain_id: string;
  status: string;
  total_devices: number;
  acknowledged_devices: number;
  last_error: string | null;
  created_at: number;
  updated_at: number;
};

type RuntimeEvent = {
  id: number;
  public_domain_id: string | null;
  domain: string | null;
  level: "error" | "warning" | "info" | "debug" | string;
  category: string;
  stage: string | null;
  summary: string;
  error_code: string | null;
  retry_at: number | null;
  technical_detail: string | null;
  occurred_at: number;
};

type RuntimeEventPage = {
  events: RuntimeEvent[];
  next_cursor: number | null;
};

type GatewayReport = {
  ipv4_forwarding: boolean;
  ipv6_forwarding: boolean;
  subnet_gateway: "ready" | "unavailable";

  local_networks?: LocalNetwork[];
};

type LocalNetwork = {
  interface_id: string;
  prefix: string;
  gateway_address: string | null;
};


type Device = {
  id: string;
  tenant_id: string;

  name: string;
  os: string | null;
  architecture: string | null;
  agent_version: string | null;
  status: string;
  gateway_report: GatewayReport | null;
  mesh_status?: "joining" | "connected" | "mesh_offline" | "needs_recovery" | "failed" | "disabled" | "not_joined";
  mesh_address?: string | null;
  mesh_name?: string | null;
  active_mesh_name?: string | null;
  mesh_fqdn?: string | null;
  mesh_name_status?: "not_joined" | "applying" | "ready" | string;
  connection_type?: "nexo_agent" | "tailscale_client" | string;
  owner_user_id?: string | null;
  owner_username?: string | null;
  registration_method?: "browser" | "auth_key" | "oidc" | string | null;
  tags?: string[];
  tailscale_ipv4?: string | null;
  tailscale_ipv6?: string | null;
  expires_at?: number | null;
  control_plane_state?: string | null;
  last_seen_at: number | null;
  needs_name?: boolean;
  tunnel_count?: number;
};

type Enrollment = {
  enrollment_id: string;
  status: "pending" | "awaiting_approval" | "approved" | "consumed" | "expired" | "revoked";
  tenant_id: string;

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

type TailscaleClientConfig = {
  magic_dns_enabled: boolean;
  dns_base_domain: string;
  login_server: string;
  browser_authorization_url: string | null;
  supported_platforms: string[];
  notes: string[];
};

type TailscaleAuthKey = {
  id: string;
  label: string;
  key: string | null;
  login_server: string;
  reusable: boolean;
  ephemeral: boolean;
  expires_at: number;
  state: string;
  created_at: number;
};

type TailscaleExternalNode = {
  node_id: string;
  name: string;
  online: boolean;
  addresses: string[];
  claim_state: string;
  discovered_at: number;
  last_seen_at: number;
  needs_name?: boolean;
};

type MeshStatus = {
  status: "normal" | "starting" | "abnormal" | "restricted" | "version_incompatible";
  message: string;
};

type AccessGrant = {
  workspace_id: string;
  workspace_name: string;
  status: string;
  accepted_at: number | null;
};

type AccessRule = {
  id: string;
  owner_workspace_id: string;
  owner_username: string;
  name: string;
  target_type: "device" | "network" | "exit_node" | "file_share" | string;
  target_id: string;
  target_label: string;
  protocols: string[];
  ports: string[];
  ssh_enabled: boolean;
  enabled: boolean;
  desired_revision: number;
  applied_revision: number;
  apply_status: string;
  apply_error: string | null;
  grants: AccessGrant[];
  created_at: number;
  updated_at: number;
};

type AccessWorkspace = { id: string; name: string };

type AccessPolicyPreview = {
  status?: "valid" | "invalid" | "unavailable";
  valid: boolean;
  grant_count: number;
  ssh_rule_count: number;
  affected_targets: string[];
  summary: string;
  error: string | null;
};





type SiteNetwork = {
  status_reason: string;
  updated_at: number;
  id: string;
  tenant_id: string;


  name: string;
  publisher_device_name: string;
  publisher_device_id: string;
  interface_id: string | null;
  source: "detected" | "manual" | string;
  gateway_address: string | null;
  desired_prefix: string;
  applied_prefix: string | null;
  enabled: boolean;
  apply_status: "disabled" | "checking" | "applying" | "ready" | "retrying" | "failed";
  apply_error: string | null;
  health_status: "ready" | "degraded" | "failed" | "disabled";
  health_error: string | null;
  deletion_pending: boolean;
};

type MeshConnection = {
  client_device_id: string;
  client_device_name: string;
  gateway_device_id: string;
  gateway_device_name: string;
  site_network_id: string;
  site_network_prefix: string;
  connection_type: "direct" | "peer_relay" | "derp" | "idle" | "unknown" | string;
  updated_at: number | null;
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
  const [siteNetworks, setSiteNetworks] = useState<SiteNetwork[]>([]);
  const [meshConnections, setMeshConnections] = useState<MeshConnection[]>([]);
  const [accessRules, setAccessRules] = useState<AccessRule[]>([]);
  const [accessWorkspaces, setAccessWorkspaces] = useState<AccessWorkspace[]>([]);
  const [accessPolicyPreview, setAccessPolicyPreview] = useState<AccessPolicyPreview | null>(null);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [meshStatus, setMeshStatus] = useState<MeshStatus | null>(null);
  const [tailscaleClientConfig, setTailscaleClientConfig] = useState<TailscaleClientConfig | null>(null);
  const [tailscaleAuthKeys, setTailscaleAuthKeys] = useState<TailscaleAuthKey[]>([]);
  const [tailscaleExternalNodes, setTailscaleExternalNodes] = useState<TailscaleExternalNode[]>([]);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [publicDomains, setPublicDomains] = useState<PublicDomain[]>([]);
  const [loading, setLoading] = useState(false);
  const [showTunnelForm, setShowTunnelForm] = useState(false);
  const [editingTunnel, setEditingTunnel] = useState<Tunnel | null>(null);
  const [editTrigger, setEditTrigger] = useState<HTMLButtonElement | null>(null);
  const [deletingTunnel, setDeletingTunnel] = useState<Tunnel | null>(null);
  const [deleteTunnelTrigger, setDeleteTunnelTrigger] = useState<HTMLButtonElement | null>(null);
  const [editingDevice, setEditingDevice] = useState<Device | null>(null);
  const [editDeviceTrigger, setEditDeviceTrigger] = useState<HTMLButtonElement | null>(null);
  const [deletingDevice, setDeletingDevice] = useState<Device | null>(null);
  const [deleteDeviceTrigger, setDeleteDeviceTrigger] = useState<HTMLButtonElement | null>(null);
  const [showEnrollmentForm, setShowEnrollmentForm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [deletingResource, setDeletingResource] = useState<string | null>(null);
  const previousPendingDeletionIds = useRef<Set<string>>(new Set());

  useEffect(() => {
    const updateRoute = () => setRoute(readRoute());
    window.addEventListener("hashchange", updateRoute);
    return () => window.removeEventListener("hashchange", updateRoute);
  }, []);

  useEffect(() => {
    document.title = `${routeTitle(route)} - Nexo`;
    setMobileNavigationOpen(false);
    window.requestAnimationFrame(() => document.querySelector<HTMLElement>("#main-content h1")?.focus());
  }, [route]);

  // 域名和全局证书仍是系统级设置；普通工作空间保留公网服务状态查看，
  // 直接打开设置地址时回到组网服务页，不短暂渲染无权限内容。
  useEffect(() => {
    if (auth.role === "tenant" && route === "#/network/settings/domains") {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/network/settings/service`);
      setRoute("#/network/settings/service");
    }
  }, [auth.role, route]);

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
      if (route === "#/overview") {
        const [nextOverview, nextEnrollments, nextTunnels, nextNetworks] = await Promise.all([
          read<Overview>("/api/v1/overview", "暂时无法读取概览"),
          read<Enrollment[]>("/api/v1/enrollments", "暂时无法读取入网请求"),
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取公网服务"),
          read<SiteNetwork[]>("/api/v1/site-networks", "暂时无法读取共享网络"),

        ]);
        setOverview(nextOverview); setEnrollments(nextEnrollments); setTunnels(nextTunnels);
        setSiteNetworks(nextNetworks);
      } else if (route === "#/network/devices") {
        const [nextDevices, nextEnrollments, nextMeshStatus, nextNetworks, nextTunnels] = await Promise.all([
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),

          read<Enrollment[]>("/api/v1/enrollments", "暂时无法读取入网请求"),
          read<MeshStatus>("/api/v1/mesh/status", "暂时无法读取设备互联状态"),
          read<SiteNetwork[]>("/api/v1/site-networks", "暂时无法读取共享网段"),
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取公网服务"),
        ]);
        setDevices(nextDevices);  setEnrollments(nextEnrollments); setMeshStatus(nextMeshStatus);
        setSiteNetworks(nextNetworks); setTunnels(nextTunnels);
        setMeshConnections(await read<MeshConnection[]>("/api/v1/mesh/connections", "暂时无法读取连接情况"));
        const domainsResponse = await request("/api/v1/public-domains");
        if (domainsResponse.ok) setPublicDomains(await domainsResponse.json());
        const clientConfigResponse = await request("/api/v1/mesh/client-config");
        const clientConfigBody: unknown = await clientConfigResponse.json().catch(() => null);
        if (!clientConfigResponse.ok) throw new Error(readApiError(clientConfigBody, "暂时无法读取客户端配置"));
        setTailscaleClientConfig(clientConfigBody as TailscaleClientConfig);
        if (auth.role === "system_admin") {
          const externalNodesResponse = await request("/api/v1/mesh/external-nodes");
          const externalNodesBody: unknown = await externalNodesResponse.json().catch(() => null);
          if (!externalNodesResponse.ok) throw new Error(readApiError(externalNodesBody, "暂时无法同步隔离设备"));
          setTailscaleExternalNodes(externalNodesBody as TailscaleExternalNode[]);
        }
      } else if (route === "#/network/access") {
        const [nextDevices, nextNetworks, nextRules, nextWorkspaces] = await Promise.all([
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
          read<SiteNetwork[]>("/api/v1/site-networks", "暂时无法读取共享网络"),
          read<AccessRule[]>("/api/v1/access-control/rules", "暂时无法读取访问规则"),
          read<AccessWorkspace[]>("/api/v1/access-control/workspaces", "暂时无法读取可授权工作空间"),
        ]);
        setDevices(nextDevices); setSiteNetworks(nextNetworks); setAccessRules(nextRules); setAccessWorkspaces(nextWorkspaces);
        const previewResponse = await request("/api/v1/access-control/policy/preview");
        const previewBody: unknown = await previewResponse.json().catch(() => null);
        if (previewResponse.ok) setAccessPolicyPreview(previewBody as AccessPolicyPreview);
      } else if (route === "#/network/settings/domains") {
        const domainsResponse = await request("/api/v1/public-domains");
        const domainsBody: unknown = await domainsResponse.json().catch(() => null);
        if (domainsResponse.ok) {
          setPublicDomains(Array.isArray(domainsBody) ? domainsBody as PublicDomain[] : []);
        } else {
          setPublicDomains([]);
          throw new Error(readApiError(domainsBody, "暂时无法读取域名与 HTTPS 配置"));
        }
      } else if (route === "#/network/public") {
        const [nextTunnels, nextDevices] = await Promise.all([
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取公网服务"),
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
        ]);
        setTunnels(nextTunnels); setDevices(nextDevices);
        const domainsResponse = await request("/api/v1/public-domains");
        const domainsBody: unknown = await domainsResponse.json().catch(() => null);
        if (domainsResponse.ok) setPublicDomains(Array.isArray(domainsBody) ? domainsBody as PublicDomain[] : []);
      } else if (route === "#/network/private") {
        const [nextDevices, nextNetworks, nextConnections] = await Promise.all([

          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
          read<SiteNetwork[]>("/api/v1/site-networks", "暂时无法读取共享网络"),

          read<MeshConnection[]>("/api/v1/mesh/connections", "暂时无法读取连接路径"),
        ]);
         setDevices(nextDevices); setSiteNetworks(nextNetworks);
        setMeshConnections(nextConnections);
      } else if (route === "#/network/settings/keys") {
        setTailscaleAuthKeys(await read<TailscaleAuthKey[]>("/api/v1/mesh/auth-keys", "暂时无法读取客户端密钥"));
      } else if (route === "#/network/settings/service") {
        const nextMeshStatus = await read<MeshStatus>("/api/v1/mesh/status", "暂时无法读取组网服务状态");
        setMeshStatus(nextMeshStatus);
        setTailscaleClientConfig(await read<TailscaleClientConfig>("/api/v1/mesh/client-config", "暂时无法读取组网名称解析"));
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法读取页面数据");
    } finally {
      setLoading(false);
    }
  }, [auth.role, request, route]);

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
      return null;
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : "暂时无法批准设备";
      setError(message);
      return message;
    }
  }, [request, refreshCurrentPage]);

  const deleteResource = useCallback(async (
    resourceKey: string,
    path: string,
    confirmation: string,
    fallback: string,
  ) => {
    if (!window.confirm(confirmation)) return;
    setDeletingResource(resourceKey);
    setError(null);
    setStatusMessage(null);
    try {
      const response = await request(path, { method: "DELETE" });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, fallback));
      setStatusMessage((body as DeleteResponse).message);
      await refreshCurrentPage();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : fallback);
    } finally {
      setDeletingResource(null);
    }
  }, [request, refreshCurrentPage]);



  /** 共享网络开关复用服务端 Desired State，避免 UI 本地状态与 Agent 脱节。 */


  useEffect(() => {
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  /**
   * 设备在线状态与连接观测持续更新。串行轮询避免慢请求堆积；资源快照
   * 更新不卸载详情表单，因此保留用户输入及当前焦点。
   */
  useEffect(() => {
    if (!["#/network/private", "#/network/devices", "#/network/public"].includes(route)) {
      return;
    }
    let cancelled = false;
    let timer: number;
    const poll = async () => {
      if (!document.hidden) await refreshCurrentPage();
      if (!cancelled) timer = window.setTimeout(() => void poll(), 4000);
    };
    timer = window.setTimeout(() => void poll(), 4000);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [refreshCurrentPage, route]);

  const hasPendingPublicDomainChanges = publicDomains.some((domain) =>
    ["pending", "checking", "configuring", "retrying", "rate_limited"].includes(domain.apply_status.toLowerCase()),
  );
  useEffect(() => {
    if (!hasPendingPublicDomainChanges || route !== "#/network/settings/domains") {
      return;
    }
    const timer = window.setInterval(() => void refreshCurrentPage(), 5000);
    return () => window.clearInterval(timer);
  }, [hasPendingPublicDomainChanges, refreshCurrentPage, route]);

  const pendingDeletionIds = [
    ...siteNetworks.filter((item) => item.deletion_pending).map((item) => `network:${item.id}`),

  ];
  const hasVisiblePendingDeletion = pendingDeletionIds.length > 0
    && route === "#/overview";
  useEffect(() => {
    if (!hasVisiblePendingDeletion) return;
    const timer = window.setInterval(() => void refreshCurrentPage(), 4000);
    return () => window.clearInterval(timer);
  }, [hasVisiblePendingDeletion, refreshCurrentPage]);

  useEffect(() => {
    const current = new Set(pendingDeletionIds);
    if ([...previousPendingDeletionIds.current].some((id) => !current.has(id))) {
      setStatusMessage("资源删除已完成");
    }
    previousPendingDeletionIds.current = current;
  }, [pendingDeletionIds.join("|")]);

  const applyTunnelUpdate = useCallback((updated: Tunnel) => {
    setTunnels((current) => current.map((tunnel) => tunnel.id === updated.id ? updated : tunnel));
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  const applyTunnelDeletion = useCallback((response: DeleteResponse) => {
    setTunnels((current) => current.filter((tunnel) => tunnel.id !== response.id));
    setStatusMessage(response.message);
    setDeletingTunnel(null);
    setDeleteTunnelTrigger(null);
    // 等待 dialog 卸载时的焦点恢复完成，再把焦点送到更新后的列表标题。
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("#tunnel-list-heading")?.focus();
    }));
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  const applyDeviceUpdate = useCallback((updated: Device) => {
    setDevices((current) => current.map((device) => device.id === updated.id ? updated : device));
    setEditingDevice(null);
    setEditDeviceTrigger(null);
    setStatusMessage("设备资料已更新");
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  const applyDeviceDeletion = useCallback((response: DeleteResponse) => {
    setDevices((current) => current.filter((device) => device.id !== response.id));
    setDeletingDevice(null);
    setDeleteDeviceTrigger(null);
    setStatusMessage(response.message);
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("#device-list-heading")?.focus();
    }));
    void refreshCurrentPage();
  }, [refreshCurrentPage]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <Sidebar route={route} role={auth.role} />
      <MobileHeader onOpen={() => setMobileNavigationOpen(true)} />
      {mobileNavigationOpen && <MobileNavigation route={route} role={auth.role} onClose={() => setMobileNavigationOpen(false)} />}

      <main className="content" id="main-content" aria-busy={loading}>
        {statusMessage && <p className="action-status" role="status">{statusMessage}</p>}
        <div className="page-transition" key={route}>
          {route === "#/overview" && (
            <OverviewPage
              auth={auth}
              overview={overview}
              enrollments={enrollments}
              tunnels={tunnels}
              siteNetworks={siteNetworks}

              error={error}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route === "#/network/devices" && (
            <DevicesPage
              auth={auth}
              devices={devices}

              siteNetworks={siteNetworks}
              tunnels={tunnels}
              publicDomains={publicDomains}
              meshConnections={meshConnections}
              enrollments={enrollments}
              meshStatus={meshStatus}
              clientConfig={tailscaleClientConfig}
              externalNodes={tailscaleExternalNodes}
              error={error}
              showEnrollmentForm={showEnrollmentForm}
              onToggleEnrollmentForm={() => setShowEnrollmentForm((visible) => !visible)}
              onCloseEnrollmentForm={() => setShowEnrollmentForm(false)}
              onApprove={approveEnrollment}
              request={request}
              onRefresh={refreshCurrentPage}
              deletingResource={deletingResource}
              onEditDevice={(device, trigger) => { setEditingDevice(device); setEditDeviceTrigger(trigger); }}
              onDeleteDevice={(device, trigger) => { setDeletingDevice(device); setDeleteDeviceTrigger(trigger); }}
            />
          )}
          {route === "#/network/access" && (
            <AccessControlPage
              devices={devices}
              siteNetworks={siteNetworks}
              rules={accessRules}
              workspaces={accessWorkspaces}
              policyPreview={accessPolicyPreview}
              request={request}
              error={error}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route === "#/network/public" && (
            <PublicAccessPage
              auth={auth}
              publicDomains={publicDomains}
              tunnels={tunnels}
              devices={devices}
              error={error}
              request={request}
              showCreate={showTunnelForm}
              onOpenCreate={() => setShowTunnelForm(true)}
              onCloseCreate={() => setShowTunnelForm(false)}
              onRefresh={refreshCurrentPage}
              onTunnelChanged={applyTunnelUpdate}
              onEdit={(tunnel, trigger) => { setEditingTunnel(tunnel); setEditTrigger(trigger); }}
              onDeleteTunnel={(tunnel, trigger) => {
                setDeletingTunnel(tunnel);
                setDeleteTunnelTrigger(trigger);
              }}
            />
          )}
          {route === "#/network/private" && (
            <PrivateAccessPage devices={devices} siteNetworks={siteNetworks} meshConnections={meshConnections}
              error={error} request={request} onRefresh={refreshCurrentPage} />
          )}
          {route.startsWith("#/network/settings/") && (
            <NetworkSettingsPage
              route={route}
              auth={auth}
              domains={publicDomains}
              meshStatus={meshStatus}
              devices={devices}
              clientConfig={tailscaleClientConfig}
              authKeys={tailscaleAuthKeys}
              externalNodes={tailscaleExternalNodes}
              error={error}
              request={request}
              onRefresh={refreshCurrentPage}
              onEditDevice={(device, trigger) => { setEditingDevice(device); setEditDeviceTrigger(trigger); }}
            />
          )}
          {route === "#/settings" && (
            <SettingsPage auth={auth} request={request} onLogout={onLogout} onSessionEnded={onSessionEnded} />
          )}
        </div>
      </main>

      {editingTunnel && (
        <TunnelDetailSheet
          auth={auth}
          onRefresh={refreshCurrentPage}
          tunnel={tunnels.find(item => item.id === editingTunnel.id) ?? editingTunnel}
          devices={devices}
          publicDomains={publicDomains}
          request={request}
          returnFocus={editTrigger}
          onClose={() => { setEditingTunnel(null); setEditTrigger(null); }}
        />
      )}
      {deletingTunnel && (
        <DeleteTunnelDialog
          tunnel={deletingTunnel}
          request={request}
          returnFocus={deleteTunnelTrigger}
          onDeleted={applyTunnelDeletion}
          onClose={() => { setDeletingTunnel(null); setDeleteTunnelTrigger(null); }}
        />
      )}
      {editingDevice && (
        <EditDeviceDialog
          device={editingDevice}

          request={request}
          returnFocus={editDeviceTrigger}
          onUpdated={applyDeviceUpdate}
          onClose={() => { setEditingDevice(null); setEditDeviceTrigger(null); }}
        />
      )}
      {deletingDevice && (
        <DeleteDeviceDialog
          device={deletingDevice}
          request={request}
          returnFocus={deleteDeviceTrigger}
          onDeleted={applyDeviceDeletion}
          onClose={() => { setDeletingDevice(null); setDeleteDeviceTrigger(null); }}
        />
      )}
    </div>
  );
}

type DevicePageProps = {
  auth: AuthStatus; devices: Device[]; siteNetworks: SiteNetwork[]; tunnels: Tunnel[];
  publicDomains: PublicDomain[]; meshConnections: MeshConnection[]; enrollments: Enrollment[];
  meshStatus: MeshStatus | null; clientConfig: TailscaleClientConfig | null; externalNodes: TailscaleExternalNode[];
  error: string | null; showEnrollmentForm: boolean; onToggleEnrollmentForm: () => void;
  onCloseEnrollmentForm: () => void; onApprove: (item: Enrollment) => Promise<string | null>;
  request: ApiRequest; onRefresh: () => Promise<void>; deletingResource: string | null;
  onEditDevice: (device: Device, trigger: HTMLButtonElement | null) => void;
  onDeleteDevice: (device: Device, trigger: HTMLButtonElement) => void;
};

/** 设备是唯一操作入口；轮询只替换资源快照，不重置列表筛选或详情位置。 */
function DevicesPage(props: DevicePageProps) {
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("all");
  const [status, setStatus] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [trigger, setTrigger] = useState<HTMLButtonElement | null>(null);
  const [claimError, setClaimError] = useState<string | null>(null);
  const [claiming, setClaiming] = useState<string | null>(null);
  const matches = (name: string, searchFields = "") => `${name} ${searchFields}`.toLowerCase().includes(search.trim().toLowerCase());
  const deviceSearchFields = (device: Device) => [
    device.mesh_name,
    device.active_mesh_name,
    device.mesh_fqdn,
    device.mesh_address,
    device.tailscale_ipv4,
    device.tailscale_ipv6,
  ].filter(Boolean).join(" ");
  const visible = props.devices.filter((device) => matches(device.name, deviceSearchFields(device)) && (kind === "all" || device.connection_type === kind) && (status === "all" || device.status === status));
  const pending = props.enrollments.filter((item) => item.status === "awaiting_approval" && matches(item.device_name ?? "") && (kind === "all" || kind === "nexo_agent") && (status === "all" || status === "pending"));
  const external = props.auth.role === "system_admin" ? props.externalNodes.filter((item) => matches(item.name, item.addresses.join(" ")) && (kind === "all" || kind === "tailscale_client") && (status === "all" || status === "unassigned")) : [];
  const selected = props.devices.find((device) => device.id === selectedId);
  const claim = async (node: TailscaleExternalNode) => {
    setClaiming(node.node_id); setClaimError(null);
    try {
      const response = await props.request(`/api/v1/mesh/external-nodes/${encodeURIComponent(node.node_id)}/claim`, { method: "POST" });
      const body: unknown = await response.json();
      if (!response.ok) throw new Error(readApiError(body, "暂时无法确认设备归属"));
      await props.onRefresh();
    } catch (error) { setClaimError(error instanceof Error ? error.message : "暂时无法确认设备归属"); }
    finally { setClaiming(null); }
  };
  return <>
    <PageHeader eyebrow="网络" title="设备" subtitle="查看设备，并管理它的子网和公网服务。" action={<button className="primary-button" onClick={props.onToggleEnrollmentForm}><Plus size={16} aria-hidden="true" />添加设备</button>} />
    <PageError error={props.error} onRetry={props.onRefresh} />
    <section className="panel page-panel">
      <div className="device-filters"><label><span className="sr-only">搜索设备</span><input placeholder="搜索名称、访问名、域名或 IP 地址" aria-label="搜索设备" value={search} onChange={(event) => setSearch(event.target.value)} /></label><label><span className="sr-only">设备类型</span><select aria-label="设备类型筛选" value={kind} onChange={(event) => setKind(event.target.value)}><option value="all">所有类型</option><option value="nexo_agent">Nexo Agent</option><option value="tailscale_client">Tailscale 客户端</option></select></label><label><span className="sr-only">设备状态</span><select aria-label="设备状态筛选" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">所有状态</option><option value="online">在线</option><option value="offline">离线</option><option value="pending">待批准</option><option value="unassigned">待归属</option></select></label></div>
      <div className="unified-device-table" role="table" aria-label="设备列表">
        <div className="unified-device-head" role="row"><span role="columnheader">名称</span><span role="columnheader">类型</span><span role="columnheader">组网地址</span><span role="columnheader">状态</span></div>
        {visible.map((device) => <div className="unified-device-row" role="row" key={device.id}><div role="cell"><button className="device-name-button" onClick={(event) => {setSelectedId(device.id); setTrigger(event.currentTarget);}}>{device.name}</button></div><span role="cell">{device.connection_type === "nexo_agent" ? "Nexo Agent" : "Tailscale 客户端"}</span><code role="cell">{device.tailscale_ipv4 ?? device.mesh_address ?? "地址待分配"}</code><span role="cell" className={`status-pill ${device.status === "online" ? "ready" : "disabled"}`}><i />{device.status === "online" ? "在线" : "离线"}</span></div>)}
        {pending.map((item) => <div className="unified-device-row" role="row" key={item.enrollment_id}><strong role="cell">{item.device_name ?? "新设备"}</strong><span role="cell">Nexo Agent</span><span role="cell">待批准</span><div role="cell"><button className="secondary-button" disabled={claiming === item.enrollment_id} onClick={async () => {setClaiming(item.enrollment_id);try {await props.onApprove(item);} finally {setClaiming(null);}}}>批准设备</button></div></div>)}
        {external.map((node) => <div className="unified-device-row" role="row" key={node.node_id}><div role="cell"><strong>{node.name}</strong></div><span role="cell">Tailscale 客户端</span><span role="cell">待归属</span><div role="cell"><button className="secondary-button" disabled={claiming === node.node_id} onClick={() => void claim(node)}>归属当前工作空间</button></div></div>)}
      </div>
      {visible.length + pending.length + external.length === 0 && <EmptyState icon={MonitorSmartphone} title="没有匹配的设备" detail="调整筛选，或添加设备开始使用。" />}
      {claimError && <p className="form-error" role="alert">{claimError}</p>}
    </section>
    {selected && <DeviceDetailSheet {...props} device={selected} returnFocus={trigger} onClose={() => setSelectedId(null)} />}
    {props.showEnrollmentForm && <AddDeviceSheet tenantId={props.auth.workspace_id ?? "default"} enrollments={props.enrollments} onApprove={props.onApprove} clientConfig={props.clientConfig} request={props.request} onCreated={props.onRefresh} onClose={props.onCloseEnrollmentForm} />}
  </>;
}

function DeviceDetailSheet(props: DevicePageProps & { device: Device; returnFocus: HTMLElement | null; onClose: () => void }) {
  const [page, setPage] = useState<"details" | "subnets" | "rename" | "create" | "delete">("details");
  const [service, setService] = useState<Tunnel | null>(null);
  const [networkId, setNetworkId] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const detailPosition = useRef({scrollTop: 0, action: "", moreOpen: false});
  const detailRoot = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (page !== "details" || service || networkId) return;
    const frame = window.requestAnimationFrame(() => {
      const root = detailRoot.current;
      if (!root) return;
      const more = root.querySelector('details');
      if (more) more.open = detailPosition.current.moreOpen;
      const action = [...root.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent === detailPosition.current.action);
      action?.focus({preventScroll:true});
      const body = root.closest('.form-dialog-body');
      if (body) body.scrollTop = detailPosition.current.scrollTop;
    });
    return () => window.cancelAnimationFrame(frame);
  }, [page, service, networkId]);
  const back = () => setPage("details");
  const networks = props.siteNetworks.filter((item) => item.publisher_device_id === props.device.id);
  const services = props.tunnels.filter((item) => item.device_id === props.device.id);
  const selectedNetwork = networks.find((item) => item.id === networkId);
  const meshName = props.device.mesh_name ?? props.device.active_mesh_name;
  const activeMeshName = props.device.active_mesh_name;
  const meshFqdn = props.device.mesh_fqdn;
  const meshNameApplying = props.device.mesh_name_status === "applying";
  const copyMeshValue = async (label: string, value: string | null | undefined) => {
    if (!value) return;
    try {
      if (!navigator.clipboard) throw new Error("clipboard-unavailable");
      await navigator.clipboard.writeText(value);
      setCopyStatus(`${label}已复制`);
    } catch {
      setCopyStatus("复制失败，请检查浏览器剪贴板权限");
    }
  };
  if (page === "subnets") return <SharedNetworksEditor device={props.device} networks={networks} request={props.request} onRefresh={props.onRefresh} onClose={back} />;
  if (page === "rename") return <EditDeviceDialog device={props.device} request={props.request} returnFocus={null} onUpdated={() => {void props.onRefresh();back();}} onClose={back} />;
  if (page === "delete") return <DeleteDeviceDialog device={props.device} request={props.request} returnFocus={null} onDeleted={() => {void props.onRefresh();props.onClose();}} onClose={back} />;
  if (service) return <TunnelDetailSheet auth={props.auth} onRefresh={props.onRefresh} tunnel={props.tunnels.find((item) => item.id === service.id) ?? service} devices={props.devices} publicDomains={props.publicDomains} request={props.request} returnFocus={null} onClose={() => setService(null)} />;
  if (selectedNetwork) return <NetworkDetailSheet network={selectedNetwork} connections={props.meshConnections.filter((item) => item.site_network_id === selectedNetwork.id)} request={props.request} returnFocus={null} onRefresh={props.onRefresh} onClose={() => setNetworkId(null)} />;
  if (page === "create") return <FormDialog confirmDiscard title="添加公网服务" eyebrow={props.device.name} description="从这台设备发布服务。" onClose={back}><CreateTunnelForm auth={props.auth} devices={[props.device]} publicDomains={props.publicDomains} request={props.request} onDomainsChanged={props.onRefresh} onCancel={back} onCreated={async () => {await props.onRefresh();back();}} /></FormDialog>;
  return <FormDialog title={props.device.name} eyebrow="设备详情" description={`${props.device.connection_type === "nexo_agent" ? "Nexo Agent" : "Tailscale 客户端"} · ${props.device.mesh_address ?? props.device.tailscale_ipv4 ?? "地址待分配"}`} returnFocus={props.returnFocus} onClose={props.onClose}>
    <div ref={detailRoot} onClickCapture={(event) => {
      const button = (event.target as HTMLElement).closest('button');
      if (!button) return;
      detailPosition.current = {scrollTop: event.currentTarget.closest('.form-dialog-body')?.scrollTop ?? 0, action:button.textContent ?? "", moreOpen: Boolean(event.currentTarget.querySelector('details')?.open)};
    }}>

    <div className="detail-section"><div className="panel-heading"><h3>子网 · {networks.length}</h3>{props.device.connection_type === "nexo_agent" && <button className="secondary-button" onClick={() => setPage("subnets")}>编辑子网</button>}</div>{networks.map((item) => <button className="detail-resource" key={item.id} onClick={() => setNetworkId(item.id)}><span>{item.desired_prefix}</span><NetworkState network={item} /></button>)}{networks.length === 0 && <p className="form-hint">{props.device.connection_type === "nexo_agent" ? "选择本机网段后，当前工作空间的设备即可访问。" : "此设备可访问已授权的共享网段。"}</p>}</div>
    <section className="detail-section mesh-access-section" aria-labelledby="mesh-access-heading">
      <div className="panel-heading mesh-access-heading"><div><h3 id="mesh-access-heading">组网访问</h3><p className="form-hint">使用短访问名或完整域名访问这台设备。</p></div>{meshNameApplying && <span className="status-pill working"><i />正在更新访问名</span>}</div>
      <div className="mesh-access-values">
        <div className="mesh-access-value"><span>短访问名</span><div><code>{meshName ?? "等待分配"}</code><button className="icon-button compact-icon-button" type="button" disabled={!meshName} title="复制短访问名" aria-label="复制短访问名" onClick={() => void copyMeshValue("短访问名", meshName)}><Copy size={16} aria-hidden="true" /></button></div>{meshNameApplying && activeMeshName && activeMeshName !== meshName && <small>当前有效：{activeMeshName}</small>}</div>
        <div className="mesh-access-value"><span>{meshNameApplying && activeMeshName ? "当前完整域名" : "完整域名"}</span><div><code>{meshFqdn ?? "加入组网后生成"}</code><button className="icon-button compact-icon-button" type="button" disabled={!meshFqdn} title="复制完整域名" aria-label="复制完整域名" onClick={() => void copyMeshValue("完整域名", meshFqdn)}><Copy size={16} aria-hidden="true" /></button></div></div>
      </div>
      {meshNameApplying && <p className="mesh-access-hint">访问名更新完成前，当前完整域名仍然有效；后台会自动继续处理。</p>}
      {copyStatus && <p className="mesh-access-feedback" role="status">{copyStatus}</p>}
    </section>
    <div className="detail-section"><div className="panel-heading"><h3>公网服务 · {services.length}</h3>{props.device.connection_type === "nexo_agent" && <button className="secondary-button" onClick={() => setPage("create")}>添加服务</button>}</div>{services.map((item) => <button className="detail-resource" key={item.id} onClick={() => setService(item)}><span>{item.name}<small>{item.public_address ?? "地址待生成"}</small></span><span>{item.apply_status === "ready" ? "正常" : item.enabled ? "处理中" : "已关闭"}</span></button>)}{services.length === 0 && <p className="form-hint">暂无公网服务。</p>}</div>
    <details className="detail-section"><summary>设备信息与更多操作</summary><p>组网 IPv4：<code>{props.device.tailscale_ipv4 ?? props.device.mesh_address ?? "暂无"}</code></p><p>组网 IPv6：<code>{props.device.tailscale_ipv6 ?? "暂无"}</code></p><p>系统：{props.device.os ?? "未知"} · Agent：{props.device.agent_version ?? "不适用"}</p><p>最近连接：{props.device.last_seen_at ? formatSessionTime(props.device.last_seen_at) : "暂无记录"}</p><div className="dialog-actions"><button className="secondary-button" onClick={() => setPage("rename")}><Pencil size={15} aria-hidden="true" />编辑设备</button><button className="danger-button" onClick={() => setPage("delete")}>删除设备</button></div></details>
    </div>
  </FormDialog>;
}

/** 配置状态与客户端路径独立呈现，避免已启用或 P2P 被误认为服务可达。 */
function NetworkState({ network }: { network: SiteNetwork }) {
  const reason = network.status_reason;
  const label = network.apply_status === "disabled" ? "已关闭" : reason === "device_offline" ? "需处理" : network.apply_status === "failed" || network.health_status === "failed" ? "需处理" : network.apply_status === "ready" && network.health_status === "ready" ? "正常" : "处理中";
  return <span className={`status-pill ${label === "正常" ? "ready" : label === "需处理" ? "error" : label === "已关闭" ? "disabled" : "working"}`}><i />{label}</span>;
}

function PrivateAccessPage({devices, siteNetworks, meshConnections, error, request, onRefresh}: {devices: Device[]; siteNetworks: SiteNetwork[]; meshConnections: MeshConnection[]; error: string | null; request: ApiRequest; onRefresh: () => Promise<void>}) {
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [networkId, setNetworkId] = useState<string | null>(null);
  const [manual, setManual] = useState(false);
  const agents = devices.filter((item) => item.connection_type === "nexo_agent");
  const device = agents.find((item) => item.id === deviceId);
  const network = siteNetworks.find((item) => item.id === networkId);
  return <><PageHeader eyebrow="网络" title="私网访问" subtitle="共享家庭网段，供当前工作空间的设备访问。" /> <PageError error={error} onRetry={onRefresh} />
    <section className="panel page-panel"><div className="panel-heading"><h2>共享子网 · {siteNetworks.length}</h2><button className="secondary-button" onClick={() => setManual(true)}>手动添加网段</button></div>
      {agents.map((agent) => <div className="detail-resource" key={agent.id}><span>{agent.name}</span><button className="secondary-button" onClick={() => setDeviceId(agent.id)}>管理子网</button></div>)}
      {siteNetworks.map((item) => <div className="private-network-row" key={item.id}><div><strong>{item.desired_prefix}</strong><span>{item.publisher_device_name}</span></div><NetworkState network={item} /><button className="secondary-button" onClick={() => setNetworkId(item.id)}>查看详情</button></div>)}
      {agents.length === 0 && <EmptyState icon={Network} title="还没有 Agent" detail="先添加一台 Nexo Agent，再选择家庭网段。" />}
    </section>
    {device && <SharedNetworksEditor device={device} networks={siteNetworks.filter((item) => item.publisher_device_id === device.id)} request={request} onRefresh={onRefresh} onClose={() => setDeviceId(null)} />}
    {network && <NetworkDetailSheet network={network} connections={meshConnections.filter((item) => item.site_network_id === network.id)} request={request} returnFocus={null} onRefresh={onRefresh} onClose={() => setNetworkId(null)} />}
    {manual && <FormDialog confirmDiscard title="手动添加网段" eyebrow="私网访问" description="用于 Agent 能访问、但无法自动检测的网段。" onClose={() => setManual(false)}><CreateSiteNetworkForm devices={agents} request={request} onCancel={() => setManual(false)} onCreated={async () => {await onRefresh();setManual(false);}} /></FormDialog>}
  </>;
}

function SharedNetworksEditor({device, networks, request, onRefresh, onClose}: {device: Device; networks: SiteNetwork[]; request: ApiRequest; onRefresh: () => Promise<void>; onClose: () => void}) {
  // 编辑快照保持稳定，轮询不会覆盖用户正在勾选的集合。
  const [rows] = useState(() => [...networks.map((item) => ({id:item.id,interface_id:item.interface_id,prefix:item.desired_prefix,enabled:item.enabled,source:item.source})), ...(device.gateway_report?.local_networks ?? []).filter((item) => !networks.some((network) => network.desired_prefix === item.prefix)).map((item) => ({id:undefined,interface_id:item.interface_id,prefix:item.prefix,enabled:false,source:"detected"}))]);
  const [selection, setSelection] = useState(rows.map((item) => item.enabled));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = selection.some((value,index) => value !== rows[index].enabled);
  const close = () => {if (!dirty || window.confirm("放弃尚未保存的子网修改？")) onClose();};
  return <FormDialog title="编辑子网" eyebrow={device.name} description="保存后自动配置，允许当前工作空间内的设备访问所选网段。" onClose={() => {if (!busy) close();}}>
    <form onSubmit={async (event) => {event.preventDefault();setBusy(true);setError(null);try {const response=await request(`/api/v1/devices/${encodeURIComponent(device.id)}/shared-networks`,{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify({networks:rows.map((item,index)=>({...item,enabled:selection[index]}))})});const body:unknown=await response.json();if(!response.ok)throw new Error(readApiError(body,"暂时无法保存子网"));await onRefresh();onClose();}catch(error){setError(error instanceof Error?error.message:"暂时无法保存子网");}finally{setBusy(false);}}}>
      <fieldset className="network-checklist" disabled={busy}><legend>可共享网段</legend>{rows.map((row,index)=> {
        const missing=row.source!=="manual"&&!device.gateway_report?.local_networks.some(item=>item.prefix===row.prefix);
        const forwarding=device.gateway_report?forwardingRequirement(device.gateway_report,row.prefix):null;
        const blocked=device.gateway_report?forwarding ?? (missing?"未检测到此网段，已保留原配置":null):"等待设备上报网络信息";
        return <div key={`${row.interface_id}:${row.prefix}`}><label><input type="checkbox" checked={selection[index]} disabled={Boolean(blocked)&&!selection[index]} onChange={(event)=>setSelection(selection.map((value,i)=>i===index?event.target.checked:value))}/><span><strong>{row.prefix}</strong><small>{blocked ?? (row.interface_id || "手动网段")}</small></span></label>{blocked && <details className="form-hint"><summary>查看处理方法</summary>{forwarding ? <><p>请在运行 Agent 的 Linux 主机开启对应地址族转发，然后等待设备更新。</p><code>{row.prefix.includes(":")?"sudo sysctl -w net.ipv6.conf.all.forwarding=1":"sudo sysctl -w net.ipv4.ip_forward=1"}</code><p>重启后持续生效需将该设置写入主机的 sysctl 配置。</p></> : <p>{device.gateway_report ? "检查 Agent 的网卡是否连接到该局域网、地址是否发生变化；恢复后会自动更新。已有配置会保留，也可以取消勾选以关闭。" : "请确认 Agent 已在线并完成网络信息上报，页面会自动更新。"}</p>}</details>}</div>;
      })}{rows.length===0&&<p>等待 Agent 上报本地网段。</p>}</fieldset>
      {error&&<p className="form-error" role="alert">{error}</p>}<div className="dialog-actions"><button type="button" className="secondary-button" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy||!dirty}>{busy?"保存中…":"保存"}</button></div>
    </form>
  </FormDialog>;
}

function AddDeviceSheet({tenantId, enrollments, onApprove, clientConfig, request, onCreated, onClose}: {tenantId:string; enrollments:Enrollment[]; onApprove:(item:Enrollment)=>Promise<string | null>; clientConfig:TailscaleClientConfig|null; request:ApiRequest; onCreated:()=>Promise<void>; onClose:()=>void}) {
  const [kind,setKind]=useState("tailscale");
  const [platform,setPlatform]=useState("ios");
  const [copied,setCopied]=useState(false);
  const [error,setError]=useState<string|null>(null);
  return <FormDialog title="添加设备" eyebrow="网络" description="手机和电脑使用 Tailscale；共享子网或发布服务使用 Nexo Agent。" onClose={onClose}>
    <div className="device-kind-switch" role="tablist" aria-label="设备用途"><button role="tab" aria-selected={kind==="tailscale"} onClick={()=>setKind("tailscale")}>手机或电脑</button><button role="tab" aria-selected={kind==="agent"} onClick={()=>setKind("agent")}>共享网络或发布服务</button></div>
    <div hidden={kind!=="agent"}><CreateEnrollmentForm tenantId={tenantId} enrollments={enrollments} onApprove={onApprove} request={request} onCreated={onCreated} onDone={onClose}/></div>
    <div hidden={kind!=="tailscale"} className="tailscale-enrollment-guide"><label><span>操作系统</span><select value={platform} onChange={(event)=>setPlatform(event.target.value)}><option value="ios">iPhone / iPad</option><option value="android">Android</option><option value="windows">Windows</option><option value="macos">macOS</option><option value="linux">Linux</option></select></label>
      <ol className="official-client-steps"><li><strong>安装 Tailscale</strong><a href="https://tailscale.com/download" target="_blank" rel="noreferrer">打开官方下载页面</a></li><li><strong>使用 Nexo 控制服务器登录</strong><span>{platform==="ios"?"在账户登录的选项菜单中选择自定义协调服务器。":platform==="linux"?"使用下方命令发起登录，在浏览器完成身份验证。":"在客户端登录选项中选择自定义服务器；也可通过 Tailscale CLI 指定登录服务器。"}</span><div className="copyable-value"><code>{platform==="linux"?`sudo tailscale up --login-server=${clientConfig?.login_server??""}`:clientConfig?.login_server??"正在读取地址…"}</code><button className="secondary-button" disabled={!clientConfig?.login_server} onClick={async()=>{try{await navigator.clipboard.writeText(platform==="linux"?`sudo tailscale up --login-server=${clientConfig!.login_server}`:clientConfig!.login_server);setCopied(true);}catch{setError("无法复制，请手动选择服务器地址。");}}}>{copied?"已复制":"复制"}</button></div></li><li><strong>登录后自动加入所属工作空间</strong><span>设备加入后可访问已授权的子网，无需在手机上再次批准路由。</span></li></ol>
      {platform==="linux"&&<p className="form-hint">Linux 访问共享子网时执行 <code>sudo tailscale set --accept-routes</code>。</p>}{error&&<p className="form-error" role="alert">{error}</p>}
    </div>
  </FormDialog>;
}

/** 密钥页仅管理凭证，设备加入与归属统一留在设备页。 */
function ClientKeysPanel({authKeys,request,onRefresh}: {authKeys:TailscaleAuthKey[];request:ApiRequest;onRefresh:()=>Promise<void>}) {
  const [creating,setCreating]=useState(false);const [label,setLabel]=useState("");const [days,setDays]=useState("7");const [reusable,setReusable]=useState(false);const [ephemeral,setEphemeral]=useState(false);const [tags,setTags]=useState("");const [customHours,setCustomHours]=useState("24");const [key,setKey]=useState<string|null>(null);const [busy,setBusy]=useState(false);const [error,setError]=useState<string|null>(null);
  const close=()=>{if(!busy&& (key||!label&&!tags&&days==="7"&&!reusable&&!ephemeral||window.confirm("放弃尚未保存的密钥设置？"))){setCreating(false);setKey(null);setLabel("");setTags("");setDays("7");setReusable(false);setEphemeral(false);setError(null);}};
  return <><section className="panel page-panel"><div className="panel-heading"><h2>客户端密钥 · {authKeys.length}</h2><button className="primary-button" onClick={()=>setCreating(true)}>创建密钥</button></div>{authKeys.map(item=><div className="detail-resource" key={item.id}><div><strong>{item.label}</strong><small>{item.reusable?"可重复使用":"单次使用"} · {item.ephemeral?"临时设备":"持久设备"}</small></div><span>{item.state==="issued"?"正常":"已关闭"}</span><button className="secondary-button" disabled={busy||item.state!=="issued"} onClick={async()=>{if(!window.confirm(`吊销“${item.label}”？已登录的设备不会因此退出。`))return;setBusy(true);setError(null);try{const response=await request(`/api/v1/mesh/auth-keys/${encodeURIComponent(item.id)}/revoke`,{method:"POST"});if(!response.ok)throw new Error(readApiError(await response.json(),"无法吊销密钥"));await onRefresh();}catch(e){setError(e instanceof Error?e.message:"无法吊销密钥");}finally{setBusy(false);}}}>吊销</button></div>)}{!authKeys.length&&<EmptyState icon={KeyRound} title="还没有客户端密钥" detail="无交互登录的设备可以使用短期密钥加入。"/>}{error&&!creating&&<p role="alert" className="form-error">{error}</p>}</section>
    {creating&&<FormDialog title="创建客户端密钥" eyebrow="网络设置" description="密钥只显示一次，请妥善保存。" onClose={close}>{key?<div className="secret-reveal"><code>{key}</code><button className="secondary-button" onClick={async()=>{try{await navigator.clipboard.writeText(key);}catch{setError("无法复制，请手动选择密钥。");}}}>复制密钥</button><button className="primary-button" onClick={close}>完成</button></div>:<form onSubmit={async event=>{event.preventDefault();setBusy(true);setError(null);try{const response=await request("/api/v1/mesh/auth-keys",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({label:label.trim()||"客户端密钥",ttl_seconds:Math.round(days==="custom"?Number(customHours)*3600:Number(days)*86400),reusable,ephemeral,tags:tags.split(",").map(x=>x.trim()).filter(Boolean)})});const body=await response.json();if(!response.ok)throw new Error(readApiError(body,"无法创建密钥"));setKey(body.key);await onRefresh();}catch(e){setError(e instanceof Error?e.message:"无法创建密钥");}finally{setBusy(false);}}}><fieldset className="form-grid" disabled={busy}><label><span>名称</span><input value={label} onChange={e=>setLabel(e.target.value)}/></label><label><span>有效期</span><select value={days} onChange={e=>setDays(e.target.value)}><option value={1/24}>1 小时</option><option value="1">1 天</option><option value="7">7 天</option><option value="30">30 天</option><option value="custom">自定义时长</option></select></label>{days==="custom"&&<label><span>有效小时数</span><input type="number" min={1/60} max="720" step="any" required value={customHours} onChange={e=>setCustomHours(e.target.value)}/><small>允许 1 分钟至 30 天，可填写小数小时。</small></label>}<label className="checkbox-field"><input type="checkbox" checked={reusable} onChange={e=>setReusable(e.target.checked)}/>可重复使用</label><label className="checkbox-field"><input type="checkbox" checked={ephemeral} onChange={e=>setEphemeral(e.target.checked)}/>临时设备</label><label><span>标签（可选）</span><input value={tags} onChange={e=>setTags(e.target.value)} placeholder="tag:team"/></label></fieldset><div className="dialog-actions"><button type="button" className="secondary-button" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy}>{busy?"创建中…":"创建密钥"}</button></div></form>}{error&&<p role="alert" className="form-error">{error}</p>}</FormDialog>}
  </>;
}

function CreateSiteNetworkForm({devices,request,onCancel,onCreated}: {devices:Device[];request:ApiRequest;onCancel:()=>void;onCreated:()=>Promise<void>}) {
  const [deviceId,setDeviceId]=useState(devices[0]?.id??"");const [prefix,setPrefix]=useState("");const [name,setName]=useState("");const [busy,setBusy]=useState(false);const [error,setError]=useState<string|null>(null);
  const close=()=>{if(!prefix&&!name||window.confirm("放弃尚未保存的网段？"))onCancel();};
  return <form onSubmit={async event=>{event.preventDefault();const device=devices.find(item=>item.id===deviceId);if(!device)return;setBusy(true);setError(null);try{const response=await request("/api/v1/site-networks",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({tenant_id:device.tenant_id,publisher_device_id:device.id,name:name.trim()||prefix.trim(),prefix:prefix.trim(),source:"manual"})});const body=await response.json();if(!response.ok)throw new Error(readApiError(body,"无法添加网段"));await onCreated();}catch(e){setError(e instanceof Error?e.message:"无法添加网段");}finally{setBusy(false);}}}><fieldset className="form-grid" disabled={busy}><label><span>设备</span><select value={deviceId} onChange={e=>setDeviceId(e.target.value)} required>{devices.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label><span>网段 CIDR</span><input value={prefix} onChange={e=>setPrefix(e.target.value)} placeholder="10.0.0.0/24" required/></label><label><span>名称（可选）</span><input value={name} onChange={e=>setName(e.target.value)}/></label></fieldset>{error&&<p className="form-error" role="alert">{error}</p>}<div className="dialog-actions"><button className="secondary-button" type="button" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy||!deviceId}>保存</button></div></form>;
}

function BrandMark() {
  return (
    <div className="brand-mark" aria-label="Nexo 联巢">
      <span className="brand-icon">N</span>
      <span><strong>Nexo</strong><small>联巢</small></span>
    </div>
  );
}

function NavigationLinks({ route, role, onNavigate }: { route: AppRoute; role: string; onNavigate?: () => void }) {
  const active = primaryRoute(route);
  return (
    <nav className="primary-navigation" aria-label="主导航">
      {navigationItems.filter((item) => item.id === "overview").map((item) => {
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
      <div className={`nav-group${active === "network" ? " active" : ""}`}>
        <div className="nav-group-label"><Network size={18} strokeWidth={1.8} aria-hidden="true" /><span>网络</span></div>
        <div className="nav-group-links">
          {networkNavigationItems.filter((item) => !item.systemOnly || role === "system_admin").map((item) => {
            const Icon = item.icon;
            const current = route === item.href || (item.href === "#/network/settings/service" && route.startsWith("#/network/settings/"));
            return (
              <a className={`nav-subitem${current ? " active" : ""}`} href={item.href} aria-current={current ? "page" : undefined} onClick={onNavigate} key={item.href}>
                <Icon size={16} strokeWidth={1.8} aria-hidden="true" /><span>{item.label}</span>
              </a>
            );
          })}
        </div>
      </div>
      {navigationItems.filter((item) => item.id === "settings" && (!item.systemOnly || role === "system_admin")).map((item) => {
        const Icon = item.icon;
        return (
          <a className={`nav-item ${active === item.id ? "active" : ""}`} href={item.href} aria-current={active === item.id ? "page" : undefined} onClick={onNavigate} key={item.id}>
            <Icon size={18} strokeWidth={1.8} aria-hidden="true" /><span>{item.label}</span>
          </a>
        );
      })}
    </nav>
  );
}

function Sidebar({ route, role }: { route: AppRoute; role: string }) {
  return (
    <aside className="sidebar">
      <BrandMark />
      <NavigationLinks route={route} role={role} />
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
function MobileNavigation({ route, role, onClose }: { route: AppRoute; role: string; onClose: () => void }) {
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
        <NavigationLinks route={route} role={role} onNavigate={onClose} />
      </div>
    </dialog>
  );
}

function PageHeader({
  eyebrow,
  title,
  subtitle,
  action,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
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

  error,
  onRefresh,
}: {
  auth: AuthStatus;
  overview: Overview;
  enrollments: Enrollment[];
  tunnels: Tunnel[];
  siteNetworks: SiteNetwork[];

  error: string | null;
  onRefresh: () => Promise<void>;
}) {
  const pendingEnrollments = enrollments.filter((item) => item.status === "awaiting_approval").length;
  const failedTunnels = tunnels.filter((item) => item.apply_status === "failed").length;
  const failedNetworks = siteNetworks.filter((item) => item.apply_status === "failed").length;
  const failedResources = failedTunnels + failedNetworks;
  const applyingTunnels = tunnels.filter((item) => ["checking", "applying", "retrying"].includes(item.apply_status)).length;
  const applyingNetworks = siteNetworks.filter((item) => ["checking", "applying", "retrying"].includes(item.apply_status)).length;
  const applyingResources = applyingTunnels + applyingNetworks;
  const failedHref: AppRoute = failedTunnels ? "#/network/public" : failedNetworks ? "#/network/private" : "#/overview";
  const applyingHref: AppRoute = applyingTunnels ? "#/network/public" : "#/network/private";
  return (
    <>
      <PageHeader eyebrow="运行状态" title="概览" subtitle="先处理异常，再进入具体页面完成配置。" />
      <section className="metric-grid" aria-label="系统概览">
        <Metric label="设备" value={overview.devices} hint="已加入 Nexo" />
        <Metric label="正常公网服务" value={overview.running_tunnels} hint="公网地址可用" />
        <Metric label="组网设备" value={overview.mesh_devices} hint="已加入 Nexo 网络" />
        <Metric label="在线设备" value={overview.current_connections} hint="当前与服务端连接" />
      </section>
      <PageError error={error} onRetry={onRefresh} />
      {auth.local_http_warning && (
        <div className="notice warning" role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div><strong>当前为未加密 HTTP</strong><span>仅在可信局域网使用；需要远程管理时，请先配置公网 HTTPS。</span></div>
          <a className="notice-action" href="#/network/settings/domains">前往配置</a>
        </div>
      )}
      <section className="overview-grid">
        <article className="panel attention-panel">
          <div className="panel-heading"><div><p className="eyebrow">待处理</p><h2>需要你关注</h2></div></div>
          <div className="attention-list">
            <AttentionRow icon={UserPlus} label="待批准设备" count={pendingEnrollments} href="#/network/devices" />
            <AttentionRow icon={CircleAlert} label="配置生效失败" count={failedResources} href={failedHref} />
            <AttentionRow icon={RefreshCw} label="处理中" count={applyingResources} href={applyingHref} />
          </div>
        </article>
        <article className="panel quick-panel">
          <div className="panel-heading"><div><p className="eyebrow">快速前往</p><h2>继续管理</h2></div></div>
          <div className="quick-links">
            <QuickLink icon={MonitorSmartphone} title="设备" detail="加入和管理所有组网设备" href="#/network/devices" />
            <QuickLink icon={Globe2} title="公网服务" detail="管理 Web 服务与 TCP 端口" href="#/network/public" />
            <QuickLink icon={Network} title="私网访问" detail="管理共享家庭网段" href="#/network/private" />
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


/** 添加设备保持为一个连续 Sheet；切换类型不会关闭面板，已填写内容由各自
 * 子表单保留，关闭后焦点由 FormDialog 返回到“添加设备”触发按钮。 */

/** 官方客户端控制面：浏览器授权由 Headscale 完成，Nexo 负责凭证、隔离节点
 * 和工作空间认领。Auth Key 明文只在创建成功时展示，刷新后不会再次出现。 */

/** 访问控制只编辑结构化字段；策略文本和影响范围由服务端生成并校验。 */
function AccessControlPage({
  devices,
  siteNetworks,
  rules,
  workspaces,
  policyPreview,
  request,
  error,
  onRefresh,
}: {
  devices: Device[];
  siteNetworks: SiteNetwork[];
  rules: AccessRule[];
  workspaces: AccessWorkspace[];
  policyPreview: AccessPolicyPreview | null;
  request: ApiRequest;
  error: string | null;
  onRefresh: () => Promise<void>;
}) {
  const [editing, setEditing] = useState<AccessRule | null>(null);
  const [name, setName] = useState("");
  const [targetType, setTargetType] = useState<AccessRule["target_type"]>("device");
  const [targetId, setTargetId] = useState("");
  const [protocols, setProtocols] = useState<string[]>(["tcp", "udp"]);
  const [ports, setPorts] = useState("*");
  const [sshEnabled, setSshEnabled] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [grantees, setGrantees] = useState<string[]>([]);
  const [preview, setPreview] = useState<AccessPolicyPreview | null>(policyPreview);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    setPreview(policyPreview);
  }, [policyPreview]);

  useEffect(() => {
    if (!editing) {
      setName(""); setTargetType("device"); setTargetId(devices[0]?.id ?? "");
      setProtocols(["tcp", "udp"]); setPorts("*"); setSshEnabled(false); setEnabled(true); setGrantees([]);
      return;
    }
    setName(editing.name); setTargetType(editing.target_type); setTargetId(editing.target_id);
    setProtocols(editing.protocols); setPorts(editing.ports.join(", ")); setSshEnabled(editing.ssh_enabled);
    setEnabled(editing.enabled); setGrantees(editing.grants.filter((grant) => grant.status === "accepted").map((grant) => grant.workspace_id));
  }, [devices, editing]);

  const previewStatus = preview?.status ?? (preview?.valid ? "valid" : "invalid");
  const previewStatusLabel = previewStatus === "valid"
    ? "校验通过"
    : previewStatus === "invalid"
      ? "策略内容有误"
      : "组网服务不可用";
  const previewStatusClass = previewStatus === "valid" ? "ready" : previewStatus === "invalid" ? "error" : "working";

  const targetOptions = targetType === "device"
    ? devices.map((device) => ({ id: device.id, label: `${device.name}${device.mesh_address ? ` · ${device.mesh_address}` : ""}` }))
    : targetType === "network"
      ? siteNetworks.map((network) => ({ id: network.id, label: `${network.name} · ${network.desired_prefix}` }))
      : [];

  const candidate = () => ({
    name: name.trim() || "未命名规则",
    target_type: targetType,
    target_id: targetId.trim(),
    protocols,
    ports: ports.split(",").map((value) => value.trim()).filter(Boolean),
    ssh_enabled: sshEnabled,
    enabled,
    grantee_workspace_ids: grantees,
  });

  const runPreview = async () => {
    setFormError(null);
    try {
      const response = await request("/api/v1/access-control/policy/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(candidate()),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法校验访问策略"));
      setPreview(body as AccessPolicyPreview);
    } catch (requestError) {
      setFormError(requestError instanceof Error ? requestError.message : "暂时无法校验访问策略");
    }
  };

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true); setFormError(null);
    try {
      const response = await request(editing ? `/api/v1/access-control/rules/${encodeURIComponent(editing.id)}` : "/api/v1/access-control/rules", {
        method: editing ? "PUT" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(candidate()),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法保存访问规则"));
      setEditing(null);
      await onRefresh();
    } catch (requestError) {
      setFormError(requestError instanceof Error ? requestError.message : "暂时无法保存访问规则");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (rule: AccessRule) => {
    if (!window.confirm(`确定撤销“${rule.name}”吗？撤销失败时规则会保留并继续重试。`)) return;
    setBusy(true); setFormError(null);
    try {
      const response = await request(`/api/v1/access-control/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法撤销访问规则"));
      await onRefresh();
    } catch (requestError) {
      setFormError(requestError instanceof Error ? requestError.message : "暂时无法撤销访问规则");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader eyebrow="网络" title="访问策略" subtitle="按资源所有权建立直接授权，策略由 Nexo 校验并应用到组网服务。" action={<button className="secondary-button" type="button" onClick={() => void onRefresh()}><RefreshCw size={15} aria-hidden="true" />刷新</button>} />
      <PageError error={error} onRetry={onRefresh} />
      <section className="panel access-policy-preview" aria-labelledby="access-policy-preview-heading">
        <div className="panel-heading"><div><p className="eyebrow">影响预览</p><h2 id="access-policy-preview-heading">当前结构化策略</h2></div><div className="panel-heading-actions"><span className={`status-pill ${preview ? previewStatusClass : "working"}`}><i />{preview ? previewStatusLabel : "等待校验"}</span><button className="secondary-button compact-button" type="button" onClick={() => void onRefresh()}><RefreshCw size={15} aria-hidden="true" />重新校验</button></div></div>
        <p className="panel-note">{preview?.summary ?? "先创建或校验一条规则，页面会显示受影响目标和组网服务校验结果。"}</p>
        {preview?.error && <p className="form-error" role="alert">{preview.error}</p>}
        {preview && <div className="access-policy-facts"><span>Grant {preview.grant_count}</span><span>SSH {preview.ssh_rule_count}</span><span>目标 {preview.affected_targets.length}</span></div>}
      </section>
      <section className="panel access-rule-editor" aria-labelledby="access-rule-editor-heading">
        <div className="panel-heading"><div><p className="eyebrow">结构化规则</p><h2 id="access-rule-editor-heading">{editing ? "编辑访问规则" : "新增访问规则"}</h2></div>{editing && <button className="secondary-button compact-button" type="button" onClick={() => setEditing(null)}>取消编辑</button>}</div>
        <form className="access-rule-form" onSubmit={(event) => void save(event)}>
          <label><span>规则名称</span><input value={name} onChange={(event) => setName(event.target.value)} maxLength={128} required placeholder="例如：给协作者访问家庭网段" /></label>
          <label><span>目标类型</span><select value={targetType} onChange={(event) => { const next = event.target.value as AccessRule["target_type"]; setTargetType(next); setTargetId(next === "device" ? devices[0]?.id ?? "" : next === "network" ? siteNetworks[0]?.id ?? "" : ""); }}><option value="device">设备</option><option value="network">共享网络</option><option value="exit_node">Exit Node</option><option value="file_share">文件共享</option></select></label>
          <label><span>{targetType === "device" ? "设备" : targetType === "network" ? "共享网络" : "目标标识"}</span>{targetOptions.length > 0 ? <select value={targetId} onChange={(event) => setTargetId(event.target.value)} required><option value="">请选择目标</option>{targetOptions.map((option) => <option value={option.id} key={option.id}>{option.label}</option>)}</select> : <input value={targetId} onChange={(event) => setTargetId(event.target.value)} required placeholder={targetType === "exit_node" ? "输入已批准的设备标识" : "输入文件共享目标标识"} />}</label>
          <fieldset className="access-rule-fieldset"><legend>协议</legend><div className="access-choice-list">{["tcp", "udp", "icmp"].map((protocol) => <label key={protocol}><input type="checkbox" checked={protocols.includes(protocol)} onChange={(event) => setProtocols((current) => event.target.checked ? [...current, protocol] : current.filter((value) => value !== protocol))} /><span>{protocol.toUpperCase()}</span></label>)}</div></fieldset>
          <label><span>端口</span><input value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="*、22、80-443" /><small>多个端口用逗号分隔。</small></label>
          <label className="access-toggle"><input type="checkbox" checked={sshEnabled} onChange={(event) => setSshEnabled(event.target.checked)} /><span>允许 Tailscale SSH</span></label>
          <label className="access-toggle"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} /><span>保存后启用</span></label>
          {workspaces.length > 0 && <fieldset className="access-rule-fieldset access-grantee-fieldset"><legend>直接授权工作空间</legend><div className="access-choice-list access-grantee-list">{workspaces.map((workspace) => <label key={workspace.id}><input type="checkbox" checked={grantees.includes(workspace.id)} onChange={(event) => setGrantees((current) => event.target.checked ? [...current, workspace.id] : current.filter((value) => value !== workspace.id))} /><span>{workspace.name}</span><small>{workspace.id}</small></label>)}</div></fieldset>}
          {formError && <p className="form-error" role="alert">{formError}</p>}
          <div className="dialog-actions access-rule-actions"><button className="secondary-button" type="button" onClick={() => void runPreview()} disabled={busy}><ShieldCheck size={15} aria-hidden="true" />校验影响</button><button className="primary-button" type="submit" disabled={busy}>{busy ? "保存中…" : editing ? "保存修改" : "保存规则"}</button></div>
        </form>
      </section>
      <section className="panel access-rule-list-panel" aria-labelledby="access-rule-list-heading">
        <div className="panel-heading"><div><p className="eyebrow">已保存规则</p><h2 id="access-rule-list-heading">资源授权</h2></div><span className="status-pill"><i />{rules.length} 条</span></div>
        {rules.length === 0 ? <EmptyState icon={ShieldCheck} title="还没有访问规则" detail="保存一条规则后，直接授权会出现在这里。" /> : <div className="access-rule-table" role="table" aria-label="访问规则列表"><div className="access-rule-table-head" role="row"><span role="columnheader">规则</span><span role="columnheader">目标</span><span role="columnheader">直接授权</span><span role="columnheader">状态</span><span role="columnheader">操作</span></div>{rules.map((rule) => <div className="access-rule-table-row" role="row" key={rule.id}><div role="cell"><strong>{rule.name}</strong><small>{rule.protocols.join(" / ").toUpperCase()} · {rule.ports.join(", ")}{rule.ssh_enabled ? " · SSH" : ""}</small></div><div role="cell"><strong>{rule.target_label}</strong><small>{rule.target_type === "device" ? "设备" : rule.target_type === "network" ? "共享网络" : rule.target_type}</small></div><div role="cell"><span>{rule.grants.length > 0 ? rule.grants.map((grant) => grant.workspace_name).join("、") : "未授权"}</span></div><div role="cell"><span className={`entry-state ${rule.apply_status === "ready" ? "ready" : rule.apply_status === "error" ? "error" : "applying"}`}><i />{rule.apply_status === "ready" ? (rule.enabled ? "正常" : "已关闭") : rule.apply_status === "error" ? "需处理" : "处理中"}</span>{rule.apply_error && <small className="access-rule-error">{rule.apply_error}</small>}</div><div role="cell" className="access-rule-row-actions"><button className="icon-button" type="button" aria-label={`编辑${rule.name}`} title="编辑" onClick={() => setEditing(rule)}><Pencil size={16} aria-hidden="true" /></button>{rule.enabled && <button className="delete-icon-button" type="button" aria-label={`撤销${rule.name}`} title="撤销" disabled={busy} onClick={() => void revoke(rule)}><PowerOff size={16} aria-hidden="true" /></button>}</div></div>)}</div>}
      </section>
    </>
  );
}

function NetworkSettingsPage({ route, auth, domains, meshStatus, devices, clientConfig, authKeys, externalNodes, error, request, onRefresh, onEditDevice }: { route: AppRoute; auth: AuthStatus; domains: PublicDomain[]; meshStatus: MeshStatus | null; devices: Device[]; clientConfig: TailscaleClientConfig | null; authKeys: TailscaleAuthKey[]; externalNodes: TailscaleExternalNode[]; error: string | null; request: ApiRequest; onRefresh: () => Promise<void>; onEditDevice: (device: Device, trigger: HTMLButtonElement | null) => void }) {
  const tabs = [
    ...(auth.role === "system_admin" ? [{ href: "#/network/settings/domains" as AppRoute, label: "域名与 HTTPS", icon: LockKeyhole }] : []),
    { href: "#/network/settings/keys" as AppRoute, label: "客户端密钥", icon: KeyRound },
    { href: "#/network/settings/service" as AppRoute, label: "组网服务", icon: Network },
  ];
  return <>
    <SectionTabs label="网络设置" route={route} items={tabs} />
    {route === "#/network/settings/domains" && <DomainsPage domains={domains} error={error} request={request} onRefresh={onRefresh} />}
    {route === "#/network/settings/keys" && <><PageHeader eyebrow="网络设置" title="客户端密钥" subtitle="管理用于设备登录的短期密钥。" /><PageError error={error} onRetry={onRefresh} /><ClientKeysPanel authKeys={authKeys} request={request} onRefresh={onRefresh} /></>}
    {route === "#/network/settings/service" && <><PageHeader eyebrow="网络设置" title="组网服务" subtitle="查看设备协调服务状态和客户端入口。" /><PageError error={error} onRetry={onRefresh} /><section className="panel page-panel"><div className="panel-heading"><div><p className="eyebrow">运行状态</p><h2>{meshStatus?.message ?? "正在检查组网服务"}</h2></div><span className={`status-pill ${meshStatus?.status === "normal" ? "ready" : "working"}`}><i />{meshStatus?.status === "normal" ? "正常" : "需处理"}</span></div></section><section className="panel page-panel"><h2>组网名称解析</h2><p>MagicDNS：{clientConfig ? (clientConfig.magic_dns_enabled ? "已开启" : "已关闭") : "正在读取"}</p><p>设备域名：<code>{clientConfig?.dns_base_domain ?? "正在读取"}</code></p><p className="form-hint">用于 Nexo 网络内的设备名称解析。公网服务域名在“域名与 HTTPS”中管理。</p></section>{auth.role === "system_admin" && <details className="advanced-network panel page-panel"><summary><span><strong>高级诊断</strong><small>Headscale 组件状态与故障排查入口</small></span><ChevronDown size={18} aria-hidden="true" /></summary><div className="advanced-network-body"><p className="panel-note">Headscale 仅作为底层组网组件显示在系统管理员诊断中。</p><button className="secondary-button" type="button" onClick={() => void onRefresh()}><RefreshCw size={16} aria-hidden="true" />重新检查</button></div></details>}</>}
  </>;
}

function DomainsPage({ domains, error, request, onRefresh }: {
  domains: PublicDomain[];
  error: string | null;
  request: ApiRequest;
  onRefresh: () => Promise<void>;
}) {
  return <>
    <PageHeader eyebrow="网络设置" title="域名与 HTTPS" subtitle="统一管理系统入口、组网入口和 Web 服务使用的域名。" />
    <PageError error={error} onRetry={onRefresh} />
    <PublicDomainsPanel domains={domains} request={request} onRefresh={onRefresh} />
  </>;
}

function PublicAccessPage({
  auth,
  publicDomains,
  tunnels,
  devices,
  error,
  request,
  showCreate,
  onOpenCreate,
  onCloseCreate,
  onRefresh,
  onTunnelChanged,
  onEdit,
  onDeleteTunnel,
}: {
  auth: AuthStatus;
  publicDomains: PublicDomain[];
  tunnels: Tunnel[];
  devices: Device[];
  error: string | null;
  request: ApiRequest;
  showCreate: boolean;
  onOpenCreate: () => void;
  onCloseCreate: () => void;
  onRefresh: () => Promise<void>;
  onTunnelChanged: (updated: Tunnel) => void;
  onEdit: (tunnel: Tunnel, trigger: HTMLButtonElement) => void;
  onDeleteTunnel: (tunnel: Tunnel, trigger: HTMLButtonElement) => void;
}) {
  const [selectedTunnelIds, setSelectedTunnelIds] = useState<string[]>([]);
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchMessage, setBatchMessage] = useState<string | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchDeviceDialog, setBatchDeviceDialog] = useState(false);
  const [batchDeleteDialog, setBatchDeleteDialog] = useState(false);
  const [batchDeviceTrigger, setBatchDeviceTrigger] = useState<HTMLButtonElement | null>(null);
  const [batchDeleteTrigger, setBatchDeleteTrigger] = useState<HTMLButtonElement | null>(null);
  const selectAllRef = useRef<HTMLInputElement>(null);
  const selectableTunnels = tunnels.filter((tunnel) => !tunnel.deletion_pending);
  const selectedTunnelSet = new Set(selectedTunnelIds);
  const selectedTunnels = tunnels.filter((tunnel) => selectedTunnelSet.has(tunnel.id));
  const allTunnelsSelected = selectableTunnels.length > 0 && selectableTunnels.every((tunnel) => selectedTunnelSet.has(tunnel.id));
  const someTunnelsSelected = selectedTunnelIds.length > 0 && !allTunnelsSelected;

  useEffect(() => {
    if (selectAllRef.current) selectAllRef.current.indeterminate = someTunnelsSelected;
  }, [someTunnelsSelected]);

  useEffect(() => {
    setSelectedTunnelIds((current) => {
      const next = current.filter((id) => tunnels.some((tunnel) => tunnel.id === id && !tunnel.deletion_pending));
      return next.length === current.length ? current : next;
    });
  }, [tunnels]);

  const toggleTunnelSelection = (tunnel: Tunnel, checked: boolean) => {
    if (tunnel.deletion_pending) return;
    setSelectedTunnelIds((current) => checked
      ? current.includes(tunnel.id) ? current : [...current, tunnel.id]
      : current.filter((id) => id !== tunnel.id));
  };

  const toggleAllTunnels = (checked: boolean) => {
    setSelectedTunnelIds(checked ? selectableTunnels.map((tunnel) => tunnel.id) : []);
  };

  const runBatchToggle = async (enabled: boolean) => {
    setBatchBusy(true);
    setBatchError(null);
    setBatchMessage(null);
    try {
      const response = await request(`/api/v1/tunnels/batch/${enabled ? "enable" : "disable"}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tunnel_ids: selectedTunnelIds }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, enabled ? "暂时无法批量启用公网服务" : "暂时无法批量停用公网服务"));
      const result = body as BatchTunnelResponse;
      setBatchMessage(result.message);
      setSelectedTunnelIds(enabled ? result.skipped.map((item) => item.id) : []);
      await onRefresh();
    } catch (requestError) {
      setBatchError(requestError instanceof Error ? requestError.message : "暂时无法批量更新公网服务");
    } finally {
      setBatchBusy(false);
    }
  };

  const handleBatchDeviceUpdated = async (result: BatchTunnelResponse) => {
    setBatchDeviceDialog(false);
    setBatchDeviceTrigger(null);
    setBatchMessage(result.message);
    setSelectedTunnelIds([]);
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("#tunnel-list-heading")?.focus();
    }));
    await onRefresh();
  };

  const handleBatchDeleted = async (result: BatchTunnelDeleteResponse) => {
    setBatchDeleteDialog(false);
    setBatchDeleteTrigger(null);
    setBatchMessage(result.message);
    setSelectedTunnelIds([]);
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("#tunnel-list-heading")?.focus();
    }));
    await onRefresh();
  };

  const primaryDomain = publicDomains.find((domain) => domain.is_primary);
  const publicDomainReady = Boolean(primaryDomain && publicDomainStatus(primaryDomain.apply_status).kind === "ready");

  return (
    <>
      <PageHeader
        eyebrow="网络"
        title="公网服务"
        subtitle="将设备上的 Web 服务或 TCP 端口安全开放到公网。"
        action={<button className="primary-button" type="button" onClick={onOpenCreate}><Plus size={16} aria-hidden="true" />添加服务</button>}
      />
      <PageError error={error} onRetry={onRefresh} />
      <section className={`domain-dependency-notice ${publicDomainReady ? "ready" : "warning"}`}>
        <div><strong>{publicDomainReady ? `Web 服务默认使用 ${primaryDomain?.domain}` : "Web 服务域名尚未就绪"}</strong><span>{publicDomainReady ? "域名证书与路由由系统统一管理。" : "TCP 服务不受影响；创建或启用 Web 服务前需要可用的主域名。"}</span></div>
        {auth.role === "system_admin" && <a className="secondary-button compact-button" href="#/network/settings/domains">管理域名</a>}
      </section>
      <section className="panel page-panel">
        <div className="panel-heading tunnel-panel-heading">
          <div><p className="eyebrow">公网服务</p><h2 id="tunnel-list-heading" tabIndex={-1}>{tunnels.length} 个公网服务</h2></div>
          {selectedTunnelIds.length > 0 && <div className="batch-toolbar" role="toolbar" aria-label="公网服务批量操作">
            <span className="batch-selection-count">已选 {selectedTunnelIds.length} 项</span>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={() => void runBatchToggle(true)}><Power size={15} aria-hidden="true" />启用</button>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={() => void runBatchToggle(false)}><PowerOff size={15} aria-hidden="true" />停用</button>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={(event) => { setBatchDeviceTrigger(event.currentTarget); setBatchDeviceDialog(true); }}><RefreshCw size={15} aria-hidden="true" />更换设备</button>
            <button className="danger-button compact-button" type="button" disabled={batchBusy} onClick={(event) => { setBatchDeleteTrigger(event.currentTarget); setBatchDeleteDialog(true); }}><Trash2 size={15} aria-hidden="true" />删除</button>
          </div>}
        </div>
        {(batchMessage || batchError) && <p className={batchError ? "network-error batch-feedback" : "action-status batch-feedback"} role={batchError ? "alert" : "status"}>{batchError ?? batchMessage}</p>}
        {tunnels.length === 0 ? (
          <EmptyState icon={Globe2} title="还没有公网服务" detail="添加 Web 服务或 TCP 端口后，配置生效状态会显示在这里。" />
        ) : (
          <div className="tunnel-list">
            <div className="tunnel-list-header">
              <label className="selection-control"><input ref={selectAllRef} type="checkbox" checked={allTunnelsSelected} onChange={(event) => toggleAllTunnels(event.target.checked)} aria-label="全选公网服务" disabled={selectableTunnels.length === 0} /><span>全选</span></label>
              <span>{selectedTunnelIds.length ? `已选择 ${selectedTunnelIds.length} 项` : "选择服务后可批量操作"}</span>
            </div>
            {tunnels.map((tunnel) => (
              <TunnelRow
                key={tunnel.id}
                tunnel={tunnel}
                request={request}
                onChanged={onTunnelChanged}
                onEdit={(trigger) => onEdit(tunnel, trigger)}
                onDelete={(trigger) => onDeleteTunnel(tunnel, trigger)}
                selected={selectedTunnelSet.has(tunnel.id)}
                onSelect={(checked) => toggleTunnelSelection(tunnel, checked)}
              />
            ))}
          </div>
        )}
      </section>
      {showCreate && (
        <FormDialog eyebrow="公网服务" confirmDiscard title="添加服务" description="选择设备和本地服务，将 Web 服务或 TCP 端口开放到公网。" onClose={onCloseCreate} variant="sheet">
          <CreateTunnelForm auth={auth} devices={devices} publicDomains={publicDomains} request={request} onDomainsChanged={onRefresh} onCancel={onCloseCreate} onCreated={async () => { onCloseCreate(); await onRefresh(); }} />
        </FormDialog>
      )}
      {batchDeviceDialog && (
        <BatchTunnelDeviceDialog
          tunnels={selectedTunnels}
          devices={devices}
          request={request}
          returnFocus={batchDeviceTrigger}
          onUpdated={(result) => void handleBatchDeviceUpdated(result)}
          onClose={() => { setBatchDeviceDialog(false); setBatchDeviceTrigger(null); }}
        />
      )}
      {batchDeleteDialog && (
        <BatchTunnelDeleteDialog
          tunnels={selectedTunnels}
          request={request}
          returnFocus={batchDeleteTrigger}
          onDeleted={(result) => void handleBatchDeleted(result)}
          onClose={() => { setBatchDeleteDialog(false); setBatchDeleteTrigger(null); }}
        />
      )}
    </>
  );
}

function formatDomainTimestamp(timestamp: number | null, empty = "未签发") {
  if (!timestamp) return empty;
  return `${new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(new Date(timestamp * 1000))} 北京时间`;
}

function publicDomainStatus(status: string): { kind: "ready" | "error" | "working"; label: string } {
  switch (status.toLowerCase()) {
    case "ready": return { kind: "ready", label: "正常" };
    case "error": return { kind: "error", label: "需要处理" };
    case "rate_limited": return { kind: "working", label: "CA 限流" };
    case "retrying": return { kind: "working", label: "自动重试中" };
    case "expired": return { kind: "error", label: "已过期" };
    case "checking": return { kind: "working", label: "检测中" };
    case "configuring": return { kind: "working", label: "配置应用中" };
    default: return { kind: "working", label: "等待证书" };
  }
}

function certificateStatusLabel(status: string): string {
  switch (status.toLowerCase()) {
    case "ready": return "正常";
    case "error": return "失败";
    case "rate_limited": return "CA 限流";
    case "expired": return "已过期";
    case "pending": return "等待签发";
    default: return "检测中";
  }
}

function dnsCheckLabel(check: { resolved?: string[]; error?: string } | undefined): { kind: "ready" | "error" | "working"; label: string } {
  if (check?.resolved?.length) return { kind: "ready", label: `${check.resolved.length} 条记录` };
  if (check?.error) return { kind: "error", label: "未解析" };
  return { kind: "working", label: "未检测" };
}

function dnsManagementLabel(management: DnsManagement): { kind: "ready" | "error" | "working"; label: string } {
  if (!management.enabled) return { kind: "working", label: "未接管" };
  switch (management.status) {
    case "ready": return { kind: "ready", label: "已同步" };
    case "drifted": return { kind: "error", label: "检测到漂移" };
    case "conflict": return { kind: "error", label: "等待确认冲突" };
    case "error": return { kind: "error", label: "同步失败" };
    case "previewed": return { kind: "working", label: "等待确认" };
    default: return { kind: "working", label: "待同步" };
  }
}

function CertificateCell({
  label,
  certificate,
  automatic,
}: {
  label: string;
  certificate: CertificateStatus;
  automatic: boolean;
}) {
  const state = publicDomainStatus(certificate.status);
  const phases = [
    ["waiting_configuration", "等待配置"],
    ["presenting_dns", "创建 DNS-01"],
    ["waiting_dns", "等待 DNS"],
    ["validating", "CA 校验"],
    ["issued", "已签发"],
    ["active", "已启用"],
  ] as const;
  const currentStage = certificate.progress?.stage ?? "waiting_configuration";
  const activeIndex = phases.findIndex(([stage]) => stage === currentStage);
  const phaseIndex = activeIndex >= 0 ? activeIndex : 0;
  const stageLabel = currentStage === "retry_wait" ? "等待自动重试" : currentStage === "failed" ? "需要修复配置" : phases[phaseIndex][1];
  return (
    <div className="domain-certificate-cell" aria-live="polite" aria-atomic="true">
      <div className="domain-certificate-heading">
        <span>{label}</span>
        <span className={`status-pill ${state.kind}`}><i />{certificateStatusLabel(certificate.status)}</span>
      </div>
      <strong className="certificate-stage-label">{stageLabel}</strong>
      <ol className="certificate-stage-track" aria-label={`${label}申请进度`}>
        {phases.map(([stage, phaseLabel], index) => <li key={stage} className={index < phaseIndex ? "complete" : index === phaseIndex ? "current" : ""} aria-current={index === phaseIndex ? "step" : undefined}><i /><span>{phaseLabel}</span></li>)}
      </ol>
      <small>SAN</small>
      <strong className="certificate-subjects">{certificate.subjects.length ? certificate.subjects.join("、") : "等待证书签发"}</strong>
      <small>签发时间</small>
      <strong>{formatDomainTimestamp(certificate.not_before)}</strong>
      <small>到期时间</small>
      <strong>{formatDomainTimestamp(certificate.not_after)}</strong>
      <small>{certificate.renewal_at
        ? `下一次续期时间（预计进入自动续期窗口）：${formatDomainTimestamp(certificate.renewal_at)}`
        : automatic
          ? "证书签发后由系统计算下一次续期时间"
          : "手动证书不会自动续期"}</small>
      <small>最近尝试：{formatDomainTimestamp(certificate.progress?.last_event_at ?? null, "暂无事件")} · {certificate.progress?.attempt_count ?? 0} 次</small>
      {certificate.progress?.next_retry_at && <small>下次自动重试：{formatDomainTimestamp(certificate.progress.next_retry_at)}</small>}
      {certificate.progress?.error_message && <details className="certificate-error"><summary>查看错误与处理建议</summary><p>{certificate.progress.error_message}</p><p>检查 Cloudflare Zone DNS 编辑权限、DNS only 设置及 DNS 传播；修复后系统会继续处理。</p></details>}
    </div>
  );
}

// 行内菜单项打开弹窗前先收起菜单，并把焦点回归点固定到仍可见的菜单触发器。
function closeDomainActionMenu(button: HTMLButtonElement): HTMLElement {
  const menu = button.closest("details");
  const trigger = menu?.querySelector<HTMLElement>("summary") ?? button;
  menu?.removeAttribute("open");
  return trigger;
}

function PublicDomainsPanel({
  domains,
  request,
  onRefresh,
}: {
  domains: PublicDomain[];
  request: ApiRequest;
  onRefresh: () => Promise<void>;
}) {
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchMessage, setBatchMessage] = useState<string | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [usageFilter, setUsageFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editorDomain, setEditorDomain] = useState<PublicDomain | null | undefined>(undefined);
  const [editorTrigger, setEditorTrigger] = useState<HTMLElement | null>(null);
  const [deletingDomain, setDeletingDomain] = useState<PublicDomain | null>(null);
  const [deleteTrigger, setDeleteTrigger] = useState<HTMLElement | null>(null);
  const [primaryDomain, setPrimaryDomain] = useState<PublicDomain | null>(null);
  const [primaryTrigger, setPrimaryTrigger] = useState<HTMLElement | null>(null);
  const [dnsDomains, setDnsDomains] = useState<PublicDomain[] | null>(null);
  const [dnsTrigger, setDnsTrigger] = useState<HTMLElement | null>(null);
  const [logDomain, setLogDomain] = useState<PublicDomain | null | undefined>(undefined);
  const [logTrigger, setLogTrigger] = useState<HTMLButtonElement | null>(null);
  const selectAllRef = useRef<HTMLInputElement>(null);
  const selectedSet = new Set(selectedIds);
  const allSelected = domains.length > 0 && domains.every((domain) => selectedSet.has(domain.id));
  const someSelected = selectedIds.length > 0 && !allSelected;
  const filteredDomains = domains.filter((domain) => {
    const state = publicDomainStatus(domain.apply_status);
    return domain.domain.toLowerCase().includes(search.trim().toLowerCase())
      && (statusFilter === "all" || state.kind === statusFilter)
      && (sourceFilter === "all" || domain.certificate_mode === sourceFilter)
      && (usageFilter === "all" || (usageFilter === "web" ? domain.usage_count > 0 : domain.is_primary));
  });
  const readyCount = domains.filter((domain) => publicDomainStatus(domain.apply_status).kind === "ready").length;
  const issueCount = domains.filter((domain) => publicDomainStatus(domain.apply_status).kind === "error").length;
  const workingCount = Math.max(0, domains.length - readyCount - issueCount);

  useEffect(() => {
    if (selectAllRef.current) selectAllRef.current.indeterminate = someSelected;
  }, [someSelected]);

  useEffect(() => {
    setSelectedIds((current) => {
      const next = current.filter((id) => domains.some((domain) => domain.id === id));
      return next.length === current.length ? current : next;
    });
  }, [domains]);

  const runBatch = async (action: "recheck" | "renew", targetIds = selectedIds, preserveSelection = false) => {
    setBatchBusy(true);
    setBatchError(null);
    setBatchMessage(null);
    try {
      const response = await request(`/api/v1/public-domains/batch/${action}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ids: targetIds }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, action === "recheck" ? "暂时无法批量检测域名" : "暂时无法批量申请证书"));
      const result = body as { message: string; skipped?: BatchSkippedItem[] };
      const skipped = result.skipped ?? [];
      setBatchMessage(skipped.length ? `${result.message}；${skipped.length} 项未执行：${skipped.map((item) => item.reason).join("；")}` : result.message);
      if (!preserveSelection) setSelectedIds(skipped.map((item) => item.id));
      await onRefresh();
    } catch (requestError) {
      setBatchError(requestError instanceof Error ? requestError.message : "批量操作失败");
    } finally {
      setBatchBusy(false);
    }
  };

  const runSingle = async (domain: PublicDomain, action: "recheck" | "renew") => {
    setBatchBusy(true);
    setBatchError(null);
    setBatchMessage(null);
    try {
      const response = await request(`/api/v1/public-domains/${encodeURIComponent(domain.id)}/${action}`, { method: "POST" });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, action === "recheck" ? "暂时无法检测域名" : "暂时无法申请证书"));
      setBatchMessage(action === "recheck" ? `已重新检测 ${domain.domain}` : `已提交 ${domain.domain} 的自动证书申请；限流时系统会按计划重试`);
      await onRefresh();
    } catch (requestError) {
      setBatchError(requestError instanceof Error ? requestError.message : "域名操作失败");
    } finally {
      setBatchBusy(false);
    }
  };

  const handleEditorSaved = async () => {
    setEditorDomain(undefined);
    setEditorTrigger(null);
    await onRefresh();
  };

  return (
    <section className="panel page-panel domains-panel">
      <div className="panel-heading domains-panel-heading">
        <div>
          <p className="eyebrow">域名资源</p>
          <h2 id="public-domain-list-heading" tabIndex={-1}>{domains.length ? `${domains.length} 个域名` : "还没有域名"}</h2>
        </div>
        <div className="panel-heading-actions domains-heading-actions">
          {selectedIds.length > 0 && <div className="batch-toolbar" role="toolbar" aria-label="公网域名批量操作">
            <span className="batch-selection-count">已选 {selectedIds.length} 项</span>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={() => void runBatch("recheck")}><RefreshCw size={15} aria-hidden="true" />重新检测</button>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={() => void runBatch("renew")}><ShieldCheck size={15} aria-hidden="true" />申请证书</button>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy || !domains.some((domain) => selectedSet.has(domain.id) && domain.dns_management.enabled)} onClick={(event) => { setDnsTrigger(event.currentTarget); setDnsDomains(domains.filter((domain) => selectedSet.has(domain.id) && domain.dns_management.enabled)); }}><Globe2 size={15} aria-hidden="true" />同步 DNS</button>
          </div>}
          <button className="secondary-button" type="button" disabled={batchBusy || domains.length === 0} onClick={() => void runBatch("recheck", domains.map((domain) => domain.id), true)}><RefreshCw size={16} aria-hidden="true" />重新检测</button>
          <button className="secondary-button" type="button" onClick={(event) => { setLogTrigger(event.currentTarget); setLogDomain(null); }}><ScrollText size={16} aria-hidden="true" />运行日志</button>
          <button className="primary-button" type="button" onClick={(event) => { setEditorTrigger(event.currentTarget); setEditorDomain(null); }}><Plus size={16} aria-hidden="true" />添加域名</button>
        </div>
      </div>
      <div className="domain-summary-strip" aria-label="域名状态摘要">
        <button type="button" className={statusFilter === "all" ? "active" : ""} onClick={() => setStatusFilter("all")}>全部 <strong>{domains.length}</strong></button>
        <button type="button" className={statusFilter === "ready" ? "active" : ""} onClick={() => setStatusFilter("ready")}>正常 <strong>{readyCount}</strong></button>
        <button type="button" className={statusFilter === "working" ? "active" : ""} onClick={() => setStatusFilter("working")}>处理中 <strong>{workingCount}</strong></button>
        <button type="button" className={statusFilter === "error" ? "active" : ""} onClick={() => setStatusFilter("error")}>需处理 <strong>{issueCount}</strong></button>
      </div>
      <div className="domain-filter-bar">
        <label className="domain-search"><Search size={15} aria-hidden="true" /><span className="sr-only">搜索域名</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索域名" /></label>
        <label><span className="sr-only">证书来源</span><select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}><option value="all">全部证书来源</option><option value="cloudflare">自动证书</option><option value="manual">手动证书</option></select></label>
        <label><span className="sr-only">用途</span><select value={usageFilter} onChange={(event) => setUsageFilter(event.target.value)}><option value="all">全部用途</option><option value="web">Web 穿透</option><option value="entry">系统与网络入口</option></select></label>
      </div>
      {(batchMessage || batchError) && <p className={batchError ? "network-error batch-feedback" : "action-status batch-feedback"} role={batchError ? "alert" : "status"}>{batchError ?? batchMessage}</p>}
      {domains.length === 0 ? (
        <EmptyState icon={Globe2} title="还没有公网域名" detail="添加根域名后，可以配置系统入口、组网入口和 Web 服务。" />
      ) : (
        <div className="domain-table" role="table" aria-label="域名与 HTTPS 列表">
          <div className="domain-table-head" role="row">
            <span role="columnheader"><input ref={selectAllRef} type="checkbox" checked={allSelected} onChange={(event) => setSelectedIds(event.target.checked ? domains.map((domain) => domain.id) : [])} aria-label="全选公网域名" /></span>
            <span role="columnheader">域名与用途</span><span role="columnheader">证书</span><span role="columnheader">综合状态</span><span role="columnheader">有效期</span><span role="columnheader">操作</span>
          </div>
          {filteredDomains.map((domain) => {
            const state = publicDomainStatus(domain.apply_status);
            const rootDns = dnsCheckLabel(domain.dns_check.root);
            const wildcardDns = dnsCheckLabel(domain.dns_check.wildcard);
            const rateLimited = domain.apply_status.toLowerCase() === "rate_limited" || domain.error_code === "acme_rate_limited";
            const expiresAt = [domain.root_certificate.not_after, domain.wildcard_certificate.not_after].filter((value): value is number => Boolean(value)).sort((a, b) => a - b)[0] ?? null;
            const expanded = expandedId === domain.id;
            const sourceLabel = domain.certificate_mode === "cloudflare" ? "自动证书" : "手动证书";
            return (
              <div className={`domain-table-item${expanded ? " expanded" : ""}`} key={domain.id} role="rowgroup">
                <div className="domain-table-row" role="row">
                  <span role="cell"><input type="checkbox" checked={selectedSet.has(domain.id)} onChange={(event) => setSelectedIds((current) => event.target.checked ? (current.includes(domain.id) ? current : [...current, domain.id]) : current.filter((id) => id !== domain.id))} aria-label={`选择 ${domain.domain}`} /></span>
                  <div className="domain-identity" role="cell"><div className="domain-title"><strong>{domain.domain}</strong>{domain.is_primary && <span className="domain-primary-badge">主域名</span>}</div><span>{domain.usage_count} 个 Web 服务{domain.is_primary ? " · 组网入口" : ""}</span></div>
                  <div className="domain-certificate-summary" role="cell"><strong>{sourceLabel}</strong><span>{domain.certificate_mode === "cloudflare" ? "DNS-01 自动申请与续期" : "自动申请已停止"}</span></div>
                  <div className="domain-combined-status" role="cell">
                    <strong className={`status-pill ${state.kind}`}><i />{state.label}</strong>
                    <span>根 DNS {rootDns.label} · 泛 DNS {wildcardDns.label} · HTTPS {domain.https_enabled && expiresAt ? "正常" : "待配置"}{domain.is_primary ? ` · Nexo ${expiresAt ? "可用" : "待配置"} · Mesh ${wildcardDns.kind === "ready" && expiresAt ? "可用" : "异常"}` : ""}</span>
                  </div>
                  <div className="domain-validity" role="cell"><strong>{formatDomainTimestamp(expiresAt, "未签发")}</strong><span>{domain.certificate_mode === "cloudflare" ? `预计续期 ${formatDomainTimestamp(domain.root_certificate.renewal_at, "待计算")}` : "到期后不会自动续期"}</span></div>
                  <div className="domain-compact-actions" role="cell">
                    <button className="secondary-button compact-button" type="button" disabled={batchBusy || (rateLimited && domain.certificate_mode === "cloudflare")} onClick={(event) => { if (state.kind === "error" || domain.certificate_mode === "manual") { setEditorTrigger(event.currentTarget); setEditorDomain(domain); } else { setExpandedId(expanded ? null : domain.id); } }}>{state.kind === "error" ? "修复问题" : domain.certificate_mode === "manual" ? "更新证书" : "查看进度"}</button>
                    <button className="icon-button compact-icon-button" type="button" title="运行日志" aria-label={`查看 ${domain.domain} 运行日志`} onClick={(event) => { setLogTrigger(event.currentTarget); setLogDomain(domain); }}><ScrollText size={16} aria-hidden="true" /></button>
                    <details className="domain-action-menu" name="domain-actions"><summary aria-label={`更多 ${domain.domain} 操作`} title="更多操作"><MoreHorizontal size={18} aria-hidden="true" /></summary><div>
                      <button type="button" onClick={(event) => { setEditorTrigger(closeDomainActionMenu(event.currentTarget)); setEditorDomain(domain); }}>编辑设置</button>
                      <button type="button" onClick={(event) => { closeDomainActionMenu(event.currentTarget); void runSingle(domain, "recheck"); }}>重新检测</button>
                      {domain.certificate_mode === "cloudflare" && <button type="button" disabled={rateLimited} onClick={(event) => { closeDomainActionMenu(event.currentTarget); void runSingle(domain, "renew"); }}>申请自动证书</button>}
                      {domain.dns_management.enabled && <button type="button" onClick={(event) => { setDnsTrigger(closeDomainActionMenu(event.currentTarget)); setDnsDomains([domain]); }}>同步 DNS</button>}
                      {!domain.is_primary && <button type="button" onClick={(event) => { setPrimaryTrigger(closeDomainActionMenu(event.currentTarget)); setPrimaryDomain(domain); }}>设为主域名</button>}
                      <button className="danger-menu-item" type="button" onClick={(event) => { setDeleteTrigger(closeDomainActionMenu(event.currentTarget)); setDeletingDomain(domain); }}>删除域名</button>
                    </div></details>
                    <button className="icon-button compact-icon-button" type="button" aria-expanded={expanded} aria-label={`${expanded ? "收起" : "展开"} ${domain.domain} 详情`} onClick={() => setExpandedId(expanded ? null : domain.id)}><ChevronDown className={expanded ? "rotated" : ""} size={17} aria-hidden="true" /></button>
                  </div>
                </div>
                {expanded && <div className="domain-expanded" role="row"><div role="cell" className="domain-expanded-grid">
                  {(domain.apply_error || domain.dns_management.error) && <div className="domain-expanded-problem"><strong>当前问题</strong><p>{domain.apply_error ?? domain.dns_management.error}</p>{rateLimited && <span>系统将在 {formatDomainTimestamp(domain.next_retry_at ?? domain.retry_after, "稍后")} 自动重试。</span>}</div>}
                  <div><span>DNS</span><strong>@ {rootDns.label} · * {wildcardDns.label}</strong><small>{domain.dns_management.enabled ? `自动管理 · ${[domain.dns_management.target_ipv4, domain.dns_management.target_ipv6].filter(Boolean).join(" · ")}` : "外部管理"}</small>{domain.is_primary && <><span>服务入口</span><small>管理入口：{domain.management_entry ?? `https://nexo.${domain.domain}`}</small><small>Mesh 入口：{domain.mesh_entry ?? `https://mesh.${domain.domain}`}</small></>}</div>
                  <CertificateCell label="根证书" certificate={domain.root_certificate} automatic={domain.certificate_mode === "cloudflare"} />
                  <CertificateCell label="泛域名证书" certificate={domain.wildcard_certificate} automatic={domain.certificate_mode === "cloudflare"} />
                </div></div>}
              </div>
            );
          })}
          {filteredDomains.length === 0 && <p className="domain-no-results">没有符合筛选条件的域名</p>}
        </div>
      )}
      {editorDomain !== undefined && <FormDialog eyebrow="域名与 HTTPS" title={editorDomain ? `编辑 ${editorDomain.domain}` : "添加公网域名"} description="配置域名、证书来源和可选的 DNS 自动管理。" onClose={() => { setEditorDomain(undefined); setEditorTrigger(null); }} returnFocus={editorTrigger} variant="sheet"><PublicDomainEditor domain={editorDomain} request={request} onCancel={() => { setEditorDomain(undefined); setEditorTrigger(null); }} onSaved={handleEditorSaved} /></FormDialog>}
      {deletingDomain && <PublicDomainDeleteDialog domain={deletingDomain} domains={domains} request={request} returnFocus={deleteTrigger} onDeleted={async () => { setDeletingDomain(null); setDeleteTrigger(null); await onRefresh(); }} onClose={() => { setDeletingDomain(null); setDeleteTrigger(null); }} />}
      {primaryDomain && <PublicDomainPrimaryDialog domain={primaryDomain} request={request} returnFocus={primaryTrigger} onStarted={onRefresh} onClose={() => { setPrimaryDomain(null); setPrimaryTrigger(null); }} />}
      {dnsDomains && <ManagedDnsDialog domains={dnsDomains} request={request} returnFocus={dnsTrigger} onApplied={async () => { setDnsDomains(null); setDnsTrigger(null); await onRefresh(); }} onClose={() => { setDnsDomains(null); setDnsTrigger(null); }} />}
      {logDomain !== undefined && <RuntimeLogDialog domain={logDomain} domains={domains} request={request} returnFocus={logTrigger} onClose={() => { setLogDomain(undefined); setLogTrigger(null); }} />}
    </section>
  );
}

const runtimeCategoryLabels: Record<string, string> = {
  configuration: "配置应用",
  automatic_certificate: "自动证书",
  manual_certificate: "手动证书",
  dns_validation: "DNS 校验",
  certificate_storage: "证书加载",
  https: "HTTPS",
  reverse_proxy: "反向代理",
  service_runtime: "服务运行",
};

function runtimeLevelLabel(level: string): string {
  switch (level.toLowerCase()) {
    case "error": return "错误";
    case "warning": return "警告";
    case "debug": return "调试";
    default: return "信息";
  }
}

/**
 * 运行日志使用独立模态承载排障时间线。后台轮询只缓存新事件数量，避免用户
 * 阅读历史详情时被插入内容推走；由用户主动合并后才更新列表和滚动位置。
 */
function RuntimeLogDialog({
  domain,
  domains,
  request,
  returnFocus,
  onClose,
}: {
  domain: PublicDomain | null;
  domains: PublicDomain[];
  request: ApiRequest;
  returnFocus: HTMLElement | null;
  onClose: () => void;
}) {
  const [events, setEvents] = useState<RuntimeEvent[]>([]);
  const eventsRef = useRef<RuntimeEvent[]>([]);
  const [pendingEvents, setPendingEvents] = useState<RuntimeEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<number | null>(null);
  const [domainFilter, setDomainFilter] = useState(domain?.id ?? "all");
  const [level, setLevel] = useState("all");
  const [category, setCategory] = useState("all");
  const [range, setRange] = useState("24h");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);

  useEffect(() => { eventsRef.current = events; }, [events]);

  const queryString = (cursor?: number | null) => {
    const params = new URLSearchParams({ limit: "100" });
    if (domainFilter !== "all") params.set("public_domain_id", domainFilter);
    if (level !== "all") params.set("level", level);
    if (category !== "all") params.set("category", category);
    if (search.trim()) params.set("search", search.trim());
    const seconds = range === "1h" ? 3600 : range === "24h" ? 86400 : 604800;
    params.set("since", String(Math.floor(Date.now() / 1000) - seconds));
    if (cursor) params.set("cursor", String(cursor));
    return params.toString();
  };

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      setError(null);
      setPendingEvents([]);
      try {
        const response = await request(`/api/v1/public-domain-runtime-events?${queryString()}`);
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, "暂时无法读取域名服务运行日志"));
        if (active) {
          const page = body as RuntimeEventPage;
          setEvents(page.events);
          setNextCursor(page.next_cursor);
        }
      } catch (requestError) {
        if (active) setError(requestError instanceof Error ? requestError.message : "暂时无法读取域名服务运行日志");
      } finally {
        if (active) setLoading(false);
      }
    }, 180);
    return () => { active = false; window.clearTimeout(timer); };
  }, [category, domainFilter, level, range, request, search]);

  useEffect(() => {
    let active = true;
    const timer = window.setInterval(async () => {
      const response = await request(`/api/v1/public-domain-runtime-events?${queryString()}`);
      const body: unknown = await response.json().catch(() => null);
      if (!active || !response.ok) return;
      const known = new Set(eventsRef.current.map((event) => event.id));
      setPendingEvents((current) => {
        const currentIds = new Set(current.map((event) => event.id));
        return [...(body as RuntimeEventPage).events.filter((event) => !known.has(event.id) && !currentIds.has(event.id)), ...current];
      });
    }, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [category, domainFilter, level, range, request, search]);

  const mergePending = () => {
    setEvents((current) => {
      const ids = new Set(current.map((event) => event.id));
      return [...pendingEvents.filter((event) => !ids.has(event.id)), ...current];
    });
    setPendingEvents([]);
  };

  const loadMore = async () => {
    if (!nextCursor) return;
    setLoadingMore(true);
    setError(null);
    try {
      const response = await request(`/api/v1/public-domain-runtime-events?${queryString(nextCursor)}`);
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法加载更多运行日志"));
      const page = body as RuntimeEventPage;
      setEvents((current) => [...current, ...page.events]);
      setNextCursor(page.next_cursor);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法加载更多运行日志");
    } finally {
      setLoadingMore(false);
    }
  };

  const copyVisible = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(events, null, 2));
      setCopyStatus(`已复制 ${events.length} 条脱敏日志`);
    } catch {
      setCopyStatus("复制失败，请检查浏览器剪贴板权限");
    }
  };

  const exportEvents = async () => {
    setError(null);
    try {
      const response = await request(`/api/v1/public-domain-runtime-events/export?${queryString()}`);
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => null);
        throw new Error(readApiError(body, "暂时无法导出运行日志"));
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `domain-runtime-events-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法导出运行日志");
    }
  };

  return <FormDialog eyebrow="域名与 HTTPS" title="域名服务运行日志" description={domain ? `已筛选 ${domain.domain}，用于定位证书、DNS、HTTPS 与反向代理问题。` : "查看域名服务的配置、证书、DNS、HTTPS 与反向代理事件。"} onClose={onClose} returnFocus={returnFocus} initialFocusSelector="input[type=search]" wide>
    <div className="runtime-log-dialog">
      <div className="runtime-log-filters">
        <label className="domain-search"><Search size={15} aria-hidden="true" /><span className="sr-only">搜索运行日志</span><input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索摘要、错误代码或详情" /></label>
        <label><span className="sr-only">域名</span><select aria-label="域名" value={domainFilter} onChange={(event) => setDomainFilter(event.target.value)}><option value="all">全部域名与全局事件</option>{domains.map((item) => <option key={item.id} value={item.id}>{item.domain}</option>)}</select></label>
        <label><span className="sr-only">级别</span><select aria-label="级别" value={level} onChange={(event) => setLevel(event.target.value)}><option value="all">全部级别</option><option value="error">错误</option><option value="warning">警告</option><option value="info">信息</option><option value="debug">调试</option></select></label>
        <label><span className="sr-only">类型</span><select aria-label="类型" value={category} onChange={(event) => setCategory(event.target.value)}><option value="all">全部类型</option>{Object.entries(runtimeCategoryLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <label><span className="sr-only">时间范围</span><select aria-label="时间范围" value={range} onChange={(event) => setRange(event.target.value)}><option value="1h">最近 1 小时</option><option value="24h">最近 24 小时</option><option value="7d">最近 7 天</option></select></label>
      </div>
      <div className="runtime-log-toolbar" role="toolbar" aria-label="运行日志操作">
        <span>{loading ? "读取中…" : `${events.length} 条事件`}</span>
        <div><button className="secondary-button compact-button" type="button" onClick={() => void copyVisible()} disabled={events.length === 0}><Copy size={15} aria-hidden="true" />复制</button><button className="secondary-button compact-button" type="button" onClick={() => void exportEvents()}><Download size={15} aria-hidden="true" />导出</button></div>
      </div>
      {pendingEvents.length > 0 && <button className="runtime-log-new" type="button" onClick={mergePending}>有 {pendingEvents.length} 条新日志</button>}
      {copyStatus && <p className="runtime-log-feedback" role="status">{copyStatus}</p>}
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="runtime-log-list" aria-live="polite" aria-busy={loading}>
        {!loading && events.length === 0 && <EmptyState icon={ScrollText} title="当前筛选范围没有日志" detail="更改筛选条件，或稍后刷新查看新的运行事件。" />}
        {events.map((event) => <article className={`runtime-log-event ${event.level.toLowerCase()}`} key={event.id}>
          <div className="runtime-log-event-main"><time dateTime={new Date(event.occurred_at * 1000).toISOString()}>{formatDomainTimestamp(event.occurred_at)}</time><span className={`runtime-log-level ${event.level.toLowerCase()}`}>{runtimeLevelLabel(event.level)}</span><strong>{runtimeCategoryLabels[event.category] ?? "服务运行"}</strong><span>{event.domain ?? "全局"}</span></div>
          <p>{event.summary}</p>
          {(event.error_code || event.retry_at || event.technical_detail) && <details><summary>查看技术详情</summary>{event.error_code && <p>错误代码：{event.error_code}</p>}{event.retry_at && <p>下次重试：{formatDomainTimestamp(event.retry_at)}</p>}{event.technical_detail && <pre>{event.technical_detail}</pre>}</details>}
        </article>)}
      </div>
      {nextCursor && <button className="secondary-button runtime-log-more" type="button" onClick={() => void loadMore()} disabled={loadingMore}>{loadingMore ? "加载中…" : "加载更早日志"}</button>}
    </div>
  </FormDialog>;
}

function PublicDomainEditor({
  domain: existing,
  request,
  onCancel,
  onSaved,
}: {
  domain: PublicDomain | null;
  request: ApiRequest;
  onCancel: () => void;
  onSaved: () => Promise<void>;
}) {
  const [domain, setDomain] = useState(existing?.domain ?? "");
  const [httpsEnabled, setHttpsEnabled] = useState(existing?.https_enabled ?? true);
  const [certificateMode, setCertificateMode] = useState(existing?.certificate_mode ?? "cloudflare");
  const [dnsManagementEnabled, setDnsManagementEnabled] = useState(existing?.dns_management.enabled ?? false);
  const [dnsTargetIpv4, setDnsTargetIpv4] = useState(existing?.dns_management.target_ipv4 ?? "");
  const [dnsTargetIpv6, setDnsTargetIpv6] = useState(existing?.dns_management.target_ipv6 ?? "");
  const [deleteManagedRecords, setDeleteManagedRecords] = useState(false);
  const [cloudflareToken, setCloudflareToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [certificateFile, setCertificateFile] = useState<File | null>(null);
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const manualCertificatePresent = Boolean(existing?.certificate_mode === "manual"
    && (existing.root_certificate.subjects.length || existing.wildcard_certificate.subjects.length));

  const save = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const normalized = domain.trim().replace(/\.+$/, "").toLowerCase();
    if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(normalized)) {
      setError("根域名格式无效，请填写例如 example.com");
      return;
    }
    if (certificateMode === "manual" && Boolean(certificateFile) !== Boolean(privateKeyFile)) {
      setError("手动证书需要同时选择证书和私钥文件");
      return;
    }
    if (httpsEnabled && certificateMode === "manual" && existing?.certificate_mode !== "manual" && (!certificateFile || !privateKeyFile)) {
      setError("切换到手动证书时，请同时选择证书和私钥文件");
      return;
    }
    if (dnsManagementEnabled && !dnsTargetIpv4.trim() && !dnsTargetIpv6.trim()) {
      setError("启用 DNS 托管时必须填写公网 IPv4 或 IPv6 地址");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const secrets: Record<string, string | boolean> = {};
      const token = cloudflareToken.trim();
      if ((dnsManagementEnabled || (httpsEnabled && certificateMode === "cloudflare")) && token) secrets.cloudflare_token = token;
      if (httpsEnabled && certificateMode === "manual" && certificateFile && privateKeyFile) {
        secrets.certificate_pem = await certificateFile.text();
        secrets.private_key_pem = await privateKeyFile.text();
        secrets.activate_manual_certificate = true;
      }
      const uploadSecrets = async (domainId: string) => {
        if (Object.keys(secrets).length === 0) return;
        const secretResponse = await request(`/api/v1/public-domains/${encodeURIComponent(domainId)}/credentials`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(secrets),
        });
        const secretBody: unknown = await secretResponse.json().catch(() => null);
        if (!secretResponse.ok) throw new Error(readApiError(secretBody, "证书或 Cloudflare Token 上传失败"));
      };

      if (existing?.dns_management.enabled && !dnsManagementEnabled && deleteManagedRecords) {
        const releaseResponse = await request(`/api/v1/public-domains/${encodeURIComponent(existing.id)}/dns/managed-records`, {
          method: "DELETE",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ delete_created_records: true }),
        });
        const releaseBody: unknown = await releaseResponse.json().catch(() => null);
        if (!releaseResponse.ok) throw new Error(readApiError(releaseBody, "无法安全删除 Nexo 创建的 DNS 记录"));
      }
      // 已有自动域名先通过原子凭据接口完成证书校验与模式切换，避免保存表单时提前停止自动维护。
      const activatedBeforeSave = Boolean(existing
        && existing.certificate_mode !== "manual"
        && certificateMode === "manual"
        && certificateFile
        && privateKeyFile);
      if (activatedBeforeSave) await uploadSecrets(existing.id);
      const response = await request(existing ? `/api/v1/public-domains/${encodeURIComponent(existing.id)}` : "/api/v1/public-domains", {
        method: existing ? "PUT" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: normalized, https_enabled: httpsEnabled, certificate_mode: httpsEnabled ? certificateMode : "cloudflare", dns_management_enabled: dnsManagementEnabled, dns_target_ipv4: dnsTargetIpv4.trim(), dns_target_ipv6: dnsTargetIpv6.trim() }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法保存公网域名"));
      const saved = body as PublicDomain;
      if (!activatedBeforeSave) await uploadSecrets(saved.id);
      setCloudflareToken("");
      setCertificateFile(null);
      setPrivateKeyFile(null);
      await onSaved();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法保存公网域名");
    } finally {
      setBusy(false);
    }
  };

  const deleteManualCertificate = async () => {
    if (!existing || !window.confirm("确定删除当前手动证书吗？删除后仍保持手动模式，自动申请不会恢复，HTTPS 将不可用直到上传新证书或明确切回自动证书。")) return;
    setBusy(true);
    setError(null);
    try {
      const response = await request(`/api/v1/public-domains/${encodeURIComponent(existing.id)}/manual-certificate`, { method: "DELETE" });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法删除手动证书"));
      await onSaved();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法删除手动证书");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="inline-form network-form-table domain-editor-form" aria-busy={busy} onSubmit={save}>
      <fieldset>
        <legend>域名</legend>
        <label><span>根域名</span><input autoFocus value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.com" inputMode="url" autoCapitalize="none" spellCheck={false} required /></label>
        <label><span>HTTPS</span><select value={httpsEnabled ? "https" : "http"} onChange={(event) => setHttpsEnabled(event.target.value === "https")}><option value="https">启用 HTTPS</option><option value="http">仅 HTTP</option></select></label>
      </fieldset>
      <fieldset>
        <legend>证书来源</legend>
        <label>
          <span>签发方式</span>
          <select value={certificateMode} onChange={(event) => setCertificateMode(event.target.value)} disabled={!httpsEnabled}>
            <option value="cloudflare">Cloudflare DNS-01 自动申请</option>
            <option value="manual">手动证书</option>
          </select>
        </label>
        {(dnsManagementEnabled || (httpsEnabled && certificateMode === "cloudflare")) && <div className="domain-secret-form-row"><label htmlFor="public-domain-cloudflare-token">Cloudflare API Token</label><div className="field-control"><div className="secret-input-control"><input id="public-domain-cloudflare-token" type={showToken ? "text" : "password"} value={cloudflareToken} onChange={(event) => setCloudflareToken(event.target.value)} placeholder="留空则保留已保存的 Token" autoComplete="off" autoCapitalize="none" spellCheck={false} /><button className="secret-visibility-button" type="button" aria-label={`${showToken ? "隐藏" : "显示"} Cloudflare API Token`} onClick={() => setShowToken((value) => !value)}>{showToken ? <EyeOff size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}</button></div><small>需要 Zone DNS 编辑权限。Token 不会写入配置、日志或页面。</small></div></div>}
        {httpsEnabled && certificateMode === "manual" && <><div className="manual-certificate-warning"><AlertTriangle size={16} aria-hidden="true" /><p><strong>启用后停止自动申请和续期</strong><span>删除或过期后也不会自动恢复，需要上传新证书或明确切回自动证书。</span></p></div><label><span>证书文件</span><input type="file" accept=".pem,.crt,text/plain" onChange={(event) => setCertificateFile(event.currentTarget.files?.[0] ?? null)} /></label><label><span>私钥文件</span><input type="file" accept=".pem,.key,text/plain" onChange={(event) => setPrivateKeyFile(event.currentTarget.files?.[0] ?? null)} /></label><p className="form-hint">支持未加密的 PKCS#1、PKCS#8 和 SEC1 私钥。证书必须覆盖根域名和 *.根域名，并与私钥匹配。</p>{manualCertificatePresent && <button className="text-danger-button" type="button" disabled={busy} onClick={() => void deleteManualCertificate()}><Trash2 size={15} aria-hidden="true" />删除当前手动证书</button>}</>}
      </fieldset>
      <fieldset>
        <legend>DNS 托管</legend>
        <label className="confirmation-check"><input type="checkbox" checked={dnsManagementEnabled} onChange={(event) => setDnsManagementEnabled(event.target.checked)} /><span>由 Nexo 自动管理 Cloudflare DNS</span></label>
        {dnsManagementEnabled && <><label><span>公网 IPv4</span><input value={dnsTargetIpv4} onChange={(event) => setDnsTargetIpv4(event.target.value)} placeholder="101.36.109.178" inputMode="decimal" autoCapitalize="none" spellCheck={false} /></label><label><span>公网 IPv6</span><input value={dnsTargetIpv6} onChange={(event) => setDnsTargetIpv6(event.target.value)} placeholder="可选" inputMode="text" autoCapitalize="none" spellCheck={false} /></label></>}
        {existing?.dns_management.enabled && !dnsManagementEnabled && <label className="confirmation-check"><input type="checkbox" checked={deleteManagedRecords} onChange={(event) => setDeleteManagedRecords(event.target.checked)} /><span>同时删除仍与最后应用内容一致、且由 Nexo 创建的记录</span></label>}
        <p className="form-hint">保存设置不会立即修改 DNS。请返回列表查看变更预览，再确认同步 @ 和 * 的 A/AAAA 记录；记录始终为 DNS only。</p>
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="dialog-actions"><button className="secondary-button" type="button" onClick={onCancel} disabled={busy}>取消</button><button className="primary-button" type="submit" disabled={busy}>{busy ? "保存中…" : existing ? "保存修改" : "添加域名"}</button></div>
    </form>
  );
}

function ManagedDnsDialog({
  domains,
  request,
  returnFocus,
  onApplied,
  onClose,
}: {
  domains: PublicDomain[];
  request: ApiRequest;
  returnFocus: HTMLElement | null;
  onApplied: () => Promise<void>;
  onClose: () => void;
}) {
  const [previews, setPreviews] = useState<ManagedDnsPreview[]>([]);
  const [loading, setLoading] = useState(true);
  const [applying, setApplying] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const loaded = await Promise.all(domains.map(async (domain) => {
          const response = await request(`/api/v1/public-domains/${encodeURIComponent(domain.id)}/dns/preview`);
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, `无法预览 ${domain.domain} 的 DNS 变更`));
          return body as ManagedDnsPreview;
        }));
        if (active) setPreviews(loaded);
      } catch (requestError) {
        if (active) setError(requestError instanceof Error ? requestError.message : "无法读取 DNS 变更预览");
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    return () => { active = false; };
  }, [domains, request]);

  const hasConflicts = previews.some((preview) => preview.has_conflicts);
  const apply = async () => {
    setApplying(true);
    setError(null);
    try {
      for (const domain of domains) {
        const response = await request(`/api/v1/public-domains/${encodeURIComponent(domain.id)}/dns/apply`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ confirm_conflicts: confirmed }),
        });
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, `无法同步 ${domain.domain} 的 DNS`));
      }
      await onApplied();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "DNS 同步失败");
    } finally {
      setApplying(false);
    }
  };

  const actionLabel = (action: string) => action === "adopt" ? "接管同值记录" : action === "create" ? "创建" : "替换冲突记录";
  return <FormDialog eyebrow="Cloudflare DNS" title={domains.length === 1 ? `同步 ${domains[0].domain}` : `同步 ${domains.length} 个域名`} description="Nexo 只处理预览中的 @ 与 * 记录，所有记录固定为 DNS only。" onClose={onClose} returnFocus={returnFocus} role={hasConflicts ? "alertdialog" : "dialog"}>
    <div className="managed-dns-preview" aria-busy={loading || applying}>
      <div className="dns-preview-status" role="status" aria-live="polite">{loading ? "正在读取 Cloudflare 当前记录…" : error ? "DNS 预览或同步失败" : `已读取 ${previews.length} 个域名的变更`}</div>
      {previews.map((preview) => <section key={preview.domain_id} className="dns-preview-domain"><h3>{preview.zone_name}</h3><div className="dns-change-list">{preview.changes.map((change) => <div className={`dns-change ${change.action}`} key={`${change.record_type}-${change.name}`}><div><strong>{change.record_type} {change.name}</strong><span>{actionLabel(change.action)}</span></div><code>{change.current_content ?? "不存在"}</code><ArrowRight size={15} aria-hidden="true" /><code>{change.desired_content}</code></div>)}</div></section>)}
      {hasConflicts && <label className="confirmation-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>我确认替换上方冲突记录；MX、TXT、CAA 等其他记录不会修改</span></label>}
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="dialog-actions"><button className="secondary-button" type="button" onClick={onClose} disabled={applying}>取消</button><button className="primary-button" type="button" onClick={() => void apply()} disabled={loading || applying || previews.length === 0 || (hasConflicts && !confirmed)}>{applying ? "同步中…" : "确认同步 DNS"}</button></div>
    </div>
  </FormDialog>;
}

function PublicDomainDeleteDialog({
  domain,
  domains,
  request,
  returnFocus,
  onDeleted,
  onClose,
}: {
  domain: PublicDomain;
  domains: PublicDomain[];
  request: ApiRequest;
  returnFocus: HTMLElement | null;
  onDeleted: () => Promise<void>;
  onClose: () => void;
}) {
  const [replacement, setReplacement] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const candidates = domains.filter((item) => item.id !== domain.id && item.apply_status.toLowerCase() === "ready");
  const deletingOnlyPrimary = domain.is_primary && domains.length === 1;
  const deletingPrimaryWithAlternatives = domain.is_primary && domains.length > 1;
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!confirmed) { setError("请确认删除影响后再继续"); return; }
    if (deletingPrimaryWithAlternatives) { setError("存在其他域名时，请先将一个已就绪域名设为主域名"); return; }
    if (!deletingOnlyPrimary && domain.usage_count > 0 && !replacement) { setError("该域名仍被服务使用，请先选择状态正常的替代域名"); return; }
    setBusy(true); setError(null);
    try {
      const response = await request(`/api/v1/public-domains/${encodeURIComponent(domain.id)}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(deletingOnlyPrimary
          ? { disable_public_access: true }
          : domain.usage_count > 0 ? { replacement_domain_id: replacement } : {}),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法删除公网域名"));
      await onDeleted();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法删除公网域名");
    } finally { setBusy(false); }
  };
  const description = deletingOnlyPrimary
    ? "删除唯一主域名会关闭公网域名入口，但保留公网服务配置和启用状态。"
    : "删除会清理该域名的凭据目录；已绑定服务必须先迁移到另一个已就绪域名。";
  return <FormDialog eyebrow="域名与 HTTPS" title={`删除 ${domain.domain}`} description={description} onClose={onClose} returnFocus={returnFocus} role="alertdialog" compact initialFocusSelector="input[type=checkbox]"><form className="domain-delete-form" aria-busy={busy} onSubmit={submit}>{deletingOnlyPrimary ? <div className="domain-delete-impact"><strong>将关闭以下公网能力</strong><p>Nexo 管理入口、组网入口和全部 Web 服务公网路由会停止生成。</p><p>{domain.usage_count} 个 Web 服务会保留并解除域名绑定；添加新的首个主域名后，未显式绑定的服务会重新使用它。</p><p>Cloudflare DNS 默认保留，组网入口回退到内部地址，设备不会被自动要求重新认证。</p></div> : <p>{deletingPrimaryWithAlternatives ? "请先从更多操作中把一个已就绪域名设为主域名。未完成的主域名迁移仍会阻止删除。" : "此操作不可撤销。未完成的主域名迁移仍会阻止删除。"}</p>}{!deletingOnlyPrimary && domain.usage_count > 0 && <label><span>替代域名</span><select value={replacement} onChange={(event) => setReplacement(event.target.value)}><option value="">选择已就绪的域名</option>{candidates.map((item) => <option key={item.id} value={item.id}>{item.domain}</option>)}</select></label>}<label className="confirmation-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>{deletingOnlyPrimary ? "我确认关闭公网域名入口并删除该域名及凭据" : "我确认删除该域名及其凭据"}</span></label>{error && <p className="form-error" role="alert">{error}</p>}<div className="dialog-actions"><button className="secondary-button" type="button" onClick={onClose} disabled={busy}>取消</button><button className="danger-button" type="submit" disabled={busy || deletingPrimaryWithAlternatives}>{busy ? "删除中…" : "确认删除"}</button></div></form></FormDialog>;
}

function PublicDomainPrimaryDialog({
  domain,
  request,
  returnFocus,
  onStarted,
  onClose,
}: {
  domain: PublicDomain;
  request: ApiRequest;
  returnFocus: HTMLElement | null;
  onStarted: () => Promise<void>;
  onClose: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const [migration, setMigration] = useState<PublicDomainMigration | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const active = Boolean(migration && !["completed", "failed"].includes(migration.status));

  useEffect(() => {
    if (!migration || !active) return;
    const timer = window.setInterval(async () => {
      const response = await request(`/api/v1/public-domain-migrations/${encodeURIComponent(migration.id)}`);
      const body: unknown = await response.json().catch(() => null);
      if (response.ok) {
        const next = body as PublicDomainMigration;
        setMigration(next);
        if (["completed", "failed"].includes(next.status)) await onStarted();
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [active, migration, onStarted, request]);

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!confirmed) { setError("请确认主域名切换影响后再继续"); return; }
    setBusy(true); setError(null);
    try {
      const response = await request(`/api/v1/public-domains/${encodeURIComponent(domain.id)}/make-primary`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ confirm: true }) });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法启动主域名迁移"));
      setMigration(body as PublicDomainMigration);
      await onStarted();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法启动主域名迁移");
    } finally { setBusy(false); }
  };

  const statusLabel = migration ? ({ preparing: "准备中", switching: "切换中", waiting_devices: "等待设备确认", completed: "已完成", failed: "失败" } as Record<string, string>)[migration.status] ?? migration.status : null;
  return <FormDialog eyebrow="主域名迁移" title={`将 ${domain.domain} 设为主域名`} description="切换会保留旧域名和别名，直到所有设备完成确认；迁移激活后不能取消。" onClose={() => { if (!active && !busy) onClose(); }} returnFocus={returnFocus} role="alertdialog"><form className="domain-primary-form" aria-busy={busy || active} onSubmit={submit}><div className="migration-impact"><strong>切换前检查</strong><p>目标域名的根证书和泛域名证书状态正常。Web 服务会迁移到新主域名，在线设备立即处理，离线设备上线后继续。</p><p>mesh.{domain.domain} 必须保持仅 DNS；Nexo 会保留旧入口，直到设备逐台确认。</p></div>{migration && <div className="migration-progress" role="status" aria-live="polite"><div><span>{statusLabel}</span><strong>{migration.acknowledged_devices}/{migration.total_devices} 台设备已确认</strong></div><progress max={Math.max(migration.total_devices, 1)} value={migration.acknowledged_devices} /><small>{migration.last_error ?? "任务可恢复，页面轮询会在离开时停止。"}</small></div>}{!migration && <label className="confirmation-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>我已阅读影响并确认启动不可取消的迁移</span></label>}{error && <p className="form-error" role="alert">{error}</p>}<div className="dialog-actions"><button className="secondary-button" type="button" onClick={onClose} disabled={active || busy}>取消</button>{!migration && <button className="primary-button" type="submit" disabled={busy}>{busy ? "启动中…" : "开始迁移"}</button>}{migration && !active && <button className="primary-button" type="button" onClick={onClose}>关闭</button>}</div></form></FormDialog>;
}





function connectionTypeLabel(type: string): string {
  if (type === "direct") return "P2P 直连";
  if (type === "peer_relay") return "节点中继";
  if (type === "derp") return "DERP 中继";
  if (type === "idle") return "空闲";
  return "未知";
}

function connectionStatusKind(type: string): string {
  return type === "direct" ? "ready" : type === "unknown" ? "working" : "disabled";
}

function networkStatusExplanation(network: SiteNetwork): string {
  const reasons: Record<string, string> = {
    disabled: "网段已关闭，设备广告与控制面路由已撤回。",
    device_offline: "设备离线，上线后自动继续。",
    disabling: "正在撤回设备广告和控制面路由。",
    ipv4_forwarding_disabled: "设备未开启 IPv4 转发，请在 Agent 主机开启 net.ipv4.ip_forward。",
    ipv6_forwarding_disabled: "设备未开启 IPv6 转发，请在 Agent 主机开启 net.ipv6.conf.all.forwarding。",
    network_missing: "Agent 未检测到原有网段。已保留配置，请检查网卡和本地网络。",
    apply_failed: "配置需要处理，请查看下方原因，修复后重新检查。",
    ready: "配置与必要批准已完成；此状态不代表已实测所有家庭服务。",
    applying: "正在配置，后台自动完成设备广告、路由批准和工作空间授权。",
  };
  return reasons[network.status_reason] ?? "正在读取配置状态。";
}

function NetworkDetailSheet({ network, connections, request, returnFocus, onRefresh, onClose }: { network: SiteNetwork; connections: MeshConnection[]; request: ApiRequest; returnFocus: HTMLButtonElement | null; onRefresh: () => Promise<void>; onClose: () => void }) {
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const apply = async (remove: boolean) => {
    if (remove && !window.confirm(`删除共享网段 ${network.desired_prefix}？已保存的授权将撤销。`)) return;
    setBusy(true); setError(null);
    try {
      const response = await request(`/api/v1/site-networks/${encodeURIComponent(network.id)}${remove ? "" : "/recheck"}`, {method: remove ? "DELETE" : "POST"});
      if (!response.ok) throw new Error(readApiError(await response.json(), "暂时无法应用操作"));
      await onRefresh();
      if (remove) onClose();
    } catch (error) {setError(error instanceof Error ? error.message : "暂时无法应用操作");}
    finally {setBusy(false);}
  };
  const check = async (clientDeviceId: string) => {
    setCheckingId(clientDeviceId); setError(null);
    try {
      const response = await request("/api/v1/mesh/connection-checks", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_device_id: clientDeviceId, site_network_id: network.id }) });
      const body = await response.json().catch(() => null) as { id?: string; error?: string } | null;
      if (!response.ok || !body?.id) throw new Error(body?.error ?? "暂时无法开始连接检测");
      for (let attempt = 0; attempt < 12; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        const poll = await request(`/api/v1/mesh/connection-checks/${encodeURIComponent(body.id)}`);
        const result = await poll.json().catch(() => null) as { status?: string; error_message?: string } | null;
        if (!poll.ok) throw new Error("暂时无法读取连接检测结果");
        if (result?.status === "succeeded") { await onRefresh(); return; }
        if (result?.status === "failed") throw new Error(result.error_message ?? "连接检测失败");
      }
      throw new Error("检测仍在进行，请稍后刷新");
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "连接检测失败"); }
    finally { setCheckingId(null); }
  };
  return <FormDialog eyebrow="共享网段" title={network.name} description={`${network.desired_prefix} · 由 ${network.publisher_device_name} 承载`} variant="sheet" returnFocus={returnFocus} onClose={() => {if (!busy) onClose();}}>
    <section className="device-detail-section" aria-busy={busy}>
      <h3>配置状态</h3><NetworkState network={network} />
      <p>{networkStatusExplanation(network)}</p>
      {!["ready", "disabled"].includes(network.status_reason) && Date.now() / 1000 - network.updated_at > 60 && <p className="form-hint">耗时较长，请查看配置详情；后台会继续处理。</p>}
      {(network.apply_error || network.health_error) && <p className="form-hint">{network.apply_error ?? network.health_error}</p>}
      <div className="dialog-actions"><button className="secondary-button" disabled={busy} onClick={() => void apply(false)}>{busy ? "处理中…" : "重新检查"}</button><button className="secondary-button danger-button" disabled={busy || network.deletion_pending} onClick={() => void apply(true)}>{network.deletion_pending ? "正在删除" : "删除网段"}</button></div>
    </section>
    <section className="device-detail-section"><h3>客户端连接</h3><p className="form-hint">连接方式按客户端到 Agent 分别显示。中继连接同样保持端到端加密。</p>
      <div className="connection-detail-list">{connections.length === 0 ? <EmptyState icon={Network} title="尚无连接观测" detail="客户端产生流量后，路径状态会在 15 秒内更新。" /> : connections.map((connection) => <div className="connection-detail-row" key={connection.client_device_id}><div><strong>{connection.client_device_name}</strong><span>到 {connection.gateway_device_name}</span></div><span className={`status-pill ${connectionStatusKind(connection.connection_type)}`}><i />{connectionTypeLabel(connection.connection_type)}</span><button className="secondary-button compact-button" type="button" disabled={checkingId === connection.client_device_id} onClick={() => void check(connection.client_device_id)}><RefreshCw size={15} aria-hidden="true" />{checkingId === connection.client_device_id ? "检测中" : "检测"}</button></div>)}</div>
    </section>{error && <p className="form-error" role="alert">{error}</p>}
  </FormDialog>;
}




/**
 * 表单与危险确认共用的模态外壳。原生 dialog 负责焦点约束；关闭时把焦点
 * 送回触发按钮，提交中的表单则拒绝 Esc 和遮罩关闭，避免请求状态丢失。
 */
function FormDialog({
  eyebrow,
  title,
  description,
  onClose,
  children,
  returnFocus: explicitReturnFocus,
  role,
  compact = false,
  confirmDiscard = false,
  wide = false,
  variant = "sheet",
  initialFocusSelector,
}: {
  eyebrow: string;
  title: string;
  description: string;
  onClose: () => void;
  children: ReactNode;
  returnFocus?: HTMLElement | null;
  role?: "dialog" | "alertdialog";
  compact?: boolean;
  confirmDiscard?: boolean;
  wide?: boolean;
  variant?: "modal" | "sheet";
  initialFocusSelector?: string;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const returnFocus = useRef<HTMLElement | null>(explicitReturnFocus ?? document.activeElement as HTMLElement | null);
  const titleId = useRef(`dialog-${Math.random().toString(36).slice(2)}`);
  const dirty = useRef(false);
  const canClose = () => !confirmDiscard || !dirty.current || window.confirm("放弃尚未保存的修改？");
  const submitting = () => dialogRef.current?.querySelector('[aria-busy="true"]') !== null;
  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) {
      dialog.showModal();
      if (initialFocusSelector) dialog.querySelector<HTMLElement>(initialFocusSelector)?.focus();
    }
    return () => {
      if (dialog?.open) dialog.close();
      returnFocus.current?.focus();
    };
  }, [initialFocusSelector]);
  return (
    <dialog
      ref={dialogRef}
      className={`form-dialog ${variant === "sheet" ? "form-sheet" : ""}`}
      role={role}
      aria-labelledby={titleId.current}
      onChangeCapture={() => {dirty.current = true;}}
      onClickCapture={(event) => {
        const button = (event.target as HTMLElement).closest('button');
        if (button?.type === "button" && button.textContent?.trim() === "取消" && !submitting()) {
          if (!canClose()) {event.preventDefault();event.stopPropagation();}
          else dirty.current = false;
        }
      }}
      onCancel={(event) => { event.preventDefault(); if (!submitting() && canClose()) onClose(); }}
      onClick={(event) => { if (event.target === event.currentTarget && !submitting() && canClose()) onClose(); }}
    >
      <div className={`form-dialog-surface${compact ? " compact" : ""}${wide ? " wide" : ""}`} onClick={(event) => event.stopPropagation()}>
        <header className="form-dialog-header">
          <div><p className="eyebrow">{eyebrow}</p><h2 id={titleId.current}>{title}</h2><p>{description}</p></div>
          <button className="icon-button" type="button" aria-label={`关闭${title}窗口`} onClick={() => { if (!submitting() && canClose()) onClose(); }}>
            <X size={20} aria-hidden="true" />
          </button>
        </header>
        <div className="form-dialog-body">{children}</div>
      </div>
    </dialog>
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
      <PageHeader eyebrow={auth.role === "system_admin" ? "系统管理" : "账号"} title="设置" subtitle="修改登录密码并管理仍有效的登录会话。" />
      <PageError error={error} onRetry={loadSessions} />
      {auth.local_http_warning && (
        <div className="notice warning" role="status"><AlertTriangle size={18} aria-hidden="true" /><div><strong>当前通过局域网 HTTP 登录</strong><span>这个入口只应在可信网络内使用。</span></div></div>
      )}
      <div className="settings-layout" aria-busy={loading}>
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
          <div><strong>{auth.username ?? "当前账号"}</strong><span>退出当前设备上的登录会话。</span></div>
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


/** 设备资料编辑同时提交显示名称和独立的 MagicDNS 访问名称。 */
function EditDeviceDialog({
  device,
  request,
  returnFocus,
  onUpdated,
  onClose,
}: {
  device: Device;

  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onUpdated: (updated: Device) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(device.name);
  const [meshName, setMeshName] = useState(device.mesh_name ?? "");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <FormDialog
      eyebrow="设备管理"
      confirmDiscard
      title="编辑设备"
      description="显示名称用于管理界面，组网访问名用于 MagicDNS；两者互不影响。"
      returnFocus={returnFocus}
      onClose={onClose}
    >
      <form className="inline-form network-form-table" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        if (!name.trim()) {
          setError("设备名称不能为空");
          return;
        }
        if (isPlaceholderDeviceName(name)) {
          setError("设备名称不能使用 localhost，请填写可识别的设备名称");
          return;
        }
        if (!meshName.trim()) {
          setError("组网访问名不能为空");
          return;
        }
        setSubmitting(true);
        setError(null);
        try {
          const response = await request(`/api/v1/devices/${encodeURIComponent(device.id)}`, {
            method: "PUT",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ name: name.trim(), mesh_name: meshName.trim() }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法保存设备资料"));
          onUpdated(body as Device);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法保存设备资料");
        } finally {
          setSubmitting(false);
        }
      }}>
        <fieldset className="form-grid device-edit-grid" disabled={submitting}>
          <legend className="sr-only">设备编辑信息</legend>
          <label><span>显示名称</span><input autoFocus value={name} onChange={(event) => setName(event.target.value)} required /></label>
          <label><span>组网访问名</span><div className="field-control"><input value={meshName} onChange={(event) => setMeshName(event.target.value)} autoCapitalize="none" autoCorrect="off" spellCheck={false} aria-describedby="mesh-name-help" required /><small id="mesh-name-help">仅支持字母、数字和内部连字符，最多 32 个字符；保存后统一使用小写。</small></div></label>
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

/** 设备专用危险确认窗；Tunnel 会被保留并关闭，共享网络依赖仍由服务端拒绝删除。 */
function DeleteDeviceDialog({
  device,
  request,
  returnFocus,
  onDeleted,
  onClose,
}: {
  device: Device;
  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onDeleted: (response: DeleteResponse) => void;
  onClose: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tunnelCount = device.tunnel_count ?? 0;
  return (
    <FormDialog
      eyebrow="危险操作"
      title="删除设备"
      description={`设备“${device.name}”的身份和组网节点会立即撤销。${tunnelCount} 个公网服务将保留为未分配并关闭。`}
      role="alertdialog"
      compact
      initialFocusSelector="[data-delete-cancel]"
      returnFocus={returnFocus}
      onClose={onClose}
    >
      <form className="delete-confirmation-form" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        setSubmitting(true);
        setError(null);
        try {
          const response = await request(`/api/v1/devices/${encodeURIComponent(device.id)}`, { method: "DELETE" });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法删除设备"));
          const deletion = body as DeleteResponse | null;
          if (!deletion || deletion.deleted !== true || deletion.pending !== false || deletion.id !== device.id) {
            throw new Error("服务端未确认设备已删除");
          }
          onDeleted(deletion);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法删除设备");
          setSubmitting(false);
        }
      }}>
        <div className="delete-confirmation-copy">
          <AlertTriangle size={20} aria-hidden="true" />
          <p>删除设备不会删除公网服务，它们会立即停止公网入口。若设备仍承载共享网络，服务端仍会阻止删除。</p>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <button className="secondary-button" type="button" data-delete-cancel disabled={submitting} onClick={onClose}>取消</button>
          <button className="danger-button" type="submit" disabled={submitting}><Trash2 size={16} aria-hidden="true" />{submitting ? "删除中…" : "永久删除"}</button>
        </div>
      </form>
    </FormDialog>
  );
}

function networkAddressFamily(prefix: string): "ipv4" | "ipv6" {
  return prefix.includes(":") ? "ipv6" : "ipv4";
}

function forwardingRequirement(report: GatewayReport, prefix: string): string | null {
  if (networkAddressFamily(prefix) === "ipv6") {
    return report.ipv6_forwarding ? null : "需开启 IPv6 转发";
  }
  return report.ipv4_forwarding ? null : "需开启 IPv4 转发";
}

function gatewayFamilyAvailability(report: GatewayReport): string | null {
  if (report.ipv4_forwarding && report.ipv6_forwarding) return "IPv4/IPv6 可用";
  if (report.ipv4_forwarding) return "IPv4 可用";
  if (report.ipv6_forwarding) return "IPv6 可用";
  return null;
}



const RELEASE_AGENT_IMAGE = "ghcr.io/thelinyue/nexo-agent:0.1.17";

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
      TZ: \${TZ:-Asia/Shanghai}
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
  tenantId,
  enrollments,
  onApprove,

  request,
  onCreated,
  onDone,
}: {
  tenantId: string;
  enrollments: Enrollment[];
  onApprove: (item: Enrollment) => Promise<string | null>;

  request: ApiRequest;
  onCreated: () => Promise<void>;
  onDone: () => void;
}) {
  const [deviceName, setDeviceName] = useState("");
  const [serverUrl, setServerUrl] = useState(() => window.location.origin);
  const [created, setCreated] = useState<CreatedEnrollment | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [error, setError] = useState<string | null>(null);

  const normalizedServerUrl = serverUrl.trim().replace(/\/+$/, "");
  const compose = created ? buildAgentCompose(normalizedServerUrl, created.token) : "";

  if (created) {
    const enrollment = enrollments.find((item) => item.enrollment_id === created.enrollment_id);
    const joined = enrollment?.status === "consumed";
    const expired = enrollment?.status === "expired" || (!joined && Date.now() / 1000 >= created.expires_at);
    return (
      <div className="enrollment-setup" aria-live="polite">
        <div className="enrollment-result-heading">
          <div>
            <strong>Docker Compose 配置已生成</strong>
            <span>凭证将在 {new Date(created.expires_at * 1000).toLocaleTimeString()} 前有效，且只能使用一次。</span>
          </div>
          <span className={`entry-state ${joined ? "ready" : "applying"}`}><i />{joined ? "设备已加入" : expired ? "入网凭证已过期" : enrollment?.status === "awaiting_approval" ? "待批准" : enrollment?.status === "approved" ? "正在领取设备身份" : "等待设备连接"}</span>
        </div>
        <textarea className="enrollment-compose" aria-label="Docker Compose 配置" value={compose} readOnly spellCheck={false} />
        <div className="form-footer enrollment-result-actions">
          <span className="form-hint">复制到设备后运行 <code>docker compose up -d</code>。设备领取身份后可以删除 Token。</span>
          <div className="panel-heading-actions">
            <button className="secondary-button" type="button" onClick={onDone}>{joined ? "完成" : "关闭"}</button>
            {expired && <button className="primary-button" type="button" onClick={() => setCreated(null)}>重新生成</button>}
            {!expired && enrollment?.status === "awaiting_approval" && <button className="primary-button" type="button" disabled={submitting} onClick={async () => {setSubmitting(true);setError(null);try {setError(await onApprove(enrollment));} finally {setSubmitting(false);}}}>批准设备</button>}
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
        {error && <p className="form-error" role="alert">{error}</p>}
        {enrollment?.status === "awaiting_approval" && <p className="form-hint">核对设备：{enrollment.device_name} · {enrollment.os} · {enrollment.architecture} · {enrollment.agent_version}</p>}
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

        setSubmitting(true);
        try {
          const response = await request("/api/v1/enrollments", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              tenant_id: tenantId,

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
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} placeholder="家庭 NAS" required />
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

/** 公网服务创建表单：仅展示设备、本地服务和用户可理解的访问模式。 */
function CreateTunnelForm({
  auth,
  devices,
  publicDomains,
  request,
  onDomainsChanged,
  onCancel,
  onCreated,
  existing,
  onUpdated,
}: {
  auth: AuthStatus;
  devices: Device[];
  publicDomains: PublicDomain[];
  request: ApiRequest;
  onDomainsChanged: () => Promise<void>;
  onCancel: () => void;
  onCreated: () => Promise<void>;
  existing?: Tunnel;
  onUpdated?: (tunnel: Tunnel) => void;
}) {
  const readyDomains = publicDomains.filter((item) => publicDomainStatus(item.apply_status).kind === "ready");
  const [deviceId, setDeviceId] = useState(existing?.device_id ?? devices[0]?.id ?? "");
  const [name, setName] = useState(existing?.name ?? "");
  const [protocol, setProtocol] = useState<Tunnel["protocol"]>(existing?.protocol ?? "https");
  const [localUrl, setLocalUrl] = useState(existing ? `${existing.origin_protocol ?? "http"}://${existing.local_address.includes(":") ? `[${existing.local_address}]` : existing.local_address}:${existing.local_port}` : "http://127.0.0.1:8800");
  const [localAddress, setLocalAddress] = useState(existing?.local_address ?? "127.0.0.1");
  const [localPort, setLocalPort] = useState(String(existing?.local_port ?? 8800));
  const [hostname, setHostname] = useState(existing?.hostname ?? "");
  const [publicDomainId, setPublicDomainId] = useState(existing?.public_domain_id ?? readyDomains.find((item) => item.is_primary)?.id ?? readyDomains[0]?.id ?? "");
  const [publicPort, setPublicPort] = useState(existing?.public_port ? String(existing.public_port) : "");
  const originProtocol = existing?.origin_protocol ?? "http";
  const [submitting, setSubmitting] = useState(false);
  const [configuringDomain, setConfiguringDomain] = useState(false);
  const [domainOpened, setDomainOpened] = useState(false);
  const serviceForm = useRef<HTMLFormElement>(null);
  const domainReturn = useRef<{element: HTMLElement | null; scrollTop: number}>({element:null, scrollTop:0});
  // 原地配置域名后回到原操作位置；后台刷新不触碰焦点和草稿。
  useEffect(() => {
    if (configuringDomain || !domainOpened) return;
    const frame = requestAnimationFrame(() => {
      const form = serviceForm.current;
      const target = domainReturn.current.element;
      if (target?.isConnected) target.focus({preventScroll:true});
      else form?.querySelector<HTMLElement>('input, select, button')?.focus({preventScroll:true});
      const body = form?.closest('.form-dialog-body');
      if (body) body.scrollTop = domainReturn.current.scrollTop;
    });
    return () => cancelAnimationFrame(frame);
  }, [configuringDomain, domainOpened]);
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ field: "device" | "domain" | "localPort" | "publicPort"; message: string } | null>(null);
  const device = devices.find((item) => item.id === deviceId);
  useEffect(() => {
    if (!deviceId || !devices.some((item) => item.id === deviceId)) setDeviceId(devices[0]?.id ?? "");
  }, [deviceId, devices]);
  useEffect(() => {
    if (publicDomainId && readyDomains.some((item) => item.id === publicDomainId)) return;
    setPublicDomainId(readyDomains.find((item) => item.is_primary)?.id ?? readyDomains[0]?.id ?? "");
  }, [publicDomainId, readyDomains]);
  const domainEditor = domainOpened && <div hidden={!configuringDomain} className="inline-domain-setup">
      <div className="inline-domain-heading"><button className="secondary-button compact-button" type="button" onClick={() => setConfiguringDomain(false)}><ArrowLeft size={15} aria-hidden="true" />返回服务</button><div><strong>配置域名与 HTTPS</strong><span>保存后返回，已填写的服务信息会保留。</span></div></div>
      <PublicDomainEditor domain={null} request={request} onCancel={() => setConfiguringDomain(false)} onSaved={async () => { await onDomainsChanged(); setConfiguringDomain(false); }} />
    </div>;
  return (
    <>{domainEditor}<form ref={serviceForm} hidden={configuringDomain} className="inline-form network-form-table" aria-busy={submitting} onSubmit={async (event) => {
      event.preventDefault();
      if (!device) { setValidation({ field: "device", message: "请先选择设备" }); return; }
      if (protocol !== "tcp" && !publicDomainId) { setValidation({ field: "domain", message: "Web 服务需要一个状态正常的域名" }); return; }
      let host = localAddress.trim(), port = localPort, origin = originProtocol;
      if (protocol !== "tcp") {
        try { const url = new URL(localUrl); if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error(); host = url.hostname.replace(/^\[|\]$/g, ""); port = url.port || (url.protocol === "https:" ? "443" : "80"); origin = url.protocol === "https:" ? "https" : "http"; }
        catch {setError("请输入完整的 HTTP 或 HTTPS 本地地址，不包含路径、账号或查询参数。");return;}
      }
      const ports = validateTunnelPorts(port, publicPort);
      if ("error" in ports) {
        setValidation({ field: ports.error.startsWith("本地") ? "localPort" : "publicPort", message: ports.error });
        return;
      }
      setSubmitting(true); setError(null); setValidation(null);
      try {
        const response = await request(existing ? `/api/v1/tunnels/${encodeURIComponent(existing.id)}` : "/api/v1/tunnels", {
          method: existing ? "PUT" : "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            tenant_id: device.tenant_id,
            device_id: device.id,
            name: name.trim() || (protocol === "tcp" ? "TCP 端口" : "Web 服务"),
            protocol,
            local_address: host,
            local_port: ports.localPort,
            public_port: protocol === "tcp" ? ports.publicPort : null,
            hostname: protocol === "tcp" ? null : hostname.trim(),
            origin_protocol: protocol === "tcp" ? null : origin,
            origin_tls_server_name: protocol !== "tcp" && origin === "https" ? existing?.origin_tls_server_name ?? null : null,
            origin_tls_verification: protocol !== "tcp" && origin === "https" ? existing?.origin_tls_verification ?? "system" : "system",
            service_name: protocol === "tcp" ? null : existing?.service_name ?? hostname.trim(),
            public_domain_id: protocol === "tcp" ? null : publicDomainId || null,
          }),
        });
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, "暂时无法添加公网服务"));
        if (existing) onUpdated?.(body as Tunnel);
        await onCreated();
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "暂时无法添加公网服务");
      } finally { setSubmitting(false); }
    }}>
      <fieldset className="form-grid tunnel-form-grid" disabled={submitting}>
        <legend className="sr-only">公网服务信息</legend>
        <label><span>显示名称（可选）</span><input value={name} onChange={(event) => setName(event.target.value)} placeholder="例如：家庭媒体库" /></label>
        <label><span>设备</span><select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required><option value="">选择设备</option>{devices.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>{validation?.field === "device" && <small className="field-error" role="alert">{validation.message}</small>}</label>
        <label><span>服务类型</span><select value={protocol === "tcp" ? "tcp" : "web"} onChange={(event) => setProtocol(event.target.value === "tcp" ? "tcp" : "https")}><option value="web">Web 服务</option><option value="tcp">TCP 服务</option></select></label>
        {protocol === "tcp" ? <><label><span>本地地址</span><input value={localAddress} onChange={(event) => setLocalAddress(event.target.value)} required /></label><label><span>本地端口</span><input inputMode="numeric" value={localPort} onChange={(event) => setLocalPort(event.target.value)} required /></label></> : <label><span>本地服务地址</span><input type="url" value={localUrl} onChange={(event) => setLocalUrl(event.target.value)} placeholder="http://10.0.0.10:8096" required /><small>填写设备可以访问的 HTTP 或 HTTPS 地址。</small></label>}
        {protocol === "tcp" ? <details><summary>指定公网端口（可选）</summary><label><span>公网端口（可选）</span><input inputMode="numeric" value={publicPort} onChange={(event) => setPublicPort(event.target.value)} placeholder="自动分配" />{validation?.field === "publicPort" && <small className="field-error" role="alert">{validation.message}</small>}</label></details> : <label><span>子域名前缀</span><input value={hostname} onChange={(event) => setHostname(event.target.value)} placeholder="例如：media" required /></label>}
        {protocol !== "tcp" && <label><span>公网域名</span><select value={publicDomainId} onChange={(event) => setPublicDomainId(event.target.value)} disabled={readyDomains.length === 0}><option value="">选择可用域名</option>{readyDomains.map((item) => <option key={item.id} value={item.id}>{item.domain}{item.is_primary ? "（主域名）" : ""}</option>)}</select>{validation?.field === "domain" && <small className="field-error" role="alert">{validation.message}</small>}</label>}
      </fieldset>
      {protocol !== "tcp" && publicDomainId && <p className="public-address-preview">公网地址：<code>https://{hostname || "服务名称"}.{readyDomains.find(item => item.id === publicDomainId)?.domain}</code></p>}
      {protocol !== "tcp" && readyDomains.length === 0 && <div className="inline-domain-required" role="status"><AlertTriangle size={18} aria-hidden="true" /><div><strong>Web 服务需要可用域名</strong><span>{auth.role === "system_admin" ? "先在此处完成域名与 HTTPS 配置，返回后服务草稿会继续保留。" : "请联系系统管理员完成域名与 HTTPS 配置。TCP 服务仍可直接创建。"}</span></div>{auth.role === "system_admin" && <button className="secondary-button" type="button" onClick={(event) => {domainReturn.current={element:event.currentTarget,scrollTop:serviceForm.current?.closest('.form-dialog-body')?.scrollTop ?? 0};setDomainOpened(true);setConfiguringDomain(true);}}>配置域名</button>}</div>}
      {error && <p className="form-error" role="alert">{error}</p>}
      {validation?.field === "localPort" && <p className="form-error" role="alert">{validation.message}</p>}
      <div className="form-footer">
        <span className="form-hint">{protocol === "tcp" ? "公网端口范围：20000-29999。" : "子域名前缀会与入口域名组合为完整访问地址。"}</span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting || !device || (protocol !== "tcp" && readyDomains.length === 0)}>{submitting ? "保存中…" : existing ? "保存修改" : "添加服务"}</button>
        </div>
      </div>
    </form></>
  );
}

/** 创建与编辑使用同一表单，确保 URL 解析、域名返回及 TLS 保留规则一致。 */
function EditTunnelDialog({tunnel, devices, publicDomains, auth, request, returnFocus, onUpdated, onRefresh, onClose}: {
  tunnel: Tunnel; devices: Device[]; publicDomains: PublicDomain[]; auth: AuthStatus;
  request: ApiRequest; returnFocus: HTMLButtonElement | null;
  onUpdated: (updated: Tunnel) => void; onRefresh: () => Promise<void>; onClose: () => void;
}) {
  return <FormDialog confirmDiscard eyebrow="公网服务" title={`编辑 ${tunnel.name}`} description="修改本地服务与公网地址。" returnFocus={returnFocus} onClose={onClose}>
    <CreateTunnelForm existing={tunnel} auth={auth} devices={devices} publicDomains={publicDomains} request={request} onDomainsChanged={onRefresh} onCancel={onClose} onUpdated={onUpdated} onCreated={async () => {onClose();}} />
  </FormDialog>;
}

/** 设备与全局列表共用详情；任务切换只保留一个可交互的 Sheet。 */
function TunnelDetailSheet({tunnel, devices, publicDomains, auth, request, returnFocus, onRefresh, onClose}: {
  tunnel: Tunnel; devices: Device[]; publicDomains: PublicDomain[]; auth: AuthStatus;
  request: ApiRequest; returnFocus: HTMLButtonElement | null; onRefresh: () => Promise<void>; onClose: () => void;
}) {
  const [mode, setMode] = useState<"details" | "edit" | "delete">("details");
  const detailRoot = useRef<HTMLElement>(null);
  const returnPosition = useRef({action:"",scrollTop:0});
  useEffect(() => {
    if (mode !== "details") return;
    const frame = requestAnimationFrame(() => {
      const root = detailRoot.current;
      [...(root?.querySelectorAll<HTMLButtonElement>('button') ?? [])].find(button => button.textContent === returnPosition.current.action)?.focus({preventScroll:true});
      const body = root?.closest('.form-dialog-body');
      if (body) body.scrollTop = returnPosition.current.scrollTop;
    });
    return () => cancelAnimationFrame(frame);
  }, [mode]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const back = () => setMode("details");
  if (mode === "edit") return <EditTunnelDialog {...{tunnel, devices, publicDomains, auth, request, onRefresh}} returnFocus={null} onUpdated={() => {void onRefresh();}} onClose={back} />;
  if (mode === "delete") return <DeleteTunnelDialog tunnel={tunnel} request={request} returnFocus={null} onDeleted={() => {void onRefresh();onClose();}} onClose={back} />;
  const address = navigableWebAddress(tunnel.public_address);
  return <FormDialog eyebrow="公网服务" title={tunnel.name} description={`${tunnel.protocol === "tcp" ? "TCP" : "Web"} · ${tunnel.device_name ?? "未分配设备"}`} returnFocus={returnFocus} onClose={() => {if (!busy) onClose();}}>
    <section ref={detailRoot} className="device-detail-section" aria-busy={busy} onClickCapture={(event) => {
      const button = (event.target as HTMLElement).closest('button');
      if (button) returnPosition.current={action:button.textContent ?? "",scrollTop:event.currentTarget.closest('.form-dialog-body')?.scrollTop ?? 0};
    }}>
      <p>{!tunnel.device_id ? "需处理：请选择承载设备" : !tunnel.enabled ? "已关闭" : tunnel.apply_status === "ready" ? "正常" : tunnel.apply_status === "failed" ? "需处理" : "处理中"}</p>
      {tunnel.apply_error && <p className="form-hint">{tunnel.apply_error}</p>}
      <p>本地服务：<code>{tunnel.local_address}:{tunnel.local_port}</code></p>
      <p>公网地址：{address ? <a href={address} target="_blank" rel="noreferrer">{address}</a> : <code>{tunnel.public_address ?? "正在配置"}</code>}</p>
      <div className="dialog-actions">
        <button className="secondary-button" disabled={!tunnel.public_address} onClick={async () => {try {await navigator.clipboard.writeText(tunnel.public_address!);} catch {setError("无法复制，请手动选择公网地址。");}}}>复制地址</button>
        <button className="secondary-button" disabled={busy || tunnel.deletion_pending} onClick={() => setMode("edit")}>编辑</button>
        <button className="secondary-button" disabled={busy || !tunnel.device_id || tunnel.deletion_pending} onClick={async () => {
          setBusy(true);setError(null);
          try {const response = await request(`/api/v1/tunnels/${encodeURIComponent(tunnel.id)}/${tunnel.enabled ? "disable" : "enable"}`, {method:"POST"});
            if (!response.ok) throw new Error(readApiError(await response.json(),"无法更新服务")); await onRefresh();
          } catch (e) {setError(e instanceof Error ? e.message : "无法更新服务");} finally {setBusy(false);}
        }}>{busy ? "处理中…" : tunnel.enabled ? "关闭服务" : "启用服务"}</button>
        <button className="secondary-button danger-button" disabled={busy || tunnel.deletion_pending} onClick={() => setMode("delete")}>删除服务</button>
      </div>{error && <p className="form-error" role="alert">{error}</p>}
    </section>
  </FormDialog>;
}

/** 仅把浏览器能够安全导航的 HTTP/HTTPS 地址暴露为链接。 */
function navigableWebAddress(publicAddress: string | null): string | null {
  if (!publicAddress) return null;
  try {
    const protocol = new URL(publicAddress).protocol;
    return protocol === "http:" || protocol === "https:" ? publicAddress : null;
  } catch {
    return null;
  }
}

/** 公网服务永久删除使用独立确认窗，避免与可恢复的开关操作混淆。 */
function DeleteTunnelDialog({
  tunnel,
  request,
  returnFocus,
  onDeleted,
  onClose,
}: {
  tunnel: Tunnel;
  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onDeleted: (response: DeleteResponse) => void;
  onClose: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <FormDialog
      eyebrow="危险操作"
      title="删除公网服务"
      description={`“${tunnel.name}”的公网入口和服务端配置将立即永久删除。`}
      role="alertdialog"
      compact
      initialFocusSelector="[data-delete-cancel]"
      returnFocus={returnFocus}
      onClose={onClose}
    >
      <form className="delete-confirmation-form" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        setSubmitting(true);
        setError(null);
        try {
          const response = await request(`/api/v1/tunnels/${encodeURIComponent(tunnel.id)}`, { method: "DELETE" });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法删除公网服务"));
          const deletion = body as DeleteResponse | null;
          if (!deletion || deletion.deleted !== true || deletion.pending !== false || deletion.id !== tunnel.id) {
            throw new Error("服务端未确认公网服务已永久删除");
          }
          onDeleted(deletion);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法删除公网服务");
          setSubmitting(false);
        }
      }}>
        <div className="delete-confirmation-copy">
          <AlertTriangle size={20} aria-hidden="true" />
          <p>此操作无法恢复。设备离线不影响删除；设备下次连接时会自动清理旧配置。</p>
        </div>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <button className="secondary-button" type="button" data-delete-cancel disabled={submitting} onClick={onClose}>取消</button>
          <button className="danger-button" type="submit" disabled={submitting}>
            <Trash2 size={16} aria-hidden="true" />{submitting ? "删除中…" : "永久删除"}
          </button>
        </div>
      </form>
    </FormDialog>
  );
}

/** 批量更换设备弹窗复用表格式布局，提交后保留每条服务原有启停状态。 */
function BatchTunnelDeviceDialog({
  tunnels,
  devices,
  request,
  returnFocus,
  onUpdated,
  onClose,
}: {
  tunnels: Tunnel[];
  devices: Device[];
  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onUpdated: (result: BatchTunnelResponse) => void;
  onClose: () => void;
}) {
  const [deviceId, setDeviceId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <FormDialog
      eyebrow="公网服务"
      title="批量更换设备"
      description={`为选中的 ${tunnels.length} 个公网服务选择新设备；原有启停状态会保留，运行中的连接会立即关闭。`}
      returnFocus={returnFocus}
      onClose={onClose}
    >
      <form className="inline-form network-form-table" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        if (!deviceId) {
          setError("请选择目标设备");
          return;
        }
        setSubmitting(true);
        setError(null);
        try {
          const response = await request("/api/v1/tunnels/batch/device", {
            method: "PUT",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ tunnel_ids: tunnels.map((tunnel) => tunnel.id), device_id: deviceId }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法批量更换设备"));
          onUpdated(body as BatchTunnelResponse);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法批量更换设备");
        } finally {
          setSubmitting(false);
        }
      }}>
        <fieldset className="form-grid" disabled={submitting}>
          <legend className="sr-only">批量更换设备信息</legend>
          <label><span>目标设备</span><select autoFocus value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required><option value="">选择设备</option>{devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label>
        </fieldset>
        <p className="form-hint">未分配服务重新分配后仍保持关闭，需要单独启用。</p>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <button className="secondary-button" type="button" disabled={submitting} onClick={onClose}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting}>{submitting ? "保存中…" : "更换设备"}</button>
        </div>
      </form>
    </FormDialog>
  );
}

/** 批量删除确认窗明确说明公网入口和服务端配置的不可逆影响。 */
function BatchTunnelDeleteDialog({
  tunnels,
  request,
  returnFocus,
  onDeleted,
  onClose,
}: {
  tunnels: Tunnel[];
  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onDeleted: (result: BatchTunnelDeleteResponse) => void;
  onClose: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <FormDialog
      eyebrow="危险操作"
      title="批量删除公网服务"
      description={`将永久删除 ${tunnels.length} 个公网服务及其公网入口，此操作无法恢复。`}
      role="alertdialog"
      compact
      initialFocusSelector="[data-delete-cancel]"
      returnFocus={returnFocus}
      onClose={onClose}
    >
      <form className="delete-confirmation-form" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        setSubmitting(true);
        setError(null);
        try {
          const response = await request("/api/v1/tunnels/batch", {
            method: "DELETE",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ tunnel_ids: tunnels.map((tunnel) => tunnel.id) }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法批量删除公网服务"));
          const result = body as BatchTunnelDeleteResponse | null;
          if (!result || result.deleted_ids.length !== tunnels.length) throw new Error("服务端未确认所有公网服务已删除");
          onDeleted(result);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法批量删除公网服务");
          setSubmitting(false);
        }
      }}>
        <div className="delete-confirmation-copy">
          <AlertTriangle size={20} aria-hidden="true" />
          <p>会永久移除公网监听、现有连接、Socket/CA 文件和服务端配置。公网入口将立即停止。</p>
        </div>
        <ul className="batch-delete-list">{tunnels.map((tunnel) => <li key={tunnel.id}>{tunnel.name}</li>)}</ul>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="dialog-actions">
          <button className="secondary-button" type="button" data-delete-cancel disabled={submitting} onClick={onClose}>取消</button>
          <button className="danger-button" type="submit" disabled={submitting}><Trash2 size={16} aria-hidden="true" />{submitting ? "删除中…" : "永久删除"}</button>
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
  onDelete,
  selected,
  onSelect,
}: {
  tunnel: Tunnel;
  request: ApiRequest;
  onChanged: (updated: Tunnel) => void;
  onEdit: (trigger: HTMLButtonElement) => void;
  onDelete: (trigger: HTMLButtonElement) => void;
  selected: boolean;
  onSelect: (checked: boolean) => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const actionDisabled = pending || tunnel.deletion_pending;
  const assigned = Boolean(tunnel.device_id);
  const statusKind = tunnel.deletion_pending ? "working" : !assigned || !tunnel.enabled ? "disabled" : tunnel.apply_status === "ready" ? "ready" : tunnel.apply_status === "failed" ? "failed" : "working";
  const webAddress = navigableWebAddress(tunnel.public_address);

  useEffect(() => {
    if (copyState !== "copied") return;
    const timeout = window.setTimeout(() => setCopyState("idle"), 2000);
    return () => window.clearTimeout(timeout);
  }, [copyState]);

  return (
    <div className={`tunnel-row${selected ? " selected" : ""}`}>
      <label className="selection-control tunnel-selection"><input type="checkbox" checked={selected} onChange={(event) => onSelect(event.target.checked)} disabled={tunnel.deletion_pending} aria-label={`选择公网服务${tunnel.name}`} /><span className="sr-only">选择 {tunnel.name}</span></label>
      <div className="tunnel-identity"><strong>{tunnel.name}</strong><span>{tunnel.device_name ?? "未分配设备"} · {tunnel.local_address}:{tunnel.local_port}</span>{tunnel.public_domain && <small className="tunnel-domain-binding">域名：{tunnel.public_domain}</small>}</div>
      <div className="tunnel-address">
        <span>访问地址</span>
        <div className="tunnel-address-value">
          {webAddress ? (
            <a className="tunnel-address-link" href={webAddress} target="_blank" rel="noopener noreferrer"><code>{webAddress}</code></a>
          ) : (
            <code>{tunnel.public_address ?? "等待配置生效"}</code>
          )}
          {tunnel.public_address && (
            <button
              className="tunnel-copy-button"
              type="button"
              data-copied={copyState === "copied" || undefined}
              aria-label={copyState === "copied" ? `${tunnel.name}的访问地址已复制` : `复制${tunnel.name}的访问地址`}
              title={copyState === "copied" ? "已复制" : "复制访问地址"}
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(tunnel.public_address!);
                  setCopyState("copied");
                } catch {
                  setCopyState("failed");
                }
              }}
            >
              {copyState === "copied" ? <CheckCircle2 size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
            </button>
          )}
          <span className="sr-only" role="status" aria-live="polite">{copyState === "copied" ? "访问地址已复制" : ""}</span>
        </div>
      </div>
      <div className="network-actions">
        <span className={`link-status ${statusKind}`}><i />{tunnel.deletion_pending ? "处理中" : !assigned ? "需处理" : tunnel.enabled ? (tunnel.apply_status === "ready" ? "正常" : tunnel.apply_status === "failed" ? "需处理" : "处理中") : "已关闭"}</span>
        <button className="link-action" type="button" disabled={actionDisabled} onClick={(event) => onEdit(event.currentTarget)}>查看详情</button>
        <button className="link-action" type="button" disabled={actionDisabled || !assigned} title={!assigned ? "请先选择设备" : undefined} onClick={async () => {
          setPending(true);
          setError(null);
          try {
            const response = await request(`/api/v1/tunnels/${encodeURIComponent(tunnel.id)}/${tunnel.enabled ? "disable" : "enable"}`, { method: "POST" });
            const body: unknown = await response.json().catch(() => null);
            if (!response.ok) throw new Error(readApiError(body, tunnel.enabled ? "暂时无法关闭公网服务" : "暂时无法启用公网服务"));
            onChanged(body as Tunnel);
          } catch (requestError) {
            setError(requestError instanceof Error ? requestError.message : "暂时无法更新公网服务");
          } finally {
            setPending(false);
          }
        }}>{pending ? "处理中…" : tunnel.deletion_pending ? "等待删除" : !assigned ? "需先选择设备" : tunnel.enabled ? "关闭" : "启用"}</button>
        <button className="delete-icon-button" type="button" aria-label={`删除公网服务${tunnel.name}`} title={tunnel.deletion_pending ? "等待删除" : "删除公网服务"} disabled={actionDisabled} onClick={(event) => onDelete(event.currentTarget)}>
          <Trash2 size={17} aria-hidden="true" />
        </button>
      </div>
      {copyState === "failed" && <p className="network-error" role="alert">浏览器无法访问剪贴板，请手动选择访问地址复制。</p>}
      {error && <p className="network-error" role="alert">{error}</p>}
      {tunnel.apply_error && <p className="network-error">{tunnel.apply_error}</p>}
    </div>
  );
}







/** 与 Server 保持一致，只把明确的 localhost 占位名标为需要用户命名。 */
function isPlaceholderDeviceName(value: string): boolean {
  const normalized = value.trim().toLocaleLowerCase("en-US");
  return normalized === "localhost" || /^localhost-\d+$/.test(normalized);
}


/** 将路由记录中的内部阶段转换成管理员可直接理解的产品文案。 */

function AuthShell({ children }: { children: ReactNode }) {
  return <main className="auth-shell"><div className="auth-panel"><div className="brand-mark auth-brand"><span className="brand-icon">N</span><span><strong>Nexo</strong><small>联巢</small></span></div>{children}</div></main>;
}

/** 鉴权状态读取失败单独呈现，避免断网时误导用户重新初始化实例。 */
function ConnectionErrorScreen({ busy, onRetry }: { busy: boolean; onRetry: () => Promise<void> }) {
  return (
    <AuthShell>
      <span className="connection-error-icon"><WifiOff size={24} aria-hidden="true" /></span>
      <p className="eyebrow">连接中断</p>
      <h1>无法连接 Nexo</h1>
      <p className="auth-copy">请检查网络或确认 Nexo 服务正在运行，然后重试。</p>
      <button className="primary-button" type="button" disabled={busy} onClick={() => void onRetry()}>
        <RefreshCw size={16} className={busy ? "spin" : ""} aria-hidden="true" />
        {busy ? "正在重试…" : "重试"}
      </button>
    </AuthShell>
  );
}

/** 新版本只给出可控提示；是否刷新始终由用户决定，填写中的表单不会丢失。 */
function PwaUpdatePrompt() {
  const [needRefresh, setNeedRefresh] = useState(false);
  const updateServiceWorker = useRef<((reloadPage?: boolean) => Promise<void>) | null>(null);

  useEffect(() => {
    updateServiceWorker.current = registerSW({ onNeedRefresh: () => setNeedRefresh(true) });
  }, []);

  if (!needRefresh) return null;
  return (
    <aside className="update-prompt" role="status" aria-label="Nexo 新版本提示">
      <div><strong>发现 Nexo 新版本</strong><span>准备好后再更新，当前填写内容不会被强制刷新。</span></div>
      <div className="update-actions">
        <button className="secondary-button compact-button" type="button" onClick={() => setNeedRefresh(false)}>稍后</button>
        <button className="primary-button compact-button" type="button" onClick={() => void updateServiceWorker.current?.(true)}>立即更新</button>
      </div>
    </aside>
  );
}

function continueOidcLogin(ticket: string) {
  window.location.replace(`/oidc/authorize?nexo_login_ticket=${encodeURIComponent(ticket)}`);
}

function InitializeScreen({ onDone }: { onDone: (body: AuthStatus & { csrf_token?: string | null }) => void }) {
  const [bootstrapCode, setBootstrapCode] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return <AuthShell><p className="eyebrow">首次设置</p><h1>创建管理员</h1><p className="auth-copy">输入本机生成的一次性初始化口令，开始管理你的设备与网络。</p><form className="auth-form" onSubmit={async (event) => { event.preventDefault(); setBusy(true); setError(null); try { const response = await fetch("/api/v1/auth/initialize", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ bootstrap_code: bootstrapCode, username, password }) }); const body = await response.json().catch(() => null) as { csrf_token?: string | null; user_id?: string; role?: string; workspace_id?: string; error?: string }; if (!response.ok) throw new Error(body.error ?? "初始化失败"); onDone({ initialized: true, authenticated: true, user_id: body.user_id ?? null, username, role: body.role ?? "system_admin", workspace_id: body.workspace_id ?? "default", channel: "local_http", csrf_token: body.csrf_token ?? null, local_http_warning: true }); } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "初始化失败"); } finally { setBusy(false); } }}><label><span>初始化口令</span><input value={bootstrapCode} onChange={(event) => setBootstrapCode(event.target.value)} type="password" autoComplete="one-time-code" required /></label><label><span>管理员用户名</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label><span>管理员密码</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="new-password" minLength={12} required /></label><button className="primary-button" type="submit" disabled={busy}>{busy ? "正在创建…" : "完成初始化"}</button>{error && <p className="form-error" role="alert">{error}</p>}</form></AuthShell>;
}

function LoginScreen({ onDone, notice }: { onDone: (body: AuthStatus & { csrf_token?: string | null }) => void; notice?: string | null }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recovery, setRecovery] = useState(false);
  if (recovery) return <RecoveryScreen onBack={() => setRecovery(false)} />;
  return <AuthShell><p className="eyebrow">安全登录</p><h1>欢迎回来</h1><p className="auth-copy">登录后统一管理设备、私网访问和公网服务。</p>{notice && <p className="form-success login-notice" role="status">{notice}</p>}<form className="auth-form" onSubmit={async (event) => { event.preventDefault(); setBusy(true); setError(null); try { const response = await fetch("/api/v1/auth/login", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) }); const body = await response.json().catch(() => null) as { user_id?: string; role?: string; workspace_id?: string; csrf_token?: string | null; error?: string; channel?: string }; if (!response.ok) throw new Error(body.error ?? "用户名或密码错误"); onDone({ initialized: true, authenticated: true, user_id: body.user_id ?? null, username, role: body.role ?? "tenant", workspace_id: body.workspace_id ?? null, channel: body.channel ?? "local_http", csrf_token: body.csrf_token ?? null, local_http_warning: body.channel !== "public_https" }); } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "登录失败"); } finally { setBusy(false); } }}><label><span>用户名</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label><span>密码</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" required /></label><button className="primary-button" type="submit" disabled={busy}>{busy ? "正在登录…" : "登录"}</button>{error && <p className="form-error" role="alert">{error}</p>}</form><button className="text-button" type="button" onClick={() => setRecovery(true)}>使用恢复码</button></AuthShell>;
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
  const [authConnectionError, setAuthConnectionError] = useState(false);
  const [loginNotice, setLoginNotice] = useState<string | null>(null);
  const oidcTicket = new URLSearchParams(window.location.search).get("oidc_ticket");
  const checkAuth = useCallback(async () => {
    setChecking(true);
    setAuthConnectionError(false);
    try {
      const response = await fetch("/api/v1/auth/status", { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error("auth status unavailable");
      const body = await response.json() as AuthStatus;
      setAuth(body);
      setCsrfToken(body.csrf_token);
    } catch {
      setAuthConnectionError(true);
    } finally {
      setChecking(false);
    }
  }, []);
  useEffect(() => { void checkAuth(); }, [checkAuth]);
  useEffect(() => {
    if (!checking && auth?.authenticated && oidcTicket) continueOidcLogin(oidcTicket);
  }, [auth?.authenticated, checking, oidcTicket]);
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
  if (checking) return <AuthShell><p className="auth-copy">正在检查登录会话…</p></AuthShell>;
  if (authConnectionError || !auth) return <ConnectionErrorScreen busy={checking} onRetry={checkAuth} />;
  if (!auth.initialized) {
    return <InitializeScreen onDone={(body) => {
      if (oidcTicket) continueOidcLogin(oidcTicket);
      else onAuthenticated(body);
    }} />;
  }
  if (!auth.authenticated) {
    return <LoginScreen onDone={(body) => {
      if (oidcTicket) continueOidcLogin(oidcTicket);
      else onAuthenticated(body);
    }} notice={loginNotice} />;
  }
  return <Dashboard request={request} auth={auth} onLogout={onLogout} onSessionEnded={onSessionEnded} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
    <PwaUpdatePrompt />
  </StrictMode>,
);
