import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  AlertTriangle,
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
  | "#/devices/list"
  | "#/devices/enrollments"
  | "#/devices/official"
  | "#/access-control"
  | "#/domains"
  | "#/public-access/tunnels"
  | "#/public-access/domain"
  | "#/networks"
  | "#/settings";

type PrimaryRoute = "overview" | "devices" | "access-control" | "domains" | "public-access" | "networks" | "settings";

type NavigationItem = {
  id: PrimaryRoute;
  label: string;
  href: AppRoute;
  icon: LucideIcon;
  systemOnly?: boolean;
};

const navigationItems: NavigationItem[] = [
  { id: "overview", label: "概览", href: "#/overview", icon: LayoutDashboard },
  { id: "devices", label: "设备", href: "#/devices/list", icon: MonitorSmartphone },
  { id: "access-control", label: "访问控制", href: "#/access-control", icon: ShieldCheck },
  { id: "domains", label: "域名与 HTTPS", href: "#/domains", icon: LockKeyhole, systemOnly: true },
  { id: "public-access", label: "公网访问", href: "#/public-access/tunnels", icon: Globe2 },
  { id: "networks", label: "网络互联", href: "#/networks", icon: Network },
  { id: "settings", label: "设置", href: "#/settings", icon: Settings },
];

const validRoutes = new Set<AppRoute>([
  "#/overview",
  "#/devices/list",
  "#/devices/enrollments",
  "#/devices/official",
  "#/access-control",
  "#/domains",
  "#/public-access/tunnels",
  "#/public-access/domain",
  "#/networks",
  "#/settings",
]);

/** Hash 路由避免改变服务端静态托管，同时让每个管理页面可以刷新和前进后退。 */
function readRoute(): AppRoute {
  const hash = window.location.hash;
  if (hash === "#/public-access/domain") {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/domains`);
    return "#/domains";
  }
  if (hash === "#/public-access") {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/public-access/tunnels`);
    return "#/public-access/tunnels";
  }
  if (["#/networks/sites", "#/networks/shared", "#/networks/links"].includes(hash)) {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/networks`);
    return "#/networks";
  }
  const route = hash as AppRoute;
  if (validRoutes.has(route)) return route;
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/overview`);
  return "#/overview";
}

function primaryRoute(route: AppRoute): PrimaryRoute {
  if (route.startsWith("#/devices/")) return "devices";
  if (route === "#/access-control") return "access-control";
  if (route === "#/domains") return "domains";
  if (route.startsWith("#/public-access/")) return "public-access";
  if (route === "#/networks") return "networks";
  if (route === "#/settings") return "settings";
  return "overview";
}

/** 子页面标题直接描述当前位置，一级导航只负责标识所属能力。 */
function routeTitle(route: AppRoute): string {
  if (route === "#/devices/list") return "设备";
  if (route === "#/devices/enrollments") return "入网请求";
  if (route === "#/devices/official") return "官方客户端";
  if (route === "#/access-control") return "访问控制";
  if (route === "#/domains") return "域名与 HTTPS";
  if (route === "#/public-access/tunnels") return "内网穿透";
  if (route === "#/public-access/domain") return "域名与 HTTPS";
  if (route === "#/networks") return "网络互联";
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
  tunnel_count?: number;
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

type TailscaleClientConfig = {
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
  tenant_id: string;
  left_site_id: string;
  right_site_id: string;
  left_site_name: string;
  right_site_name: string;
  left_networks: SiteLinkNetworkSummary[];
  right_networks: SiteLinkNetworkSummary[];
  static_routes: StaticRouteGuide[];
  route_statuses: SiteLinkRouteStatus[];
  route_confirmations?: { site_id: string; confirmed_at: number }[];
  enabled: boolean;
  apply_status: "disabled" | "checking" | "applying" | "ready" | "retrying" | "failed";
  apply_error: string | null;
  health_status: "ready" | "degraded" | "failed" | "disabled";
  health_error: string | null;
  deletion_pending: boolean;
};

type SiteLinkNetworkSummary = {
  id: string;
  name: string;
  prefix: string;
  source: "detected" | "manual" | string;
  address_family: "ipv4" | "ipv6" | string;
  publisher_device_id: string;
  publisher_device_name: string;
  gateway_address: string | null;
  apply_status: SiteLink["apply_status"];
};

type SiteLinkRouteStatus = {
  network_id: string;
  router_site_id: string;
  destination_site_id: string;
  destination_prefix: string;
  address_family: "ipv4" | "ipv6" | string;
  device_status: string;
  control_plane_status: string;
  remote_status: string;
  error: string | null;
  checked_at: number | null;
};

type SiteNetwork = {
  id: string;
  tenant_id: string;
  site_id: string;
  site_name: string;
  name: string;
  publisher_device_name: string;
  publisher_device_id: string;
  interface_id: string | null;
  source: "detected" | "manual" | string;
  gateway_address: string | null;
  desired_prefix: string;
  applied_prefix: string | null;
  enabled: boolean;
  apply_status: SiteLink["apply_status"];
  apply_error: string | null;
  health_status: SiteLink["health_status"];
  health_error: string | null;
  deletion_pending: boolean;
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
  const [actionLinkId, setActionLinkId] = useState<string | null>(null);
  const [actionNetworkId, setActionNetworkId] = useState<string | null>(null);
  const [networkFormSiteId, setNetworkFormSiteId] = useState<string | null>(null);
  const [linkFormSiteId, setLinkFormSiteId] = useState<string | null>(null);
  const [editingSiteLink, setEditingSiteLink] = useState<SiteLink | null>(null);
  const [showTunnelForm, setShowTunnelForm] = useState(false);
  const [showSiteForm, setShowSiteForm] = useState(false);
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

  // 公网域名是实例级设置，只对系统管理员开放；普通用户直接打开旧链接时
  // 回到自己的穿透列表，避免先渲染一个必然 403 的空页面。
  useEffect(() => {
    if (auth.role === "tenant" && route === "#/domains") {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/public-access/tunnels`);
      setRoute("#/public-access/tunnels");
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
      const page = primaryRoute(route);
      if (page === "overview") {
        const [nextOverview, nextEnrollments, nextTunnels, nextNetworks, nextLinks] = await Promise.all([
          read<Overview>("/api/v1/overview", "暂时无法读取概览"),
          read<Enrollment[]>("/api/v1/enrollments", "暂时无法读取入网请求"),
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取穿透服务"),
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
        if (route === "#/devices/official") {
          const [clientConfigResponse, authKeysResponse] = await Promise.all([
            request("/api/v1/mesh/client-config"),
            request("/api/v1/mesh/auth-keys"),
          ]);
          const clientConfigBody: unknown = await clientConfigResponse.json().catch(() => null);
          const authKeysBody: unknown = await authKeysResponse.json().catch(() => null);
          if (!clientConfigResponse.ok) throw new Error(readApiError(clientConfigBody, "暂时无法读取官方客户端配置"));
          if (!authKeysResponse.ok) throw new Error(readApiError(authKeysBody, "暂时无法读取 Auth Key"));
          setTailscaleClientConfig(clientConfigBody as TailscaleClientConfig);
          setTailscaleAuthKeys(authKeysBody as TailscaleAuthKey[]);
          if (auth.role === "system_admin") {
            const externalNodesResponse = await request("/api/v1/mesh/external-nodes");
            const externalNodesBody: unknown = await externalNodesResponse.json().catch(() => null);
            if (!externalNodesResponse.ok) throw new Error(readApiError(externalNodesBody, "暂时无法同步外部节点"));
            setTailscaleExternalNodes(externalNodesBody as TailscaleExternalNode[]);
          } else {
            setTailscaleExternalNodes([]);
          }
        }
      } else if (page === "access-control") {
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
      } else if (page === "domains") {
        const domainsResponse = await request("/api/v1/public-domains");
        const domainsBody: unknown = await domainsResponse.json().catch(() => null);
        if (domainsResponse.ok) {
          setPublicDomains(Array.isArray(domainsBody) ? domainsBody as PublicDomain[] : []);
        } else {
          setPublicDomains([]);
          throw new Error(readApiError(domainsBody, "暂时无法读取域名与 HTTPS 配置"));
        }
      } else if (page === "public-access") {
        const [nextTunnels, nextDevices] = await Promise.all([
          read<Tunnel[]>("/api/v1/tunnels", "暂时无法读取穿透服务"),
          read<Device[]>("/api/v1/devices", "暂时无法读取设备"),
        ]);
        setTunnels(nextTunnels); setDevices(nextDevices);
        const domainsResponse = await request("/api/v1/public-domains");
        const domainsBody: unknown = await domainsResponse.json().catch(() => null);
        if (domainsResponse.ok) setPublicDomains(Array.isArray(domainsBody) ? domainsBody as PublicDomain[] : []);
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
    if (!hasPendingGatewayChanges || route !== "#/networks") {
      return;
    }
    const timer = window.setInterval(() => {
      void refreshCurrentPage();
    }, 4000);
    return () => window.clearInterval(timer);
  }, [hasPendingGatewayChanges, refreshCurrentPage, route]);

  const hasPendingPublicDomainChanges = publicDomains.some((domain) =>
    ["pending", "checking", "configuring", "retrying", "rate_limited"].includes(domain.apply_status.toLowerCase()),
  );
  useEffect(() => {
    if (!hasPendingPublicDomainChanges || route !== "#/domains") {
      return;
    }
    const timer = window.setInterval(() => void refreshCurrentPage(), 5000);
    return () => window.clearInterval(timer);
  }, [hasPendingPublicDomainChanges, refreshCurrentPage, route]);

  const pendingDeletionIds = [
    ...siteNetworks.filter((item) => item.deletion_pending).map((item) => `network:${item.id}`),
    ...siteLinks.filter((item) => item.deletion_pending).map((item) => `link:${item.id}`),
  ];
  const hasVisiblePendingDeletion = pendingDeletionIds.length > 0
    && (route === "#/overview" || route === "#/networks" || route === "#/public-access/tunnels");
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
              siteLinks={siteLinks}
              error={error}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route.startsWith("#/devices/") && (
            <DevicesPage
              auth={auth}
              route={route}
              devices={devices}
              sites={sites}
              enrollments={enrollments}
              meshStatus={meshStatus}
              clientConfig={tailscaleClientConfig}
              authKeys={tailscaleAuthKeys}
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
          {route === "#/access-control" && (
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
          {route === "#/domains" && (
            <DomainsPage
              domains={publicDomains}
              error={error}
              request={request}
              onRefresh={refreshCurrentPage}
            />
          )}
          {route.startsWith("#/public-access/") && (
            <PublicAccessPage
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
          {route === "#/networks" && (
            <NetworksPage
              sites={sites}
              devices={devices}
              publicDomains={publicDomains}
              siteNetworks={siteNetworks}
              siteLinks={siteLinks}
              error={error}
              request={request}
              showSiteForm={showSiteForm}
              networkFormSiteId={networkFormSiteId}
              linkFormSiteId={linkFormSiteId}
              editingSiteLink={editingSiteLink}
              onToggleSiteForm={() => setShowSiteForm((visible) => !visible)}
              onOpenNetworkForm={setNetworkFormSiteId}
              onCloseNetworkForm={() => setNetworkFormSiteId(null)}
              onOpenLinkForm={setLinkFormSiteId}
              onCloseLinkForm={() => { setLinkFormSiteId(null); setEditingSiteLink(null); }}
              onEditLink={(link) => { setEditingSiteLink(link); setLinkFormSiteId(link.left_site_id); }}
              onToggleNetwork={toggleSiteNetwork}
              onToggleLink={toggleSiteLink}
              onRecheckLink={recheckSiteLink}
              onConfirmRoute={confirmRoute}
              actionNetworkId={actionNetworkId}
              actionLinkId={actionLinkId}
              deletingResource={deletingResource}
              onDeleteSite={(site) => void deleteResource(
                `site:${site.id}`,
                `/api/v1/sites/${encodeURIComponent(site.id)}`,
                `确定删除站点“${site.name}”吗？仅空站点可以删除，此操作无法撤销。`,
                "暂时无法删除站点",
              )}
              onDeleteNetwork={(network) => void deleteResource(
                `network:${network.id}`,
                `/api/v1/site-networks/${encodeURIComponent(network.id)}`,
                `确定删除共享网络“${network.name}”吗？路由会先撤销，确认完成后永久删除。`,
                "暂时无法删除共享网络",
              )}
              onDeleteLink={(link) => void deleteResource(
                `link:${link.id}`,
                `/api/v1/site-links/${encodeURIComponent(link.id)}`,
                `确定删除“${link.left_site_name} ↔ ${link.right_site_name}”的互联关系吗？两侧路由撤销后将永久删除。`,
                "暂时无法删除站点互联",
              )}
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
          publicDomains={publicDomains}
          request={request}
          returnFocus={editTrigger}
          onUpdated={applyTunnelUpdate}
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
          sites={sites}
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
      {navigationItems.filter((item) => !item.systemOnly || role === "system_admin").map((item) => {
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
  siteLinks,
  error,
  onRefresh,
}: {
  auth: AuthStatus;
  overview: Overview;
  enrollments: Enrollment[];
  tunnels: Tunnel[];
  siteNetworks: SiteNetwork[];
  siteLinks: SiteLink[];
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
  const failedHref: AppRoute = failedTunnels ? "#/public-access/tunnels" : failedNetworks || failedLinks ? "#/networks" : "#/overview";
  const applyingHref: AppRoute = applyingTunnels ? "#/public-access/tunnels" : "#/networks";
  return (
    <>
      <PageHeader eyebrow="运行状态" title="概览" subtitle="先处理异常，再进入具体页面完成配置。" />
      <section className="metric-grid" aria-label="系统概览">
        <Metric label="设备" value={overview.devices} hint="已加入 Nexo" />
        <Metric label="已生效穿透服务" value={overview.running_tunnels} hint="公网地址可用" />
        <Metric label="互联设备" value={overview.mesh_devices} hint="已加入网络互联" />
        <Metric label="在线设备" value={overview.current_connections} hint="当前与服务端连接" />
      </section>
      <PageError error={error} onRetry={onRefresh} />
      {auth.local_http_warning && (
        <div className="notice warning" role="status">
          <AlertTriangle size={18} aria-hidden="true" />
          <div><strong>当前为未加密 HTTP</strong><span>仅在可信局域网使用；需要远程管理时，请先配置公网 HTTPS。</span></div>
          <a className="notice-action" href="#/public-access/domain">前往配置</a>
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
            <QuickLink icon={Globe2} title="内网穿透" detail="管理 Web 服务与 TCP 端口" href="#/public-access/tunnels" />
            <QuickLink icon={Network} title="网络互联" detail="配置站点、共享网络与互联" href="#/networks" />
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
  auth,
  route,
  devices,
  sites,
  enrollments,
  meshStatus,
  clientConfig,
  authKeys,
  externalNodes,
  error,
  showEnrollmentForm,
  onToggleEnrollmentForm,
  onCloseEnrollmentForm,
  onApprove,
  request,
  onRefresh,
  deletingResource,
  onEditDevice,
  onDeleteDevice,
}: {
  auth: AuthStatus;
  route: AppRoute;
  devices: Device[];
  sites: Site[];
  enrollments: Enrollment[];
  meshStatus: MeshStatus | null;
  clientConfig: TailscaleClientConfig | null;
  authKeys: TailscaleAuthKey[];
  externalNodes: TailscaleExternalNode[];
  error: string | null;
  showEnrollmentForm: boolean;
  onToggleEnrollmentForm: () => void;
  onCloseEnrollmentForm: () => void;
  onApprove: (enrollment: Enrollment) => Promise<void>;
  request: ApiRequest;
  onRefresh: () => Promise<void>;
  deletingResource: string | null;
  onEditDevice: (device: Device, trigger: HTMLButtonElement) => void;
  onDeleteDevice: (device: Device, trigger: HTMLButtonElement) => void;
}) {
  const pending = enrollments.filter((item) => item.status === "awaiting_approval");
  const enrollmentView = route === "#/devices/enrollments";
  const officialView = route === "#/devices/official";
  return (
    <>
      <PageHeader
        eyebrow="设备管理"
        title={officialView ? "官方客户端" : enrollmentView ? "入网请求" : "设备"}
        subtitle={officialView ? "连接官方 Tailscale 客户端，完成浏览器授权或使用 Auth Key。" : enrollmentView ? "生成一次性配置，并批准可信设备加入。" : "查看设备在线状态、地址与网关能力。"}
        action={enrollmentView ? (
          <button className="primary-button" type="button" onClick={onToggleEnrollmentForm} aria-expanded={showEnrollmentForm}>
            <Plus size={16} aria-hidden="true" />添加设备
          </button>
        ) : undefined}
      />
      <SectionTabs label="设备页面" route={route} items={[
        { href: "#/devices/list", label: "设备列表", icon: MonitorSmartphone },
        { href: "#/devices/enrollments", label: `入网请求${pending.length ? ` (${pending.length})` : ""}`, icon: UserPlus },
        { href: "#/devices/official", label: "官方客户端", icon: KeyRound },
      ]} />
      <PageError error={error} onRetry={onRefresh} />
      {officialView ? (
        <OfficialClientPanel
          isSystemAdmin={auth.role === "system_admin"}
          clientConfig={clientConfig}
          authKeys={authKeys}
          externalNodes={externalNodes}
          request={request}
          onRefresh={onRefresh}
        />
      ) : enrollmentView ? (
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
          <div className="panel-heading"><div><p className="eyebrow">设备状态</p><h2 id="device-list-heading" tabIndex={-1}>{devices.length} 台设备</h2></div><span className="status-pill ready"><i />当前状态</span></div>
          {devices.length === 0 ? <EmptyState icon={Server} title="还没有加入设备" detail="请从入网请求页面添加第一台设备。" /> : <div className="device-list">{devices.map((device) => <DeviceRow key={device.id} device={device} sites={sites} deleting={deletingResource === `device:${device.id}`} onEdit={(trigger) => onEditDevice(device, trigger)} onDelete={(trigger) => onDeleteDevice(device, trigger)} />)}</div>}
        </section>
      )}
    </>
  );
}

/** 官方客户端控制面：浏览器授权由 Headscale 完成，Nexo 负责凭证、隔离节点
 * 和工作空间认领。Auth Key 明文只在创建成功时展示，刷新后不会再次出现。 */
function OfficialClientPanel({
  isSystemAdmin,
  clientConfig,
  authKeys,
  externalNodes,
  request,
  onRefresh,
}: {
  isSystemAdmin: boolean;
  clientConfig: TailscaleClientConfig | null;
  authKeys: TailscaleAuthKey[];
  externalNodes: TailscaleExternalNode[];
  request: ApiRequest;
  onRefresh: () => Promise<void>;
}) {
  const [label, setLabel] = useState("我的客户端");
  const [ttl, setTtl] = useState("604800");
  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [tags, setTags] = useState("");
  const [createdKey, setCreatedKey] = useState<TailscaleAuthKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const createKey = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(null); setMessage(null); setCreatedKey(null);
    try {
      const response = await request("/api/v1/mesh/auth-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          label,
          ttl_seconds: Number(ttl),
          reusable,
          ephemeral,
          tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法创建 Auth Key"));
      setCreatedKey(body as TailscaleAuthKey);
      await onRefresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法创建 Auth Key");
    } finally {
      setBusy(false);
    }
  };
  const revokeKey = async (key: TailscaleAuthKey) => {
    if (!window.confirm(`确定吊销“${key.label}”吗？已使用的客户端不会被自动退出。`)) return;
    setBusy(true); setError(null);
    try {
      const response = await request(`/api/v1/mesh/auth-keys/${encodeURIComponent(key.id)}/revoke`, { method: "POST" });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法吊销 Auth Key"));
      setMessage("Auth Key 已吊销");
      await onRefresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法吊销 Auth Key");
    } finally {
      setBusy(false);
    }
  };
  const claimNode = async (node: TailscaleExternalNode) => {
    setBusy(true); setError(null);
    try {
      const response = await request(`/api/v1/mesh/external-nodes/${encodeURIComponent(node.node_id)}/claim`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: node.name }),
      });
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) throw new Error(readApiError(body, "暂时无法认领外部节点"));
      setMessage(`已认领“${node.name}”，设备已加入当前工作空间`);
      await onRefresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "暂时无法认领外部节点");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="official-client-layout">
      <section className="panel page-panel official-client-hero">
        <div className="panel-heading">
          <div><p className="eyebrow">官方客户端</p><h2>使用同一套网络入口连接设备</h2></div>
          <span className="status-pill ready"><i />协议支持</span>
        </div>
        <div className="official-client-facts">
          <div><span>登录服务器</span><code>{clientConfig?.login_server ?? "正在读取…"}</code></div>
          <div><span>授权方式</span><strong>由客户端发起</strong></div>
          <div><span>平台</span><strong>{clientConfig?.supported_platforms.join("、") ?? "Linux、Windows、macOS、iOS、Android、tvOS"}</strong></div>
        </div>
        <p className="form-hint">请在官方 Tailscale 客户端填写登录服务器并开始连接，客户端会打开带本次注册上下文的一次性授权页面；授权完成后设备先保持隔离，确认归属后才进入当前工作空间。只有 Nexo Agent 设备可作为穿透或网关。</p>
      </section>
      <div className="official-client-grid">
        <section className="panel page-panel">
          <div className="panel-heading"><div><p className="eyebrow">Auth Key</p><h2>生成客户端密钥</h2></div></div>
          <form className="inline-form" onSubmit={(event) => void createKey(event)} aria-busy={busy}>
            <label><span>名称</span><input value={label} onChange={(event) => setLabel(event.target.value)} required /></label>
            <div className="form-grid official-key-options">
              <label><span>有效期（秒）</span><input type="number" min="60" max="2592000" value={ttl} onChange={(event) => setTtl(event.target.value)} required /></label>
              <label className="checkbox-field"><input type="checkbox" checked={reusable} onChange={(event) => setReusable(event.target.checked)} /><span>可重复使用</span></label>
              <label className="checkbox-field"><input type="checkbox" checked={ephemeral} onChange={(event) => setEphemeral(event.target.checked)} /><span>临时设备</span></label>
            </div>
            <label><span>标签（逗号分隔）</span><input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="tag:team" /></label>
            <button className="primary-button" type="submit" disabled={busy}><KeyRound size={16} aria-hidden="true" />{busy ? "正在创建…" : "生成 Auth Key"}</button>
          </form>
          {createdKey?.key && <div className="secret-reveal" role="status"><strong>只显示这一次</strong><code>{createdKey.key}</code><button className="secondary-button compact-button" type="button" onClick={() => void navigator.clipboard.writeText(createdKey.key ?? "")}><Copy size={15} aria-hidden="true" />复制密钥</button></div>}
          {error && <p className="form-error" role="alert">{error}</p>}
          {message && <p className="form-success" role="status">{message}</p>}
        </section>
        <section className="panel page-panel">
          <div className="panel-heading"><div><p className="eyebrow">已发布密钥</p><h2>{authKeys.length} 个 Auth Key</h2></div></div>
          {authKeys.length === 0 ? <EmptyState icon={KeyRound} title="还没有 Auth Key" detail="生成一个短时密钥后，在官方客户端中粘贴使用。" /> : <div className="auth-key-list">{authKeys.map((key) => <div className="auth-key-row" key={key.id}><div><strong>{key.label}</strong><span>{key.reusable ? "可重复使用" : "单次使用"} · {key.ephemeral ? "临时设备" : "持久设备"}</span></div><span className={`status-pill ${key.state === "issued" ? "working" : "disabled"}`}><i />{key.state}</span><button className="icon-button" type="button" aria-label={`吊销${key.label}`} title="吊销 Auth Key" disabled={busy || key.state !== "issued"} onClick={() => void revokeKey(key)}><Trash2 size={16} aria-hidden="true" /></button></div>)}</div>}
        </section>
      </div>
      {isSystemAdmin && <section className="panel page-panel">
        <div className="panel-heading"><div><p className="eyebrow">隔离节点</p><h2>等待认领的官方客户端</h2></div><button className="secondary-button compact-button" type="button" disabled={busy} onClick={() => void onRefresh()}><RefreshCw size={15} aria-hidden="true" />同步节点</button></div>
        {externalNodes.length === 0 ? <EmptyState icon={ShieldCheck} title="没有待认领节点" detail="完成浏览器授权或客户端登录后，节点会在这里等待确认。" /> : <div className="external-node-list">{externalNodes.map((node) => <div className="external-node-row" key={node.node_id}><div><strong>{node.name}</strong><span>{node.addresses.join(" · ") || "地址待同步"}</span></div><span className={`status-pill ${node.online ? "ready" : "disabled"}`}><i />{node.online ? "在线" : "离线"}</span><button className="primary-button compact-button" type="button" disabled={busy} onClick={() => void claimNode(node)}><CheckCircle2 size={15} aria-hidden="true" />认领</button></div>)}</div>}
      </section>}
    </div>
  );
}

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
      <PageHeader eyebrow="策略与共享" title="访问控制" subtitle="按资源所有权建立直接授权，策略由 Nexo 生成并交给 Headscale 校验。" action={<button className="secondary-button" type="button" onClick={() => void onRefresh()}><RefreshCw size={15} aria-hidden="true" />刷新</button>} />
      <PageError error={error} onRetry={onRefresh} />
      <section className="panel access-policy-preview" aria-labelledby="access-policy-preview-heading">
        <div className="panel-heading"><div><p className="eyebrow">影响预览</p><h2 id="access-policy-preview-heading">当前结构化策略</h2></div><div className="panel-heading-actions"><span className={`status-pill ${preview ? previewStatusClass : "working"}`}><i />{preview ? previewStatusLabel : "等待校验"}</span><button className="secondary-button compact-button" type="button" onClick={() => void onRefresh()}><RefreshCw size={15} aria-hidden="true" />重新校验</button></div></div>
        <p className="panel-note">{preview?.summary ?? "先创建或校验一条规则，页面会显示受影响目标和 Headscale 校验结果。"}</p>
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
        {rules.length === 0 ? <EmptyState icon={ShieldCheck} title="还没有访问规则" detail="保存一条规则后，直接授权会出现在这里。" /> : <div className="access-rule-table" role="table" aria-label="访问规则列表"><div className="access-rule-table-head" role="row"><span role="columnheader">规则</span><span role="columnheader">目标</span><span role="columnheader">直接授权</span><span role="columnheader">状态</span><span role="columnheader">操作</span></div>{rules.map((rule) => <div className="access-rule-table-row" role="row" key={rule.id}><div role="cell"><strong>{rule.name}</strong><small>{rule.protocols.join(" / ").toUpperCase()} · {rule.ports.join(", ")}{rule.ssh_enabled ? " · SSH" : ""}</small></div><div role="cell"><strong>{rule.target_label}</strong><small>{rule.target_type === "device" ? "设备" : rule.target_type === "network" ? "共享网络" : rule.target_type}</small></div><div role="cell"><span>{rule.grants.length > 0 ? rule.grants.map((grant) => grant.workspace_name).join("、") : "未授权"}</span></div><div role="cell"><span className={`entry-state ${rule.apply_status === "ready" ? "ready" : rule.apply_status === "error" ? "error" : "applying"}`}><i />{rule.apply_status === "ready" ? (rule.enabled ? "已生效" : "已撤销") : rule.apply_status === "error" ? "需要重试" : "处理中"}</span>{rule.apply_error && <small className="access-rule-error">{rule.apply_error}</small>}</div><div role="cell" className="access-rule-row-actions"><button className="icon-button" type="button" aria-label={`编辑${rule.name}`} title="编辑" onClick={() => setEditing(rule)}><Pencil size={16} aria-hidden="true" /></button>{rule.enabled && <button className="delete-icon-button" type="button" aria-label={`撤销${rule.name}`} title="撤销" disabled={busy} onClick={() => void revoke(rule)}><PowerOff size={16} aria-hidden="true" /></button>}</div></div>)}</div>}
      </section>
    </>
  );
}

function DomainsPage({ domains, error, request, onRefresh }: {
  domains: PublicDomain[];
  error: string | null;
  request: ApiRequest;
  onRefresh: () => Promise<void>;
}) {
  return <>
    <PageHeader eyebrow="公网基础设施" title="域名与 HTTPS" subtitle="统一管理公网入口、网络互联地址和 Web 服务使用的域名。" />
    <PageError error={error} onRetry={onRefresh} />
    <PublicDomainsPanel domains={domains} request={request} onRefresh={onRefresh} />
  </>;
}

function PublicAccessPage({
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
      if (!response.ok) throw new Error(readApiError(body, enabled ? "暂时无法批量启用穿透服务" : "暂时无法批量停用穿透服务"));
      const result = body as BatchTunnelResponse;
      setBatchMessage(result.message);
      setSelectedTunnelIds(enabled ? result.skipped.map((item) => item.id) : []);
      await onRefresh();
    } catch (requestError) {
      setBatchError(requestError instanceof Error ? requestError.message : "暂时无法批量更新穿透服务");
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
        eyebrow="公网访问"
        title="内网穿透"
        subtitle="将设备上的 Web 服务或 TCP 端口安全开放到公网。"
        action={<button className="primary-button" type="button" onClick={onOpenCreate}><Plus size={16} aria-hidden="true" />添加穿透服务</button>}
      />
      <PageError error={error} onRetry={onRefresh} />
      <section className={`domain-dependency-notice ${publicDomainReady ? "ready" : "warning"}`}>
        <div><strong>{publicDomainReady ? `Web 服务默认使用 ${primaryDomain?.domain}` : "Web 服务域名尚未就绪"}</strong><span>{publicDomainReady ? "域名证书与路由由系统统一管理。" : "TCP 穿透不受影响；创建或启用 Web 穿透前需要可用的主域名。"}</span></div>
        <a className="secondary-button compact-button" href="#/domains">管理域名</a>
      </section>
      <section className="panel page-panel">
        <div className="panel-heading tunnel-panel-heading">
          <div><p className="eyebrow">穿透服务</p><h2 id="tunnel-list-heading" tabIndex={-1}>{tunnels.length} 个穿透服务</h2></div>
          {selectedTunnelIds.length > 0 && <div className="batch-toolbar" role="toolbar" aria-label="穿透服务批量操作">
            <span className="batch-selection-count">已选 {selectedTunnelIds.length} 项</span>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={() => void runBatchToggle(true)}><Power size={15} aria-hidden="true" />启用</button>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={() => void runBatchToggle(false)}><PowerOff size={15} aria-hidden="true" />停用</button>
            <button className="secondary-button compact-button" type="button" disabled={batchBusy} onClick={(event) => { setBatchDeviceTrigger(event.currentTarget); setBatchDeviceDialog(true); }}><RefreshCw size={15} aria-hidden="true" />更换设备</button>
            <button className="danger-button compact-button" type="button" disabled={batchBusy} onClick={(event) => { setBatchDeleteTrigger(event.currentTarget); setBatchDeleteDialog(true); }}><Trash2 size={15} aria-hidden="true" />删除</button>
          </div>}
        </div>
        {(batchMessage || batchError) && <p className={batchError ? "network-error batch-feedback" : "action-status batch-feedback"} role={batchError ? "alert" : "status"}>{batchError ?? batchMessage}</p>}
        {tunnels.length === 0 ? (
          <EmptyState icon={Globe2} title="还没有穿透服务" detail="添加 Web 服务或 TCP 端口后，配置生效状态会显示在这里。" />
        ) : (
          <div className="tunnel-list">
            <div className="tunnel-list-header">
              <label className="selection-control"><input ref={selectAllRef} type="checkbox" checked={allTunnelsSelected} onChange={(event) => toggleAllTunnels(event.target.checked)} aria-label="全选穿透服务" disabled={selectableTunnels.length === 0} /><span>全选</span></label>
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
        <FormDialog eyebrow="内网穿透" title="添加穿透服务" description="选择设备和本地服务，将 Web 服务或 TCP 端口开放到公网。" onClose={onCloseCreate}>
          <CreateTunnelForm devices={devices} publicDomains={publicDomains} request={request} onCancel={onCloseCreate} onCreated={async () => { onCloseCreate(); await onRefresh(); }} />
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
    case "ready": return { kind: "ready", label: "READY" };
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
    case "ready": return "READY";
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
        <EmptyState icon={Globe2} title="还没有公网域名" detail="添加根域名后，可以配置公网入口、网络互联地址和 Web 服务。" />
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
                  <div className="domain-identity" role="cell"><div className="domain-title"><strong>{domain.domain}</strong>{domain.is_primary && <span className="domain-primary-badge">主域名</span>}</div><span>{domain.usage_count} 个 Web 服务{domain.is_primary ? " · 网络互联" : ""}</span></div>
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
    if (!deletingOnlyPrimary && domain.usage_count > 0 && !replacement) { setError("该域名仍被服务使用，请先选择已 READY 的替代域名"); return; }
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
    ? "删除唯一主域名会关闭公网域名入口，但保留穿透服务配置和启用状态。"
    : "删除会清理该域名的凭据目录；已绑定服务必须先迁移到另一个已就绪域名。";
  return <FormDialog eyebrow="域名与 HTTPS" title={`删除 ${domain.domain}`} description={description} onClose={onClose} returnFocus={returnFocus} role="alertdialog" compact initialFocusSelector="input[type=checkbox]"><form className="domain-delete-form" aria-busy={busy} onSubmit={submit}>{deletingOnlyPrimary ? <div className="domain-delete-impact"><strong>将关闭以下公网能力</strong><p>Nexo 管理入口、Mesh 公网入口和全部 Web 穿透公网路由会停止生成。</p><p>{domain.usage_count} 个 Web 穿透服务会保留并解除域名绑定；添加新的首个主域名后，未显式绑定的服务会重新使用它。</p><p>Cloudflare DNS 默认保留，Headscale 地址回退到内部地址，设备不会被自动要求重新认证。</p></div> : <p>{deletingPrimaryWithAlternatives ? "请先从更多操作中把一个已就绪域名设为主域名。未完成的主域名迁移仍会阻止删除。" : "此操作不可撤销。未完成的主域名迁移仍会阻止删除。"}</p>}{!deletingOnlyPrimary && domain.usage_count > 0 && <label><span>替代域名</span><select value={replacement} onChange={(event) => setReplacement(event.target.value)}><option value="">选择已就绪的域名</option>{candidates.map((item) => <option key={item.id} value={item.id}>{item.domain}</option>)}</select></label>}<label className="confirmation-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>{deletingOnlyPrimary ? "我确认关闭公网域名入口并删除该域名及凭据" : "我确认删除该域名及其凭据"}</span></label>{error && <p className="form-error" role="alert">{error}</p>}<div className="dialog-actions"><button className="secondary-button" type="button" onClick={onClose} disabled={busy}>取消</button><button className="danger-button" type="submit" disabled={busy || deletingPrimaryWithAlternatives}>{busy ? "删除中…" : "确认删除"}</button></div></form></FormDialog>;
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
  return <FormDialog eyebrow="主域名迁移" title={`将 ${domain.domain} 设为主域名`} description="切换会保留旧域名和别名，直到所有设备完成 ACK；迁移激活后不能取消。" onClose={() => { if (!active && !busy) onClose(); }} returnFocus={returnFocus} role="alertdialog"><form className="domain-primary-form" aria-busy={busy || active} onSubmit={submit}><div className="migration-impact"><strong>切换前检查</strong><p>目标域名的根证书和泛域名证书已 READY。Web Service 会迁移到新主域名，在线设备立即处理，离线设备上线后继续。</p><p>mesh.{domain.domain} 必须 DNS only；Nexo 会保留旧入口，直到设备逐台确认。</p></div>{migration && <div className="migration-progress" role="status" aria-live="polite"><div><span>{statusLabel}</span><strong>{migration.acknowledged_devices}/{migration.total_devices} 台设备已确认</strong></div><progress max={Math.max(migration.total_devices, 1)} value={migration.acknowledged_devices} /><small>{migration.last_error ?? "任务可恢复，页面轮询会在离开时停止。"}</small></div>}{!migration && <label className="confirmation-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>我已阅读影响并确认启动不可取消的迁移</span></label>}{error && <p className="form-error" role="alert">{error}</p>}<div className="dialog-actions"><button className="secondary-button" type="button" onClick={onClose} disabled={active || busy}>取消</button>{!migration && <button className="primary-button" type="submit" disabled={busy}>{busy ? "启动中…" : "开始迁移"}</button>}{migration && !active && <button className="primary-button" type="button" onClick={onClose}>关闭</button>}</div></form></FormDialog>;
}

function NetworksPage({
  sites,
  devices,
  publicDomains,
  siteNetworks,
  siteLinks,
  error,
  request,
  showSiteForm,
  networkFormSiteId,
  linkFormSiteId,
  editingSiteLink,
  onToggleSiteForm,
  onOpenNetworkForm,
  onCloseNetworkForm,
  onOpenLinkForm,
  onCloseLinkForm,
  onEditLink,
  onToggleNetwork,
  onToggleLink,
  onRecheckLink,
  onConfirmRoute,
  actionNetworkId,
  actionLinkId,
  deletingResource,
  onDeleteSite,
  onDeleteNetwork,
  onDeleteLink,
  onRefresh,
}: {
  sites: Site[];
  devices: Device[];
  publicDomains: PublicDomain[];
  siteNetworks: SiteNetwork[];
  siteLinks: SiteLink[];
  error: string | null;
  request: ApiRequest;
  showSiteForm: boolean;
  networkFormSiteId: string | null;
  linkFormSiteId: string | null;
  editingSiteLink: SiteLink | null;
  onToggleSiteForm: () => void;
  onOpenNetworkForm: (siteId: string) => void;
  onCloseNetworkForm: () => void;
  onOpenLinkForm: (siteId: string) => void;
  onCloseLinkForm: () => void;
  onEditLink: (link: SiteLink) => void;
  onToggleNetwork: (network: SiteNetwork) => Promise<void>;
  onToggleLink: (link: SiteLink) => Promise<void>;
  onRecheckLink: (link: SiteLink) => Promise<void>;
  onConfirmRoute: (link: SiteLink, siteId: string) => Promise<void>;
  actionNetworkId: string | null;
  actionLinkId: string | null;
  deletingResource: string | null;
  onDeleteSite: (site: Site) => void;
  onDeleteNetwork: (network: SiteNetwork) => void;
  onDeleteLink: (link: SiteLink) => void;
  onRefresh: () => Promise<void>;
}) {
  const [expandedSiteIds, setExpandedSiteIds] = useState<Set<string>>(() => new Set());
  const [networkView, setNetworkView] = useState<"topology" | "sites">("topology");
  const [selectedTopologyLink, setSelectedTopologyLink] = useState<SiteLink | null>(null);
  const [selectedMobileLink, setSelectedMobileLink] = useState<SiteLink | null>(null);
  const networkFormSite = sites.find((site) => site.id === networkFormSiteId);
  const linkFormSite = sites.find((site) => site.id === linkFormSiteId);
  const primaryDomain = publicDomains.find((domain) => domain.is_primary);
  const meshEntryReady = Boolean(primaryDomain
    && dnsCheckLabel(primaryDomain.dns_check.wildcard).kind === "ready"
    && primaryDomain.wildcard_certificate.status.toLowerCase() === "ready");

  /** 展开状态按站点独立保存，便于同时对照两个站点的互联状态。 */
  const toggleSite = (siteId: string) => {
    setExpandedSiteIds((current) => {
      const next = new Set(current);
      if (next.has(siteId)) next.delete(siteId);
      else next.add(siteId);
      return next;
    });
  };

  const action = (
    <button className="primary-button" type="button" onClick={onToggleSiteForm} aria-expanded={showSiteForm}><Plus size={16} aria-hidden="true" />新建站点</button>
  );
  return (
    <>
      <PageHeader eyebrow="局域网互联" title="网络互联" subtitle="按站点管理网关、共享网络、互联关系和本站静态路由。" action={action} />
      <PageError error={error} onRetry={onRefresh} />
      <section className={`domain-dependency-notice ${meshEntryReady ? "ready" : "warning"}`}>
        <div><strong>{meshEntryReady ? `网络入口 mesh.${primaryDomain?.domain} 已就绪` : "网络互联公网入口尚未就绪"}</strong><span>{meshEntryReady ? "设备继续使用统一的安全控制地址。" : "现有局域网路由配置会保留；新增设备公网接入前请完成主域名和 HTTPS 配置。"}</span></div>
        <a className="secondary-button compact-button" href="#/domains">管理域名</a>
      </section>
      <div className="network-view-switch" role="tablist" aria-label="网络互联视图">
        <button type="button" role="tab" aria-selected={networkView === "topology"} className={networkView === "topology" ? "selected" : ""} onClick={() => setNetworkView("topology")}><Network size={15} aria-hidden="true" />互联拓扑</button>
        <button type="button" role="tab" aria-selected={networkView === "sites"} className={networkView === "sites" ? "selected" : ""} onClick={() => setNetworkView("sites")}><Building2 size={15} aria-hidden="true" />站点与网段</button>
      </div>
      {showSiteForm && <CreateSiteForm request={request} onCreated={onRefresh} onDone={onToggleSiteForm} />}
      <NetworkTopology
        sites={sites}
        siteNetworks={siteNetworks}
        siteLinks={siteLinks}
        selectedLink={selectedTopologyLink}
        onSelectLink={setSelectedTopologyLink}
        onSelectSite={(siteId) => { setNetworkView("sites"); setExpandedSiteIds((current) => new Set(current).add(siteId)); }}
        onToggleLink={onToggleLink}
        onRecheckLink={onRecheckLink}
        onEditLink={onEditLink}
        onDeleteLink={onDeleteLink}
        actionPending={actionLinkId}
      />
      <section className={`panel page-panel network-sites-panel network-relations-view${networkView === "sites" ? "" : " desktop-hidden"}`}>
        {sites.length === 0 ? <EmptyState icon={Building2} title="还没有站点" detail="创建家庭、办公室等站点后，才能配置共享网络。" /> : (
          <div className="network-site-list">
            <div className="network-site-columns" aria-hidden="true">
              <span>站点</span><span>网关设备</span><span>共享网络</span><span>互联关系</span><span />
            </div>
            {sites.map((site) => {
              const siteDevices = devices.filter((device) => device.site_id === site.id);
              const gatewayDevices = siteDevices.filter((device) =>
                device.gateway_report?.subnet_gateway === "ready" || device.gateway_report?.site_gateway === "ready",
              );
              const subnetGatewayDevices = siteDevices.filter((device) =>
                device.gateway_report?.subnet_gateway === "ready" && (device.gateway_report.local_networks?.length ?? 0) > 0,
              );
              const networks = siteNetworks.filter((network) => network.site_id === site.id);
              const links = siteLinks.filter((link) => link.left_site_id === site.id || link.right_site_id === site.id);
              const networkIssues = networks.filter(hasGatewayIssue).length;
              const linkIssues = links.filter(hasGatewayIssue).length;
              const connectedSites = new Set(links.map((link) => link.left_site_id === site.id ? link.right_site_id : link.left_site_id));
              const enabledNetworks = networks.filter((network) => network.enabled);
              const targetSites = sites.filter((candidate) => candidate.id !== site.id && candidate.tenant_id === site.tenant_id && siteNetworks.some((network) => network.site_id === candidate.id && network.enabled));
              const canAddNetwork = subnetGatewayDevices.length > 0;
              const canConnect = enabledNetworks.length > 0 && targetSites.length > 0;
              const expanded = expandedSiteIds.has(site.id);
              const detailsId = `site-network-details-${site.id}`;
              return (
                <article className={`network-site${expanded ? " expanded" : ""}`} key={site.id}>
                  <div className="network-site-summary">
                    <div className="network-site-identity"><span className="site-icon"><Building2 size={18} aria-hidden="true" /></span><div className="network-site-identity-text"><strong>{site.name}</strong><span>{siteDevices.length} 台设备</span></div></div>
                    <div className="network-site-fact"><span className="network-site-label">网关设备</span><strong>{gatewayDevices.length ? gatewayDevices.map((device) => device.name).join("、") : "尚未就绪"}</strong></div>
                    <div className="network-site-fact"><span className="network-site-label">共享网络</span><strong>{networks.length} 个{networkIssues ? ` · ${networkIssues} 个异常` : " · 无异常"}</strong></div>
                    <div className="network-site-fact"><span className="network-site-label">互联关系</span><strong>{connectedSites.size} 个站点{linkIssues ? ` · ${linkIssues} 个异常` : " · 无异常"}</strong></div>
                    <div className="network-site-controls">
                      <button className="delete-icon-button" type="button" aria-label={`删除站点${site.name}`} title="删除站点" disabled={deletingResource === `site:${site.id}`} onClick={() => onDeleteSite(site)}>
                        <Trash2 size={17} aria-hidden="true" />
                      </button>
                      <button className="network-site-toggle" type="button" aria-expanded={expanded} aria-controls={detailsId} aria-label={`${expanded ? "收起" : "展开"}${site.name}`} onClick={() => toggleSite(site.id)}>
                        <ChevronDown size={18} aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                  {expanded && (
                    <div className="network-site-details" id={detailsId}>
                      <section className="network-inline-section" aria-labelledby={`${detailsId}-networks`}>
                        <div className="network-inline-heading"><div><h2 id={`${detailsId}-networks`}>共享网络</h2><p>本站向已连接站点开放的局域网网段。</p></div><button className="secondary-button compact-button" type="button" onClick={() => onOpenNetworkForm(site.id)} disabled={!canAddNetwork}><Plus size={15} aria-hidden="true" />添加共享网络</button></div>
                        {!canAddNetwork && <p className="network-prerequisite">需要本站有一台共享网络能力就绪、且已探测到本地网段的设备。</p>}
                        {networks.length === 0 ? <p className="network-inline-empty">本站还没有共享网络。</p> : <div className="network-list">{networks.map((network) => <SiteNetworkRow key={network.id} network={network} actionPending={actionNetworkId === network.id || deletingResource === `network:${network.id}`} onToggle={() => void onToggleNetwork(network)} onDelete={() => onDeleteNetwork(network)} />)}</div>}
                      </section>
                      <section className="network-inline-section" aria-labelledby={`${detailsId}-links`}>
                        <div className="network-inline-heading"><div><h2 id={`${detailsId}-links`}>互联关系</h2><p>本站与其他站点的连接，以及本站需要配置的静态路由。</p></div><button className="secondary-button compact-button" type="button" onClick={() => onOpenLinkForm(site.id)} disabled={!canConnect}><Plus size={15} aria-hidden="true" />连接站点</button></div>
                        {!canConnect && <p className="network-prerequisite">{enabledNetworks.length === 0 ? "请先为本站添加并启用一个共享网络。" : "需要另一个站点具备已启用的共享网络。"}</p>}
                        {links.length === 0 ? <p className="network-inline-empty">本站还没有连接其他站点。</p> : <div className="link-list">{links.map((link) => <SiteLinkCard key={link.id} link={link} currentSiteId={site.id} actionPending={actionLinkId === link.id || deletingResource === `link:${link.id}`} onToggle={() => void onToggleLink(link)} onRecheck={() => void onRecheckLink(link)} onConfirmRoute={(siteId) => void onConfirmRoute(link, siteId)} onEdit={() => onEditLink(link)} onDelete={() => onDeleteLink(link)} onOpenDetails={() => setSelectedMobileLink(link)} />)}</div>}
                      </section>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>
      {networkFormSite && (
        <FormDialog eyebrow="共享网络" title="添加共享网络" description={`为“${networkFormSite.name}”选择网关设备及其最近探测到的本地网段。`} onClose={onCloseNetworkForm}>
          <CreateSiteNetworkForm sourceSiteId={networkFormSite.id} sites={sites} devices={devices} request={request} onCancel={onCloseNetworkForm} onCreated={async () => { onCloseNetworkForm(); await onRefresh(); }} />
        </FormDialog>
      )}
      {linkFormSite && (
        <FormDialog eyebrow="站点互联" title={editingSiteLink ? "编辑互联关系" : "连接站点"} description={`从“${linkFormSite.name}”配置两侧网关、网段和下一跳。`} onClose={onCloseLinkForm}>
          <CreateSiteLinkForm sourceSiteId={linkFormSite.id} sites={sites} devices={devices} siteNetworks={siteNetworks} request={request} initialLink={editingSiteLink} onCancel={onCloseLinkForm} onCreated={async () => { onCloseLinkForm(); await onRefresh(); }} />
        </FormDialog>
      )}
      {selectedMobileLink && (
        <MobileSiteLinkDetail
          link={selectedMobileLink}
          actionPending={actionLinkId === selectedMobileLink.id || deletingResource === `link:${selectedMobileLink.id}`}
          onClose={() => setSelectedMobileLink(null)}
          onToggle={() => void onToggleLink(selectedMobileLink)}
          onRecheck={() => void onRecheckLink(selectedMobileLink)}
          onEdit={() => onEditLink(selectedMobileLink)}
          onDelete={() => onDeleteLink(selectedMobileLink)}
        />
      )}
    </>
  );
}

function hasGatewayIssue(item: SiteNetwork | SiteLink): boolean {
  return item.apply_status === "failed" || item.health_status === "failed" || item.health_status === "degraded";
}

/** 桌面端只读拓扑：节点与连线可聚焦、可点击，位置由当前站点顺序计算。 */
function NetworkTopology({
  sites,
  siteNetworks,
  siteLinks,
  selectedLink,
  onSelectLink,
  onSelectSite,
  onToggleLink,
  onRecheckLink,
  onEditLink,
  onDeleteLink,
  actionPending,
}: {
  sites: Site[];
  siteNetworks: SiteNetwork[];
  siteLinks: SiteLink[];
  selectedLink: SiteLink | null;
  onSelectLink: (link: SiteLink | null) => void;
  onSelectSite: (siteId: string) => void;
  onToggleLink: (link: SiteLink) => Promise<void>;
  onRecheckLink: (link: SiteLink) => Promise<void>;
  onEditLink: (link: SiteLink) => void;
  onDeleteLink: (link: SiteLink) => void;
  actionPending: string | null;
}) {
  const width = 1000;
  // 4 列以内保持一行；5-12 个站点分成 2-3 行，避免节点名称在桌面端互相遮挡。
  const columns = Math.min(4, Math.max(1, sites.length));
  const rows = Math.ceil(sites.length / columns);
  const height = rows === 1 ? 280 : rows === 2 ? 420 : 560;
  const positionFor = (index: number) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    const x = columns === 1 ? width / 2 : 110 + (column * (width - 220)) / (columns - 1);
    const y = rows === 1 ? height / 2 : 72 + (row * (height - 144)) / (rows - 1);
    return { x, y };
  };
  const siteIndex = new Map(sites.map((site, index) => [site.id, index]));
  return (
    <section className="panel page-panel network-topology" aria-labelledby="network-topology-heading">
      <div className="topology-heading"><div><h2 id="network-topology-heading">互联拓扑</h2><p>选择节点查看站点网段，选择连线查看逐阶段状态。</p></div><span className="topology-scale">{sites.length} 个站点 · {siteLinks.length} 条关系</span></div>
      {sites.length < 2 ? <p className="network-inline-empty">至少需要两个站点才能显示互联拓扑。</p> : <div className="topology-layout">
        <div className="topology-canvas" style={{ aspectRatio: `${width} / ${height}` }}>
          <svg className="topology-lines" viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
            {siteLinks.map((link) => {
              const left = positionFor(siteIndex.get(link.left_site_id) ?? 0);
              const right = positionFor(siteIndex.get(link.right_site_id) ?? 0);
              return <line key={link.id} x1={left.x} y1={left.y} x2={right.x} y2={right.y} className={selectedLink?.id === link.id ? "selected" : ""} />;
            })}
          </svg>
          <div className="topology-nodes">
            {sites.map((site, index) => {
              const networks = siteNetworks.filter((network) => network.site_id === site.id);
              const position = positionFor(index);
              return <button key={site.id} type="button" className="topology-node" style={{ left: `${(position.x / width) * 100}%`, top: `${(position.y / height) * 100}%` }} onClick={() => onSelectSite(site.id)} aria-label={`查看站点${site.name}`}>
                <Building2 size={18} aria-hidden="true" /><strong>{site.name}</strong><span>{networks.length} 个共享网段</span>
              </button>;
            })}
          </div>
          <div className="topology-link-buttons">
            {siteLinks.map((link) => {
              const left = positionFor(siteIndex.get(link.left_site_id) ?? 0);
              const right = positionFor(siteIndex.get(link.right_site_id) ?? 0);
              return <button key={link.id} type="button" className={`topology-link-button${selectedLink?.id === link.id ? " selected" : ""}`} style={{ left: `${(((left.x + right.x) / 2) / width) * 100}%`, top: `${(((left.y + right.y) / 2) / height) * 100}%` }} onClick={() => onSelectLink(selectedLink?.id === link.id ? null : link)} aria-label={`查看${link.left_site_name}与${link.right_site_name}的互联`}>
                <span className={`link-status ${siteLinkStatus(link.apply_status).kind}`}><i />{siteLinkStatus(link.apply_status).label}</span>
              </button>;
            })}
          </div>
        </div>
        {selectedLink && <aside className="topology-detail" aria-label="互联详情">
          <div className="topology-detail-heading"><div><span className="eyebrow">互联详情</span><h3>{selectedLink.left_site_name} ↔ {selectedLink.right_site_name}</h3></div><button className="icon-button" type="button" aria-label="关闭互联详情" title="关闭" onClick={() => onSelectLink(null)}><X size={17} aria-hidden="true" /></button></div>
          <div className="topology-network-pairs"><div><strong>{selectedLink.left_site_name}</strong>{selectedLink.left_networks.map((network) => <code key={network.id}>{network.prefix}</code>)}</div><ArrowRight size={16} aria-hidden="true" /><div><strong>{selectedLink.right_site_name}</strong>{selectedLink.right_networks.map((network) => <code key={network.id}>{network.prefix}</code>)}</div></div>
          <div className="topology-status-list">{selectedLink.route_statuses.map((status) => <div key={`${status.router_site_id}-${status.network_id}`}><span>{status.destination_prefix}</span><small>{routeStageLabel("device", status.device_status)} · {routeStageLabel("control", status.control_plane_status)} · {routeStageLabel("remote", status.remote_status)}{status.error ? ` · ${status.error}` : ""}</small></div>)}</div>
          <div className="topology-detail-actions"><button className="secondary-button compact-button" type="button" onClick={() => onEditLink(selectedLink)}>编辑</button><button className="secondary-button compact-button" type="button" disabled={actionPending === selectedLink.id} onClick={() => void onRecheckLink(selectedLink)}>重试</button><button className="secondary-button compact-button" type="button" disabled={actionPending === selectedLink.id} onClick={() => void onToggleLink(selectedLink)}>{selectedLink.enabled ? "停用" : "启用"}</button><button className="delete-icon-button" type="button" aria-label="删除互联关系" title="删除" onClick={() => onDeleteLink(selectedLink)}><Trash2 size={16} aria-hidden="true" /></button></div>
        </aside>}
      </div>}
    </section>
  );
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
  wide = false,
  variant = "modal",
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
  wide?: boolean;
  variant?: "modal" | "sheet";
  initialFocusSelector?: string;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const returnFocus = useRef<HTMLElement | null>(explicitReturnFocus ?? document.activeElement as HTMLElement | null);
  const titleId = useRef(`dialog-${Math.random().toString(36).slice(2)}`);
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
      onCancel={(event) => { event.preventDefault(); if (!submitting()) onClose(); }}
      onClick={(event) => { if (event.target === event.currentTarget && !submitting()) onClose(); }}
    >
      <div className={`form-dialog-surface${compact ? " compact" : ""}${wide ? " wide" : ""}`} onClick={(event) => event.stopPropagation()}>
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

function DeviceRow({ device, sites, deleting, onEdit, onDelete }: { device: Device; sites: Site[]; deleting: boolean; onEdit: (trigger: HTMLButtonElement) => void; onDelete: (trigger: HTMLButtonElement) => void }) {
  const online = device.status === "online";
  const subnetReady = device.gateway_report?.subnet_gateway === "ready";
  const siteReady = device.gateway_report?.site_gateway === "ready";
  const familyAvailability = device.gateway_report ? gatewayFamilyAvailability(device.gateway_report) : null;
  const siteName = device.site_id ? sites.find((site) => site.id === device.site_id)?.name ?? "未知站点" : "未分配站点";
  const tailscaleAddresses = Array.from(new Set([
    device.tailscale_ipv4,
    device.tailscale_ipv6,
    device.mesh_address,
  ].filter((address): address is string => Boolean(address))));
  const connectionLabel = device.connection_type === "tailscale_client" ? "官方 Tailscale" : "Nexo Agent";
  const registrationLabel = device.registration_method === "auth_key" ? "Auth Key" : device.registration_method === "oidc" ? "OIDC" : device.registration_method === "browser" ? "浏览器授权" : null;
  return (
    <div className="device-row">
      <span className={`device-avatar ${online ? "online" : ""}`}>{device.name.slice(0, 1).toUpperCase()}</span>
      <div className="device-identity">
        <strong>{device.name}</strong>
        <span>{siteName} · {[device.os, device.architecture, device.agent_version].filter(Boolean).join(" · ") || "设备信息待上报"}</span>
      </div>
      <div className="device-capabilities">
        <span className={`device-status ${online ? "online" : "offline"}`}><i />{online ? "在线" : "离线"}</span>
        <span className="capability">{connectionLabel}</span>
        {device.owner_username && <span className="capability">所有者：{device.owner_username}</span>}
        {registrationLabel && <span className="capability">注册：{registrationLabel}</span>}
        <span className={`capability ${device.mesh_status === "connected" ? "ready" : ""}`}>网络互联：{meshStatusLabel(device.mesh_status)}</span>
        {tailscaleAddresses.map((address) => <span className="capability" key={address}>{address}</span>)}
        {device.tags?.length ? <span className="capability">标签：{device.tags.join("、")}</span> : null}
        {device.expires_at && <span className="capability">有效期至 {formatSessionTime(device.expires_at)}</span>}
        {device.control_plane_state && <span className="capability">控制面：{device.control_plane_state}</span>}
        {device.gateway_report && (
          <span className={`capability ${subnetReady ? "ready" : ""}`}>共享网络 {subnetReady && familyAvailability ? familyAvailability : "待检查"}</span>
        )}
        {device.gateway_report && (
          <span className={`capability ${siteReady ? "ready" : ""}`}>站点互联 {siteReady && familyAvailability ? familyAvailability : "待检查"}</span>
        )}
      </div>
      <button className="icon-button" type="button" aria-label={`编辑设备${device.name}`} title="编辑设备" disabled={deleting} onClick={(event) => onEdit(event.currentTarget)}>
        <Pencil size={17} aria-hidden="true" />
      </button>
      <button className="delete-icon-button" type="button" aria-label={deleting ? `正在删除设备${device.name}` : `删除设备${device.name}`} aria-busy={deleting} title="删除设备" disabled={deleting} onClick={(event) => onDelete(event.currentTarget)}>
        <Trash2 size={17} aria-hidden="true" />
      </button>
    </div>
  );
}

/** 设备资料编辑窗；名称和所属站点是本地资料，提交时由 Server 再校验站点归属。 */
function EditDeviceDialog({
  device,
  sites,
  request,
  returnFocus,
  onUpdated,
  onClose,
}: {
  device: Device;
  sites: Site[];
  request: ApiRequest;
  returnFocus: HTMLButtonElement | null;
  onUpdated: (updated: Device) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(device.name);
  const [siteId, setSiteId] = useState(device.site_id ?? "");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <FormDialog
      eyebrow="设备管理"
      title="编辑设备"
      description="修改设备名称或所属站点。正在承载共享网络或站点网关的设备不能跨站点移动。"
      returnFocus={returnFocus}
      onClose={onClose}
    >
      <form className="inline-form network-form-table" aria-busy={submitting} onSubmit={async (event) => {
        event.preventDefault();
        if (!name.trim()) {
          setError("设备名称不能为空");
          return;
        }
        setSubmitting(true);
        setError(null);
        try {
          const response = await request(`/api/v1/devices/${encodeURIComponent(device.id)}`, {
            method: "PUT",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ name: name.trim(), site_id: siteId || null }),
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
          <label><span>设备名称</span><input autoFocus value={name} onChange={(event) => setName(event.target.value)} required /></label>
          <label><span>所属站点</span><select value={siteId} onChange={(event) => setSiteId(event.target.value)}><option value="">未分配站点</option>{sites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}</select></label>
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
      description={`设备“${device.name}”的身份和组网节点会立即撤销。${tunnelCount} 个穿透服务将保留为未分配并关闭。`}
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
          <p>删除设备不会删除穿透服务，它们会立即停止公网入口。若设备仍承载共享网络或活动站点网关，服务端仍会阻止删除。</p>
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

/**
 * 共享网络创建表单：只呈现站点、设备和 Agent 已探测到的本地网段。
 * 表单提交后由服务端再次校验能力和网段，避免浏览器状态成为配置真源。
 */
function CreateSiteNetworkForm({
  sourceSiteId,
  sites,
  devices,
  request,
  onCancel,
  onCreated,
}: {
  sourceSiteId: string;
  sites: Site[];
  devices: Device[];
  request: ApiRequest;
  onCancel: () => void;
  onCreated: () => Promise<void>;
}) {
  const siteId = sourceSiteId;
  const [source, setSource] = useState<"detected" | "manual">("detected");
  const [deviceId, setDeviceId] = useState("");
  const [networkKey, setNetworkKey] = useState("");
  const [manualPrefix, setManualPrefix] = useState("");
  const [manualError, setManualError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selectedSite = sites.find((site) => site.id === siteId);
  const eligibleDevices = devices.filter(
    (device) => device.site_id === siteId && device.gateway_report?.subnet_gateway === "ready",
  );
  const selectedDevice = eligibleDevices.find((device) => device.id === deviceId);
  const localNetworks = selectedDevice?.gateway_report?.local_networks ?? [];
  const selectedNetworkCandidate = localNetworks.find((network) => `${network.interface_id}|${network.prefix}` === networkKey);
  const selectedNetwork = selectedNetworkCandidate
    && selectedDevice?.gateway_report
    && !forwardingRequirement(selectedDevice.gateway_report, selectedNetworkCandidate.prefix)
    ? selectedNetworkCandidate
    : undefined;

  const validateManualPrefix = (value: string): string | null => {
    const trimmed = value.trim();
    if (!trimmed) return "请输入要共享的 CIDR";
    const slash = trimmed.lastIndexOf("/");
    if (slash <= 0 || slash === trimmed.length - 1) return "请输入合法的 IPv4 或 IPv6 CIDR";
    const address = trimmed.slice(0, slash);
    const prefixLength = Number(trimmed.slice(slash + 1));
    const ipv6 = address.includes(":");
    const max = ipv6 ? 128 : 32;
    if (!Number.isInteger(prefixLength) || prefixLength < 1 || prefixLength > max) return "不能使用默认路由或无效前缀长度";
    if (!ipv6 && (!/^\d{1,3}(\.\d{1,3}){3}$/.test(address) || address.split(".").some((part) => Number(part) > 255))) return "请输入合法的 IPv4 CIDR";
    if (ipv6 && !/^[0-9a-f:]+$/i.test(address)) return "请输入合法的 IPv6 CIDR";
    return null;
  };

  /** Agent 能力更新后清空失效选择，避免提交已经不存在的设备状态。 */
  useEffect(() => {
    if (deviceId && !eligibleDevices.some((device) => device.id === deviceId)) {
      setDeviceId("");
      setNetworkKey("");
    }
  }, [deviceId, eligibleDevices]);

  useEffect(() => {
    if (networkKey && !localNetworks.some((network) => {
      const matches = `${network.interface_id}|${network.prefix}` === networkKey;
      return matches && selectedDevice?.gateway_report
        && !forwardingRequirement(selectedDevice.gateway_report, network.prefix);
    })) {
      setNetworkKey("");
    }
  }, [localNetworks, networkKey, selectedDevice]);

  return (
    <form
      className="inline-form network-form-table"
      aria-busy={submitting}
      onSubmit={async (event) => {
        event.preventDefault();
        const cidrError = source === "manual" ? validateManualPrefix(manualPrefix) : null;
        setManualError(cidrError);
        if (!selectedSite || !selectedDevice || !name.trim() || (source === "detected" && !selectedNetwork) || cidrError) {
          setError("请填写显示名称，并选择站点、网关设备和有效的共享网段");
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
                source,
                interface_id: source === "detected" ? selectedNetwork?.interface_id ?? "" : "",
                prefix: source === "detected" ? selectedNetwork?.prefix ?? "" : manualPrefix.trim(),
            }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) {
            throw new Error(readApiError(body, "暂时无法创建共享网络"));
          }
          setName("");
          setNetworkKey("");
          setManualPrefix("");
          setManualError(null);
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
        <div className="network-source-switch" role="radiogroup" aria-label="共享网段来源">
          <span>网段来源</span>
          <div className="segmented-control">
            <button type="button" role="radio" aria-checked={source === "detected"} className={source === "detected" ? "selected" : ""} onClick={() => { setSource("detected"); setError(null); }}>自动探测</button>
            <button type="button" role="radio" aria-checked={source === "manual"} className={source === "manual" ? "selected" : ""} onClick={() => { setSource("manual"); setError(null); }}>手动填写</button>
          </div>
        </div>
        <label>
          <span>站点</span>
          <select value={siteId} disabled aria-label="来源站点">
            {selectedSite && <option value={selectedSite.id}>{selectedSite.name}</option>}
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
        {source === "detected" ? <label>
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
              const requirement = selectedDevice?.gateway_report
                ? forwardingRequirement(selectedDevice.gateway_report, network.prefix)
                : null;
              return <option key={value} value={value} disabled={Boolean(requirement)}>{network.prefix} · {network.interface_id}{requirement ? ` · ${requirement}` : ""}</option>;
            })}
          </select>
        </label> : <label>
          <span>共享 CIDR</span>
          <input value={manualPrefix} onChange={(event) => { setManualPrefix(event.target.value); setManualError(null); setError(null); }} onBlur={() => setManualError(validateManualPrefix(manualPrefix))} placeholder="192.168.50.0/24 或 2001:db8:50::/64" aria-invalid={Boolean(manualError)} aria-describedby={manualError ? "manual-cidr-error" : undefined} required />
          {manualError && <small className="field-error" id="manual-cidr-error">{manualError}</small>}
        </label>}
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-footer">
        <span className="form-hint">
          {sites.length === 0 ? "还没有可用站点。" : eligibleDevices.length === 0 ? "该站点暂无可用于共享网络的设备。" : source === "detected" ? "自动探测会严格匹配 Agent 最近报告的网卡和网段。" : "手动 CIDR 表示该网关可达的网络，服务端会再次检查转发能力。"}
        </span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting || !selectedSite || !selectedDevice || (source === "detected" ? !selectedNetwork : !manualPrefix.trim())}>
            {submitting ? "创建中…" : "创建共享网络"}
          </button>
        </div>
      </div>
    </form>
  );
}

/**
 * SiteLink 三步表单：先确定两侧唯一网关，再选择网段集合，最后逐地址族
 * 确认下一跳。服务端仍是最终校验者，编辑时会清理旧的静态路由确认。
 */
function CreateSiteLinkForm({
  sourceSiteId,
  sites,
  devices,
  siteNetworks,
  request,
  onCancel,
  onCreated,
  initialLink,
}: {
  sourceSiteId: string;
  sites: Site[];
  devices: Device[];
  siteNetworks: SiteNetwork[];
  request: ApiRequest;
  onCancel: () => void;
  onCreated: () => Promise<void>;
  initialLink?: SiteLink | null;
}) {
  const availableNetworks = siteNetworks.filter((network) => network.enabled);
  const leftSiteId = initialLink?.left_site_id ?? sourceSiteId;
  const leftSite = sites.find((site) => site.id === leftSiteId);
  const candidateTargetSites = sites.filter((site) =>
    site.id !== leftSiteId
    && site.tenant_id === leftSite?.tenant_id
    && availableNetworks.some((network) => network.site_id === site.id),
  );
  const [rightSiteId, setRightSiteId] = useState(initialLink?.right_site_id ?? candidateTargetSites[0]?.id ?? "");
  const [leftGatewayId, setLeftGatewayId] = useState(initialLink?.left_networks?.[0]?.publisher_device_id ?? "");
  const [rightGatewayId, setRightGatewayId] = useState(initialLink?.right_networks?.[0]?.publisher_device_id ?? "");
  const [leftNetworkIds, setLeftNetworkIds] = useState<string[]>(initialLink?.left_networks?.map((network) => network.id) ?? []);
  const [rightNetworkIds, setRightNetworkIds] = useState<string[]>(initialLink?.right_networks?.map((network) => network.id) ?? []);
  const [step, setStep] = useState(1);
  const [leftIpv4, setLeftIpv4] = useState("");
  const [leftIpv6, setLeftIpv6] = useState("");
  const [rightIpv4, setRightIpv4] = useState("");
  const [rightIpv6, setRightIpv6] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const leftGatewayOptions = devices.filter((device) => device.site_id === leftSiteId && device.gateway_report?.site_gateway === "ready");
  const rightGatewayOptions = devices.filter((device) => device.site_id === rightSiteId && device.gateway_report?.site_gateway === "ready");
  const leftNetworks = availableNetworks.filter((network) => network.site_id === leftSiteId && (!leftGatewayId || network.publisher_device_id === leftGatewayId));
  const selectedLeftNetworks = leftNetworks.filter((network) => leftNetworkIds.includes(network.id));
  const targetSites = candidateTargetSites;
  const rightNetworks = availableNetworks.filter((network) => network.site_id === rightSiteId && (!rightGatewayId || network.publisher_device_id === rightGatewayId));
  const selectedRightNetworks = rightNetworks.filter((network) => rightNetworkIds.includes(network.id));
  const rightSite = sites.find((site) => site.id === rightSiteId);
  const selectedLeftFamilies = new Set(selectedLeftNetworks.map((network) => networkAddressFamily(network.desired_prefix)));
  const selectedRightFamilies = new Set(selectedRightNetworks.map((network) => networkAddressFamily(network.desired_prefix)));
  const familyMismatch = selectedLeftFamilies.size !== selectedRightFamilies.size || [...selectedLeftFamilies].some((family) => !selectedRightFamilies.has(family));
  const selectedLeftDevice = leftGatewayOptions.find((device) => device.id === leftGatewayId);
  const selectedRightDevice = rightGatewayOptions.find((device) => device.id === rightGatewayId);
  const gatewayAddress = (device: Device | undefined, family: "ipv4" | "ipv6") => device?.gateway_report?.local_networks?.find((network) => network.gateway_address && networkAddressFamily(network.gateway_address) === family)?.gateway_address ?? "";

  useEffect(() => {
    if (!leftGatewayId && leftGatewayOptions[0]) setLeftGatewayId(leftGatewayOptions[0].id);
  }, [leftGatewayId, leftGatewayOptions]);
  useEffect(() => {
    if (!rightGatewayId && rightGatewayOptions[0]) setRightGatewayId(rightGatewayOptions[0].id);
  }, [rightGatewayId, rightGatewayOptions]);
  useEffect(() => {
    if (!leftIpv4 && selectedLeftFamilies.has("ipv4")) setLeftIpv4(gatewayAddress(selectedLeftDevice, "ipv4"));
    if (!leftIpv6 && selectedLeftFamilies.has("ipv6")) setLeftIpv6(gatewayAddress(selectedLeftDevice, "ipv6"));
    if (!rightIpv4 && selectedRightFamilies.has("ipv4")) setRightIpv4(gatewayAddress(selectedRightDevice, "ipv4"));
    if (!rightIpv6 && selectedRightFamilies.has("ipv6")) setRightIpv6(gatewayAddress(selectedRightDevice, "ipv6"));
  }, [leftIpv4, leftIpv6, rightIpv4, rightIpv6, selectedLeftDevice, selectedRightDevice, selectedLeftFamilies, selectedRightFamilies]);

  /**
   * 轮询期间共享网络可能被关闭或删除；目标站点失效时回到当前可用项，
   * 来源站点始终由打开弹窗的站点行锁定。
   */
  useEffect(() => {
    if (!rightSiteId && targetSites.length > 0) {
      setRightSiteId(targetSites[0].id);
      setRightNetworkIds([]);
    }
    if (rightSiteId && !targetSites.some((site) => site.id === rightSiteId)) {
      setRightSiteId(targetSites[0]?.id ?? "");
      setRightNetworkIds([]);
    }
  }, [rightSiteId, targetSites]);

  useEffect(() => {
    setLeftNetworkIds((ids) => ids.filter((id) => leftNetworks.some((network) => network.id === id)));
    setRightNetworkIds((ids) => ids.filter((id) => rightNetworks.some((network) => network.id === id)));
  }, [leftNetworks, rightNetworks]);

  const toggleNetwork = (side: "left" | "right", id: string) => {
    const setter = side === "left" ? setLeftNetworkIds : setRightNetworkIds;
    setter((ids) => ids.includes(id) ? ids.filter((current) => current !== id) : [...ids, id]);
  };

  return (
    <form
      className="inline-form network-form-table"
      aria-busy={submitting}
      onSubmit={async (event) => {
        event.preventDefault();
        if (step < 3) {
          if (step === 1 && (!leftGatewayId || !rightGatewayId || !rightSite)) { setError("请先选择两侧站点和唯一网关"); return; }
          if (step === 2 && (!leftNetworkIds.length || !rightNetworkIds.length || familyMismatch)) { setError(familyMismatch ? "两侧网段的 IPv4/IPv6 地址族集合必须一致" : "每侧至少选择一个共享网络"); return; }
          setError(null); setStep((current) => current + 1); return;
        }
        if (!leftSite || !rightSite || !leftNetworkIds.length || !rightNetworkIds.length || familyMismatch) {
          setError("请完成两侧网关、网段和地址族复核"); return;
        }
        if (leftSite.id === rightSite.id) {
          setError("站点互联需要选择两个不同站点");
          return;
        }
        if (leftSite.tenant_id !== rightSite.tenant_id) {
          setError("暂不支持跨租户建立站点互联");
          return;
        }
        if ((selectedLeftFamilies.has("ipv4") && !leftIpv4) || (selectedLeftFamilies.has("ipv6") && !leftIpv6) || (selectedRightFamilies.has("ipv4") && !rightIpv4) || (selectedRightFamilies.has("ipv6") && !rightIpv6)) { setError("请为每个实际使用的地址族确认下一跳"); return; }
        setSubmitting(true);
        setError(null);
        try {
          const response = await request(initialLink ? `/api/v1/site-links/${encodeURIComponent(initialLink.id)}` : "/api/v1/site-links", {
            method: initialLink ? "PATCH" : "POST",
            headers: {
              "content-type": "application/json",
            },
            body: JSON.stringify({
              tenant_id: leftSite.tenant_id,
              left_site_id: leftSite.id,
              left_network_ids: leftNetworkIds,
              right_site_id: rightSite.id,
              right_network_ids: rightNetworkIds,
              next_hops: { left: { ipv4: leftIpv4 || null, ipv6: leftIpv6 || null }, right: { ipv4: rightIpv4 || null, ipv6: rightIpv6 || null } },
            }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) {
            throw new Error(readApiError(body, "暂时无法创建站点互联"));
          }
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
          <span>左侧站点</span>
          <select value={leftSiteId} disabled aria-label="来源站点">
            {leftSite && <option value={leftSite.id}>{leftSite.name}</option>}
          </select>
        </label>
        <label>
          <span>目标站点</span>
          <select value={rightSiteId} onChange={(event) => { setRightSiteId(event.target.value); setRightGatewayId(""); setRightNetworkIds([]); }} required>
            <option value="">选择站点</option>
            {targetSites.map((site) => <option key={site.id} value={site.id}>{site.name}</option>)}
          </select>
        </label>
        {step === 1 && <>
          <label><span>左侧 Site Gateway</span><select value={leftGatewayId} onChange={(event) => { setLeftGatewayId(event.target.value); setLeftNetworkIds([]); }} required><option value="">选择网关</option>{leftGatewayOptions.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label>
          <label><span>右侧 Site Gateway</span><select value={rightGatewayId} onChange={(event) => { setRightGatewayId(event.target.value); setRightNetworkIds([]); }} required><option value="">选择网关</option>{rightGatewayOptions.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label>
        </>}
        {step === 2 && <>
          <fieldset className="network-checklist"><legend>左侧网段</legend>{leftNetworks.map((network) => <label key={network.id}><input type="checkbox" checked={leftNetworkIds.includes(network.id)} onChange={() => toggleNetwork("left", network.id)} /><span>{network.name} · {network.desired_prefix}</span></label>)}</fieldset>
          <fieldset className="network-checklist"><legend>右侧网段</legend>{rightNetworks.map((network) => <label key={network.id}><input type="checkbox" checked={rightNetworkIds.includes(network.id)} onChange={() => toggleNetwork("right", network.id)} /><span>{network.name} · {network.desired_prefix}</span></label>)}</fieldset>
        </>}
        {step === 3 && <div className="next-hop-grid">
          {selectedLeftFamilies.has("ipv4") && <label><span>左侧 IPv4 下一跳</span><input value={leftIpv4} onChange={(event) => setLeftIpv4(event.target.value)} placeholder="网关 LAN IPv4" required /></label>}
          {selectedLeftFamilies.has("ipv6") && <label><span>左侧 IPv6 下一跳</span><input value={leftIpv6} onChange={(event) => setLeftIpv6(event.target.value)} placeholder="网关 LAN IPv6" required /></label>}
          {selectedRightFamilies.has("ipv4") && <label><span>右侧 IPv4 下一跳</span><input value={rightIpv4} onChange={(event) => setRightIpv4(event.target.value)} placeholder="网关 LAN IPv4" required /></label>}
          {selectedRightFamilies.has("ipv6") && <label><span>右侧 IPv6 下一跳</span><input value={rightIpv6} onChange={(event) => setRightIpv6(event.target.value)} placeholder="网关 LAN IPv6" required /></label>}
        </div>}
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-footer">
        <span className="form-hint">第 {step} / 3 步 · {step === 1 ? "每侧只能使用一台 Site Gateway。" : step === 2 ? "两侧地址族集合必须一致，重叠网段会被服务端拒绝。" : "下一跳仅用于静态路由指引，不代表真实 LAN 已连通。"}</span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          {step > 1 && <button className="secondary-button" type="button" onClick={() => setStep((current) => current - 1)} disabled={submitting}>上一步</button>}
          <button className="primary-button" type="submit" disabled={submitting}>
            {submitting ? "保存中…" : step < 3 ? "下一步" : initialLink ? "保存互联关系" : "建立站点互联"}
          </button>
        </div>
      </div>
    </form>
  );
}

const RELEASE_AGENT_IMAGE = "ghcr.io/thelinyue/nexo-agent:0.1.14";

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

/** 穿透服务创建表单：仅展示设备、本地服务和用户可理解的访问模式。 */
function CreateTunnelForm({
  devices,
  publicDomains,
  request,
  onCancel,
  onCreated,
}: {
  devices: Device[];
  publicDomains: PublicDomain[];
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
  const [publicDomainId, setPublicDomainId] = useState(publicDomains.find((item) => item.is_primary)?.id ?? publicDomains[0]?.id ?? "");
  const [publicPort, setPublicPort] = useState("");
  const [originProtocol, setOriginProtocol] = useState<"http" | "https">("http");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ field: "device" | "localPort" | "publicPort"; message: string } | null>(null);
  const device = devices.find((item) => item.id === deviceId);
  useEffect(() => {
    if (!deviceId || !devices.some((item) => item.id === deviceId)) setDeviceId(devices[0]?.id ?? "");
  }, [deviceId, devices]);
  useEffect(() => {
    if (publicDomainId && publicDomains.some((item) => item.id === publicDomainId)) return;
    setPublicDomainId(publicDomains.find((item) => item.is_primary)?.id ?? publicDomains[0]?.id ?? "");
  }, [publicDomainId, publicDomains]);
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
            public_domain_id: protocol === "tcp" ? null : publicDomainId || null,
          }),
        });
        const body: unknown = await response.json().catch(() => null);
        if (!response.ok) throw new Error(readApiError(body, "暂时无法添加穿透服务"));
        setName(""); setHostname(""); setPublicPort(""); await onCreated();
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "暂时无法添加穿透服务");
      } finally { setSubmitting(false); }
    }}>
      <fieldset className="form-grid tunnel-form-grid" disabled={submitting}>
        <legend className="sr-only">穿透服务信息</legend>
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
        {protocol !== "tcp" && <label><span>公网域名</span><select value={publicDomainId} onChange={(event) => setPublicDomainId(event.target.value)} disabled={publicDomains.length === 0}><option value="">使用主域名</option>{publicDomains.map((item) => <option key={item.id} value={item.id}>{item.domain}{item.is_primary ? "（主域名）" : ""}</option>)}</select></label>}
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-footer">
        <span className="form-hint">{protocol === "tcp" ? "公网端口范围：20000-29999。" : "子域名前缀会与入口域名组合为完整访问地址。"}</span>
        <div className="form-actions">
          <button className="secondary-button" type="button" onClick={onCancel} disabled={submitting}>取消</button>
          <button className="primary-button" type="submit" disabled={submitting || !device}>{submitting ? "添加中…" : "添加穿透服务"}</button>
        </div>
      </div>
    </form>
  );
}

/** 穿透服务编辑弹窗：基础字段可修改，未展示的 TLS 元数据按适用性原样保留。 */
function EditTunnelDialog({
  tunnel,
  devices,
  publicDomains,
  request,
  returnFocus,
  onUpdated,
  onClose,
}: {
  tunnel: Tunnel;
  devices: Device[];
  publicDomains: PublicDomain[];
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
  const [publicDomainId, setPublicDomainId] = useState(tunnel.public_domain_id ?? publicDomains.find((item) => item.is_primary)?.id ?? publicDomains[0]?.id ?? "");
  const [publicPort, setPublicPort] = useState(tunnel.public_port === null ? "" : String(tunnel.public_port));
  const [originProtocol, setOriginProtocol] = useState<"http" | "https">(tunnel.origin_protocol ?? "http");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ field: "device" | "name" | "address" | "hostname" | "localPort" | "publicPort"; message: string } | null>(null);

  return (
    <FormDialog
      eyebrow="内网穿透"
      title="编辑穿透服务"
      description="修改公网地址与设备本地服务之间的连接信息。"
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
              public_domain_id: protocol === "tcp" ? null : publicDomainId || null,
            }),
          });
          const body: unknown = await response.json().catch(() => null);
          if (!response.ok) throw new Error(readApiError(body, "暂时无法保存穿透服务"));
          onUpdated(body as Tunnel);
          onClose();
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法保存穿透服务");
        } finally {
          setSubmitting(false);
        }
      }}>
        <fieldset className="form-grid tunnel-edit-grid" disabled={submitting}>
          <legend className="sr-only">穿透服务编辑信息</legend>
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
          {protocol !== "tcp" && <label><span>公网域名</span><select value={publicDomainId} onChange={(event) => setPublicDomainId(event.target.value)} disabled={publicDomains.length === 0}><option value="">使用主域名</option>{publicDomains.map((item) => <option key={item.id} value={item.id}>{item.domain}{item.is_primary ? "（主域名）" : ""}</option>)}</select></label>}
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

/** 穿透服务永久删除使用独立确认窗，避免与可恢复的开关操作混淆。 */
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
      title="删除穿透服务"
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
          if (!response.ok) throw new Error(readApiError(body, "暂时无法删除穿透服务"));
          const deletion = body as DeleteResponse | null;
          if (!deletion || deletion.deleted !== true || deletion.pending !== false || deletion.id !== tunnel.id) {
            throw new Error("服务端未确认穿透服务已永久删除");
          }
          onDeleted(deletion);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法删除穿透服务");
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
      eyebrow="内网穿透"
      title="批量更换设备"
      description={`为选中的 ${tunnels.length} 个穿透服务选择新设备；原有启停状态会保留，运行中的连接会立即关闭。`}
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
      title="批量删除穿透服务"
      description={`将永久删除 ${tunnels.length} 个穿透服务及其公网入口，此操作无法恢复。`}
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
          if (!response.ok) throw new Error(readApiError(body, "暂时无法批量删除穿透服务"));
          const result = body as BatchTunnelDeleteResponse | null;
          if (!result || result.deleted_ids.length !== tunnels.length) throw new Error("服务端未确认所有穿透服务已删除");
          onDeleted(result);
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : "暂时无法批量删除穿透服务");
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
      <label className="selection-control tunnel-selection"><input type="checkbox" checked={selected} onChange={(event) => onSelect(event.target.checked)} disabled={tunnel.deletion_pending} aria-label={`选择穿透服务${tunnel.name}`} /><span className="sr-only">选择 {tunnel.name}</span></label>
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
        <span className={`link-status ${statusKind}`}><i />{tunnel.deletion_pending ? "等待删除" : !assigned ? "未分配" : tunnel.enabled ? (tunnel.apply_status === "ready" ? "已生效" : tunnel.apply_status === "failed" ? "配置失败" : "配置生效中") : "已关闭"}</span>
        <button className="link-action" type="button" disabled={actionDisabled} onClick={(event) => onEdit(event.currentTarget)}>编辑</button>
        <button className="link-action" type="button" disabled={actionDisabled || !assigned} title={!assigned ? "请先选择设备" : undefined} onClick={async () => {
          setPending(true);
          setError(null);
          try {
            const response = await request(`/api/v1/tunnels/${encodeURIComponent(tunnel.id)}/${tunnel.enabled ? "disable" : "enable"}`, { method: "POST" });
            const body: unknown = await response.json().catch(() => null);
            if (!response.ok) throw new Error(readApiError(body, tunnel.enabled ? "暂时无法关闭穿透服务" : "暂时无法启用穿透服务"));
            onChanged(body as Tunnel);
          } catch (requestError) {
            setError(requestError instanceof Error ? requestError.message : "暂时无法更新穿透服务");
          } finally {
            setPending(false);
          }
        }}>{pending ? "处理中…" : tunnel.deletion_pending ? "等待删除" : !assigned ? "需先选择设备" : tunnel.enabled ? "关闭" : "启用"}</button>
        <button className="delete-icon-button" type="button" aria-label={`删除穿透服务${tunnel.name}`} title={tunnel.deletion_pending ? "等待删除" : "删除穿透服务"} disabled={actionDisabled} onClick={(event) => onDelete(event.currentTarget)}>
          <Trash2 size={17} aria-hidden="true" />
        </button>
      </div>
      {copyState === "failed" && <p className="network-error" role="alert">浏览器无法访问剪贴板，请手动选择访问地址复制。</p>}
      {error && <p className="network-error" role="alert">{error}</p>}
      {tunnel.apply_error && <p className="network-error">{tunnel.apply_error}</p>}
    </div>
  );
}

/** 站点互联摘要卡片：只显示用户需要的站点、网段、下一跳和应用状态。 */
function SiteLinkCard({
  link,
  currentSiteId,
  actionPending,
  onToggle,
  onRecheck,
  onConfirmRoute,
  onEdit,
  onDelete,
  onOpenDetails,
}: {
  link: SiteLink;
  currentSiteId: string;
  actionPending: boolean;
  onToggle: () => void;
  onRecheck: () => void;
  onConfirmRoute: (siteId: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onOpenDetails: () => void;
}) {
  const status = link.deletion_pending ? { label: "等待删除", kind: "working" } : siteLinkStatus(link.apply_status);
  const actionsDisabled = actionPending || link.deletion_pending;
  const health = gatewayHealthStatus(link.health_status, link.left_networks.some((network) => network.source === "manual") || link.right_networks.some((network) => network.source === "manual"));
  const currentSiteName = link.left_site_id === currentSiteId ? link.left_site_name : link.right_site_name;
  const otherSiteName = link.left_site_id === currentSiteId ? link.right_site_name : link.left_site_name;
  const currentRoutes = link.static_routes.filter((route) => route.router_site_id === currentSiteId);
  return (
    <div className="site-link-card">
      <div className="site-link-heading">
        <div className="site-link-title">
          <strong>{currentSiteName}</strong>
          <span>↔</span>
          <strong>{otherSiteName}</strong>
        </div>
        <div className="site-link-actions">
          <span className={`link-status ${status.kind}`}><i />{status.label}</span>
          <span className={`link-status ${health.kind}`}><i />{health.label}</span>
          <button
            className="link-action"
            type="button"
            onClick={onToggle}
            disabled={actionsDisabled}
            aria-label={link.enabled ? "关闭站点互联" : "重新启用站点互联"}
          >
            {actionPending ? "处理中…" : link.deletion_pending ? "等待删除" : link.enabled ? "关闭" : "启用"}
          </button>
          <button className="link-action" type="button" onClick={onEdit} disabled={actionsDisabled}>编辑</button>
          <button className="link-action" type="button" onClick={onRecheck} disabled={actionsDisabled}>重新检测</button>
          <button className="link-action mobile-detail-trigger" type="button" onClick={onOpenDetails} disabled={actionsDisabled}>查看详情</button>
          <button className="delete-icon-button" type="button" aria-label={`删除${link.left_site_name}到${link.right_site_name}的站点互联`} title={link.deletion_pending ? "等待删除" : "删除站点互联"} disabled={actionsDisabled} onClick={onDelete}>
            <Trash2 size={17} aria-hidden="true" />
          </button>
        </div>
      </div>
      {link.apply_error && <p className="link-error">{link.apply_error}</p>}
      {link.health_error && link.health_error !== link.apply_error && <p className="link-health-error">网关状态：{link.health_error}</p>}
      <div className="route-guide-list">
        {currentRoutes.map((route) => (
          <div className="route-guide" key={`${route.router_site_id}-${route.destination_site_id}-${route.destination_prefix}`}>
            <span className="route-site">{route.router_site_name}</span>
            <span className="route-arrow">→</span>
            <span className="route-destination">{route.destination_site_name} · {route.destination_prefix}</span>
            <span className="route-via">下一跳：{route.next_hop ?? "等待设备地址"}</span>
            {route.router_confirmed ? (
              <span className="route-confirmed">路由已配置</span>
            ) : (
              <button className="route-confirm-button" type="button" disabled={actionsDisabled} onClick={() => onConfirmRoute(route.router_site_id)}>
                确认路由已配置
              </button>
            )}
          </div>
        ))}
        {currentRoutes.length === 0 && <p className="network-inline-empty">本站暂时没有需要确认的静态路由。</p>}
      </div>
    </div>
  );
}

/** 移动端互联详情底部面板；关系列表保留可扫描摘要，详细状态在触发点附近展开。 */
function MobileSiteLinkDetail({
  link,
  actionPending,
  onClose,
  onToggle,
  onRecheck,
  onEdit,
  onDelete,
}: {
  link: SiteLink;
  actionPending: boolean;
  onClose: () => void;
  onToggle: () => void;
  onRecheck: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const status = link.deletion_pending ? { label: "等待删除", kind: "working" } : siteLinkStatus(link.apply_status);
  const health = gatewayHealthStatus(link.health_status, link.left_networks.some((network) => network.source === "manual") || link.right_networks.some((network) => network.source === "manual"));
  const actionsDisabled = actionPending || link.deletion_pending;
  return (
    <aside className="mobile-site-link-detail" aria-label="互联详情">
      <div className="mobile-detail-heading">
        <div>
          <span className="eyebrow">互联详情</span>
          <h2>{link.left_site_name} ↔ {link.right_site_name}</h2>
          <div className="mobile-detail-statuses"><span className={`link-status ${status.kind}`}><i />{status.label}</span><span className={`link-status ${health.kind}`}><i />{health.label}</span></div>
        </div>
        <button className="icon-button" type="button" aria-label="关闭互联详情" title="关闭" onClick={onClose}><X size={17} aria-hidden="true" /></button>
      </div>
      <div className="mobile-detail-network-pairs">
        <div><strong>{link.left_site_name}</strong>{link.left_networks.map((network) => <code key={network.id}>{network.prefix}</code>)}</div>
        <ArrowRight size={16} aria-hidden="true" />
        <div><strong>{link.right_site_name}</strong>{link.right_networks.map((network) => <code key={network.id}>{network.prefix}</code>)}</div>
      </div>
      <div className="mobile-detail-status-list">
        {link.route_statuses.map((route) => (
          <div key={`${route.router_site_id}-${route.network_id}`}>
            <strong>{route.destination_prefix}</strong>
            <span>{routeStageLabel("device", route.device_status)} · {routeStageLabel("control", route.control_plane_status)} · {routeStageLabel("remote", route.remote_status)}</span>
            {route.error && <small>{route.error}</small>}
          </div>
        ))}
        {link.route_statuses.length === 0 && <p className="network-inline-empty">暂时没有逐路由状态。</p>}
      </div>
      <div className="mobile-detail-route-guide">
        {link.static_routes.map((route) => <div key={`${route.router_site_id}-${route.destination_site_id}-${route.destination_prefix}`}><span>{route.router_site_name} → {route.destination_site_name}</span><code>{route.destination_prefix}</code><small>下一跳：{route.next_hop ?? "等待设备地址"}</small></div>)}
      </div>
      <div className="mobile-detail-actions">
        <button className="secondary-button compact-button" type="button" onClick={onEdit} disabled={actionsDisabled}>编辑</button>
        <button className="secondary-button compact-button" type="button" onClick={onRecheck} disabled={actionsDisabled}>重试</button>
        <button className="secondary-button compact-button" type="button" onClick={onToggle} disabled={actionsDisabled}>{link.enabled ? "停用" : "启用"}</button>
        <button className="delete-icon-button" type="button" aria-label="删除互联关系" title="删除" onClick={onDelete} disabled={actionsDisabled}><Trash2 size={16} aria-hidden="true" /></button>
      </div>
    </aside>
  );
}

/** 共享网络行：用已确认网段和应用阶段替代底层路由术语。 */
function SiteNetworkRow({
  network,
  actionPending,
  onToggle,
  onDelete,
}: {
  network: SiteNetwork;
  actionPending: boolean;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const status = network.deletion_pending ? { label: "等待删除", kind: "working" } : siteLinkStatus(network.apply_status);
  const actionsDisabled = actionPending || network.deletion_pending;
  const health = gatewayHealthStatus(network.health_status, network.source === "manual");
  return (
    <div className="network-row">
      <div className="network-identity">
        <strong>{network.name}</strong>
        <span>{network.site_name} · {network.publisher_device_name} · {network.source === "manual" ? "手动声明" : "自动探测"}</span>
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
          disabled={actionsDisabled}
          aria-label={network.enabled ? "停止共享本地网络" : "重新共享本地网络"}
        >
          {actionPending ? "处理中…" : network.deletion_pending ? "等待删除" : network.enabled ? "停止共享" : "重新启用"}
        </button>
        <button className="delete-icon-button" type="button" aria-label={`删除共享网络${network.name}`} title={network.deletion_pending ? "等待删除" : "删除共享网络"} disabled={actionsDisabled} onClick={onDelete}>
          <Trash2 size={17} aria-hidden="true" />
        </button>
      </div>
      {network.health_error && network.health_error !== network.apply_error && <p className="network-health-error">网关状态：{network.health_error}</p>}
    </div>
  );
}

/** 网关健康状态翻译；与 Desired / Applied 状态并列，避免把设备在线当成路由可用。 */
function gatewayHealthStatus(status: SiteLink["health_status"], manual = false): { label: string; kind: string } {
  switch (status) {
    case "ready":
      return { label: manual ? "配置就绪" : "网关正常", kind: "ready" };
    case "degraded":
      return { label: manual ? "配置检查中" : "部分可用", kind: "working" };
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

/** 将路由记录中的内部阶段转换成管理员可直接理解的产品文案。 */
function routeStageLabel(stage: "device" | "control" | "remote", value: string): string {
  if (value === "failed" || value === "upgrade_required") return stage === "device" ? "设备发布失败" : "阶段失败";
  if (value === "disabled") return "已停用";
  if (stage === "device") {
    if (value === "applied") return "设备已发布";
    return "等待设备发布";
  }
  if (stage === "control") {
    if (value === "serving") return "路由服务中";
    if (value === "approved") return "控制端已批准";
    if (value === "discovered") return "控制端已发现";
    return "等待控制端批准";
  }
  if (value === "accepted") return "对端已接受";
  return "等待对端接受";
}

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
  return <AuthShell><p className="eyebrow">安全登录</p><h1>欢迎回来</h1><p className="auth-copy">登录后管理公网访问、设备和网络互联。</p>{notice && <p className="form-success login-notice" role="status">{notice}</p>}<form className="auth-form" onSubmit={async (event) => { event.preventDefault(); setBusy(true); setError(null); try { const response = await fetch("/api/v1/auth/login", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) }); const body = await response.json().catch(() => null) as { user_id?: string; role?: string; workspace_id?: string; csrf_token?: string | null; error?: string; channel?: string }; if (!response.ok) throw new Error(body.error ?? "用户名或密码错误"); onDone({ initialized: true, authenticated: true, user_id: body.user_id ?? null, username, role: body.role ?? "tenant", workspace_id: body.workspace_id ?? null, channel: body.channel ?? "local_http", csrf_token: body.csrf_token ?? null, local_http_warning: body.channel !== "public_https" }); } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "登录失败"); } finally { setBusy(false); } }}><label><span>用户名</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label><label><span>密码</span><input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" required /></label><button className="primary-button" type="submit" disabled={busy}>{busy ? "正在登录…" : "登录"}</button>{error && <p className="form-error" role="alert">{error}</p>}</form><button className="text-button" type="button" onClick={() => setRecovery(true)}>使用恢复码</button></AuthShell>;
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
