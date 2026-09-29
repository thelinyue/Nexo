import { lazy, Suspense, useId, useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Ellipsis, Globe2, House, LogOut, Network, Server, Settings, UserRound, Users } from "./icons";
import type { ManagedWorkspace } from "./accounts";
import { Loading, PageLoadBoundary, Notice, PageAccountContext, PageHeader, UserAvatar, WorkspaceContext, WorkspaceLabelContext, errorText, rememberInteraction, request } from "./ui";
import type { Auth } from "./ui";
import { PageNavigationContext, homeRoute, navigationLocked, rootRoutes, useWorkspaceNavigation } from "./navigation";

/** 按访问页面加载模块；已打开页面仍保留原实例和草稿。 */
const HomePage = lazy(() => import("./home").then(module => ({ default: module.HomePage })));
const UsersPage = lazy(() => import("./accounts").then(module => ({ default: module.UsersPage })));
const AgentsPage = lazy(() => import("./management").then(module => ({ default: module.AgentsPage })));
const NodesPage = lazy(() => import("./nodes").then(module => ({ default: module.NodesPage })));
const DomainsPage = lazy(() => import("./management").then(module => ({ default: module.DomainsPage })));
const ManagePage = lazy(() => import("./management").then(module => ({ default: module.ManagePage })));
const SessionsPage = lazy(() => import("./management").then(module => ({ default: module.SessionsPage })));
const ServicesPage = lazy(() => import("./services").then(module => ({ default: module.ServicesPage })));

const resources = [
  { route: homeRoute, label: "首页", icon: House },
  { route: "#/services", label: "服务", icon: Network },
  { route: "#/agents", label: "设备", icon: Server },
  { route: "#/nodes", label: "节点", icon: Server },
  { route: "#/domains", label: "域名", icon: Globe2 },
];

/** 桌面菜单使用原生 popover 处理外部点击与 Escape，焦点和账号权限始终属于登录人。 */
function AccountMenu({ auth, onLogout }: { auth: Auth; onLogout: () => Promise<void> }) {
  const menu = useRef<HTMLDivElement>(null); const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const close = () => menu.current?.hidePopover();
  // 菜单按实际触发器定位；内容滚动或窗口变化时关闭，避免悬空在旧坐标。
  const position = () => {
    const bounds = trigger.current?.getBoundingClientRect();
    if (!bounds || !menu.current) return;
    menu.current.style.top = `${bounds.bottom + 6}px`;
    menu.current.style.right = `${Math.max(12, window.innerWidth - bounds.right)}px`;
  };
  useEffect(() => {
    const dismiss = (event: Event) => {
      if (event.target instanceof Node && menu.current?.contains(event.target)) return;
      menu.current?.hidePopover();
    };
    window.addEventListener("scroll", dismiss, true); window.addEventListener("resize", dismiss);
    return () => { window.removeEventListener("scroll", dismiss, true); window.removeEventListener("resize", dismiss); };
  }, []);
  return <div className="account-menu">
    <button ref={trigger} className="account-trigger" popoverTarget="account-menu" aria-expanded={open} aria-controls="account-menu" onClick={() => { setError(null); position(); }}><UserAvatar role={auth.role} size={28} /><span title={auth.username}>{auth.username}</span><ChevronDown size={16} aria-hidden="true" /></button>
    <div ref={menu} id="account-menu" popover="auto" className="account-popover" onToggle={event => setOpen((event.nativeEvent as ToggleEvent).newState === "open")} onKeyDown={event => { if (event.key === "Escape") trigger.current?.focus(); }}>
      <a href="#/manage" onClick={close}><Settings size={18} aria-hidden="true" />账号设置</a>
      <button disabled={busy} onClick={async () => { setBusy(true); setError(null); try { await onLogout(); close(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}><LogOut size={18} aria-hidden="true" />{busy ? "退出中…" : "退出登录"}</button>
      <Notice error={error} />
    </div>
  </div>;
}

/** 手机只常驻三个高频入口；低频资源通过原生 popover 选择，关闭后焦点回到触发按钮。 */
function MobileNavigation({ route, desktop, admin }: { route: string; desktop: boolean; admin: boolean }) {
  const id = useId(); const menu = useRef<HTMLDivElement>(null); const trigger = useRef<HTMLButtonElement>(null); const [open, setOpen] = useState(false);
  const more = [...resources.slice(3), { route: "#/manage", label: "账号设置", icon: UserRound }, ...(admin ? [{ route: "#/users", label: "用户管理", icon: Users }] : [])];
  const active = (path: string) => route === path || route.startsWith(`${path}/`);
  const selected = more.some(item => active(item.route)) || route === "#/settings/sessions";
  useEffect(() => { menu.current?.hidePopover(); }, [route, desktop]);
  return <><nav className="bottom-nav" aria-label="底部导航">
    {resources.slice(0, 3).map(item => { const Icon = item.icon; return <a key={item.route} href={item.route} aria-current={active(item.route) ? "page" : undefined} className={active(item.route) ? "active" : ""}><Icon size={22} /><span>{item.label}</span></a>; })}
    <button ref={trigger} type="button" className={selected || open ? "active" : ""} popoverTarget={id} aria-expanded={open} aria-controls={id} aria-label="更多功能"><Ellipsis size={22} /><span>更多</span></button>
  </nav><div ref={menu} id={id} popover="auto" className="mobile-more" onToggle={event => { const shown = (event.nativeEvent as ToggleEvent).newState === "open"; setOpen(shown); if (shown) menu.current?.querySelector<HTMLAnchorElement>("a")?.focus(); }} onKeyDown={event => { if (event.key === "Escape") trigger.current?.focus(); }}>
    <nav aria-label="更多功能">{more.map(item => { const Icon = item.icon; return <a key={item.route} href={item.route} aria-current={active(item.route) ? "page" : undefined} onClick={() => menu.current?.hidePopover()}><Icon size={21} /><span>{item.label}</span>{active(item.route) ? <span className="sr-only">当前页面</span> : null}<ChevronRight size={16} /></a>; })}</nav>
  </div></>;
}

/** 同一业务页面实例跨桌面/手机保留；桌面侧栏和手机底栏仅改变导航呈现。 */
export function Workspace({ auth, onAuth, onExpired, managed, onManage, message, onRenamed, onDeleted }: { auth: Auth; onAuth: (value: Auth) => void; onExpired: () => void; managed: ManagedWorkspace | null; onManage: (value: ManagedWorkspace | null) => void; message: string | null; onRenamed: (username: string) => void; onDeleted: (workspace: string, message: string) => void }) {
  const navigation = useWorkspaceNavigation();
  const { route, desktop } = navigation;
  const desktopItems = [...resources, ...(auth.role === "system_admin" ? [{ route: "#/users", label: "用户管理", icon: Users }] : [])];
  async function logout() {
    if (navigationLocked()) return;
    await request("/api/v1/auth/logout", { method: "POST" }, auth.csrf_token);
    onAuth({ ...auth, authenticated: false });
  }
  function switchWorkspace(value: ManagedWorkspace | null) {
    if (navigationLocked()) return;
    const resume = () => { window.history.replaceState(null, "", homeRoute); onManage(value); };
    if (window.dispatchEvent(new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume } }))) resume();
  }
  useEffect(() => {
    const click = (event: MouseEvent) => {
      if (navigationLocked() && (event.target as Element | null)?.closest('a[href^="#/"]')) event.preventDefault();
    };
    document.addEventListener("click", click, true);
    return () => document.removeEventListener("click", click, true);
  }, []);
  const links = (items: typeof resources) => items.map(item => { const Icon = item.icon; const active = route === item.route || route.startsWith(`${item.route}/`); return <a key={item.route} href={item.route} aria-current={active ? "page" : undefined} className={active ? "active" : ""}><Icon size={22} aria-hidden="true" /><span>{item.label}</span></a>; });
  return <WorkspaceContext.Provider value={managed?.id}><WorkspaceLabelContext.Provider value={managed?.name}>
    <div className="app-shell" data-root-page={rootRoutes.includes(route)} data-detail-page={/^#\/(services|agents|nodes|domains)\//.test(route)} onPointerDownCapture={event => rememberInteraction(event.target)} onKeyDownCapture={() => rememberInteraction(null)}>
      <aside className="sidebar"><div className="sidebar-brand" aria-label="Nexo"><picture aria-hidden="true"><source media="(prefers-color-scheme: dark)" srcSet="/brand/nexo-banner-dark.webp" /><img src="/brand/nexo-banner-light.webp" width="168" height="56" alt="" /></picture></div><nav aria-label="主导航">{links(desktopItems)}</nav></aside>
      <main className="content">
        {message && <p role="status" className="action-status">{message}</p>}
        {managed && <div className="workspace-banner" role="status"><div><strong>{managed.name}</strong><span>管理员访问{!managed.enabled && " · 用户已停用，服务暂停转发"}</span></div><button className="secondary-button" onClick={() => switchWorkspace(null)}>返回我的空间</button></div>}
        {navigation.pages.map(page => {
          const active = page.route === route;
          return <PageNavigationContext.Provider key={page.route} value={{ route: page.route, desktop, deletions: navigation.deletions, removePages: navigation.removePages, openDomainConfiguration: navigation.openDomainConfiguration }}>
            <PageAccountContext.Provider value={active && desktop ? <AccountMenu auth={auth} onLogout={logout} /> : null}>
              <section className="page-slot" id={`page-${encodeURIComponent(page.route)}`} hidden={!active} aria-labelledby={`heading-${encodeURIComponent(page.route)}`}>
                <PageLoadBoundary><Suspense fallback={<Loading />} >{page.route === homeRoute ? <HomePage active={active} auth={auth} managed={managed} /> : page.route.startsWith("#/services") ? <ServicesPage admin={auth.role === "system_admin"} route={page.route} back={page.back} active={active} csrf={auth.csrf_token} /> :
                  page.route.startsWith("#/agents") ? <AgentsPage route={page.route} back={page.back ?? "#/agents"} active={active} csrf={auth.csrf_token} /> :
                  page.route === "#/nodes" ? <NodesPage admin={auth.role === "system_admin"} active={active} csrf={auth.csrf_token} /> :
                  page.route.startsWith("#/domains") ? <DomainsPage route={page.route} back={page.back ?? "#/domains"} initialConfiguration={page.configureDomain} active={active} csrf={auth.csrf_token} /> :
                  <WorkspaceLabelContext.Provider value={undefined}>{page.route === "#/manage" ? <ManagePage auth={auth} active={active} onLogout={logout} onExpired={onExpired} /> : page.route === "#/settings/sessions" ? <SessionsPage auth={auth} active={active} onExpired={onExpired} /> : auth.role === "system_admin" ? <UsersPage active={active} auth={auth} onManage={switchWorkspace} onRenamed={onRenamed} onDeleted={onDeleted} onExpired={onExpired} /> : <><PageHeader title="用户管理" /><Notice error="此页面需要管理员权限" /></>}</WorkspaceLabelContext.Provider>}</Suspense></PageLoadBoundary>
              </section>
            </PageAccountContext.Provider>
          </PageNavigationContext.Provider>;
        })}
      </main>
      <MobileNavigation route={route} desktop={desktop} admin={auth.role === "system_admin"} />
    </div>
  </WorkspaceLabelContext.Provider></WorkspaceContext.Provider>;
}
