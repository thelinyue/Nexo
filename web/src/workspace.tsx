import { lazy, Suspense, useId, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ChevronRight, Ellipsis, Globe2, House, Network, Server, Settings, Users } from "./icons";
import { AccountMenu } from "./account-menu";
import type { ManagedWorkspace } from "./accounts";
import { Loading, MobileCreateContext, WorkspaceHeaderContext, PageLoadBoundary, Notice, PageHeader, WorkspaceContext, WorkspaceLabelContext, rememberInteraction, request } from "./ui";
import type { Auth } from "./ui";
import { PageNavigationContext, homeRoute, navigationLocked, rootRoutes, routeInfo, useWorkspaceNavigation } from "./navigation";

/** 按访问页面加载模块；已打开页面仍保留原实例和草稿。 */
const HomePage = lazy(() => import("./home").then(module => ({ default: module.HomePage })));
const UsersPage = lazy(() => import("./accounts").then(module => ({ default: module.UsersPage })));
const AgentsPage = lazy(() => import("./management").then(module => ({ default: module.AgentsPage })));
const NodesPage = lazy(() => import("./nodes").then(module => ({ default: module.NodesPage })));
const DomainsPage = lazy(() => import("./management").then(module => ({ default: module.DomainsPage })));
const SessionsPage = lazy(() => import("./management").then(module => ({ default: module.SessionsPage })));
const ServerSettingsPage = lazy(() => import("./server-settings").then(module => ({ default: module.ServerSettingsPage })));
const ServicesPage = lazy(() => import("./services").then(module => ({ default: module.ServicesPage })));

const resources = [
  { route: homeRoute, label: "首页", icon: House },
  { route: "#/services", label: "服务", icon: Network },
  { route: "#/agents", label: "设备", icon: Server },
  { route: "#/nodes", label: "节点", icon: Server },
  { route: "#/domains", label: "域名", icon: Globe2 },
];

const adminNavigation = [{ route: "#/users", label: "用户管理", icon: Users }, { route: "#/settings/server", label: "服务器设置", icon: Settings }];

/** 手机只常驻三个高频入口；更多只承载业务和管理员页面，个人操作统一进入头像菜单。
 * 触摸展开不抢焦点，键盘展开才聚焦菜单；选项导航交由目标页面接管焦点。
 * 链接显式进入 Tab 顺序，使 WebKit 默认键盘设置下也能逐项访问。
 */
function MobileNavigation({ route, desktop, admin, standalone }: { route: string; desktop: boolean; admin: boolean; standalone: boolean }) {
  const id = useId(); const menu = useRef<HTMLDivElement>(null); const trigger = useRef<HTMLButtonElement>(null); const [open, setOpen] = useState(false);
  const keyboard = useRef(false);
  const more = [...resources.slice(3), ...(admin ? adminNavigation : [])];
  const active = (path: string) => route === path || route.startsWith(`${path}/`);
  const selected = more.some(item => active(item.route));
  useEffect(() => { menu.current?.hidePopover(); }, [route, desktop, standalone]);
  useEffect(() => {
    if (!open) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || !menu.current?.matches(":popover-open")) return;
      event.preventDefault();
      menu.current.hidePopover();
      requestAnimationFrame(() => trigger.current?.focus({ preventScroll: true }));
    };
    document.addEventListener("keydown", closeOnEscape, true);
    return () => document.removeEventListener("keydown", closeOnEscape, true);
  }, [open]);
  return <><nav className="bottom-nav" aria-label="底部导航">
    {resources.slice(0, 3).map(item => { const Icon = item.icon; return <a key={item.route} href={item.route} aria-current={active(item.route) ? "page" : undefined} className={active(item.route) ? "active" : ""}><Icon size={22} /><span>{item.label}</span></a>; })}
    <button ref={trigger} type="button" className={selected || open ? "active" : ""} popoverTarget={id} aria-expanded={open} aria-controls={id} aria-label="更多功能" onClick={event => { keyboard.current = event.detail === 0; }}><Ellipsis size={22} /><span>更多</span></button>
  </nav><div ref={menu} id={id} popover="auto" className="mobile-more" onToggle={event => {
    const shown = event.currentTarget.matches(":popover-open");
    setOpen(shown);
    if (shown && keyboard.current) menu.current?.querySelector<HTMLAnchorElement>("a")?.focus({ preventScroll: true });
  }}>
    <nav aria-label="更多功能">{more.map(item => { const Icon = item.icon; return <a key={item.route} href={item.route} tabIndex={0} aria-current={active(item.route) ? "page" : undefined} onClick={() => {
      // 原生 popover 关闭会恢复焦点；先释放菜单焦点，避免切页时短暂拉回旧按钮。
      if (item.route !== route && document.activeElement instanceof HTMLElement && menu.current?.contains(document.activeElement)) document.activeElement.blur();
      menu.current?.hidePopover();
      if (item.route === route && keyboard.current) trigger.current?.focus({ preventScroll: true });
    }}><Icon size={21} /><span>{item.label}</span>{active(item.route) ? <span className="sr-only">当前页面</span> : null}<ChevronRight size={16} /></a>; })}</nav>
  </div></>;
}

/** 同一业务页面实例跨桌面/手机保留；桌面侧栏和手机底栏仅改变导航呈现。 */
export function Workspace({ auth, onAuth, onExpired, managed, onManage, message, onRenamed, onDeleted }: { auth: Auth; onAuth: (value: Auth) => void; onExpired: () => void; managed: ManagedWorkspace | null; onManage: (value: ManagedWorkspace | null) => void; message: string | null; onRenamed: (username: string) => void; onDeleted: (workspace: string, message: string) => void }) {
  const navigation = useWorkspaceNavigation();
  const { route, desktop, standalone } = navigation;
  const [createTarget, setCreateTarget] = useState<HTMLDivElement | null>(null);
  const [headerTarget, setHeaderTarget] = useState<HTMLDivElement | null>(null);
  const [accountTarget, setAccountTarget] = useState<HTMLDivElement | null>(null);
  const shell = useRef<HTMLDivElement>(null); const header = useRef<HTMLDivElement>(null);
  const topHeader = standalone || !desktop;
  const desktopItems = [...resources, ...(auth.role === "system_admin" ? adminNavigation : [])];
  // 安全区包含在实际首行高度中，正文只补一次间距；字体放大不会遮挡页面内容。
  useLayoutEffect(() => {
    if (!topHeader || !header.current) return;
    let frame = 0;
    const update = () => {
      const height = `${header.current!.getBoundingClientRect().height}px`;
      if (shell.current?.style.getPropertyValue("--workspace-top-height") !== height) shell.current?.style.setProperty("--workspace-top-height", height);
    };
    // 在下一帧回写正文间距，避免 WebKit 在尺寸通知中再次布局形成观察循环。
    update(); const observer = new ResizeObserver(() => { cancelAnimationFrame(frame); frame = requestAnimationFrame(update); }); observer.observe(header.current);
    return () => { observer.disconnect(); cancelAnimationFrame(frame); };
  }, [topHeader]);
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
    <div ref={shell} className="app-shell" data-pwa={standalone} data-top-header={topHeader} data-root-page={rootRoutes.includes(route)} data-detail-page={/^#\/(services|agents|nodes|domains)\//.test(route)} onPointerDownCapture={event => rememberInteraction(event.target)} onKeyDownCapture={() => rememberInteraction(null)}>
      <aside className="sidebar"><div className="sidebar-brand" aria-label="Nexo"><picture aria-hidden="true"><source media="(prefers-color-scheme: dark)" srcSet="/brand/nexo-banner-dark.webp" /><img src="/brand/nexo-banner-light.webp" width="168" height="56" alt="" /></picture></div><nav aria-label="主导航">{links(desktopItems)}</nav>
        {!topHeader && <div className="sidebar-account-slot" ref={setAccountTarget} />}
      </aside>
      <div ref={header} className="workspace-topbar" hidden={!topHeader}><div className="workspace-top-content" data-title={routeInfo(route).label} ref={setHeaderTarget} />{topHeader && <div className="account-trigger-slot" ref={setAccountTarget} />}</div>
      <AccountMenu auth={auth} target={accountTarget} compact={topHeader} route={route} requestId={navigation.accountRequest} onLogout={logout} onExpired={onExpired} />
      <WorkspaceHeaderContext.Provider value={headerTarget}><MobileCreateContext.Provider value={createTarget}><main className="content">
        {message && <p role="status" className="action-status">{message}</p>}
        {managed && <div className="workspace-banner" role="status"><div><strong>{managed.name}</strong><span>管理员访问{!managed.enabled && " · 用户已停用，服务暂停转发"}</span></div><button className="secondary-button" onClick={() => switchWorkspace(null)}>返回我的空间</button></div>}
        {navigation.pages.map(page => {
          const active = page.route === route;
          return <PageNavigationContext.Provider key={page.route} value={{ route: page.route, active, desktop, standalone, deletions: navigation.deletions, removePages: navigation.removePages, openDomainConfiguration: navigation.openDomainConfiguration }}>
            <section className="page-slot" id={`page-${encodeURIComponent(page.route)}`} hidden={!active} aria-labelledby={`heading-${encodeURIComponent(page.route)}`}>
              <PageLoadBoundary><Suspense fallback={<Loading />} >{page.route === homeRoute ? <HomePage active={active} auth={auth} managed={managed} /> : page.route.startsWith("#/services") ? <ServicesPage admin={auth.role === "system_admin"} route={page.route} back={page.back} active={active} csrf={auth.csrf_token} /> :
                page.route.startsWith("#/agents") ? <AgentsPage route={page.route} back={page.back ?? "#/agents"} active={active} csrf={auth.csrf_token} /> :
                page.route === "#/nodes" ? <NodesPage admin={auth.role === "system_admin"} active={active} csrf={auth.csrf_token} /> :
                page.route.startsWith("#/domains") ? <DomainsPage route={page.route} back={page.back ?? "#/domains"} initialConfiguration={page.configureDomain} active={active} csrf={auth.csrf_token} /> :
                <WorkspaceLabelContext.Provider value={undefined}>{page.route === "#/settings/sessions" ? <SessionsPage auth={auth} active={active} back={page.back ?? homeRoute} onExpired={onExpired} /> : auth.role === "system_admin" ? page.route === "#/settings/server" ? <ServerSettingsPage active={active} auth={auth} /> : <UsersPage active={active} auth={auth} onManage={switchWorkspace} onRenamed={onRenamed} onDeleted={onDeleted} /> : <><PageHeader title={page.route === "#/settings/server" ? "服务器设置" : "用户管理"} showTitle /><Notice error="此页面需要管理员权限" /></>}</WorkspaceLabelContext.Provider>}</Suspense></PageLoadBoundary>
            </section>
          </PageNavigationContext.Provider>;
        })}
      </main></MobileCreateContext.Provider></WorkspaceHeaderContext.Provider>
      {/* 添加入口与导航共用一层底座，空槽不占宽度，避免另叠一排悬浮控件。 */}
      <div className="mobile-dock"><MobileNavigation route={route} desktop={desktop} admin={auth.role === "system_admin"} standalone={standalone} /><div className="mobile-create-slot" ref={setCreateTarget} /></div>
    </div>
  </WorkspaceLabelContext.Provider></WorkspaceContext.Provider>;
}
