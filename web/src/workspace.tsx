import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Globe2, House, LogOut, Network, Server, Settings, UserRound, Users, X } from "lucide-react";
import { HomePage } from "./home";
import { UsersPage } from "./accounts";
import type { ManagedWorkspace } from "./accounts";
import { AgentsPage, DomainsPage, ManagePage, SessionsPage } from "./management";
import { ServicesPage } from "./services";
import { Notice, UserAvatar, WorkspaceContext, WorkspaceLabelContext, errorText, rememberInteraction, request } from "./ui";
import type { Auth } from "./ui";
import { PageNavigationContext, clearSavedTabs, emptyRoute, homeRoute, navigationLocked, rootRoutes, routeInfo, useWorkspaceNavigation } from "./navigation";

const resources = [
  { route: homeRoute, label: "首页", icon: House },
  { route: "#/services", label: "服务", icon: Network },
  { route: "#/agents", label: "设备", icon: Server },
  { route: "#/domains", label: "域名", icon: Globe2 },
];

/** 桌面菜单使用原生 popover 处理外部点击与 Escape，焦点和账号权限始终属于登录人。 */
function AccountMenu({ auth, onLogout }: { auth: Auth; onLogout: () => Promise<void> }) {
  const menu = useRef<HTMLDivElement>(null); const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const close = () => menu.current?.hidePopover();
  return <div className="account-menu">
    <button ref={trigger} className="account-trigger" popoverTarget="account-menu" aria-expanded={open} aria-controls="account-menu" onClick={() => setError(null)}><UserAvatar role={auth.role} size={28} /><span title={auth.username}>{auth.username}</span><ChevronDown size={16} aria-hidden="true" /></button>
    <div ref={menu} id="account-menu" popover="auto" className="account-popover" onToggle={event => setOpen((event.nativeEvent as ToggleEvent).newState === "open")} onKeyDown={event => { if (event.key === "Escape") trigger.current?.focus(); }}>
      <a href="#/manage" onClick={close}><Settings size={18} aria-hidden="true" />账号设置</a>
      <button disabled={busy} onClick={async () => { setBusy(true); setError(null); try { await onLogout(); close(); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}><LogOut size={18} aria-hidden="true" />{busy ? "退出中…" : "退出登录"}</button>
      <Notice error={error} />
    </div>
  </div>;
}

/** 同一业务页面实例跨桌面/手机保留；桌面标签和手机底栏仅改变导航呈现。 */
export function Workspace({ auth, onAuth, onExpired, managed, onManage, message, onRenamed, onDeleted }: { auth: Auth; onAuth: (value: Auth) => void; onExpired: () => void; managed: ManagedWorkspace | null; onManage: (value: ManagedWorkspace | null) => void; message: string | null; onRenamed: (username: string) => void; onDeleted: (workspace: string, message: string) => void }) {
  const user = auth.user_id ?? auth.username ?? "";
  const navigation = useWorkspaceNavigation(user, managed?.id ?? auth.workspace_id ?? "own", auth.role === "system_admin");
  const { route, desktop, titles } = navigation;
  const parent = routeInfo(route).parent;
  const title = titles[route] ?? routeInfo(route).label;
  const desktopItems = [...resources, ...(auth.role === "system_admin" ? [{ route: "#/users", label: "用户管理", icon: Users }] : [])];
  const mobileItems = [...resources, { route: "#/manage", label: "我的", icon: UserRound }];
  const tabRefs = useRef(new Map<string, HTMLAnchorElement>());
  async function logout() {
    if (navigationLocked()) return;
    await request("/api/v1/auth/logout", { method: "POST" }, auth.csrf_token);
    clearSavedTabs(user); onAuth({ ...auth, authenticated: false });
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
    <div className="app-shell" data-root-page={rootRoutes.includes(route)} data-detail-page={/^#\/(services|agents|domains)\//.test(route)} onPointerDownCapture={event => rememberInteraction(event.target)} onKeyDownCapture={() => rememberInteraction(null)}>
      <aside className="sidebar"><div className="sidebar-brand" aria-label="Nexo"><picture aria-hidden="true"><source media="(prefers-color-scheme: dark)" srcSet="/brand/nexo-banner-dark.webp" /><img src="/brand/nexo-banner-light.webp" width="168" height="56" alt="" /></picture></div><nav aria-label="主导航">{links(desktopItems)}</nav></aside>
      <header className="workspace-header">
        <div className="workspace-topbar"><nav className="breadcrumbs" aria-label="面包屑">{parent && <><a href={parent}>{routeInfo(parent).label}</a><ChevronRight size={16} aria-hidden="true" /></>}<span aria-current="page" title={title}>{title}</span></nav><AccountMenu auth={auth} onLogout={logout} /></div>
        <div className="workspace-tabs" role="tablist" aria-label="已开页面" onKeyDown={event => {
          const index = navigation.tabs.indexOf(route);
          const target = event.key === "ArrowRight" ? navigation.tabs[(index + 1) % navigation.tabs.length] : event.key === "ArrowLeft" ? navigation.tabs[(index - 1 + navigation.tabs.length) % navigation.tabs.length] : event.key === "Home" ? navigation.tabs[0] : event.key === "End" ? navigation.tabs.at(-1) : undefined;
          if (target) { event.preventDefault(); if (!navigationLocked()) { window.location.hash = target; tabRefs.current.get(target)?.focus(); } }
          if (event.key === "Delete") { event.preventDefault(); navigation.closeTab(route); }
        }}>{navigation.tabs.map(item => <div className="workspace-tab" key={item} role="presentation" data-active={item === route}>
          <a ref={element => { if (element) tabRefs.current.set(item, element); else tabRefs.current.delete(item); }} href={item} role="tab" id={`tab-${encodeURIComponent(item)}`} aria-selected={item === route} aria-controls={`page-${encodeURIComponent(item)}`} tabIndex={item === route ? 0 : -1} title={titles[item] ?? routeInfo(item).label}>{titles[item] ?? routeInfo(item).label}</a>
          {item !== homeRoute && <button className="tab-close" aria-label={`关闭 ${titles[item] ?? routeInfo(item).label}`} title="关闭标签" onClick={() => navigation.closeTab(item)}><X size={16} aria-hidden="true" /></button>}
        </div>)}</div>
      </header>
      <main className="content">
        {message && <p role="status" className="action-status">{message}</p>}
        {managed && <div className="workspace-banner" role="status"><div><strong>{managed.name}</strong><span>管理员访问{!managed.enabled && " · 用户已停用，服务暂停转发"}</span></div><button className="secondary-button" onClick={() => switchWorkspace(null)}>返回我的空间</button></div>}
        {route === emptyRoute && <section className="page-slot"><div className="empty"><p>从侧栏打开页面</p></div></section>}
        {navigation.pages.map(page => {
          const active = page.route === route;
          return <PageNavigationContext.Provider key={page.route} value={{ route: page.route, desktop, deletions: navigation.deletions, reportTitle: navigation.reportTitle, removePages: navigation.removePages, openDomainConfiguration: navigation.openDomainConfiguration }}>
            <section className="page-slot" id={`page-${encodeURIComponent(page.route)}`} hidden={!active} role={desktop ? "tabpanel" : undefined} aria-labelledby={desktop && navigation.tabs.includes(page.route) ? `tab-${encodeURIComponent(page.route)}` : undefined}>
              {page.route === homeRoute ? <HomePage active={active} auth={auth} managed={managed} /> : page.route.startsWith("#/services") ? <ServicesPage admin={auth.role === "system_admin"} route={page.route} back={page.back} active={active} csrf={auth.csrf_token} /> :
                page.route.startsWith("#/agents") ? <AgentsPage route={page.route} back={page.back ?? "#/agents"} active={active} csrf={auth.csrf_token} /> :
                page.route.startsWith("#/domains") ? <DomainsPage route={page.route} back={page.back ?? "#/domains"} initialConfiguration={page.configureDomain} active={active} csrf={auth.csrf_token} /> :
                <WorkspaceLabelContext.Provider value={undefined}>{page.route === "#/manage" ? <ManagePage auth={auth} active={active} onLogout={logout} onExpired={onExpired} /> : page.route === "#/settings/sessions" ? <SessionsPage auth={auth} active={active} onExpired={onExpired} /> : auth.role === "system_admin" ? <UsersPage active={active} auth={auth} onManage={switchWorkspace} onRenamed={onRenamed} onDeleted={onDeleted} onExpired={onExpired} /> : <Notice error="此页面需要管理员权限" />}</WorkspaceLabelContext.Provider>}
            </section>
          </PageNavigationContext.Provider>;
        })}
      </main>
      <nav className="bottom-nav" aria-label="底部导航">{links(mobileItems)}</nav>
    </div>
  </WorkspaceLabelContext.Provider></WorkspaceContext.Provider>;
}
