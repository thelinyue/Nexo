import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Domain } from "./ui";

export const homeRoute = "#/home";
export const emptyRoute = "#/workspace";
export const rootRoutes = [homeRoute, "#/services", "#/agents", "#/nodes", "#/domains", "#/users", "#/settings/server"];
const accountRoute = (value: string) => value === "#/manage" || value === "#/settings";
export function normalizeRoute(value: string) {
  if (value === emptyRoute) return homeRoute;
  return /^#\/(services|agents|nodes|domains)(\/[^/]+)?$/.test(value) || [...rootRoutes, "#/settings/sessions"].includes(value) ? value : homeRoute;
}
export function routeInfo(route: string) {
  if (route === "#/settings/server") return { label: "服务器设置", parent: undefined };
  const module = route.split("/")[1];
  const label = ({ home: "首页", services: "服务", agents: "设备", nodes: "节点", domains: "域名", users: "用户管理", settings: "登录会话" } as Record<string, string>)[module] ?? "首页";
  const detail = /^#\/(services|agents|nodes|domains)\//.test(route);
  return { label: detail ? `${label}详情` : label, parent: detail ? `#/${module}` : route === "#/settings/sessions" ? homeRoute : undefined };
}

/** 表单锁独立于 dirty；嵌套确认框不能绕过底层编辑表单的导航限制。 */
export function navigationLocked() { return Boolean(document.querySelector('dialog[open][data-navigation-lock="true"]')); }

type Page = { route: string; back?: string; configureDomain?: Domain };
type NavigationState = { route: string; pages: Page[] };
type PageNavigation = { route: string; active: boolean; desktop: boolean; standalone: boolean; deletions: EventTarget; removePages: (routes: string[], fallback: string) => void; openDomainConfiguration: (domain: Domain) => void };
export const PageNavigationContext = createContext<PageNavigation | null>(null);

/** 已成功删除的资源立即从保留的列表中移除，即使随后刷新失败也不会重新显示。
 * 通知对象归属当前空间，迟到的旧空间回调无法修改新空间的缓存。
 */
export function useResourceDeletions(onRemoved: (routes: string[]) => void) {
  const events = useContext(PageNavigationContext)?.deletions;
  const callback = useRef(onRemoved); callback.current = onRemoved;
  useEffect(() => {
    const removed = (event: Event) => callback.current((event as CustomEvent<string[]>).detail);
    events?.addEventListener("removed", removed);
    return () => events?.removeEventListener("removed", removed);
  }, [events]);
}

/** 页面实例按路由保留搜索、筛选和滚动位置，与导航入口的呈现无关。
 * 地址栏是唯一启动入口；缓存只存在于内存，用户或空间切换由外壳 key 重建，断点变化不重挂载表单。
 */
export function useWorkspaceNavigation() {
  const [desktop, setDesktop] = useState(() => matchMedia("(min-width:901px)").matches);
  const [accountRequest, setAccountRequest] = useState(() => accountRoute(window.location.hash) ? 1 : 0);
  const [standalone, setStandalone] = useState(() => matchMedia("(display-mode: standalone)").matches || (navigator as Navigator & { standalone?: boolean }).standalone === true);
  // 安装态只改变入口呈现，不重建页面；与启动屏使用相同的浏览器和 iOS 判断。
  useEffect(() => {
    const media = matchMedia("(display-mode: standalone)");
    const update = () => setStandalone(media.matches || (navigator as Navigator & { standalone?: boolean }).standalone === true);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  const [state, setState] = useState<NavigationState>(() => {
    const route = normalizeRoute(window.location.hash);
    return { route, pages: [{ route, back: routeInfo(route).parent }] };
  });
  const stateRef = useRef(state);
  const mounted = useRef(true);
  const positions = useRef(new Map<string, number>());
  const [deletions] = useState(() => new EventTarget());
  const commit = useCallback((next: NavigationState) => { stateRef.current = next; setState(next); }, []);
  const activate = useCallback((next: string, remove: string[] = []) => {
    if (!mounted.current) return;
    const current = stateRef.current;
    positions.current.set(current.route, window.scrollY);
    let pages = current.pages.filter(page => !remove.includes(page.route));
    const parent = routeInfo(next).parent;
    const existing = pages.find(page => page.route === next);
    // 进入另一个详情时记住来源；从后退链接返回已有页不覆盖它原本的返回关系。
    const source = current.pages.find(page => page.route === current.route);
    const back = parent && next !== source?.back && !remove.includes(current.route) ? current.route : parent;
    if (!existing) pages = [...pages, { route: next, back }];
    // 会话页复用数据和滚动位置，但每次打开都返回本次来源，而非第一次打开时的页面。
    else if (next === "#/settings/sessions" && next !== current.route) pages = pages.map(page => page.route === next ? { ...page, back: current.route } : page);
    remove.forEach(route => positions.current.delete(route));
    commit({ route: next, pages });
  }, [commit]);
  const removePages = useCallback((routes: string[], fallback: string) => {
    if (!mounted.current) return;
    // 仅由删除成功回调调用：允许完成中的确认框关闭对应页面。
    deletions.dispatchEvent(new CustomEvent("removed", { detail: routes }));
    const next = routes.includes(stateRef.current.route) ? fallback : stateRef.current.route;
    activate(next, routes.filter(route => route !== homeRoute));
    window.history.replaceState(null, "", next);
  }, [activate, deletions]);
  const openDomainConfiguration = useCallback((domain: Domain) => {
    if (!mounted.current) return;
    // 创建成功后把一次性配置意图交给新详情实例；配置意图仅在当前空间内存中保留。
    const route = `#/domains/${encodeURIComponent(domain.id)}`;
    activate(route);
    commit({ ...stateRef.current, pages: stateRef.current.pages.map(page => page.route === route ? { ...page, configureDomain: domain } : page) });
    window.history.pushState(null, "", route);
  }, [activate, commit]);
  useLayoutEffect(() => {
    mounted.current = true;
    window.history.replaceState(null, "", stateRef.current.route);
    const update = () => {
      const legacyAccount = accountRoute(window.location.hash);
      const next = normalizeRoute(window.location.hash);
      if (legacyAccount) {
        // 旧入口保留导航保护，仅替换当前历史项；菜单本身不写入 URL。
        const resume = () => { activate(homeRoute); window.history.replaceState(null, "", homeRoute); setAccountRequest(value => value + 1); };
        if (!navigationLocked() && window.dispatchEvent(new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume } }))) resume();
        else window.history.replaceState(null, "", stateRef.current.route);
        return;
      }
      if (next === stateRef.current.route) {
        if (window.location.hash !== next) window.history.replaceState(null, "", next);
        return;
      }
      const event = new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume: () => { window.location.hash = next; } } });
      if (navigationLocked() || !window.dispatchEvent(event)) { window.history.replaceState(null, "", stateRef.current.route); return; }
      activate(next);
      if (window.location.hash !== next) window.history.replaceState(null, "", next);
    };
    const media = matchMedia("(min-width:901px)");
    const resize = () => setDesktop(media.matches);
    const previous = window.history.scrollRestoration; window.history.scrollRestoration = "manual";
    window.addEventListener("hashchange", update); window.addEventListener("popstate", update); media.addEventListener("change", resize);
    return () => { mounted.current = false; window.removeEventListener("hashchange", update); window.removeEventListener("popstate", update); media.removeEventListener("change", resize); window.history.scrollRestoration = previous; };
  }, [activate]);
  useLayoutEffect(() => {
    window.scrollTo(0, positions.current.get(state.route) ?? 0);
    const focusHeading = () => {
      const heading = document.getElementById(`heading-${encodeURIComponent(state.route)}`);
      if (!heading) return false;
      if (!document.querySelector("dialog[open],.account-menu:popover-open")) heading.focus({ preventScroll: true });
      return true;
    };
    // 分包首次加载时标题尚未挂载；仅等待当前页面，切页时取消，避免迟到焦点抢占。
    const shell = document.querySelector(".app-shell");
    if (!focusHeading() && shell) {
      const observer = new MutationObserver(() => { if (focusHeading()) observer.disconnect(); });
      observer.observe(shell, { childList: true, subtree: true });
      return () => observer.disconnect();
    }
  }, [state.route]);
  return { ...state, desktop, standalone, accountRequest, deletions, removePages, openDomainConfiguration };
}
