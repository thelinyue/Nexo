import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Domain } from "./ui";

export const homeRoute = "#/home";
export const emptyRoute = "#/workspace";
export const rootRoutes = [homeRoute, "#/services", "#/agents", "#/domains", "#/manage"];
export function normalizeRoute(value: string) {
  if (value === "#/settings") return "#/manage";
  if (value === emptyRoute) return homeRoute;
  return /^#\/(services|agents|domains)(\/[^/]+)?$/.test(value) || [homeRoute, "#/manage", "#/users", "#/settings/sessions"].includes(value) ? value : homeRoute;
}
export function routeInfo(route: string) {
  const module = route.split("/")[1];
  const label = ({ home: "首页", services: "服务", agents: "设备", domains: "域名", manage: "账号设置", users: "用户管理", settings: "登录会话" } as Record<string, string>)[module] ?? "首页";
  const detail = /^#\/(services|agents|domains)\//.test(route);
  return { label: detail ? `${label}详情` : label, parent: detail ? `#/${module}` : route === "#/settings/sessions" ? "#/manage" : undefined };
}

/** 表单锁独立于 dirty；嵌套确认框不能绕过底层编辑表单的导航限制。 */
export function navigationLocked() { return Boolean(document.querySelector('dialog[open][data-navigation-lock="true"]')); }

type Page = { route: string; back?: string; configureDomain?: Domain };
type NavigationState = { route: string; pages: Page[]; tabs: string[] };
type PageNavigation = { route: string; desktop: boolean; deletions: EventTarget; reportTitle: (route: string, title: string) => void; removePages: (routes: string[], fallback: string) => void; openDomainConfiguration: (domain: Domain) => void };
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

export function clearSavedTabs(user: string) {
  try {
    const prefix = `nexo:tabs:${encodeURIComponent(user)}:`;
    Object.keys(sessionStorage).filter(key => key.startsWith(prefix)).forEach(key => sessionStorage.removeItem(key));
  } catch { /* 禁用存储时仍可正常使用当前页面。 */ }
}

/** 页面实例按路由隔离，桌面标签只是实例的入口；断点变化不会重新挂载活动表单。
 * 存储仅包含路由，资源、草稿和凭据不落盘；空间由已认证外壳指定，不能由缓存选择。
 */
export function useWorkspaceNavigation(user: string, space: string, admin: boolean) {
  const [desktop, setDesktop] = useState(() => matchMedia("(min-width:901px)").matches);
  const desktopRef = useRef(desktop);
  const key = `nexo:tabs:${encodeURIComponent(user)}:${encodeURIComponent(space)}`;
  const [state, setState] = useState<NavigationState>(() => {
    let tabs = [homeRoute]; let savedRoute = homeRoute;
    if (desktop) {
      try {
        const saved = JSON.parse(sessionStorage.getItem(key) ?? "null");
        if (Array.isArray(saved?.tabs)) tabs = [...new Set(saved.tabs.filter((value: unknown) => typeof value === "string" && value !== emptyRoute && normalizeRoute(value) === value && (admin || value !== "#/users")))] as string[];
        if (tabs.includes(saved?.route) || saved?.route === emptyRoute) savedRoute = saved.route;
      } catch { /* 旧记录或禁用存储不阻断页面加载。 */ }
    }
    tabs = [homeRoute, ...tabs.filter(item => item !== homeRoute)];
    let route = normalizeRoute(window.location.hash || savedRoute);
    if (!desktop && route === emptyRoute) route = homeRoute;
    if (route !== emptyRoute && !tabs.includes(route)) tabs.push(route);
    return { route, tabs, pages: tabs.map(route => ({ route, back: routeInfo(route).parent })) };
  });
  const stateRef = useRef(state);
  const mounted = useRef(true);
  const positions = useRef(new Map<string, number>());
  const [deletions] = useState(() => new EventTarget());
  const [titles, setTitles] = useState<Record<string, string>>({});
  const reportTitle = useCallback((route: string, title: string) => setTitles(previous => previous[route] === title ? previous : { ...previous, [route]: title }), []);
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
    if (!existing && next !== emptyRoute) pages = [...pages, { route: next, back }];
    let tabs = current.tabs.filter(route => !remove.includes(route));
    if (desktopRef.current && next !== emptyRoute && !tabs.includes(next)) tabs = [...tabs, next];
    remove.forEach(route => positions.current.delete(route));
    commit({ route: next, pages, tabs });
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
    // 创建成功后把一次性配置意图交给新详情实例；该数据不会写入标签存储。
    const route = `#/domains/${encodeURIComponent(domain.id)}`;
    activate(route);
    commit({ ...stateRef.current, pages: stateRef.current.pages.map(page => page.route === route ? { ...page, configureDomain: domain } : page) });
    window.history.pushState(null, "", route);
  }, [activate, commit]);
  const closeTab = useCallback((route: string) => {
    if (route === homeRoute) return;
    if (navigationLocked() || document.querySelector("dialog[open]")) return;
    const current = stateRef.current;
    const index = current.tabs.indexOf(route);
    if (index < 0) return;
    // 首页固定在首位，其他标签关闭后优先激活左邻。
    const next = current.route === route ? current.tabs[index - 1] ?? homeRoute : current.route;
    activate(next, [route]);
    if (next !== current.route) window.history.pushState(null, "", next);
  }, [activate]);

  useLayoutEffect(() => {
    mounted.current = true;
    window.history.replaceState(null, "", stateRef.current.route);
    const update = () => {
      const normalized = normalizeRoute(window.location.hash);
      const next = !desktopRef.current && normalized === emptyRoute ? homeRoute : normalized;
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
    const resize = () => {
      desktopRef.current = media.matches; setDesktop(media.matches);
      // 空工作区仅存在于桌面；切换到手机时回到隧道入口，避免出现没有导航的空屏。
      if (!media.matches && stateRef.current.route === emptyRoute) {
        activate(homeRoute); window.history.replaceState(null, "", homeRoute);
      } else if (media.matches && stateRef.current.route !== emptyRoute && !stateRef.current.tabs.includes(stateRef.current.route)) commit({ ...stateRef.current, tabs: [...stateRef.current.tabs, stateRef.current.route] });
    };
    const previous = window.history.scrollRestoration; window.history.scrollRestoration = "manual";
    window.addEventListener("hashchange", update); window.addEventListener("popstate", update); media.addEventListener("change", resize);
    return () => { mounted.current = false; window.removeEventListener("hashchange", update); window.removeEventListener("popstate", update); media.removeEventListener("change", resize); window.history.scrollRestoration = previous; };
  }, [activate, commit]);
  useLayoutEffect(() => {
    if (desktop) {
      try { sessionStorage.setItem(key, JSON.stringify({ tabs: state.tabs, route: state.route })); } catch { /* 当前会话继续可用，仅不恢复标签。 */ }
    }
  }, [desktop, key, state.tabs, state.route]);
  useLayoutEffect(() => {
    window.scrollTo(0, positions.current.get(state.route) ?? 0);
    if (!document.querySelector("dialog[open]")) document.querySelector<HTMLElement>(".page-slot:not([hidden]) h1")?.focus({ preventScroll: true });
    const selected = document.querySelector<HTMLElement>('.workspace-tabs [aria-selected="true"]');
    if (desktopRef.current && selected) {
      const strip = selected.closest<HTMLElement>(".workspace-tabs");
      if (strip) { const box = selected.getBoundingClientRect(); const bounds = strip.getBoundingClientRect(); if (box.left < bounds.left) strip.scrollLeft -= bounds.left - box.left; else if (box.right > bounds.right) strip.scrollLeft += box.right - bounds.right; }
    }
  }, [state.route]);
  return { ...state, desktop, titles, deletions, reportTitle, removePages, openDomainConfiguration, closeTab };
}
