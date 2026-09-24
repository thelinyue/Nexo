import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { InvitationScreen, UsersPage } from "./accounts";
import type { ManagedWorkspace } from "./accounts";
import { AuthScreen, Reauthenticate } from "./auth";
import { createRoot } from "react-dom/client";
import { Settings, Zap } from "lucide-react";
import { AgentsPage, DomainsPage, ManagePage, SessionsPage } from "./management";
import { ServicesPage } from "./services";
import { Brand, Loading, Notice, consumeModalNavigation, errorText, rememberInteraction, request, resumeSession, WorkspaceContext } from "./ui";
import type { Auth } from "./ui";
import "./styles.css";

const tabs = [
  { id: "services", label: "服务", icon: Zap },
  { id: "manage", label: "管理", icon: Settings },
];
function readRoute() {
  const hash = window.location.hash;
  return hash === "#/settings" ? "#/manage" : /^#\/(services|agents)(\/[^/]+)?$/.test(hash) || ["#/manage", "#/users", "#/domains", "#/settings/sessions"].includes(hash) ? hash : "#/services";
}

/** Hash 路由保持旧链接兼容；页面保持挂载，只有当前页面可见和接收焦点。 */
function Workspace({ auth, onAuth, onExpired, managed, onManage, message, onRenamed, onDeleted }: { auth: Auth; onAuth: (value: Auth) => void; onExpired: () => void; managed: ManagedWorkspace | null; onManage: (value: ManagedWorkspace | null) => void; message: string | null; onRenamed: (username: string) => void; onDeleted: (workspace: string, message: string) => void }) {
  const [route, setRoute] = useState(readRoute);
  const positions = useRef(new Map<string, number>());
  const currentRoute = useRef(route);
  const lastServices = useRef("#/services"); const lastAgents = useRef("#/agents");
  const agentReturn = useRef("#/agents");
  // 空间切换会重新挂载页面；显示新界面前接管路由，避免立即导航时丢失事件。
  useLayoutEffect(() => {
    const update = () => {
      const next = readRoute();
      if (!consumeModalNavigation(next)) {
        const transition = new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume: () => { window.location.hash = next; } } });
        if (!window.dispatchEvent(transition)) { window.history.replaceState(null, "", currentRoute.current); return; }
      }
      // 只有从服务详情进入 Agent 才保留来源；列表和外部直达仍按管理层级返回。
      if (next.startsWith("#/agents/") && next !== currentRoute.current) agentReturn.current = currentRoute.current.startsWith("#/services/") ? currentRoute.current : "#/agents";
      positions.current.set(currentRoute.current, window.scrollY); currentRoute.current = next; setRoute(next);
    };
    window.addEventListener("hashchange", update);
    const previous = window.history.scrollRestoration; window.history.scrollRestoration = "manual";
    return () => { window.removeEventListener("hashchange", update); window.history.scrollRestoration = previous; };
  }, []);
  useLayoutEffect(() => {
    if (window.location.hash === "#/settings") window.history.replaceState(null, "", "#/manage");
    window.scrollTo(0, positions.current.get(route) ?? 0);
    const heading = document.querySelector<HTMLElement>(".page-slot:not([hidden]) h1");
    if (!document.querySelector("dialog[open]")) heading?.focus({ preventScroll: true });
  }, [route]);
  const serviceActive = route.startsWith("#/services"); const agentActive = route.startsWith("#/agents");
  if (serviceActive) lastServices.current = route;
  if (agentActive) lastAgents.current = route;
  const tab = serviceActive ? "services" : "manage";
  const nav = tabs.map(item => { const Icon = item.icon; return <a key={item.id} href={`#/${item.id}`} aria-current={tab === item.id ? "page" : undefined} className={tab === item.id ? "active" : ""}><Icon size={21} /><span>{item.label}</span></a>; });
  async function logout() { await request("/api/v1/auth/logout", { method: "POST" }, auth.csrf_token); onAuth({ ...auth, authenticated: false }); }
  function switchWorkspace(value: ManagedWorkspace | null) {
    const resume = () => { window.history.replaceState(null, "", "#/services"); onManage(value); };
    if (window.dispatchEvent(new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume } }))) resume();
  }
  return <WorkspaceContext.Provider value={managed?.id}><div className="app-shell" onPointerDownCapture={event => rememberInteraction(event.target)} onKeyDownCapture={() => rememberInteraction(null)}><aside className="sidebar"><Brand /><nav aria-label="主导航">{nav}</nav><div className="sidebar-footer">{auth.username}</div></aside><main className="content">{message && <p role="status" className="action-status">{message}</p>}{managed && <div className="workspace-banner" role="status"><div><strong>{managed.name}</strong><span>管理员访问{!managed.enabled && " · 用户已停用，服务暂停转发"}</span></div><button className="secondary-button" onClick={() => switchWorkspace(null)}>返回我的空间</button></div>}<section className="page-slot" hidden={!serviceActive}><ServicesPage route={lastServices.current} active={serviceActive} csrf={auth.csrf_token} /></section><section className="page-slot" hidden={!agentActive}><AgentsPage back={agentReturn.current} route={lastAgents.current} active={agentActive} csrf={auth.csrf_token} /></section><section className="page-slot" hidden={route !== "#/manage"}><ManagePage auth={auth} active={route === "#/manage"} onLogout={logout} onExpired={onExpired} /></section><section className="page-slot" hidden={route !== "#/users"}>{auth.role === "system_admin" ? <UsersPage active={route === "#/users"} auth={auth} onManage={switchWorkspace} onRenamed={onRenamed} onDeleted={onDeleted} onExpired={onExpired} /> : <Notice error="此页面需要管理员权限" />}</section><section className="page-slot" hidden={route !== "#/domains"}><DomainsPage active={route === "#/domains"} csrf={auth.csrf_token} /></section><section className="page-slot" hidden={route !== "#/settings/sessions"}><SessionsPage active={route === "#/settings/sessions"} auth={auth} onExpired={onExpired} /></section></main><nav className="bottom-nav" aria-label="底部导航">{nav}</nav></div></WorkspaceContext.Provider>;
}

/** 邀请/恢复也可在已打开的标签页进入；凭据读取后立即从地址栏移除。 */
function readEntryLink() {
  const match = window.location.hash.match(/^#\/(invite|recover)\?token=([^&]+)$/);
  if (!match) return null;
  window.history.replaceState(null, "", "#/services");
  try { return { kind: match[1], token: decodeURIComponent(match[2]) }; } catch { return null; }
}

function App() {
  const [auth, setAuth] = useState<Auth | null>(null); const [error, setError] = useState<string | null>(null); const [message, setMessage] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const [managed, setManaged] = useState<ManagedWorkspace | null>(null);
  const [entry, setEntry] = useState(readEntryLink);
  async function connect() { setError(null); try { setAuth(await request<Auth>("/api/v1/auth/status")); } catch (e) { setError(errorText(e)); } }
  useEffect(() => {
    void connect(); const expiry = () => setExpired(true);
    const readLink = () => { const value = readEntryLink(); if (value) setEntry(value); };
    window.addEventListener("nexo:session-expired", expiry); window.addEventListener("hashchange", readLink);
    return () => { window.removeEventListener("nexo:session-expired", expiry); window.removeEventListener("hashchange", readLink); };
  }, []);
  function authenticated(value: Auth) { if (auth?.user_id !== value.user_id) setManaged(null); if (value.authenticated) setEntry(null); setMessage(null); setExpired(false); setAuth(value); resumeSession(); }
  if (!auth) return <main className="loading-screen"><Brand />{error ? <Notice error={error} onRetry={() => void connect()} /> : <Loading />}</main>;
  if (entry?.kind === "invite") return <InvitationScreen token={entry.token} auth={auth} onAuth={authenticated} onCancel={() => setEntry(null)} />;
  if (!auth.authenticated) return <AuthScreen key={entry?.token ?? "auth"} initial={auth} message={message} recoveryCode={entry?.kind === "recover" ? entry.token : undefined} onAuth={authenticated} />;
  if (entry?.kind === "recover") return <main className="auth-shell"><section className="auth-panel"><Brand /><h1>重设密码</h1><p>当前登录为 {auth.username}，请先退出再使用恢复链接。</p><Notice error={error} /><button className="primary-button" onClick={async () => { try { await request("/api/v1/auth/logout", { method: "POST" }, auth.csrf_token); setAuth({ ...auth, authenticated: false }); } catch (e) { setError(errorText(e)); } }}>退出并继续</button><button className="text-button" onClick={() => setEntry(null)}>返回</button></section></main>;
  return <><Workspace key={`${auth.user_id ?? auth.username}:${managed?.id ?? "own"}`} managed={managed} onManage={setManaged} message={message} onRenamed={username => { setMessage(`用户名已改为 ${username}，请使用新用户名重新登录。`); setManaged(null); setExpired(false); setAuth({ ...auth, username, authenticated: false }); }} onDeleted={(workspace, notice) => { setMessage(notice); if (managed?.id === workspace) setManaged(null); }} auth={auth} onAuth={value => { if (!value.authenticated) setManaged(null); setExpired(false); setAuth(value); }} onExpired={() => { setMessage("会话已失效，请重新登录"); setExpired(false); setAuth({ ...auth, authenticated: false }); }} />{expired && <Reauthenticate auth={auth} onAuth={authenticated} onAbandon={() => { setExpired(false); setAuth({ ...auth, authenticated: false }); }} />}</>;
}

export default App;
createRoot(document.getElementById("root")!).render(<App />);
