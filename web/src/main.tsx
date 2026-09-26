import { useEffect, useState } from "react";
import { InvitationScreen } from "./accounts";
import type { ManagedWorkspace } from "./accounts";
import { AuthScreen, Reauthenticate } from "./auth";
import { createRoot } from "react-dom/client";
import { Workspace } from "./workspace";
import { homeRoute } from "./navigation";
import { Brand, Loading, Notice, errorText, request, resumeSession } from "./ui";
import type { Auth } from "./ui";
import "./styles.css";

/** 邀请/恢复也可在已打开的标签页进入；凭据读取后立即从地址栏移除。 */
function readEntryLink() {
  const match = window.location.hash.match(/^#\/(invite|recover)\?token=([^&]+)$/);
  if (!match) return null;
  window.history.replaceState(null, "", homeRoute);
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
