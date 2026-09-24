import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Brand, Confirm, CopyButton, Loading, Modal, Notice, PageHeader, Refresh, errorText, request, useResource } from "./ui";
import type { Auth } from "./ui";
import { PasswordForm } from "./management";

export type ManagedWorkspace = { id: string; name: string; enabled: boolean };
type User = { id: string; username: string; role: string; workspace_id: string; workspace_name: string; enabled: boolean; created_at: number; devices: number; services: number; domains: number };
type Invitation = { id: string; expires_at: number; status: string; username: string | null };
type Link = { token: string; expires_at: number };
const accountDate = (value?: number) => value ? new Date(value * 1000).toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "暂无记录";

/** 数量与字段分列，小屏和删除确认复用同一组易于扫读的信息。 */
function UserResources({ user }: { user: Pick<User, "devices" | "services" | "domains"> }) {
  return <dl className="user-resources"><div><dt>Agent</dt><dd>{user.devices}</dd></div><div><dt>服务</dt><dd>{user.services}</dd></div><div><dt>域名</dt><dd>{user.domains}</dd></div></dl>;
}

/** 链接凭据仅保留在组件内存和 URL fragment，不写入浏览器存储或服务器访问日志。 */
export function UsersPage({ active, auth, onManage, onRenamed, onDeleted, onExpired }: { active: boolean; auth: Auth; onManage: (workspace: ManagedWorkspace) => void; onRenamed: (username: string) => void; onDeleted: (workspace: string, message: string) => void; onExpired: () => void }) {
  const resource = useResource(async () => {
    const [users, invitations] = await Promise.all([request<User[]>("/api/v1/admin/users"), request<Invitation[]>("/api/v1/admin/invitations")]);
    return { users, invitations };
  }, active);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<(Link & { kind: "invite" | "recover"; username?: string }) | null>(null);
  useEffect(() => { if (!active) setLink(null); }, [active]);
  const [changing, setChanging] = useState<User | null>(null); const [revoking, setRevoking] = useState<Invitation | null>(null);
  const [editing, setEditing] = useState<User | null>(null); const [deleting, setDeleting] = useState<User | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [password, setPassword] = useState(false); const [notice, setNotice] = useState<string | null>(null);
  async function createLink(user?: User) {
    setBusy(true); setError(null);
    try {
      const result = await request<Link>(user ? `/api/v1/admin/users/${encodeURIComponent(user.id)}/recovery` : "/api/v1/admin/invitations", { method: "POST" }, auth.csrf_token);
      setLink({ ...result, kind: user ? "recover" : "invite", username: user?.username }); void resource.reload();
    } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  const url = link ? `${window.location.origin}${window.location.pathname}#/${link.kind}?token=${encodeURIComponent(link.token)}` : "";
  return <>
    <PageHeader title="用户管理" back="#/manage" action={<Refresh label="用户" busy={resource.busy} onClick={() => void resource.reload()} />} />
    <Notice error={error || resource.error} />
    {notice && <p role="status" className="action-status">{notice}</p>}
    <div className="users-toolbar"><span className="helper">{resource.data ? `共 ${resource.data.users.length} 个账号` : "账号与资源管理"}</span><button className="primary-button" disabled={busy} onClick={() => void createLink()}>{busy ? "生成中…" : "邀请用户"}</button></div>
    {!resource.data && resource.busy && <Loading />}
    {resource.data && <><section className="user-list" aria-label="用户列表">{resource.data.users.map(user => <article className="panel user-card" key={user.id} data-expanded={expanded === user.id}>
      <div className="user-heading"><h2 title={user.username}>{user.username}</h2><span className={`status ${user.enabled ? "ready" : "neutral"}`}>{user.role === "system_admin" ? `管理员${user.id === auth.user_id ? " · 本人" : ""}` : user.enabled ? "已启用" : "已停用"}</span></div>
      <p className="user-resource-summary">Agent {user.devices} · 服务 {user.services} · 域名 {user.domains}</p>
      <div className="user-card-actions"><button className="secondary-button" disabled={busy} aria-label={`管理 ${user.username} 的空间`} onClick={() => onManage({ id: user.workspace_id, name: user.workspace_name, enabled: user.enabled })}>管理资源</button><button className="secondary-button" disabled={busy} aria-expanded={expanded === user.id} aria-controls={`user-settings-${user.id}`} onClick={() => setExpanded(expanded === user.id ? null : user.id)}>账号设置</button></div>
      {expanded === user.id && <section className="user-settings" id={`user-settings-${user.id}`} aria-label={`${user.username} 的账号设置`}>
        <dl className="user-profile"><div><dt>身份</dt><dd>{user.role === "system_admin" ? "管理员" : "普通用户"}</dd></div><div><dt>创建时间</dt><dd>{accountDate(user.created_at)}</dd></div></dl>
        <div className="user-account-actions"><button className="secondary-button" disabled={busy} onClick={() => setEditing(user)}>修改用户名</button>{user.id === auth.user_id && <><button className="secondary-button" disabled={busy} onClick={() => setPassword(true)}>修改密码</button><a className="secondary-button" href="#/settings/sessions">登录会话</a></>}{user.role !== "system_admin" && <><button className="secondary-button" disabled={busy || !user.enabled} onClick={() => void createLink(user)}>重设密码</button><button className="secondary-button" disabled={busy} onClick={() => setChanging(user)}>{user.enabled ? "停用用户" : "启用用户"}</button><button className="secondary-button user-delete" disabled={busy} onClick={() => setDeleting(user)}>删除用户</button></>}</div>
      </section>}
    </article>)}</section>{resource.data.invitations.length ? <details className="panel invitation-history"><summary>邀请记录 · {resource.data.invitations.filter(item => item.status === "pending").length} 待接受</summary><div>{resource.data.invitations.map(invitation => <div className="pending-row invitation-row" key={invitation.id}><div><strong>{{ pending: "等待接受", used: "已接受", revoked: "已撤销", expired: "已过期" }[invitation.status] ?? invitation.status}{invitation.username ? ` · ${invitation.username}` : ""}</strong><small>到期时间：{accountDate(invitation.expires_at)}</small></div>{invitation.status === "pending" && <button className="text-button" onClick={() => setRevoking(invitation)}>撤销邀请</button>}</div>)}</div></details> : <p className="helper invitation-empty">暂无邀请</p>}</>}
    {link && active && <Modal title={link.kind === "invite" ? "邀请链接" : `重设 ${link.username} 的密码`} onClose={() => setLink(null)}><div className="modal-body"><p>{link.kind === "invite" ? "单次使用，请发给受邀人。" : "单次使用，请发给本人。重设后需重新登录。"}</p><code className="token">{url}</code><CopyButton value={url} label="复制链接" /><p className="helper">到期时间：{accountDate(link.expires_at)}</p></div></Modal>}
    {changing && active && <Confirm title={`${changing.enabled ? "停用" : "启用"} ${changing.username}？`} description={changing.enabled ? "退出登录并断开全部转发，资源配置保留。" : "恢复此前开启的服务。用户需重新登录。"} label={changing.enabled ? "停用用户" : "启用用户"} onClose={() => setChanging(null)} onConfirm={async () => { await request(`/api/v1/admin/users/${encodeURIComponent(changing.id)}`, { method: "PATCH", body: JSON.stringify({ enabled: !changing.enabled }) }, auth.csrf_token); await resource.reload(); }} />}
    {revoking && active && <Confirm title="撤销邀请？" description="链接将立即失效，无法再用于创建账号。" label="撤销邀请" onClose={() => setRevoking(null)} onConfirm={async () => { await request(`/api/v1/admin/invitations/${encodeURIComponent(revoking.id)}`, { method: "DELETE" }, auth.csrf_token); await resource.reload(); }} />}
    {editing && active && <UsernameForm user={editing} csrf={auth.csrf_token} onClose={() => setEditing(null)} onSaved={async result => { setEditing(null); if (result.reauthenticate) { onRenamed(result.username); return; } setNotice("用户名已更新，该用户需重新登录。"); await resource.reload(); }} />}
    {deleting && active && <DeleteUserForm user={deleting} csrf={auth.csrf_token} onClose={() => setDeleting(null)} onDeleted={async result => { const workspace = deleting.workspace_id; setDeleting(null); onDeleted(workspace, result.message); await resource.reload(); }} />}
    {password && active && <PasswordForm csrf={auth.csrf_token} onClose={() => setPassword(false)} onExpired={onExpired} />}
  </>;
}

/** 改名只改变登录名；失败时保留草稿，管理员本人成功改名后交由应用切回登录页。 */
function UsernameForm({ user, csrf, onClose, onSaved }: { user: User; csrf?: string | null; onClose: () => void; onSaved: (value: { username: string; reauthenticate: boolean }) => Promise<void> }) {
  const [username, setUsername] = useState(user.username); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const dirty = username.trim() !== user.username;
  async function submit(event: FormEvent) {
    event.preventDefault(); if (busy || !dirty) return; setBusy(true); setError(null);
    try { const result = await request<{ username: string; reauthenticate: boolean }>(`/api/v1/admin/users/${encodeURIComponent(user.id)}`, { method: "PATCH", body: JSON.stringify({ username: username.trim() }) }, csrf); await onSaved(result); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <Modal title="修改用户名" dirty={dirty} busy={busy} onClose={onClose}><form className="modal-form management-form" onSubmit={submit}><div className="modal-body"><p className="user-target">{user.username}</p><p className="helper">所有会话及恢复码将失效，需重新登录。</p><fieldset disabled={busy}><label>新用户名<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required /></label></fieldset><Notice error={error} /></div><footer className="modal-actions"><button className="primary-button" disabled={busy || !dirty}>{busy ? "保存中…" : "保存用户名"}</button></footer></form></Modal>;
}

/** 删除会清除整个独立空间；确认文本随请求送到后端，防止账号已改名时误删。 */
function DeleteUserForm({ user, csrf, onClose, onDeleted }: { user: User; csrf?: string | null; onClose: () => void; onDeleted: (value: { message: string }) => Promise<void> }) {
  const [confirm, setConfirm] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (busy || confirm !== user.username) return; setBusy(true); setError(null);
    try { const result = await request<{ message: string }>(`/api/v1/admin/users/${encodeURIComponent(user.id)}`, { method: "DELETE", body: JSON.stringify({ confirm_username: confirm }) }, csrf); await onDeleted(result); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <Modal title="删除用户" busy={busy} onClose={onClose}><form className="modal-form" onSubmit={submit}><div className="modal-body"><p className="user-target">{user.username}</p><p>删除账号及全部资源，无法恢复。</p><UserResources user={user} /><fieldset disabled={busy}><label>输入用户名确认<input value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required /></label></fieldset><Notice error={error} /></div><footer className="modal-actions"><button type="button" className="secondary-button" disabled={busy} onClick={onClose}>取消</button><button className="danger-button" disabled={busy || confirm !== user.username}>{busy ? "删除中…" : "永久删除"}</button></footer></form></Modal>;
}

/** 注册只能凭单次邀请进入。已有登录时先明确退出，避免覆盖当前账号。 */
export function InvitationScreen({ token, auth, onAuth, onCancel }: { token: string; auth: Auth; onAuth: (auth: Auth) => void; onCancel: () => void }) {
  const [expires, setExpires] = useState<number | null>(null); const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  useEffect(() => { let live = true; request<Link>("/api/v1/auth/invitations/inspect", { method: "POST", body: JSON.stringify({ token }) }).then(result => { if (live) setExpires(result.expires_at); }).catch(e => { if (live) setError(errorText(e)); }); return () => { live = false; }; }, [token]);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (password !== confirm) { setError("两次输入的密码不一致"); return; }
    setBusy(true); setError(null);
    try { await request("/api/v1/auth/invitations/accept", { method: "POST", body: JSON.stringify({ token, username, password }) }); onAuth(await request<Auth>("/api/v1/auth/status")); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <main className="auth-shell"><section className="auth-panel invitation-auth"><Brand /><h1>接受邀请</h1><Notice error={error} />{auth.authenticated ? <><p>当前登录为 {auth.username}。请退出后继续注册。</p><button className="primary-button" disabled={busy} onClick={async () => { setBusy(true); try { await request("/api/v1/auth/logout", { method: "POST" }, auth.csrf_token); onAuth({ ...auth, authenticated: false }); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>退出当前账号</button></> : expires && <form className="auth-form" onSubmit={submit}><fieldset disabled={busy}><label>用户名<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required /></label><label>密码<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" minLength={12} required /></label><label>确认密码<input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="new-password" minLength={12} required /></label><p className="helper">密码至少 12 个字符。邀请到期时间：{accountDate(expires)}。</p></fieldset><button className="primary-button" disabled={busy}>{busy ? "创建中…" : "创建账号"}</button></form>}<button className="text-button" disabled={busy} onClick={onCancel}>返回登录</button></section></main>;
}
