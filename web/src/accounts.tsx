import { Ellipsis, Plus, Search } from "./icons";
import { useContext, useEffect, useId, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Brand, PasswordInput, Empty, Confirm, CopyButton, Loading, Modal, Notice, PageHeader, UserAvatar, currentCreateButton, errorText, rememberInteraction, request, useResource } from "./ui";
import { PageNavigationContext } from "./navigation";
import type { Auth } from "./ui";
import { QuotaForm } from "./traffic-quota";

export type ManagedWorkspace = { id: string; name: string; enabled: boolean };
type User = { id: string; username: string; role: string; workspace_id: string; workspace_name: string; enabled: boolean; created_at: number; devices: number; services: number; domains: number };
type Invitation = { id: string; expires_at: number; status: string; username: string | null };
type Link = { token: string; expires_at: number };
const accountDate = (value?: number) => value ? new Date(value * 1000).toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "暂无记录";

/** 数量与字段分列，小屏和删除确认复用同一组易于扫读的信息。 */
function UserResources({ user }: { user: Pick<User, "devices" | "services" | "domains"> }) {
  return <dl className="user-resources"><div><dt>设备</dt><dd>{user.devices}</dd></div><div><dt>服务</dt><dd>{user.services}</dd></div><div><dt>域名</dt><dd>{user.domains}</dd></div></dl>;
}

/** 原生浮层不占列表高度；操作前记录行内入口，后续弹窗关闭时焦点回到“更多”。 */
function UserMenu({ user, active, busy, children }: { user: User; active: boolean; busy: boolean; children: ReactNode }) {
  const id = useId(); const menu = useRef<HTMLDivElement>(null); const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const close = () => menu.current?.hidePopover();
  function show() {
    const panel = menu.current!; const button = trigger.current!;
    if (panel.matches(":popover-open")) { close(); return; }
    panel.showPopover();
    const row = button.getBoundingClientRect(); const viewport = window.visualViewport;
    const left = (viewport?.offsetLeft ?? 0) + 16; const top = (viewport?.offsetTop ?? 0) + 16;
    const right = left + (viewport?.width ?? innerWidth) - 32; const bottom = top + (viewport?.height ?? innerHeight) - 32;
    panel.style.width = `${Math.min(300, right - left)}px`; panel.style.maxHeight = `${bottom - top}px`;
    const box = panel.getBoundingClientRect();
    panel.style.left = `${Math.max(left, Math.min(row.right - box.width, right - box.width))}px`;
    panel.style.top = `${Math.max(top, Math.min(row.bottom + 6 + box.height <= bottom ? row.bottom + 6 : row.top - box.height - 6, bottom - box.height))}px`;
    panel.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus({ preventScroll: true });
  }
  useEffect(() => { if (!active) close(); }, [active]);
  useEffect(() => {
    if (!open) return;
    const dismiss = () => { const restore = menu.current?.contains(document.activeElement); close(); if (restore) trigger.current?.focus({ preventScroll: true }); };
    window.addEventListener("resize", dismiss); window.addEventListener("scroll", dismiss);
    return () => { window.removeEventListener("resize", dismiss); window.removeEventListener("scroll", dismiss); };
  }, [open]);
  return <>
    <button ref={trigger} className="text-button user-more" disabled={busy} title="更多" aria-label="更多" aria-haspopup="dialog" aria-expanded={open} aria-controls={id} onClick={show}><span>更多</span><Ellipsis size={18} aria-hidden="true" /></button>
    <div ref={menu} id={id} popover="auto" role="dialog" aria-label={`${user.username} 的账号操作`} className="user-menu" onToggle={event => setOpen(event.currentTarget.matches(":popover-open"))} onKeyDown={event => { if (event.key === "Escape") { event.preventDefault(); close(); trigger.current?.focus(); } }} onBlur={event => { if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget as Node) && event.relatedTarget !== trigger.current) close(); }} onClickCapture={event => {
      if ((event.target as Element).closest("button,a")) { close(); trigger.current?.focus({ preventScroll: true }); rememberInteraction(trigger.current); }
    }}>
      <div className="user-menu-summary"><div className="user-menu-identity"><UserAvatar role={user.role} size={32} /><div><strong>{user.username}</strong><p>创建于 {accountDate(user.created_at)}</p></div></div><UserResources user={user} /></div>
      <div className="user-account-actions">{children}</div>
    </div>
  </>;
}

/** 链接凭据仅保留在组件内存和 URL fragment，不写入浏览器存储或服务器访问日志。 */
export function UsersPage({ active, auth, onManage, onRenamed, onDeleted }: { active: boolean; auth: Auth; onManage: (workspace: ManagedWorkspace) => void; onRenamed: (username: string) => void; onDeleted: (workspace: string, message: string) => void }) {
  const navigation = useContext(PageNavigationContext);
  const standalone = navigation?.standalone ?? false;
  const topHeader = Boolean(navigation && (standalone || !navigation.desktop));
  const resource = useResource(async () => {
    const [users, invitations] = await Promise.all([request<User[]>("/api/v1/admin/users"), request<Invitation[]>("/api/v1/admin/invitations")]);
    return { users, invitations };
  }, active);
  const [query, setQuery] = useState(""); const [statusFilter, setStatusFilter] = useState("all");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<(Link & { kind: "invite" | "recover"; username?: string }) | null>(null);
  useEffect(() => { if (!active) setLink(null); }, [active]);
  const [changing, setChanging] = useState<User | null>(null); const [revoking, setRevoking] = useState<Invitation | null>(null);
  const [editing, setEditing] = useState<User | null>(null); const [deleting, setDeleting] = useState<User | null>(null);
  const [quotaUser, setQuotaUser] = useState<User | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const creatingLink = useRef(false);
  async function createLink(user?: User) {
    if (creatingLink.current) return;
    creatingLink.current = true;
    setBusy(true); setError(null);
    try {
      const result = await request<Link>(user ? `/api/v1/admin/users/${encodeURIComponent(user.id)}/recovery` : "/api/v1/admin/invitations", { method: "POST" }, auth.csrf_token);
      setLink({ ...result, kind: user ? "recover" : "invite", username: user?.username }); void resource.reload();
    } catch (e) { setError(`${user ? "生成恢复链接" : "邀请用户"}失败：${errorText(e)}`); } finally { creatingLink.current = false; setBusy(false); }
  }
  const filtered = Boolean(query.trim() || statusFilter !== "all");
  const visibleUsers = resource.data?.users.filter(user => user.username.toLowerCase().includes(query.trim().toLowerCase()) && (statusFilter === "all" || user.enabled === (statusFilter === "enabled"))) ?? [];
  const url = link ? `${window.location.origin}${window.location.pathname}#/${link.kind}?token=${encodeURIComponent(link.token)}` : "";
  // 邀请仍由用户页发起；PWA 复用底栏入口，断点切换后按资源标记恢复当前按钮焦点。
  const invitation = <button className="primary-button page-create" data-resource="用户" aria-label={standalone ? "邀请用户" : undefined} title={standalone ? "邀请用户" : undefined} aria-busy={busy || undefined} disabled={busy} onClick={() => void createLink()}><Plus size={18} /><span>{busy ? "生成中…" : standalone ? "邀请" : "邀请用户"}</span></button>;
  const search = <label className="search"><Search size={18} aria-hidden="true" /><input aria-label="搜索用户" placeholder="搜索用户" value={query} onChange={e => setQuery(e.target.value)} /></label>;
  const filter = <select aria-label="用户状态筛选" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}><option value="all">全部</option><option value="enabled">启用</option><option value="disabled">停用</option></select>;
  return <>
    <PageHeader title="用户管理" topContent={<div className="users-filter">{search}{standalone && filter}</div>} action={!topHeader && invitation} createAction={standalone && invitation} />
    {topHeader && !standalone && <div className="users-filter users-secondary-filter">{filter}{invitation}</div>}
    <Notice updatedAt={resource.updatedAt} error={resource.error} onRetry={() => void resource.reload()} /><Notice error={error} />
    {notice && <p role="status" className="action-status">{notice}</p>}
    {!resource.data && resource.busy && <Loading />}
    {resource.data && <>{!topHeader && <div className="users-filter">{search}{filter}</div>}<div className="users-caption"><span>{filtered ? `显示 ${visibleUsers.length} / ${resource.data.users.length} 个账号` : `共 ${resource.data.users.length} 个账号`}</span>{filtered && visibleUsers.length > 0 && <button className="text-button" onClick={() => { setQuery(""); setStatusFilter("all"); }}>清除筛选</button>}</div>{!visibleUsers.length && <Empty kind="search" title="没有匹配的用户" detail="更换关键词或清除筛选。"><button className="secondary-button" onClick={() => { setQuery(""); setStatusFilter("all"); }}>清除筛选</button></Empty>}{visibleUsers.length > 0 && <section className="panel user-list" aria-label="用户列表"><div className="user-list-header" aria-hidden="true"><div className="user-heading"><span>用户</span><span>状态</span></div><span>资源</span><span>操作</span></div>{visibleUsers.map(user => <article className="user-card" key={user.id}>
      <div className="user-heading"><UserAvatar role={user.role} size={32} /><h2 title={user.username}>{user.username}</h2><span className={`status ${user.enabled ? "ready" : "neutral"}`}>{user.role === "system_admin" ? `管理员${user.id === auth.user_id ? " · 本人" : ""}` : user.enabled ? "已启用" : "已停用"}</span></div>
      <button className="user-resource-link" disabled={busy} title={`设备 ${user.devices} · 服务 ${user.services} · 域名 ${user.domains}`} aria-label={`管理 ${user.username} 的空间`} onClick={() => onManage({ id: user.workspace_id, name: user.workspace_name, enabled: user.enabled })}><span className="user-resource-summary">设备 {user.devices} · 服务 {user.services} · 域名 {user.domains}</span><span className="user-resource-mobile">资源</span></button>
      <div className="user-card-actions"><UserMenu user={user} active={active} busy={busy}>
        <button className="secondary-button" disabled={busy} onClick={() => setQuotaUser(user)}>流量限制</button><button className="secondary-button" disabled={busy} onClick={() => setEditing(user)}>修改用户名</button>{user.role !== "system_admin" && <><button className="secondary-button" disabled={busy || !user.enabled} onClick={() => void createLink(user)}>重设密码</button><button className="secondary-button" disabled={busy} onClick={() => setChanging(user)}>{user.enabled ? "停用用户" : "启用用户"}</button><button className="secondary-button user-delete" disabled={busy} onClick={() => setDeleting(user)}>删除用户</button></>}
      </UserMenu></div>
    </article>)}</section>}{resource.data.invitations.length ? <details className="panel invitation-history"><summary>邀请记录 · {resource.data.invitations.filter(item => item.status === "pending").length} 待接受</summary><div>{resource.data.invitations.map(invitation => <div className="pending-row invitation-row" key={invitation.id}><div><strong>{{ pending: "等待接受", used: "已接受", revoked: "已撤销", expired: "已过期" }[invitation.status] ?? invitation.status}{invitation.username ? ` · ${invitation.username}` : ""}</strong><small>到期时间：{accountDate(invitation.expires_at)}</small></div>{invitation.status === "pending" && <button className="text-button" onClick={() => setRevoking(invitation)}>撤销邀请</button>}</div>)}</div></details> : null}</>}
    {link && active && <Modal title={link.kind === "invite" ? "邀请链接" : `重设 ${link.username} 的密码`} returnFocus={link.kind === "invite" ? () => currentCreateButton("用户") : undefined} onClose={() => setLink(null)}><div className="modal-body"><p>{link.kind === "invite" ? "链接仅显示一次、单次有效，请在到期前发给受邀人。" : "链接仅本次显示，单次使用，请发给本人。重设后需重新登录。"}</p><code className="token">{url}</code><p className="helper">到期时间：{accountDate(link.expires_at)}</p><div className="link-actions"><CopyButton value={url} label="复制链接" /></div></div></Modal>}
    {changing && active && <Confirm tone={changing.enabled ? "danger" : "primary"} title={`${changing.enabled ? "停用" : "启用"} ${changing.username}？`} description={changing.enabled ? "退出登录并断开全部转发，资源配置保留。" : "恢复此前开启的服务。用户需重新登录。"} label={changing.enabled ? "停用用户" : "启用用户"} onClose={() => setChanging(null)} onConfirm={async () => { await request(`/api/v1/admin/users/${encodeURIComponent(changing.id)}`, { method: "PATCH", body: JSON.stringify({ enabled: !changing.enabled }) }, auth.csrf_token); await resource.reload(); }} />}
    {revoking && active && <Confirm title="撤销邀请？" description="链接将立即失效，无法再用于创建账号。" label="撤销邀请" onClose={() => setRevoking(null)} onConfirm={async () => { await request(`/api/v1/admin/invitations/${encodeURIComponent(revoking.id)}`, { method: "DELETE" }, auth.csrf_token); await resource.reload(); }} />}
    {editing && active && <UsernameForm user={editing} csrf={auth.csrf_token} onClose={() => setEditing(null)} onSaved={async result => { setEditing(null); if (result.reauthenticate) { onRenamed(result.username); return; } setNotice("用户名已更新，该用户需重新登录。"); await resource.reload(); }} />}
    {deleting && active && <DeleteUserForm user={deleting} csrf={auth.csrf_token} onClose={() => setDeleting(null)} onDeleted={async result => { const workspace = deleting.workspace_id; setDeleting(null); onDeleted(workspace, result.message); await resource.reload(); }} />}
    {quotaUser && active && <QuotaForm key={quotaUser.id} user={quotaUser} csrf={auth.csrf_token} onClose={() => setQuotaUser(null)} onSaved={() => { setQuotaUser(null); setNotice("流量限制已更新，统计数据保留。"); void resource.reload(); }} />}
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
  return <Modal title="修改用户名" full dirty={dirty} busy={busy} onClose={onClose}>{close => <form className="modal-form management-form" onSubmit={submit}><div className="modal-body"><p className="user-target">{user.username}</p><p className="helper">所有会话及恢复码将失效，需重新登录。</p><fieldset disabled={busy}><label>新用户名<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required /></label></fieldset><Notice error={error} /></div><footer className="modal-actions"><button type="button" className="secondary-button desktop-modal-cancel modal-dismiss" onClick={close} disabled={busy}>取消</button><button className="primary-button" disabled={busy || !dirty}>{busy ? "保存中…" : "保存用户名"}</button></footer></form>}</Modal>;
}

/** 删除会清除整个独立空间；确认文本随请求送到后端，防止账号已改名时误删。 */
function DeleteUserForm({ user, csrf, onClose, onDeleted }: { user: User; csrf?: string | null; onClose: () => void; onDeleted: (value: { message: string }) => Promise<void> }) {
  const [confirm, setConfirm] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (busy || confirm !== user.username) return; setBusy(true); setError(null);
    try { const result = await request<{ message: string }>(`/api/v1/admin/users/${encodeURIComponent(user.id)}`, { method: "DELETE", body: JSON.stringify({ confirm_username: confirm }) }, csrf); await onDeleted(result); }
    catch (e) { setError(`删除用户失败：${errorText(e)}`); } finally { setBusy(false); }
  }
  return <Modal title="删除用户" busy={busy} onClose={onClose}><form className="modal-form" onSubmit={submit}><div className="modal-body"><p className="user-target">{user.username}</p><p className="helper">工作空间：{user.workspace_name}</p><p>删除账号及全部资源，无法恢复。</p><UserResources user={user} /><fieldset disabled={busy}><label>输入用户名确认<input value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required /></label></fieldset><Notice error={error} /></div><footer className="modal-actions"><button type="button" className="secondary-button modal-dismiss" disabled={busy} onClick={onClose}>取消</button><button className="danger-button" disabled={busy || confirm !== user.username}>{busy ? "删除中…" : "永久删除"}</button></footer></form></Modal>;
}

/** 注册只能凭单次邀请进入。已有登录时先明确退出，避免覆盖当前账号。 */
export function InvitationScreen({ token, auth, onAuth, onCancel }: { token: string; auth: Auth; onAuth: (auth: Auth) => void; onCancel: () => void }) {
  const [expires, setExpires] = useState<number | null>(null); const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const [inspecting, setInspecting] = useState(true); const submitting = useRef(false);
  useEffect(() => {
    let live = true; setInspecting(true); setExpires(null); setError(null);
    request<Link>("/api/v1/auth/invitations/inspect", { method: "POST", body: JSON.stringify({ token }) })
      .then(result => { if (live) setExpires(result.expires_at); })
      .catch(e => { if (live) setError(errorText(e)); })
      .finally(() => { if (live) setInspecting(false); });
    return () => { live = false; };
  }, [token]);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (submitting.current) return;
    if (password !== confirm) { setError("两次输入的密码不一致"); return; }
    submitting.current = true; setBusy(true); setError(null);
    try { await request("/api/v1/auth/invitations/accept", { method: "POST", body: JSON.stringify({ token, username, password }) }); onAuth(await request<Auth>("/api/v1/auth/status")); }
    catch (e) { setError(errorText(e)); } finally { submitting.current = false; setBusy(false); }
  }
  return <main className="auth-shell"><section className="auth-panel"><Brand /><h1>接受邀请</h1>
    {auth.authenticated ? <><p className="auth-copy">当前登录为 {auth.username}。请退出后继续注册。</p><Notice error={error} /><button className="primary-button" disabled={busy} onClick={async () => { setBusy(true); try { await request("/api/v1/auth/logout", { method: "POST" }, auth.csrf_token); onAuth({ ...auth, authenticated: false }); } catch (e) { setError(errorText(e)); } finally { setBusy(false); } }}>退出当前账号</button></>
      : inspecting ? <p className="auth-copy" role="status">正在验证邀请…</p>
      : expires ? <form className="auth-form" onSubmit={submit}>
        <fieldset disabled={busy}>
          <label>用户名<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required /></label>
          <label>密码<PasswordInput aria-label="密码" aria-describedby="invitation-password-help" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" minLength={6} required /><span className="helper" id="invitation-password-help">至少 6 个字符</span></label>
          <label>确认密码<PasswordInput aria-label="确认密码" value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="new-password" minLength={6} required /></label>
          <p className="helper">邀请到期：{accountDate(expires)}</p>
        </fieldset>
        <Notice error={error} /><button className="primary-button" disabled={busy}>{busy ? "创建中…" : "创建账号"}</button>
      </form> : <Notice error={error} />}
    <button className="text-button" disabled={busy} onClick={onCancel}>返回登录</button>
  </section></main>;
}
