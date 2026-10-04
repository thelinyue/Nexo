import { lazy, Suspense, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { KeyRound, LogOut, ShieldCheck } from "./icons";
import { navigationLocked } from "./navigation";
import { Loading, Notice, UserAvatar, WorkspaceLabelContext, errorText, rememberInteraction } from "./ui";
import type { Auth } from "./ui";

const PasswordForm = lazy(() => import("./management").then(module => ({ default: module.PasswordForm })));

/** 账号操作属于登录人，独立于业务页面和代管空间。
 * 同一菜单实例跨屏保留密码草稿；触发器仅投递到顶部或侧栏，实际动作复用离页保护。
 */
export function AccountMenu({ auth, target, compact, route, requestId, onLogout, onExpired }: { auth: Auth; target: HTMLElement | null; compact: boolean; route: string; requestId: number; onLogout: () => Promise<void>; onExpired: () => void }) {
  const id = useId(); const trigger = useRef<HTMLButtonElement>(null); const panel = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false); const [password, setPassword] = useState(false);
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null);
  const loggingOut = useRef(false); const lastRequest = useRef(0);
  const close = () => { if (panel.current?.matches(":popover-open")) panel.current.hidePopover(); };
  const focusTrigger = () => trigger.current?.focus({ preventScroll: true });
  function show(index = 0) {
    const menu = panel.current; const button = trigger.current;
    if (!menu || !button || document.querySelector("dialog[open]")) return;
    menu.showPopover();
    const viewport = window.visualViewport; const row = button.getBoundingClientRect();
    const left = (viewport?.offsetLeft ?? 0) + 16; const top = (viewport?.offsetTop ?? 0) + 16;
    const right = left + (viewport?.width ?? innerWidth) - 32; const bottom = top + (viewport?.height ?? innerHeight) - 32;
    // 宽度由用户名和菜单内容决定；先约束可见视口，再测量以保证贴近头像且不越界。
    menu.style.setProperty("--menu-available-width", `${right - left}px`); menu.style.maxHeight = `${bottom - top}px`;
    const box = menu.getBoundingClientRect();
    menu.style.left = `${Math.max(left, Math.min(row.right - box.width, right - box.width))}px`;
    menu.style.top = `${Math.max(top, Math.min(row.bottom + 8 + box.height <= bottom ? row.bottom + 8 : row.top - box.height - 8, bottom - box.height))}px`;
    (menu.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled):not([aria-disabled=true])')[index] ?? menu).focus({ preventScroll: true });
  }
  function perform(resume: () => void) {
    close(); focusTrigger(); rememberInteraction(trigger.current);
    if (!navigationLocked() && window.dispatchEvent(new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume } }))) resume();
  }
  async function logout() {
    if (loggingOut.current) return;
    loggingOut.current = true; setBusy(true); setError(null);
    let failed = false;
    try { await onLogout(); }
    catch (e) { failed = true; setError(`退出失败：${errorText(e)}`); }
    finally { loggingOut.current = false; setBusy(false); if (failed) window.setTimeout(() => show(2), 0); }
  }
  useEffect(() => { close(); }, [route, compact]);
  useEffect(() => {
    if (!target || !requestId || lastRequest.current === requestId) return;
    lastRequest.current = requestId; show();
  }, [requestId, target]);
  useEffect(() => {
    if (!open) return;
    const dismiss = () => { const restore = panel.current?.contains(document.activeElement); close(); if (restore) requestAnimationFrame(focusTrigger); };
    const observer = new MutationObserver(() => { if (document.querySelector("dialog[open]")) close(); });
    observer.observe(document.body, { subtree: true, attributes: true, attributeFilter: ["open"] });
    window.addEventListener("resize", dismiss); window.visualViewport?.addEventListener("resize", dismiss);
    return () => { observer.disconnect(); window.removeEventListener("resize", dismiss); window.visualViewport?.removeEventListener("resize", dismiss); };
  }, [open]);
  const selected = open || password || route === "#/settings/sessions";
  return <>
    {target && createPortal(<button ref={trigger} type="button" className={compact ? "pwa-account" : "sidebar-settings"} data-selected={selected} title={auth.username} aria-label="账号菜单" aria-haspopup="menu" aria-expanded={open} aria-controls={id} popoverTarget={id} onClick={event => { event.preventDefault(); if (panel.current?.matches(":popover-open")) { close(); focusTrigger(); } else show(); }} onKeyDown={event => { if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); show(event.key === "ArrowUp" ? 2 : 0); } }}><UserAvatar role={auth.role} size={32} />{!compact && <span className="sidebar-account-name"><strong title={auth.username}>{auth.username}</strong></span>}</button>, target)}
    <div ref={panel} id={id} popover="auto" role="menu" aria-label="本人账号" tabIndex={-1} className="account-menu" onToggle={event => setOpen(event.currentTarget.matches(":popover-open"))} onBlur={event => { if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget as Node) && event.relatedTarget !== trigger.current) close(); }} onKeyDown={event => {
      const items = Array.from(panel.current!.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled):not([aria-disabled=true])'));
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
        event.preventDefault();
        const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
        items[next]?.focus({ preventScroll: true });
      } else if (event.key === "Escape") { event.preventDefault(); close(); focusTrigger(); }
      else if (event.key === "Tab") {
        event.preventDefault(); close();
        const controls = Array.from(document.querySelectorAll<HTMLElement>('a[href],button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),summary,[tabindex="0"]')).filter(item => item.getClientRects().length && !panel.current?.contains(item) && !item.closest("[hidden]"));
        const position = controls.indexOf(trigger.current!);
        (controls[position + (event.shiftKey ? -1 : 1)] ?? trigger.current)?.focus({ preventScroll: true });
      }
    }}>
      <div className="account-menu-identity"><strong title={auth.username}>{auth.username}</strong><small>{auth.role === "system_admin" ? "管理员" : "普通用户"}</small>{auth.local_http_warning && <p className="notice" role="status">当前连接未加密，公网访问请使用 HTTPS。</p>}</div>
      <div role="none" className="account-menu-actions">
        <button role="menuitem" type="button" disabled={busy} onClick={() => perform(() => setPassword(true))}><KeyRound size={18} aria-hidden="true" />修改密码</button>
        <a role="menuitem" href="#/settings/sessions" aria-disabled={busy || undefined} tabIndex={busy ? -1 : 0} onClick={event => { event.preventDefault(); if (!busy) perform(() => { window.location.hash = "#/settings/sessions"; }); }}><ShieldCheck size={18} aria-hidden="true" />登录会话</a>
        <button role="menuitem" type="button" className="account-menu-logout" disabled={busy} aria-busy={busy || undefined} onClick={() => perform(() => void logout())}><LogOut size={18} aria-hidden="true" />{busy ? "退出中…" : "退出登录"}</button>
      </div>
      <Notice error={error} />
    </div>
    {password && <WorkspaceLabelContext.Provider value={undefined}><Suspense fallback={<Loading />}><PasswordForm csrf={auth.csrf_token} onClose={() => setPassword(false)} onExpired={onExpired} returnFocus={() => trigger.current} /></Suspense></WorkspaceLabelContext.Provider>}
  </>;
}
