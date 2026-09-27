import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { Brand, PasswordInput, Confirm, Modal, Notice, errorText, request } from "./ui";
import type { Auth } from "./ui";

/** 登录与恢复共用短表单。会话过期时叠加在当前页面上，原表单只保留在内存中。 */
function AuthForm({ initial, message, onAuth, reauth = false, recoveryCode }: { initial: Auth; message?: string | null; onAuth: (auth: Auth) => void; reauth?: boolean; recoveryCode?: string }) {
  const [mode, setMode] = useState<"login" | "recover">(recoveryCode ? "recover" : "login");
  const [username, setUsername] = useState(initial.username ?? "");
  const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState(""); const [code, setCode] = useState(recoveryCode ?? "");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [notice, setNotice] = useState<string | null>(null);
  const submitting = useRef(false);
  function switchMode(next: typeof mode) { setMode(next); setError(null); setNotice(null); setPassword(""); setConfirm(""); setCode(""); }
  async function submit(event: FormEvent) {
    event.preventDefault(); if (submitting.current) return; setError(null);
    if (mode === "recover" && password !== confirm) { setError("两次输入的密码不一致"); return; }
    submitting.current = true; setBusy(true);
    try {
      if (mode === "recover") {
        const result = await request<{ username: string }>("/api/v1/auth/recover", { method: "POST", body: JSON.stringify({ recovery_code: code.trim(), new_password: password }) });
        switchMode("login"); if (!reauth) setUsername(result.username); setNotice("密码已重设，请使用新密码登录。");
      } else {
        await request("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
        onAuth(await request<Auth>("/api/v1/auth/status"));
      }
    } catch (e) { setError(errorText(e)); } finally { submitting.current = false; setBusy(false); }
  }
  return <>
    {!reauth && <><Brand /><h1>{mode === "recover" ? "找回账号" : "登录"}</h1></>}
    {(mode !== "login" || reauth) && <p className="auth-copy">{mode === "recover" ? recoveryCode ? "设置新密码，恢复账号访问。" : "请联系管理员获取恢复链接。" : "重新登录后继续操作，当前填写的内容会保留。"}</p>}
    {(notice || message) && <p className="action-status" role="status">{notice || message}</p>}
    {mode === "recover" && <details className="recovery-help"><summary>管理员如何恢复账号</summary><p>在 Server 所在主机运行：</p><code>docker compose exec nexo-server nexo --data-dir /data/nexo admin recover</code><p>直接运行二进制时使用 <code>nexo-server admin recover</code>，并用 --data-dir 指定原数据目录。恢复码有效期 15 分钟，重新生成后旧码失效。</p></details>}
    <form className="auth-form" onSubmit={submit}>
      <fieldset disabled={busy}>
        {mode === "recover" && <label>一次性恢复码<input value={code} onChange={e => setCode(e.target.value)} type="password" autoComplete="one-time-code" autoCapitalize="none" spellCheck={false} required /></label>}
        {mode !== "recover" && <label>用户名<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required /></label>}
        <label>{mode === "recover" ? "新密码" : "密码"}<PasswordInput aria-label={mode === "recover" ? "新密码" : "密码"} value={password} onChange={e => setPassword(e.target.value)} type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "login" ? undefined : 6} required /></label>
        {mode === "recover" && <label>确认新密码<PasswordInput aria-label="确认新密码" value={confirm} onChange={e => setConfirm(e.target.value)} type="password" autoComplete="new-password" minLength={6} required /></label>}
        {mode !== "login" && <p className="helper">密码至少 6 个字符。{mode === "recover" && "重设后，此账号的所有登录会话都会失效。"}</p>}
      </fieldset>
      <Notice error={error} /><button className="primary-button" disabled={busy}>{busy ? "处理中…" : mode === "recover" ? "重设密码" : "登录"}</button>
    </form>
    <button className="text-button" disabled={busy} onClick={() => switchMode(mode === "recover" ? "login" : "recover")}>{mode === "recover" ? "返回登录" : "忘记密码"}</button>
  </>;
}

export function AuthScreen(props: { initial: Auth; message?: string | null; recoveryCode?: string; onAuth: (auth: Auth) => void }) {
  return <main className="auth-shell"><section className="auth-panel"><AuthForm {...props} /></section></main>;
}
export function Reauthenticate({ auth, onAuth, onAbandon }: { auth: Auth; onAuth: (auth: Auth) => void; onAbandon: () => void }) {
  const [abandon, setAbandon] = useState(false);
  return <><Modal title="登录已过期" onClose={() => {}} dismissible={false}><div className="modal-body"><AuthForm initial={auth} onAuth={onAuth} reauth /><button className="text-button" onClick={() => setAbandon(true)}>退出并放弃当前草稿</button></div></Modal>{abandon && <Confirm title="放弃当前草稿？" description="未提交的内容将丢失，并返回登录页。" label="放弃并返回登录" onClose={() => setAbandon(false)} onConfirm={async () => onAbandon()} />}</>;
}
