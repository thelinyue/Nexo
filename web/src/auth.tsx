import { useState } from "react";
import type { FormEvent } from "react";
import { Brand, Confirm, Modal, Notice, errorText, request } from "./ui";
import type { Auth } from "./ui";

/** 登录与恢复共用短表单。会话过期时叠加在当前页面上，原表单只保留在内存中。 */
function AuthForm({ initial, message, onAuth, reauth = false, recoveryCode }: { initial: Auth; message?: string | null; onAuth: (auth: Auth) => void; reauth?: boolean; recoveryCode?: string }) {
  const [mode, setMode] = useState<"login" | "initialize" | "recover">(recoveryCode ? "recover" : initial.initialized ? "login" : "initialize");
  const [username, setUsername] = useState(initial.username ?? "");
  const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState(""); const [code, setCode] = useState(recoveryCode ?? "");
  const [busy, setBusy] = useState(false); const [error, setError] = useState<string | null>(null); const [notice, setNotice] = useState<string | null>(null);
  function switchMode(next: typeof mode) { setMode(next); setError(null); setNotice(null); setPassword(""); setConfirm(""); setCode(""); }
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null);
    if (mode === "recover" && password !== confirm) { setError("两次输入的密码不一致"); return; }
    setBusy(true);
    try {
      if (mode === "recover") {
        const result = await request<{ username: string }>("/api/v1/auth/recover", { method: "POST", body: JSON.stringify({ recovery_code: code.trim(), new_password: password }) });
        switchMode("login"); if (!reauth) setUsername(result.username); setNotice("密码已重设，请使用新密码登录。");
      } else {
        await request("/api/v1/auth/" + mode, { method: "POST", body: JSON.stringify({ username, password, ...(mode === "initialize" ? { bootstrap_code: code.trim() } : {}) }) });
        onAuth(await request<Auth>("/api/v1/auth/status"));
      }
    } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <>
    {!reauth && <><Brand /><h1>{mode === "recover" ? "找回账号" : mode === "initialize" ? "创建管理员" : "欢迎回来"}</h1></>}
    {(mode !== "login" || reauth) && <p className="auth-copy">{mode === "recover" ? "使用管理员提供的恢复链接或本机生成的一次性恢复码重设密码。" : reauth ? "重新登录后继续操作，当前填写的内容会保留。" : mode === "initialize" ? "设置管理员账号，开始使用 Nexo。" : ""}</p>}
    {(notice || message) && <p className="action-status" role="status">{notice || message}</p>}
    {mode === "recover" && <details className="recovery-help"><summary>如何获取恢复码</summary><p>普通用户请联系管理员生成恢复链接。管理员可在 Server 所在主机运行：</p><code>docker compose exec nexo-server nexo admin recover</code><p>直接运行二进制时使用 <code>nexo-server admin recover</code>，并设置原来的 NEXO_DATA_DIR。恢复码有效期 15 分钟，重新生成后旧码失效。</p></details>}
    <form className="auth-form" onSubmit={submit}>
      <fieldset disabled={busy}>
        {mode !== "login" && <label>{mode === "recover" ? "一次性恢复码" : "初始化口令"}<input value={code} onChange={e => setCode(e.target.value)} type="password" autoComplete="one-time-code" autoCapitalize="none" spellCheck={false} required /></label>}
        {mode !== "recover" && <label>用户名<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required /></label>}
        <label>{mode === "recover" ? "新密码" : "密码"}<input value={password} onChange={e => setPassword(e.target.value)} type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "login" ? undefined : 12} required /></label>
        {mode === "recover" && <label>确认新密码<input value={confirm} onChange={e => setConfirm(e.target.value)} type="password" autoComplete="new-password" minLength={12} required /></label>}
        {mode !== "login" && <p className="helper">密码至少 12 个字符。{mode === "recover" && "重设后，此账号的所有登录会话都会失效。"}</p>}
      </fieldset>
      <Notice error={error} /><button className="primary-button" disabled={busy}>{busy ? "处理中…" : mode === "recover" ? "重设密码" : mode === "initialize" ? "开始使用" : "登录"}</button>
    </form>
    {initial.initialized ? <button className="text-button" disabled={busy} onClick={() => switchMode(mode === "recover" ? "login" : "recover")}>{mode === "recover" ? "返回登录" : "忘记密码"}</button> : <button className="text-button" disabled={busy} onClick={() => switchMode(mode === "initialize" ? "login" : "initialize")}>{mode === "initialize" ? "已有管理员账号？登录" : "首次安装 Nexo"}</button>}
  </>;
}

export function AuthScreen(props: { initial: Auth; message?: string | null; recoveryCode?: string; onAuth: (auth: Auth) => void }) {
  return <main className="auth-shell"><div className="auth-stage"><div className="auth-visual"><img src="/illustrations/empty-public.webp" alt="" /><p>把你的服务，带到身边。</p></div><section className="auth-panel"><AuthForm {...props} /></section></div></main>;
}
export function Reauthenticate({ auth, onAuth, onAbandon }: { auth: Auth; onAuth: (auth: Auth) => void; onAbandon: () => void }) {
  const [abandon, setAbandon] = useState(false);
  return <><Modal title="登录已过期" onClose={() => {}} dismissible={false}><div className="modal-body"><AuthForm initial={auth} onAuth={onAuth} reauth /><button className="text-button" onClick={() => setAbandon(true)}>退出并放弃当前草稿</button></div></Modal>{abandon && <Confirm title="放弃当前草稿？" description="未提交的内容将丢失，并返回登录页。" label="放弃并返回登录" onClose={() => setAbandon(false)} onConfirm={async () => onAbandon()} />}</>;
}
