import { useEffect, useRef, useState } from "react";
import { registerSW } from "virtual:pwa-register";
import { hasPendingWrites } from "./ui";

/** 普通 HTTP 没有 Service Worker；比较构建已有的入口资源地址，不另外生成版本标识。 */
function entryResources(html: Document) {
  if (!html.getElementById("root") || !html.querySelector('script[type="module"][src]')) return null;
  return JSON.stringify(Array.from(html.querySelectorAll('script[type="module"][src],link[rel="stylesheet"][href]'))
    .map(element => element.getAttribute(element.tagName === "SCRIPT" ? "src" : "href")).sort());
}

/** 更新只通知、不自动刷新；同一来源的其他标签页激活新版也不能打断当前操作。 */
export function WebUpdateNotice() {
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refresh = useRef<() => Promise<void>>(async () => {});
  const dismiss = useRef<() => void>(() => {});

  useEffect(() => {
    if (!import.meta.env.PROD) return;
    let disposed = false; let checking = false; let registration: ServiceWorkerRegistration | undefined;
    let fallback = !("serviceWorker" in navigator); let approved = false; let reloadTimer: number | undefined;
    let controller = navigator.serviceWorker?.controller;
    let availableVersion: ServiceWorker | string | undefined;
    let dismissedVersion: ServiceWorker | string | null = null;
    const currentResources = entryResources(document);
    const notify = (version: ServiceWorker | string | undefined = registration?.waiting ?? registration?.active ?? undefined) => {
      availableVersion = version;
      if (!disposed && version !== dismissedVersion) setAvailable(true);
    };
    const reset = () => { approved = false; window.clearTimeout(reloadTimer); if (!disposed) setBusy(false); };
    const reload = () => {
      reset();
      if (blockedNow()) { setError("请完成当前操作后再刷新。"); return; }
      window.location.reload();
    };
    const updateServiceWorker = registerSW({
      immediate: true,
      onNeedRefresh: () => notify(),
      // 原生接管监听覆盖本标签页首次安装后发生的后续更新，不由库自动重载。
      onNeedReload: () => {},
      onRegisteredSW: (_url, value) => { registration = value; fallback = !value; void check(); },
      onRegisterError: () => { fallback = true; void check(); },
    });
    async function check() {
      if (disposed || checking || document.visibilityState !== "visible" || !navigator.onLine) return;
      checking = true;
      try {
        if (registration) {
          await registration.update();
          if (registration.waiting) notify();
        } else if (fallback && currentResources) {
          // 独立查询参数避免已有预缓存命中；请求失败或代理错误页不视为新版。
          const response = await fetch("/index.html?nexo-update-check=1", { cache: "no-store", signal: AbortSignal.timeout(10000) });
          if (!response.ok || !response.headers.get("content-type")?.includes("text/html")) return;
          const resources = entryResources(new DOMParser().parseFromString(await response.text(), "text/html"));
          if (resources && resources !== currentResources) notify(resources);
        }
      } catch { /* 更新探测失败不影响当前页面，返回前台或网络恢复后重试。 */ }
      finally { checking = false; }
    }
    const blockedNow = () => hasPendingWrites() || Boolean(document.querySelector("dialog[open]"));
    const updateBlocked = () => setBlocked(blockedNow());
    const observer = new MutationObserver(updateBlocked);
    observer.observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ["open"] });
    window.addEventListener("nexo:writes-changed", updateBlocked);
    updateBlocked();
    dismiss.current = () => { dismissedVersion = availableVersion ?? null; setAvailable(false); };
    const controllerChanged = () => {
      const previous = controller; controller = navigator.serviceWorker.controller;
      if (disposed) return;
      if (approved) reload();
      else if (previous) notify(controller ?? undefined);
    };
    navigator.serviceWorker?.addEventListener("controllerchange", controllerChanged);
    refresh.current = async () => {
      if (approved || blockedNow()) return;
      const resume = async () => {
        if (disposed || blockedNow()) return;
        if (!navigator.onLine) { setError("网络已断开，请恢复连接后重试。"); return; }
        approved = true; setBusy(true); setError(null);
        try {
          if (registration?.waiting) {
            reloadTimer = window.setTimeout(() => { reset(); setError("更新暂未完成，请稍后重试。"); }, 15000);
            await updateServiceWorker();
          } else reload();
        } catch { reset(); setError("无法更新网页，请稍后重试。"); }
      };
      // 服务器设置沿用离页确认；确认放弃草稿前不激活新版缓存。
      if (window.dispatchEvent(new CustomEvent("nexo:route-change", { cancelable: true, detail: { resume } }))) await resume();
    };
    const trigger = () => { void check(); };
    const timer = window.setInterval(trigger, 5 * 60 * 1000);
    window.addEventListener("focus", trigger); window.addEventListener("online", trigger); window.addEventListener("pageshow", trigger);
    document.addEventListener("visibilitychange", trigger);
    void check();
    return () => {
      disposed = true; approved = false; window.clearTimeout(reloadTimer); window.clearInterval(timer); observer.disconnect();
      window.removeEventListener("nexo:writes-changed", updateBlocked);
      navigator.serviceWorker?.removeEventListener("controllerchange", controllerChanged);
      window.removeEventListener("focus", trigger); window.removeEventListener("online", trigger); window.removeEventListener("pageshow", trigger);
      document.removeEventListener("visibilitychange", trigger);
    };
  }, []);

  if (!available) return null;
  return <aside className="web-update-notice" aria-label="网页更新">
    <div role="status"><p>网页已更新，刷新后使用新版本。</p>{blocked && <small>请完成当前操作后再刷新。</small>}</div>
    <button className="secondary-button" disabled={busy || blocked} onClick={() => void refresh.current()}>{busy ? "更新中…" : "刷新页面"}</button>
    <button className="text-button" disabled={busy} onClick={() => dismiss.current()}>稍后</button>
    {error && <p className="form-error" role="alert">{error}</p>}
  </aside>;
}
