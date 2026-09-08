/// <reference lib="webworker" />

import { cleanupOutdatedCaches, createHandlerBoundToURL, precacheAndRoute } from "workbox-precaching";
import { NavigationRoute, registerRoute } from "workbox-routing";
import { NetworkOnly } from "workbox-strategies";

declare const self: ServiceWorkerGlobalScope & {
  __WB_MANIFEST: Array<{ url: string; revision?: string | null }>;
};

function hasOidcTicket(url: string): boolean {
  return new URL(url).searchParams.has("oidc_ticket");
}

function windowClients(clients: readonly Client[]): WindowClient[] {
  return clients.filter((client): client is WindowClient => client.type === "window");
}

precacheAndRoute(self.__WB_MANIFEST);
cleanupOutdatedCaches();

// Nexo 使用 hash 路由，只有应用根路径需要 SPA fallback；OIDC 和健康检查等
// 服务端路径必须直达 Server，不能被缓存的 index.html 截获。
registerRoute(
  new NavigationRoute(createHandlerBoundToURL("index.html"), {
    allowlist: [/^\/(?:index\.html)?$/],
  }),
);
registerRoute(({ url }) => url.pathname.startsWith("/api/"), new NetworkOnly(), "GET");

self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") {
    void self.skipWaiting();
  }
});

// 旧版应用壳可能不会识别 oidc_ticket。只在 OIDC 登录页存在时提前接管，
// 这样可以恢复组网登录，同时不打断普通页面中尚未提交的编辑内容。
self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (windowClients(clients).some((client) => hasOidcTicket(client.url))) {
      await self.skipWaiting();
    }
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    await self.clients.claim();
    const clients = windowClients(await self.clients.matchAll({ type: "window", includeUncontrolled: true }));
    // 不等待 navigate：导航本身可能依赖刚激活的 Worker，等待它会阻塞激活完成。
    for (const client of clients.filter((candidate) => hasOidcTicket(candidate.url))) {
      void client.navigate(client.url).catch(() => null);
    }
  })());
});
