/// <reference lib="webworker" />

import { cleanupOutdatedCaches, createHandlerBoundToURL, precacheAndRoute } from "workbox-precaching";
import { NavigationRoute, registerRoute } from "workbox-routing";
import { NetworkOnly } from "workbox-strategies";

declare const self: ServiceWorkerGlobalScope & {
  __WB_MANIFEST: Array<{ url: string; revision?: string | null }>;
};

precacheAndRoute(self.__WB_MANIFEST);
cleanupOutdatedCaches();

// Nexo 使用 hash 路由，只有应用根路径需要 SPA fallback；API 路径必须直达 Server。
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

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    await self.clients.claim();
  })());
});
