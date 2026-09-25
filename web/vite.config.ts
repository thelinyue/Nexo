import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
import { readFileSync } from "node:fs";

export default defineConfig({
  // 独立发布时沿用 Compose 中真实存在的 Agent 镜像，不借用 Server/Web 版本号。
  define: { __AGENT_COMPOSE_TEMPLATE__: JSON.stringify(readFileSync(new URL("../compose.agent.yml", import.meta.url), "utf8")) },
  plugins: [
    react(),
    VitePWA({
      registerType: "prompt",
      strategies: "injectManifest",
      srcDir: "src",
      filename: "sw.ts",
      manifest: {
        name: "Nexo 联巢",
        short_name: "Nexo",
        lang: "zh-CN",
        description: "自托管内网穿透服务管理",
        start_url: "/#/services",
        scope: "/",
        display: "standalone",
        background_color: "#151617",
        theme_color: "#151617",
        icons: [
          { src: "/pwa-192x192.png", sizes: "192x192", type: "image/png" },
          { src: "/pwa-512x512.png", sizes: "512x512", type: "image/png" },
          { src: "/pwa-maskable-512x512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      },
      injectManifest: {
        globPatterns: ["**/*.{js,css,html,png,svg,ico}"],
      },
    }),
  ],
});
