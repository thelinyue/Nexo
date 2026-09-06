import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "prompt",
      manifest: {
        name: "Nexo 联巢",
        short_name: "Nexo",
        lang: "zh-CN",
        description: "设备、穿透服务与网络互联管理",
        start_url: "/#/overview",
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
      workbox: {
        globPatterns: ["**/*.{js,css,html,png,svg,ico}"],
        navigateFallback: "index.html",
        runtimeCaching: [
          {
            urlPattern: /\/api\//,
            handler: "NetworkOnly",
            method: "GET",
          },
        ],
      },
    }),
  ],
});
