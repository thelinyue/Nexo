import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

export default defineConfig({
  // 独立发布时沿用 Compose 中真实存在的 Agent 镜像，不借用 Server/Web 版本号。
  define: { __AGENT_COMPOSE_TEMPLATE__: JSON.stringify(readFileSync(new URL("../compose.agent.yml", import.meta.url), "utf8")) },
  plugins: [
    react(),
    {
      name: "nexo-static-gzip",
      apply: "build",
      // 构建后生成静态资源旁路文件，避免请求时占用 CPU；原文件用于不支持 gzip 的客户端。
      closeBundle() {
        const compress = (directory: string) => {
          for (const item of readdirSync(directory, { withFileTypes: true })) {
            const path = join(directory, item.name);
            if (item.isDirectory()) compress(path);
            else if (/\.(js|css)$/.test(item.name)) writeFileSync(`${path}.gz`, gzipSync(readFileSync(path), { level: 9 }));
          }
        };
        compress(fileURLToPath(new URL("./dist/assets", import.meta.url)));
      },
    },
    VitePWA({
      injectRegister: false,
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
        background_color: "#171411",
        theme_color: "#171411",
        icons: [
          { src: "/pwa-192x192.png", sizes: "192x192", type: "image/png" },
          { src: "/pwa-512x512.png", sizes: "512x512", type: "image/png" },
          { src: "/pwa-maskable-512x512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      },
      injectManifest: {
        globPatterns: ["**/*.{js,css,html,png,webp,svg,ico}"],
      },
    }),
  ],
});
