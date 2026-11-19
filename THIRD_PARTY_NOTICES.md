# Third-party notices

Nexo bundles or links the following third-party components:

- Rust crates listed in `Cargo.lock`, distributed under their respective licenses.
- React, Vite, Workbox, Iconify and Tabler packages listed in `web/package-lock.json`.
- Caddy in the Server and Agent images and the standalone Linux node package, and the Cloudflare, Alibaba Cloud and Tencent Cloud DNS modules in the Server image, under their upstream licenses.

This file is a navigation index; authoritative license texts remain with each upstream project.

## DB-IP Country Lite

流量天眼在运行时下载 DB-IP 提供的 IP to Country Lite 数据库。数据库采用 CC BY 4.0 许可，页面显示来源署名。 [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) · [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## Iconify 与 Tabler Icons

界面操作图标使用 [Iconify React](https://iconify.design/docs/icon-components/react/) 的离线组件与 [Tabler Icons](https://github.com/tabler/tabler-icons) 线性图标，均使用 MIT 许可证。仅将实际使用的图标数据打包到前端，不在运行时请求 Iconify API。完整版权及许可声明位于 `web/public/licenses/Iconify.txt` 和 `web/public/licenses/Tabler.txt`，部署后可通过 `/licenses/Iconify.txt` 与 `/licenses/Tabler.txt` 查看。

## HD-Icons

应用图标目录来自 [xushier/HD-Icons](https://github.com/xushier/HD-Icons)，使用 MIT 许可证。完整版权及许可声明位于 `web/public/licenses/HD-Icons.txt`，部署后可通过 `/licenses/HD-Icons.txt` 查看。Nexo 内置图标索引，图片按需在线加载；图标中的品牌与商标属于各自权利人。

## LeiBox 交互组件

手机导航和服务视图切换分别适配自 LeiBox 的 [Glass Tab Menu](https://leibox.pantoria.cn/docs/animations/glass-tab-menu) 与 [Collection Layout Morph](https://leibox.pantoria.cn/docs/animations/collection-layout-morph) React 源码包。设计参考作者分别为 solutionb 和 Previous Leon，链接及上游声明保留在 `web/src/components/leibox/` 各组件的 `NOTICE.md` 和 `web/public/licenses/LeiBox.txt` 中。

LeiBox 目录未为组件授予统一许可证，列表布局组件的原始代码许可未提供或独立核实；不将其标为 MIT，也不以 Nexo 的 AGPL 声明覆盖上游权利。固定演示画布、内嵌 Inter 字体、Claude/Codex/Grok 演示 SVG 和通用演示运行层均已移除，原 SVG 来源记录仅作为溯源说明保留，不随适配组件展示或分发这些资源。

## GSAP 与 Flip

服务页面随页面代码加载 GSAP 3.15.1 和 Flip 插件，导航使用本地轻量弹簧。GSAP 采用 [Standard License](https://gsap.com/standard-license/)，版权和许可文本随 Web 构建分发，源文件位于 `web/public/licenses/GSAP.txt`，部署后可通过 `/licenses/GSAP.txt` 查看。
