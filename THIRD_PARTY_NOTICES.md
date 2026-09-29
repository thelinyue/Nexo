# Third-party notices

Nexo bundles or links the following third-party components:

- Rust crates listed in `Cargo.lock`, distributed under their respective licenses.
- React, Vite, Workbox, Iconify and Tabler packages listed in `web/package-lock.json`.
- Caddy and the Cloudflare DNS module in the Server image, under their upstream licenses.

This file is a navigation index; authoritative license texts remain with each upstream project.

## Iconify 与 Tabler Icons

界面操作图标使用 [Iconify React](https://iconify.design/docs/icon-components/react/) 的离线组件与 [Tabler Icons](https://github.com/tabler/tabler-icons) 线性图标，均使用 MIT 许可证。仅将实际使用的图标数据打包到前端，不在运行时请求 Iconify API。完整版权及许可声明位于 `web/public/licenses/Iconify.txt` 和 `web/public/licenses/Tabler.txt`，部署后可通过 `/licenses/Iconify.txt` 与 `/licenses/Tabler.txt` 查看。

## HD-Icons

应用图标目录来自 [xushier/HD-Icons](https://github.com/xushier/HD-Icons)，使用 MIT 许可证。完整版权及许可声明位于 `web/public/licenses/HD-Icons.txt`，部署后可通过 `/licenses/HD-Icons.txt` 查看。Nexo 内置图标索引，图片按需在线加载；图标中的品牌与商标属于各自权利人。
