# 设备中心的网络体验

参考 Tailscale 官方公开的设备、子网路由、审批与 Auth Key 流程；不声称与实时控制台逐屏一致。

组网设备的显示名称与访问名称独立保存。访问名称是全局唯一的短 ASCII 名称，
当前应用后以 `<mesh-name>.<mesh-base-domain>` 提供 MagicDNS 访问；Headscale
上游 DNS 固定为阿里公共 DNS，MagicDNS 仍负责 Nexo 内部设备名称解析。

## 操作映射与文字线框

| 官方公开流程 | Nexo 最终入口 |
| --- | --- |
| Machines → 设备 → Subnets → Edit → Save | 设备 → 详情 → 子网 → 编辑 → 保存 |
| Machines → Needs approval → Approve | 设备列表或添加设备面板 → 核对设备 → 批准 |
| Settings → Keys | 网络设置 → 客户端密钥 |
| Serve / Funnel | 保留 Nexo 公网服务体系，复用设备详情与表单 |

```text
设备 [搜索名称或 IP] [类型] [状态] [添加设备]
  家庭 NAS   Nexo Agent   100.x.x.x   在线
  → 详情：组网访问 [短名 / 完整域名] / 子网 [编辑] / 公网服务 [添加] / 连接情况
子网 [勾选检测网段或已有配置] → 保存 → 正在配置 → 正常
公网 [Web / TCP] [本地地址] [公网地址预览] → 创建
  缺少域名 → 原地配置 → 返回并恢复草稿
密钥 [密钥列表] → 创建 [名称 / 有效期 / 使用方式] → 仅展示一次
```

## 状态

| 状态 | 含义 |
| --- | --- |
| 正常 | 配置与必要的控制面批准完成，不保证任意家庭服务已实测 |
| 处理中 | 正在应用或撤销，无需人工确认 |
| 需处理 | 设备离线、转发未开启或应用失败；提供具体处理入口 |
| 已关闭 | 撤销完成 |

P2P、节点中继、DERP、空闲和未知分别属于客户端到 Agent 的连接路径，不替代配置状态。

## 升级与验收

升级前备份业务数据库。Server 与 Agent 一起升级，保留原节点身份。迁移移除站点与 SiteLink 关系，保留普通共享网段、公网服务、域名、密钥和审计。用户自行配置的历史 SiteLink 静态路由需在家庭路由器上人工清理；Nexo 不修改路由器。

真实 iPhone 验收需在用户设备上完成登录、家庭服务访问与路径对照。自动化浏览器或 Docker 验证不能替代该项。

### 安全升级步骤

本次 Server（含 Web、数据库迁移）和 Agent 均有运行时代码变化，需要同批升级。版本号在发布阶段确定，不能只升级其中一端。

1. 记录现有 Server/Agent 镜像标签与持久卷位置，安排维护窗口，停止 Server 和所有 Agent。不要删除容器卷或重新签发节点身份。
2. 在 Server 停止后复制整个数据目录（包括 `nexo.db`、存在的 WAL/SHM 文件、证书和组网服务状态），各 Agent 同样备份其持久化身份目录。不要只复制运行中的 SQLite 主文件。
3. 使用同版本的新 Server/Agent 镜像启动原服务和原持久卷。Server 启动会事务执行迁移 0023、0024；已执行迁移保持原样。0024 会为历史设备分配短访问名，并在后台逐台应用到 Headscale。
4. 检查 `/health`、设备在线状态及普通共享网段状态。重连会应用完整广告列表（包括空列表）、开启 SNAT、关闭 SiteLink 路由接收，并重新生成普通资源授权与批准；访问名更新期间仍保留旧的有效域名。
5. 由管理员清理家庭路由器上此前为 SiteLink 手动添加的静态路由；不删除正常 LAN 路由。确认现有 Web/TCP 服务和私网访问恢复后结束维护。

仓库内 Compose 示例的停止和备份方式如下；自定义部署必须使用实际挂载目录，备份目标应为尚不存在的独立目录：

```bash
docker compose -f docker/compose.phase2.yml stop nexo-server nexo-agent
sudo cp -a docker/data/nexo /srv/backups/nexo-before-network-upgrade
sudo cp -a docker/data/nexo-agent /srv/backups/nexo-agent-before-network-upgrade
```

迁移后的数据库不能直接交给旧版本运行。需要回退时，先停止新版本，再恢复完整备份和原镜像；维护后的新增数据不会包含在旧备份中。

### 本轮验收记录（2026-09-08）

- Rust 工作空间：164 项测试通过；包括含 SiteLink 旧数据迁移、事务回滚、幂等保存、名称规范化、全局冲突、旧地址保留、隔离、IPv4/IPv6、路由撤回证明与连接观测。
- Web：生产构建通过。Playwright 105 项通过、15 项按平台或矩阵条件跳过、0 失败；覆盖设备、短访问名编辑与冲突、子网、公网、密钥、域名、权限、焦点及草稿恢复，并执行桌面深色、移动竖屏和横屏验证。
- Linux/WSL2 Docker：当前 Windows 环境未安装 Docker CLI，未执行 `bash docker/network-smoke.sh`；因此本轮不把阿里 DNS 实际生效、短名解析或数据面访问写成已验收。
- 测试客户端阻断 Docker 网桥绕过 Tailscale 的 LAN 访问，确保关闭网段后不能通过宿主机旁路访问服务。
- 最后移除了未知来源客户端的重命名前置要求；管理员仍需确认归属。该调整另行通过 Rust 认领回归测试及 Tailscale 页面交互测试。
- 未完成：真实 iPhone 登录、自定义控制服务器接入、家庭服务访问及实际连接路径对照。本轮没有执行生产域名 ACME 签发，也没有提交、打标签或正式发布。

公开参考：[子网路由](https://tailscale.com/docs/features/subnet-routers)、[设备审批](https://tailscale.com/docs/features/access-control/device-management/device-approval)、[Auth Key](https://tailscale.com/docs/features/access-control/auth-keys)、[连接类型](https://tailscale.com/docs/reference/connection-types)。SiteLink 的移除来自本项目范围决定，不表示 Tailscale 不支持站点互联。
