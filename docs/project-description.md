# GitHub 项目简介建议

以下为仓库 About 和 Topics 的建议文案，不会自动修改 GitHub 设置。

## About

Nexo 联巢：自托管 TCP / HTTP / HTTPS 内网穿透平台，提供可视化管理、多用户工作空间、域名接入检查与自动 HTTPS 证书。

## Topics

`self-hosted` · `tunneling` · `reverse-proxy` · `rust` · `docker` · `caddy`

## 完整介绍

Nexo 是一个自托管内网穿透平台，通过轻量 Agent 将内网 TCP、HTTP、HTTPS 服务发布到公网。用户可以在 Web 页面管理 Agent、服务、域名与证书，并通过独立工作空间与其他用户共用部署。Server 和 Agent 的官方镜像支持 Linux/amd64，默认部署使用各组件的 latest 稳定版。

域名能力包括归属验证、访问解析检查和 Cloudflare DNS-01 证书验证；不会自动创建服务访问所需的 A/AAAA 记录。
