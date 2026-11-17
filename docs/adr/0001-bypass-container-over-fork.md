# 0001 — 用旁路容器而非 fork 主体项目

- 状态：accepted
- 日期：2026-11-17

## 背景

需求为三合一：Cloudflare 边缘 IP 测速、写入 AdGuard Home DNS 重写、把最优 IP 推送到自有域名解析记录（DDNS）。

GitHub 调研结论：没有单一项目全覆盖。neon9809/cf-dns-select 覆盖前两项（基于 XIU2/CloudflareSpeedTest 测速内核），工程质量高，但不包含 DDNS；IonRh/Cloudflare-BestIP 覆盖测速与四家 DDNS，但不含 AdGuard Home 写入。

cf-dns-select 与其上游测速内核均为 GPL-3.0（强 copyleft）。选项：

1. fork cf-dns-select 源码，直接在其内部增加 DDNS 模块；
2. 保持主体源码不变，新增独立旁路容器，通过共享卷 `config.json` 的 `LastResultIP` 字段读取最优 IP 并推送。
3. 以 BestIP 为主体改造，补 AdGuard 写入。

## 决定

选选项 2：旁路容器。主体容器使用官方多架构镜像，源码零改动；DDNS 逻辑作为独立容器实现。

## 后果

正面：
- 规避 GPL-3.0 衍生作品的 copyleft 义务。旁路容器为独立进程，通过数据文件耦合（聚合而非衍生），主体可独立升级。
- 用户为个人家庭内部使用、不分发，未触发 GPL 的源码公开义务。
- 双容器故障隔离：DDNS 推送失败不影响测速与 AdGuard 写入。
- 主体官方镜像已支持 amd64/arm64，双架构开箱即用。

负面：
- 需自行实现四家 DNS 服务商的 API 适配与签名，是本次主要工作量与风险点。
- 最优 IP 依赖配置文件轮询读取，存在检测到变化的延迟（默认 30 秒）。
- 用户需维护一个额外的容器与配置。
