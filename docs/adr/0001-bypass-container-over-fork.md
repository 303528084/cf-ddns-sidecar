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

## 修订（2026-11-17，v1.1.0）：双容器 → 单容器双进程

实测反馈：飞牛用户在实际使用中只关心「一个应用」，看到两个容器（`cf-dns-select` + `cf-ddns-sidecar`）
会困惑「为什么不整合」「哪个是后台」。容器数量本身不产生任何用户价值，反而增加心智负担。

决定：打包形态改为**单容器双进程**，仍保持主体源码零改动（从上游镜像只取二进制）。

- 镜像构建：多阶段 —— `builder` 交叉编译旁路 → `subject` 阶段从 `ghcr.io/neon9809/cf-dns-select`
  取主体二进制与 IP 段文件 → `allinone` 运行阶段把两者放进同一镜像，由 `entrypoint.sh` 并行拉起。
- 数据目录统一为 `/app/data`：主体的 `config.json`、旁路的 `ddns.env` 共处一目录，旁路直接读同目录文件。
- 端口：主体 Dashboard 占 8080；旁路健康检查降到 18080，避免冲突。

对原决策的影响：**「不 fork 源码」这一核心不变**，GPL 结论不变（仍是独立进程、通过数据文件耦合）。
仅部署拓扑从两容器收敛为一容器。代价是镜像需随上游更新重新构建（CI 打 tag 即重建），
以及两个进程共享容器生命周期（任一退出则整体重启）。

保留 `--target sidecar` 构建目标，供只想跑旁路的高级用户单独部署。

## 修订 2（v3.0.x）：双进程 → 单进程

上一段说的「单容器双进程」在实现里没有成立过，需要更正。

- **主体（cf-dns-select）最终没有被引入。** 测速能力改为直接复用 xinyitang3/cfnb（MIT）
  的 `main.py`：由本项目的 Go 主程序在需要测速时用 `exec.CommandContext("python3", ...)`
  拉起，跑完读回 `ip.txt` 即结束。**它不是常驻进程**——不监听端口、不参与请求处理、
  平时不存在。所以「双进程」这个说法只在测速那几十秒里勉强成立。
- **Go 主程序一个进程承担全部职责**：统一后台界面（`web/`）、写 AdGuard Home 重写
  （`dns/`）、推送四家 DNS 服务商（`ddns/`）、按需触发测速（`engine/`）。
  入口 `main.go`，构建产物是单个静态二进制。
- **数据耦合也随之消失。** 上一段说「主体的 `config.json` 与旁路的 `ddns.env` 共处一目录，
  旁路直接读同目录文件」，这句话描述的前提不存在了：没有两个东西需要跨进程通信。
  现在最优 IP 就是同一进程里 `engine.Result.IPs[0]`（`Result.Best()`）的返回值，
  落盘为 `config.json` 的 `last_ip`，直接供 AdGuard 写入与 DDNS 推送使用。
  **原「接缝」概念从「进程间的文件字段 `LastResultIP`」退化为「进程内的函数返回值」**，
  该字段名在代码中已完全不存在（`grep LastResultIP` 无结果）。
- 镜像仍是单容器：`Dockerfile` 的 `allinone` 阶段，基础镜像 `python:3.12-alpine`，
  里面装 Go 二进制 + cfnb 脚本 + `docker-entrypoint.sh`。入口脚本最后一行是
  `exec su-exec app:app "$APP_BIN" "$@"`——**只拉起一个进程**。

另：上一段末尾「保留 `--target sidecar` 构建目标，供只想跑旁路的高级用户单独部署」
也一并作废。`Dockerfile` 现在只有 `builder` 与 `allinone` 两个阶段，没有 `sidecar`。
「只想跑旁路」这个需求随主体消失而消失——旁路已经不存在，它自己就是全部。

对原决策的影响：**「不 fork 主体源码」这一核心不变**，而且比上一段更彻底——
cf-dns-select 的代码一行都没进入本仓库，只引用了 MIT 的 cfnb，并以子进程方式调用。
原 ADR 里「规避 GPL-3.0 copyleft」的论证随之失去实际意义：本项目自身已选择以
GPL-3.0 发布（见 `LICENSE`），不再需要靠架构隔离来规避。保留此段历史是为了记录
当时的判断依据，不是因为现在仍需遵守它。
