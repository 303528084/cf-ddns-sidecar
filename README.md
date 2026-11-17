# Cloudflare 优选 IP + DDNS（飞牛 fnOS）

在飞牛 NAS 上自动测出当前网络下最快的 Cloudflare 边缘 IP（综合访问速度/下载速度），并同时做两件事：

1. 写入你已装好的 **AdGuard Home** 的 DNS 重写规则 → 局域网设备走优选 IP；
2. 更新到你自有域名的 **DNS 解析记录**（DDNS）→ 生成一个固定的"优选域名"。

三个功能共用**同一次测速结果**（全局测速一次、结果应用到所有域名），不重复测速。

## 工作原理

```
主体容器 cf-dns-select（官方镜像，源码零改动）
    ├─ 测速 → 选出最优 IP → 写入 AdGuard Home DNS 重写
    └─ 最优 IP 持久化到 config.json 的 last_result_ip
                    │（共享卷，只读）
                    ▼
旁路容器 cf-ddns-sidecar（本项目）
    └─ 轮询 last_result_ip → 变化时推送到所选 DNS 服务商的 A 记录
```

- 主体：基于 [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 测速内核，GPL-3.0。
- 旁路：独立 Go 容器，MIT 许可（见 `LICENSE`）；四家 DNS 服务商签名算法移植自 [jeessy2/ddns-go](https://github.com/jeessy2/ddns-go)（MIT），已保留版权声明。
- 合规：旁路通过数据文件与主体耦合（聚合而非衍生），不修改主体源码，规避 GPL 传染；个人家庭内部使用不触发分发义务。详见 `docs/adr/0001-bypass-container-over-fork.md`。

## 一、安装到飞牛 NAS（推荐）

1. 到本仓库 **Releases** 下载 `cf-ddns-sidecar-<版本>.fpk`。
2. 飞牛桌面 → **应用中心** → 右上角 **设置** → **手动安装应用** → 选择该 `.fpk`。
3. 安装完成即可——首次启动会自动生成示例配置文件，旁路容器在配置完成前会**安全等待**（不会崩溃），日志提示缺什么。

### 安装后配置（关键，两处）

应用数据目录：飞牛「文件管理」中的 `cf-ddns-sidecar` 共享文件夹（含 `subject` / `sidecar` / `conf` 三个子目录，安装后自动创建）。

1. **填写 ddns.env（唯一必填入口）**：在文件管理中打开 `cf-ddns-sidecar/sidecar/ddns.env`（安装时已自动生成示例），填写：
   - `CFDDNS_PROVIDER`：`cloudflare` / `aliyun` / `dnspod` / `huawei` 四选一；
   - `CFDDNS_DOMAIN`：你的目标域名，如 `cf.example.com`；
   - 对应服务商的密钥（示例文件里有四家的注释模板，取消注释并填写即可）。
2. **配主体**：浏览器打开 `http://飞牛IP:8080`，进入主体 Dashboard：
   - 在「AdGuard Home 实例」添加你已装好的 AdGuard Home（地址 + 账号密码）；
   - 在「域名」里添加要加速的域名（即套了 Cloudflare 的网站域名，可随时增删）；
   - 触发一次「立即测速并写入」。

3. **重启应用**：ddns.env 修改后需在「应用中心 → 本应用 → 重启」生效（环境变量在容器创建时注入）。

> 主体 Dashboard 首次密码：若未设置，从主体容器日志查看（`docker logs cf-dns-select`）。
> 高级用户可选：在 `conf/` 下放 `config.yaml`（参照 `config.yaml.example`）覆盖默认轮询间隔等；不创建则纯用 ddns.env。

## 二、本地 docker compose 部署（非 FPK）

```bash
mkdir config && cp config.yaml.example config/config.yaml   # 编辑 provider / domain
cp .env.example .env                                        # 填所选服务商密钥
# 编辑 docker-compose.yml 的 DSA_ALLOWED_CIDRS 为你的局域网网段
docker compose up -d
```

## 三、配置参考

| 项 | 位置 | 说明 |
|----|------|------|
| 服务商类型 | `CFDDNS_PROVIDER` 或 `config.yaml` 的 `provider` | 四选一 |
| 目标域名 | `CFDDNS_DOMAIN` 或 `config.yaml` 的 `domain` | 要写入 A 记录的域名（**当前支持 1 个**，见下方限制） |
| 轮询间隔 | `CFDDNS_POLL_INTERVAL` | 秒，默认 30；非整数会直接报配置错误 |
| API 密钥 | 环境变量（见 `.env.example` / ddns.env） | 不落盘到配置文件 |
| 根域覆盖 | `ALIYUN_ROOT_DOMAIN` / `DNSPOD_ROOT_DOMAIN` | 仅多级公共后缀需要（如 `example.com.cn`），一般留空 |
| 要加速的域名 | 主体 Dashboard「域名」 | 套 Cloudflare 的网站域名，可随时增删 |

环境变量优先级高于 `config.yaml`，便于 FPK 安装后不改容器内文件即可配置。

### 已知限制

- **目标域名当前仅支持 1 个**：DDNS 只维护单个优选域名的 A 记录；需要多个优选域名时，可用不同 `domain` 部署第二个旁路实例。
- **同名多 A 记录只更新第一条**：若目标域名在服务商处已存在多条同名 A 记录（历史残留），仅第一条会被更新，建议手工清理只留一条。
- **接缝字段**：旁路读取主体 `config.json` 的 `last_result_ip` 键（已对照 cf-dns-select 源码核实一致）；主体大版本升级若改动该字段，需同步适配。

## 四、如何确认部署成功（验收口径）

按顺序核对四步，全部通过即部署成功：

1. **容器状态**：飞牛「应用中心 → 本应用 → 详情」，两个容器均为**运行中**；旁路容器日志开头有 `cf-ddns-sidecar vX.Y.Z 启动中`（版本号）。
2. **测速成功**：主体 Dashboard（`http://飞牛IP:8080`）能看到最新测速结果与最优 IP；或 `docker logs cf-dns-select` 查看测速日志。
3. **DDNS 已更新**：`docker logs cf-ddns-sidecar` 出现 `[成功] cf.example.com 的 A 记录已更新为 x.x.x.x（服务商名）`；或到服务商 DNS 控制台确认 A 记录值。命令行验证：`nslookup cf.example.com`（或 `dig cf.example.com +short`）应返回最优 IP。
4. **AdGuard 重写生效**：AdGuard Home 管理界面 → 「过滤器 → DNS 重写」能看到主体写入的优选规则（被加速域名 → 最优 IP）；局域网设备 `nslookup 被加速域名` 返回优选 IP 即生效。

常见问题速查：

| 现象 | 含义 | 处理 |
|------|------|------|
| 旁路日志反复 `[等待] 配置未就绪` | ddns.env 未填完 | 按提示补全后重启应用 |
| 旁路日志 `[错误] 更新 ... 失败` 且 `（下一轮自动重试）` | 服务商 API 报错 | 看具体错误（密钥错误/权限不足），修正后自动恢复 |
| 旁路日志 `[等待] 主体尚无最优 IP` | 主体还没完成第一次测速 | 到主体 Dashboard 触发测速，或等定时任务 |
| 健康检查 `curl 飞牛IP:18080/healthz` 返回 503 | 上一轮推送失败 | 查旁路日志定位服务商报错 |

## 五、开发者：构建与发布

### 本地验证

```bash
go test ./...              # 单元测试（需 Go 1.22+）
docker compose config      # 校验编排
```

### 本地多架构构建（可选）

```bash
DOCKERHUB_REPO=yourname/cf-ddns-sidecar IMAGE_TAG=v1.0.0 ./scripts/build-multiarch.sh
# 加 PUSH=1 同时推送到 DockerHub（需先 docker login）
```

### 发布流程（自动化）

1. 在 GitHub 仓库 Settings → Secrets 添加：
   - `DOCKERHUB_USERNAME`：DockerHub 用户名；
   - `DOCKERHUB_TOKEN`：DockerHub Access Token。
2. （可选）Settings → Variables 添加 `FNPACK_URL`：飞牛官方 `fnpack` 的 linux-amd64 直链（未设置时用内置默认地址，若 404 需设置此项）。
3. 打 tag 并推送：`git tag v1.0.0 && git push origin v1.0.0`。
4. GitHub Actions 自动：构建 amd64/arm64 镜像推 DockerHub → 用 fnpack 打 FPK → 创建 Release，**仅上传 `.fpk`**。
   也可在 Actions 页面手动触发（workflow_dispatch），输入版本号即可。

> 手动打 FPK：见 `scripts/build_fpk.py` 顶部注释。需先备好 `fnpack` 二进制（[飞牛开发者中心](https://developer.fnnas.com/)）。

### 架构说明

- Docker 镜像：`linux/amd64` + `linux/arm64` 双架构。
- 飞牛 FPK：当前飞牛第三方应用仅支持 x86_64（manifest `arch=x86_64`）；ARM 设备可直接使用双架构 Docker 镜像通过 compose 部署。

## 六、项目结构

```
cf-ddns-sidecar/
├── main.go, config/, provider/, sidecar/   # Go 源码 + 测试
├── Dockerfile, docker-compose.yml          # 容器构建与编排
├── config.yaml.example, .env.example       # 配置示例
├── fpk/template/                           # 飞牛 FPK 模板
├── scripts/                                # FPK 打包 / 图标 / 多架构构建
├── docs/adr/0001-*.md                      # 架构决策记录
├── LICENSE                                 # MIT
└── .github/workflows/release.yml           # CI/CD
```

## 七、参考与致谢

- 测速内核：[XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)
- 主体方案：[neon9809/cf-dns-select](https://github.com/neon9809/cf-dns-select)
- 签名实现：[jeessy2/ddns-go](https://github.com/jeessy2/ddns-go)（MIT）
- 测速思路参考：[xinyitang3/cfnb](https://github.com/xinyitang3/cfnb)（MIT，多源聚合与反代验证思路；因仅支持 Cloudflare DDNS、无 AdGuard 写入、非 Docker 部署，未作为主体采用）
- FPK 打包参考：[jiaja0502/nowen-note](https://github.com/jiaja0502/nowen-note) 的 fpk 脚本结构

> 免责声明：本工具仅供个人学习与家庭内部使用，请遵守各服务商 API 条款与相关法律法规。
