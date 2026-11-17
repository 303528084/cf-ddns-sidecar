# Cloudflare 优选 IP + AdGuard Home + DDNS（飞牛 fnOS）

在飞牛 NAS 上一键搞定三件事：**测出你家网络最快、真能连上的 Cloudflare 节点**，
把它写进 **AdGuard Home** 的 DNS 重写，同时更新你**自有域名的解析记录**。
一个容器、一个后台界面，装完点几下鼠标就能用。

## 它能干什么

| 能力 | 说明 |
|---|---|
| 优选 IP | 从 Cloudflare 官方地址段随机采样 + 多源聚合，先 TCP 筛延迟，再做**反代验证**（确认这个 IP 真能承载 HTTPS 请求），最后跑真实带宽，排出最优 |
| 写 AdGuard | 把最优 IP 写进 AdGuard Home 的 DNS 重写表，局域网设备自动走这条线路 |
| DDNS | 把最优 IP 写到你自有域名的 A 记录，支持 Cloudflare / 阿里云 / 腾讯云 DNSPod / 华为云 |
| 统一后台 | 一个界面管全部：状态、AdGuard、要加速的域名、测速参数、域名解析密钥、实时日志 |

## 为什么测速换了引擎

早期的实现用的是「TCP 延迟 + 下载测速」，选出来的 IP 经常**TCP 能连、浏览器打不开**。
现在改用 [xinyitang3/cfnb](https://github.com/xinyitang3/cfnb) 的测速引擎，
它多了一道**反代验证**（对每个候选 IP 发真实 HTTPS 请求、验证 TLS 与响应，多轮采集延迟和抖动），
能剔掉「通但不可用」的节点。

同时我们加了一层保底：**内置 Cloudflare 官方地址段快照**，在本地随机采样生成候选，
所以即使所有第三方数据源都挂了，测速依然能跑出结果，不会卡在「拉不到节点」。

## 关于代理

**测速必须直连，不能走代理。** 原因很简单：测的是「你家宽带 → Cloudflare 边缘」这条路的快慢，
走代理测出来的是代理服务器的线路，对你没用。

本程序已经强制直连（给测速引擎设了 `FORCE_DIRECT`，会清掉所有 `*_PROXY` 变量）。所以：

- 你在**电脑上**开代理 → 不影响 NAS 里的测速；
- 你在**NAS 上**设置了全局代理环境变量 → 也会被清掉，不影响；
- 但如果你的**路由器**做了全局透明代理（所有流量强制走代理），测速结果就会失真，
  这种情况需要给 NAS 单独放行直连。

## 安装（飞牛 fnOS）

1. 到本仓库 **Releases** 下载 `cf-ddns-sidecar-<版本>.fpk`；
2. 飞牛桌面 → **应用中心** → 右上角 **设置** → **手动安装应用** → 选择该文件；
3. 装完桌面会出现「优选IP DDNS」图标，点开即是后台（也可以浏览器访问 `http://飞牛IP:端口`，端口默认 8080）。

**后台密码**：安装向导里直接设；留空的话程序会自动生成一个，并打印在
「应用中心 → 本应用 → 运行日志」里，也能在数据目录的 `dashboard-password` 文件里看到。
后台**对所有 IP 开放**（不做来源网段限制），所以密码务必设置。

安装向导里可以直接填**优选域名、服务商、后台端口、测速间隔、各家密钥**，装完就能跑；
之后随时在「应用中心 → 本应用 → 设置」里改，保存后自动重启生效。
更细的项（AdGuard 地址、要加速的域名列表）在后台界面里配。

**后台端口**默认 `8080`，只有和 NAS 上别的服务撞端口时才需要改（1024-65535）。
改端口时安装脚本会同步改写飞牛的桌面入口配置，图标会跟着指向新端口，
不需要卸载重装。

## 配置（全在后台界面里）

打开后台，从上往下填：

1. **AdGuard Home**：地址（`http://192.168.1.2:3000`）+ 用户名 + 密码；
2. **要加速的域名**：点「+ 添加域名」，填套了 Cloudflare 的网站域名（如 `openai.com`）；
3. **测速设置**：自动测速间隔（默认 60 分钟，填 0 表示只在手动点时才测）；
4. **域名解析（DDNS）**：勾上启用 → 选服务商 → 填优选域名 → 填密钥；
5. 点「保存全部设置」，再点「立即测速」。

密钥留空表示「不修改已保存的值」，所以改域名时不用重新填一遍密钥。

数据目录（飞牛「文件管理」→ `cf-ddns-sidecar` → `data`）：
`config.json`（配置与状态）、`ddns.env`（密钥）、`dashboard-password`（后台密码）。

## 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 测速报「没有产出可用 IP」 | 极少见（已内置官方段保底）。若出现，多半是 NAS 完全没有外网出口，检查网络 |
| 写了 AdGuard 但设备还是走老 IP | AdGuard 客户端缓存。在该设备上重连网络，或在 AdGuard 里清一下缓存 |
| 域名解析报 403 / 401 | 密钥权限不足。Cloudflare 令牌需要「编辑区域 DNS」权限，Zone ID 要填对 |
| 后台打不开 | ① 确认用的是安装时设的端口（默认 8080）；② 端口被 NAS 上别的服务占了，换一个再保存 |
| 忘了后台密码 | 「应用中心 → 本应用 → 设置」里重设一个，保存后自动重启生效 |
| 改端口后图标点不开 | 在「应用中心 → 本应用 → 设置」里重新保存一次即可，启动脚本会把桌面入口改到新端口 |
| 卸载后想彻底清干净 | 直接卸载即可：容器、镜像、数据目录都会删掉（v3 起已实现） |

## 开发者

```bash
docker build -t cf-ddns-sidecar:dev .
docker run --rm --network host -v $PWD/data:/app/data cf-ddns-sidecar:dev
```

端口由数据目录里 `ddns.env` 的 `CFDDNS_PORT` 决定（默认 8080），
所以用 host 网络而不是 `-p` 映射——改端口不用重建容器。

目录结构：

```
├── main.go              入口
├── config/              统一配置（config.json + ddns.env）
├── engine/              测速引擎调用（封装 cfnb）
├── dns/                 AdGuard Home 写入
├── ddns/                四家 DNS 服务商适配
├── web/                 后台服务 + 单页前端（go:embed，无需 Node 构建）
├── third_party/cfnb/    测速引擎（MIT，含一处本地补丁）
└── fpk/                 飞牛 FPK 打包模板
```

发布：打 tag 推送（`git tag v3.0.0 && git push origin v3.0.0`），
GitHub Actions 自动构建 amd64/arm64 镜像推 DockerHub，并用 fnpack 打出 `.fpk` 传到 Release。

## 许可证与致谢

本项目以 **GPL-3.0** 发布（见 `LICENSE`）。

- AdGuard Home 写入能力取自 [neon9809/cf-dns-select](https://github.com/neon9809/cf-dns-select)（GPL-3.0），
  其原始许可证保留在 `LICENSE.UPSTREAM`。本项目的界面、配置层、DDNS 集成与测速引擎封装为后加部分，
  一并按 GPL-3.0 开源。
- 测速引擎：[xinyitang3/cfnb](https://github.com/xinyitang3/cfnb)（MIT），原始许可证见 `third_party/cfnb/LICENSE`。
  对其 `main.py` 打了一处补丁：支持只有纯 IP 列表的聚合源（见文件内注释）。
- 测速思路参考：[XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)。
- DDNS 签名实现参考：[jeessy2/ddns-go](https://github.com/jeessy2/ddns-go)（MIT）。

> 免责声明：本工具仅供个人学习与家庭内使用，请遵守各服务商 API 条款与相关法律法规。
