# 给 AI 的指令卡：帮我搭一个游戏联机虚拟局域网（EasyTier + frp）

> 把本文件的链接贴给任意 AI 编程/运维工具（WorkBuddy、Cursor、Claude、Codex 等），
> 它读完就能帮你把 MC / P2P 游戏联机环境一步搭好。
> 原始链接：`https://raw.githubusercontent.com/dodolu05/frp-p2p-lan/main/PROMPT.md`

## 0. 最重要的原则：朋友侧零命令

本方案要保证**所有加入联机的朋友一行命令都不用敲**：
他们只需要装 EasyTier 官方客户端 → 填 3 个框（网络名称 / 网络密码 / 中继地址）→ 点「运行网络」。
命令行加入方式只作为「进阶可选」兜底，别默认推给普通用户。

## 1. 先判断角色（只问一次，别反复问）

| 角色 | 特征 | 走哪节 |
|------|------|--------|
| **A. 房主 / 有云服务器** | 有一台阿里云/腾讯云/华为云等 VPS，能在网页控制台发命令或 SSH | 第 2 节 |
| **B. 加入别人的网络** | 手里有别人给的「联机邀请卡」三行字（网络名 + 密钥 + 接入地址） | 第 3 节 |

判断不了就问一句：「你是要自己搭一台联机服务器（需要一台云服务器），还是加入朋友已经搭好的网络？」

## 2. 分支 A：部署服务端（房主）

### 2.1 前置确认
- 云服务器：Linux（Ubuntu / Debian / CentOS / AlmaLinux 均可），有 **systemd**，能 root 执行
- 配置要求极低：1 核 1G 就够（游戏流量 P2P 直连，不经服务器）
- 运行环境：优先让用户在**云厂商控制台网页发命令**（阿里云「发送命令/云助手」、轻量叫「命令助手」、腾讯云「自动化助手」、华为云「云运维」），
  命令类型选 Shell、超时拉到 300 秒以上；用户不会或 Agent 离线再退回 SSH

### 2.2 执行（一条命令，非交互）

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/frp-p2p-lan/main/server/install.sh | sudo bash
```

可选参数（一般不填，脚本自动生成随机网络名和密钥）：
```bash
... | sudo bash -s -- --network-name mylan --port 11020 --frp-port 7000
```

脚本会做：下载 EasyTier 2.6.4 + frp 0.71.0（GitHub 不通自动切国内镜像）→
生成随机网络名/密钥 → 写 systemd 并设开机自启 → 部署联机管理台和 frp 面板 →
打印并存盘 `/opt/frp-p2p-lan/connect.txt` **联机邀请卡**。

### 2.3 必须让用户自己确认：放行安全组端口

脚本改不了云厂商的安全组（**最常见的失败原因**，务必反复提醒）：

- `TCP + UDP 11020` —— EasyTier 节点
- `TCP 7000` —— frps
- `TCP 25565` 等 —— frp 要映射出去的游戏端口（按需）
- 本机 ufw/firewalld 同步放行：`ufw allow 11020/tcp && ufw allow 11020/udp && ufw allow 7000/tcp`

### 2.4 邀请卡怎么给朋友

邀请卡分两部分，AI 要帮用户拆清楚：
- **上半部分（GUI 邀请卡）**：网络名称 / 网络密钥 / 接入地址 `tcp://服务器IP:11020`，
  连同零命令图文指南一起转发给朋友：`https://raw.githubusercontent.com/dodolu05/frp-p2p-lan/main/GUIDE_FOR_PLAYERS.md`
- **下半部分（排障信息）**：frp 兜底端口、面板口令、端口清单等，只给房主自己留着，别外发

## 3. 分支 B：加入网络（所有联机的人，默认走 GUI）

### 3.1 默认路线：EasyTier 官方 GUI（零命令）

下载地址：`https://easytier.cn/guide/download.html`（Windows / macOS / Linux / Android 都有）

照着填三框：

| 客户端里的选项 | 填什么 |
|---|---|
| 网络名称 | 邀请卡上的「网络名称」 |
| 网络密码 | 邀请卡上的「网络密钥」 |
| 网络方式/服务器 | 手动组网，地址填邀请卡上的「接入地址」`tcp://IP:11020` |
| 虚拟 IP | **DHCP / 自动，绝不手填**（手填会撞车） |

然后「保存 → 运行网络」，界面显示自己的虚拟 IP（`10.145.0.x`）即成功。
AI 在这一步的职责：引导用户核对字符、解释每个框对应邀请卡哪一行，**不要让普通用户敲命令行**。

### 3.2 进阶可选：命令行加入

仅当用户明确说「我想用命令行 / 我是开发者」才给：

```powershell
# Windows（必须管理员 PowerShell）
iex (irm https://raw.githubusercontent.com/dodolu05/frp-p2p-lan/main/client/join-windows.ps1)
Join-Lan -Name "<网络名>" -Secret "<密钥>" -Peer "tcp://<服务器IP>:11020"
```

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/dodolu05/frp-p2p-lan/main/client/join-linux.sh | sudo bash -s -- \
  --name "<网络名>" --secret "<密钥>" --peer "tcp://<服务器IP>:11020"
```

## 4. 验证（必做，别跳过）

让朋友在客户端里看两件事：自己的虚拟 IP 跟房主同网段（都 `10.145.0.x`）、节点列表看得到房主。
更进一步再 ping：`ping <对方虚拟IP>`。

不通 → 看第 6 节；**优先怀疑服务器 11020 的 UDP 没放行**。

## 5. 怎么联机（按游戏）

| 游戏 | 做法 |
|------|------|
| **MC Java 版** | 房主 Esc →「对局域网开放」→ 记端口；朋友「多人游戏 → 直接连接」填 `房主虚拟IP:端口` |
| **MC 基岩版 / 其他 LAN 游戏** | 房主开房间，朋友在局域网列表刷新即可（同网段自动发现） |
| **不支持 LAN 的游戏** | 用 frp 映射游戏端口到服务器，朋友连 `服务器公网IP:远程端口`（模板 `client/frpc.toml.example`） |

Windows 防火墙若拦 MC：允许 `javaw.exe` 通过公用+专用网络。

## 6. 故障排查速查

| 现象 | 原因 / 处理 |
|------|-------------|
| 朋友客户端连不上 | 三行有一字抄错（最常见）；或 11020 TCP+UDP 没放行 |
| 连上但看不到节点/对方 | 等 10 秒或刷新节点列表；确认双方虚拟 IP 同网段 |
| 服务起不来 | `journalctl -u frp-p2p-lan-easytier -n 50` |
| 下载失败 | 脚本内置 4 个国内镜像自动切换；仍失败手动放 release 到 `/opt/frp-p2p-lan/bin/` |
| Windows 客户端异常 | 右键以管理员身份运行（EasyTier 要建虚拟网卡） |
| 延迟高 | P2P 没打成走中转：确认 11020 UDP 放行，或换服务器地域 |
| 想重装/卸载 | 重发同一条命令（幂等）；卸载：`curl -fsSL .../server/install.sh \| sudo bash -s -- --uninstall` |

## 7. 安全约束（AI 和用户都要遵守）

- 网络密钥 = 进虚拟局域网的钥匙，**只发给要联机的人**，别发在公开评论区/视频简介
- frps token 同样别公开；服务器只放行需要的端口
- 谁进网谁就能访问网内所有设备的局域网服务 —— 只拉信得过的人

## 8. 组件版本

EasyTier `2.6.4`（实测稳定）· frp `0.71.0` · 默认网段 `10.145.0.0/24` · EasyTier 端口 `11020` · frps `7000`
配套文档：`README.md`（三步入门）· `GUIDE_FOR_PLAYERS.md`（给朋友的零命令指南）· `docs/aliyun-cloud-assistant.md`（网页部署）
