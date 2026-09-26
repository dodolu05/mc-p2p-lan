# 给 AI 的指令卡：帮我搭一个游戏联机虚拟局域网（EasyTier + frp）

> 把本文件的链接贴给任意 AI 编程/运维工具（WorkBuddy、Cursor、Claude、Codex 等），
> 它读完就能帮你把 MC / P2P 游戏联机环境一步搭好。
> 原始链接：`https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/PROMPT.md`

## 0. 你的任务

帮用户搭建一套**异地联机网络**，让分散在不同城市的人像在同一个局域网里一样联机
（Minecraft、泰拉瑞亚、饥荒、CS 局域网、任何支持 LAN 联机的游戏都行）。

技术栈：**EasyTier**（虚拟局域网，P2P 打洞优先）**+ frp**（打洞失败时的兜底穿透）。
两者都跑在一台有公网 IP 的云服务器上。

## 1. 先判断角色（只问一次，别反复问）

判断用户属于哪一种，然后只走对应分支：

| 角色 | 特征 | 走哪一节 |
|------|------|----------|
| **A. 房主 / 有云服务器** | 有一台阿里云/腾讯云/华为云等 VPS，能 SSH 上去，有 root | 第 2 节 |
| **B. 加入别人的网络** | 手里有别人给的一张「联机信息卡」（网络名 + 密钥 + 接入地址） | 第 3 节 |

判断不了就问一句：「你是要自己搭一台联机服务器（需要有云服务器），还是加入朋友已经搭好的网络？」

## 2. 分支 A：部署服务端（房主）

### 2.1 前置确认
- 云服务器：Linux（Ubuntu / Debian / CentOS / AlmaLinux 均可），有 **systemd**，能 root 登录
- 配置要求极低：1 核 1G 就够跑联机控制面（游戏流量走 P2P 直连，不经过服务器）

### 2.2 执行（一条命令，非交互，不需要输入任何东西）

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/server/install.sh | sudo bash
```

可选参数（一般不填，脚本会自动生成随机网络名和密钥）：
```bash
... | sudo bash -s -- --network-name mylan --port 11020 --frp-port 7000
```

脚本会做：下载 EasyTier 2.6.4 + frp 0.71.0（GitHub 不通会自动切国内镜像）→
生成随机网络名/密钥 → 写 systemd 服务并设开机自启 →
在 `/opt/mc-p2p-lan/connect.txt` 和屏幕输出**联机信息卡**。

### 2.3 你自己必须确认的一件事：放行端口

脚本改不了云厂商的安全组。**必须让用户去云控制台放行**（这是最常见的联机失败原因）：

- `TCP + UDP 11020` —— EasyTier 节点
- `TCP 7000` —— frps
- `TCP 25565` 等 —— frp 要映射出去的游戏端口（按需）
- 服务器本机的 ufw/firewalld 也要放行，或临时关掉验证：
  `ufw allow 11020/tcp && ufw allow 11020/udp && ufw allow 7000/tcp`

阿里云/腾讯云轻量用户：**控制台 → 防火墙 → 添加规则**，别只在服务器里改 iptables。

### 2.4 把信息卡发给朋友

把脚本输出的 `connect.txt` 内容（网络名、密钥、接入地址 `tcp://服务器IP:11020`）发给朋友，
让他们走第 3 节。

## 3. 分支 B：加入网络（所有联机的人）

### 3.1 Windows（绝大多数人）

**必须用「管理员身份」打开 PowerShell**（开始菜单搜 PowerShell → 右键 → 以管理员身份运行），然后：

```powershell
iex (irm https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-windows.ps1)
Join-Lan -Name "<网络名>" -Secret "<密钥>" -Peer "tcp://<服务器IP>:11020"
```

成功后会打印「你的虚拟 IP : 10.145.0.x」。
`Join-Lan` 不指定 `-Ip` 时自动分配 IP，别手动指定以免撞号。

### 3.2 Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-linux.sh | sudo bash -s -- \
  --name "<网络名>" --secret "<密钥>" --peer "tcp://<服务器IP>:11020"
```

## 4. 验证（必做，别跳过）

```bash
ping <对方虚拟IP>          # Windows: ping 10.145.0.x
```

- 通 → 组网成功，直接进游戏联机
- 不通 → 看第 5 节；先确认双方进程都活着、服务器端口 11020 已放行

## 5. 怎么联机（按游戏）

| 游戏 | 做法 |
|------|------|
| **MC Java 版** | 房主在世界里按 Esc → 「对局域网开放」→ 记住端口号（通常 25565）；朋友在多人游戏里直接填 `房主虚拟IP:端口`。或用 frp 把 25565 映射出去，公网直接连 |
| **MC 基岩版 / 其他 LAN 游戏** | 房主开局域网房间，朋友在「局域网」列表里刷新即可（同网段自动发现） |
| **不支持 LAN 的游戏** | 用 frp 把游戏端口映射到服务器，朋友连 `服务器公网IP:远程端口` |

Windows 防火墙如果拦了 MC：允许 `javaw.exe` 通过公用+专用网络。

## 6. 故障排查速查

| 现象 | 原因 / 处理 |
|------|-------------|
| 下载失败 / 卡住 | 脚本内置 4 个国内镜像会自动切换；还是失败就手动下载 release 放进 `/opt/mc-p2p-lan/bin/` |
| 服务起不来 | `journalctl -u mc-p2p-lan-easytier -n 50`（客户端：`journalctl -u mc-p2p-lan-client -n 50`） |
| 能 ping 通服务器但 ping 不通朋友 | 服务器 11020 的 **UDP** 没放行；或双方都是对称 NAT，改用 frp 兜底 |
| Windows 报权限不足 | 没用管理员 PowerShell；EasyTier 要创建虚拟网卡 |
| Windows 拿不到虚拟 IP | `ipconfig` 里找带 `tun` 的网卡；或看 `%LOCALAPPDATA%\mc-p2p-lan\easytier.log.err` |
| 延迟高 | P2P 没打成，走的中继。确认 11020 UDP 已放行，或换服务器地域 |
| 之前装过想重装 | 服务端：`sudo bash install.sh --uninstall` 再装；客户端：`Join-Lan -Uninstall` |

## 7. 安全约束（AI 和用户都要遵守）

- 网络密钥 = 进你虚拟局域网的钥匙，**只发给要联机的人**，别发在公开的评论区/视频简介里
- 服务器上只放行需要的端口，frps 开了 token 认证，别把 token 公开
- 谁进了这个网，谁就能访问网内所有设备的局域网服务 —— 只拉信得过的人
- 卸载：服务端 `curl -fsSL .../server/install.sh | sudo bash -s -- --uninstall`

## 8. 组件版本

EasyTier `2.6.4`（实测稳定）· frp `0.71.0` · 默认网段 `10.145.0.0/24` · EasyTier 端口 `11020` · frps `7000`
