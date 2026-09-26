# mc-p2p-lan —— 一套脚本搞定异地游戏联机

用 **EasyTier 虚拟局域网 + frp 穿透**，让天南海北的朋友像坐在同一个宿舍里一样联机。
Minecraft、泰拉瑞亚、饥荒、CS…… 凡是支持「局域网联机」的游戏都能用。

**不想看教程？把下面这个链接贴给你在用的 AI 工具（WorkBuddy / Cursor / Claude / Codex 都行），它会一步步帮你装好：**

```
https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/PROMPT.md
```

---

## 你需要什么

| 角色 | 需要 |
|------|------|
| **房主（1 人）** | 一台有公网 IP 的云服务器。1 核 1G 就够（阿里云/腾讯云轻量、学生机都行，几十块一年） |
| **联机的朋友** | 只要装个客户端，不需要服务器，也不用有公网 IP |

游戏流量是 **P2P 直连**的，不经服务器中转，所以服务器的配置不用好、带宽也不用大。

---

## 三步走

### 第 1 步：房主在服务器上执行一条命令

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/server/install.sh | sudo bash
```

跑完会打印一张**联机信息卡**（网络名、密钥、接入地址），也会存到 `/opt/mc-p2p-lan/connect.txt`。

### 第 2 步：去云控制台放行端口（最容易漏的一步）

脚本管不了云厂商的防火墙，必须手动加：

| 端口 | 用途 |
|------|------|
| TCP + UDP `11020` | EasyTier 节点 |
| TCP `7000` | frps（打洞失败时的兜底） |
| TCP `25565` 等 | frp 映射出去的游戏端口，按需 |

阿里云/腾讯云：**控制台 → 安全组/防火墙 → 添加规则**。服务器本机还有 ufw 的话也放行一遍。

### 第 3 步：所有要联机的人装客户端

**Windows**（一定要用管理员 PowerShell：开始菜单搜 PowerShell → 右键 → 以管理员身份运行）：

```powershell
iex (irm https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-windows.ps1)
Join-Lan -Name "<网络名>" -Secret "<密钥>" -Peer "tcp://<服务器IP>:11020"
```

**Linux / macOS**：

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-linux.sh | sudo bash -s -- \
  --name "<网络名>" --secret "<密钥>" --peer "tcp://<服务器IP>:11020"
```

装好会显示你的虚拟 IP，比如 `10.145.0.7`。

> Windows 脚本的命令行输出是英文的 —— 不是没汉化，是因为 Windows PowerShell 5.1 会把无 BOM 的 UTF-8 当 GBK 读，中文会直接把脚本读崩。纯 ASCII 才能保证所有 Windows 版本都不出错。

---

## 然后就可以联机了

```bash
ping 10.145.0.x     # 先互相 ping 一下，通了就说明组网成功
```

**Minecraft Java 版**：房主进世界 → Esc → 「对局域网开放」→ 记下端口；朋友在多人游戏里填 `房主虚拟IP:端口`。

**基岩版 / 其他 LAN 游戏**：房主开房间，朋友在局域网列表里刷新就能看到。

**不支持局域网的游戏**：用 frp 把端口映射出去，朋友连 `服务器公网IP:远程端口`（模板见 `client/frpc.toml.example`）。

---

## 常见问题

| 现象 | 怎么办 |
|------|--------|
| ping 不通 | 先查服务器 11020 的 TCP 和 UDP 都放行了没；Windows 看是不是没用管理员跑 |
| 服务起不来 | `journalctl -u mc-p2p-lan-easytier -n 50` |
| 延迟高 | P2P 没打成功、走了中转。确认 UDP 放行，或换个离大家都近的服务器地域 |
| GitHub 下载慢 | 脚本内置 4 个国内镜像，会自动切换，不用管 |
| 想重装 | 服务端 `--uninstall`；Windows `Join-Lan -Uninstall` |

---

## 安全提醒

- **网络密钥 = 进你虚拟局域网的钥匙**，只发给要联机的人，别贴在视频评论区
- 进了这个网就能访问网内所有设备的局域网服务，只拉信得过的人

---

## 仓库结构

```
server/install.sh        服务端一键部署（EasyTier 节点 + frps + systemd）
client/join-windows.ps1  Windows 客户端一键加入
client/join-linux.sh     Linux / macOS 客户端一键加入
client/frpc.toml.example frp 穿透配置模板（不支持 LAN 的游戏用）
PROMPT.md                贴给 AI 工具的指令卡
```

组件版本：EasyTier `2.6.4` · frp `0.71.0` · 默认网段 `10.145.0.0/24`

License: MIT
