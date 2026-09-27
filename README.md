# mc-p2p-lan —— 一套脚本搞定异地游戏联机

用 **EasyTier 虚拟局域网 + frp 穿透**，让天南海北的朋友像坐在同一个宿舍里一样联机。
Minecraft、泰拉瑞亚、饥荒、CS…… 凡是支持「局域网联机」的游戏都能用。
**朋友们全程不用敲命令**——装个官方客户端，填 3 个框，点「运行网络」就完事。

**不想看教程？把下面这个链接贴给你在用的 AI 工具（WorkBuddy / Cursor / Claude / Codex 都行），它会一步步帮你装好：**

```
https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/PROMPT.md
```

---

## 你需要什么

| 角色 | 需要 |
|------|------|
| **房主（1 人）** | 一台有公网 IP 的云服务器。1 核 1G 就够（阿里云/腾讯云轻量、学生机都行，几十块一年） |
| **联机的朋友** | 只要装个官方客户端，填 3 个框。**不需要服务器，不用有公网 IP，不用碰命令行** |

游戏流量是 **P2P 直连**的，不经服务器中转，所以服务器的配置不用好、带宽也不用大。

---

## 三步走

### 第 1 步：房主在服务器上部署（二选一）

**方式 A：阿里云 / 腾讯云网页部署（不用 SSH、不用输 root 密码）**

控制台 → 找到你的云服务器 → 「发送命令 / 云助手」（轻量应用服务器叫「命令助手」）→ 命令类型选 **Shell** → 粘贴下面这行 → 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/server/install.sh | sudo bash
```

图文版见 [`docs/aliyun-cloud-assistant.md`](docs/aliyun-cloud-assistant.md)。

**方式 B：SSH 上去执行**（任何云厂商都通用）

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/server/install.sh | sudo bash
```

跑完会打印一张**联机邀请卡**（网络名、密钥、中继地址），也存在服务器上的 `/opt/mc-p2p-lan/connect.txt`。

> 只想先用官方公共中继白嫖一台服务器都不买？可以，但那属于另一条路线，本文不展开——
> 让朋友各自装 EasyTier 客户端、公共服务器填 `tcp://public.easytier.cn:11010` 也能组网，稳定性自己承担。

### 第 2 步：去云控制台放行端口（最容易漏的一步）

脚本管不了云厂商的防火墙，必须手动加：

| 端口 | 用途 |
|------|------|
| TCP + UDP `11020` | EasyTier 节点，**必放** |
| TCP `7000` | frps（打洞失败时的兜底） |
| TCP `25565` 等 | frp 映射出去的游戏端口，按需 |

阿里云/腾讯云：**控制台 → 安全组/防火墙 → 添加规则**。服务器本机还有 ufw 的话也放行一遍。

### 第 3 步：朋友装客户端，填 3 个框（这一步零命令）

1. 打开 EasyTier 下载页，拿自己系统对应的客户端：https://easytier.cn/guide/download.html
   （Windows / macOS / Linux / Android 都有，安卓机也能进联机）
2. 打开客户端 → **添加新网络**，把邀请卡上的三行照抄进去：

   | 客户端里的框 | 填什么 |
   |---|---|
   | 网络名称 | 邀请卡上的「网络名称」 |
   | 网络密码 | 邀请卡上的「网络密钥」 |
   | 公共服务器 / 中继地址 | 邀请卡上的「接入地址」（形如 `tcp://1.2.3.4:11020`） |
   | 虚拟 IP | **选 DHCP / 自动，别手填** |

3. 点「运行网络」→ 界面显示出自己的虚拟 IP（形如 `10.145.0.7`）就成功了。

**把这张邀请卡连同这句说明直接转发给朋友就行**；想要图文版可以发这份[零命令指南](GUIDE_FOR_PLAYERS.md)。

<details>
<summary>进阶可选：朋友想用命令行加入（不推荐给普通观众）</summary>

Windows 一定要用**管理员** PowerShell：

```powershell
iex (irm https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-windows.ps1)
Join-Lan -Name "<网络名>" -Secret "<密钥>" -Peer "tcp://<服务器IP>:11020"
```

Linux / macOS：

```bash
curl -fsSL https://raw.githubusercontent.com/dodolu05/mc-p2p-lan/main/client/join-linux.sh | sudo bash -s -- \
  --name "<网络名>" --secret "<密钥>" --peer "tcp://<服务器IP>:11020"
```

> Windows 脚本的命令行输出是英文的 —— 不是没汉化，是因为 Windows PowerShell 5.1 会把无 BOM 的 UTF-8 当 GBK 读，中文会直接把脚本读崩。纯 ASCII 才能保证所有 Windows 版本都不出错。

</details>

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
| 朋友客户端连不上 | 先查服务器 `11020` 的 TCP 和 UDP 都放行了没；再核对三框有没有抄错（网络名/密钥有一个字不同都进不去） |
| 连上了但看不到对方 | 看两端虚拟 IP 是不是同网段（都是 `10.145.0.x`）；安卓端偶尔要下拉刷新节点列表 |
| ping 不通 | Windows 端确认客户端是以管理员运行的；再查安全组 |
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
server/install.sh          服务端一键部署（EasyTier 节点 + frps + 面板）
client/join-windows.ps1    Windows 客户端一键加入（可选，命令行方案）
client/join-linux.sh       Linux / macOS 客户端一键加入（可选，命令行方案）
client/frpc.toml.example   frp 穿透配置模板（不支持 LAN 的游戏用）
GUIDE_FOR_PLAYERS.md       给朋友的零命令指南（房主可直接转发）
docs/aliyun-cloud-assistant.md  阿里云/腾讯云网页部署图文章节
panel/                     自带的联机管理台 + frp 面板（原样复刻）
PROMPT.md                  贴给 AI 工具的指令卡
```

组件版本：EasyTier `2.6.4` · frp `0.71.0` · 默认网段 `10.145.0.0/24`

License: MIT
