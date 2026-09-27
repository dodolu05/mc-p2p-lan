#!/usr/bin/env bash
# =============================================================================
#  mc-p2p-lan / 服务端一键部署脚本
#  在一台有公网 IP 的云服务器上部署：
#    * EasyTier 虚拟局域网节点（P2P 打洞 + 中继，游戏联机主力）
#    * frps 内网穿透服务端（打洞失败时的兜底）
# 完全非交互，AI 工具可以直接执行；所有参数可用环境变量或命令行覆盖。
#
#  用法:
#    curl -fsSL <RAW>/server/install.sh | sudo bash
#    curl -fsSL <RAW>/server/install.sh | sudo bash -s -- --network-name mylan --port 11020
#    sudo bash install.sh --uninstall
# =============================================================================
set -euo pipefail

ET_VERSION="${ET_VERSION:-2.6.4}"
FRP_VERSION="${FRP_VERSION:-0.71.0}"
REPO="${REPO:-dodolu05/mc-p2p-lan}"
BRANCH="${BRANCH:-main}"

INSTALL_DIR="${INSTALL_DIR:-/opt/mc-p2p-lan}"
ET_PORT="${ET_PORT:-11020}"
FRP_BIND_PORT="${FRP_BIND_PORT:-7000}"
FRP_DASH_PORT="${FRP_DASH_PORT:-7500}"
ET_VIP="${ET_VIP:-10.145.0.1}"
NETWORK_NAME="${NETWORK_NAME:-}"
INSTALL_FRP="${INSTALL_FRP:-1}"
INSTALL_PANEL="${INSTALL_PANEL:-1}"
FORCE=0
UNINSTALL=0

RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
GH="https://github.com"

# ---------- 输出 ----------
if [ -t 1 ]; then
  C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
  C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""
fi
log() { printf '%s[..]%s %s\n' "$C_G" "$C_0" "$*"; }
ok()  { printf '%s[OK]%s %s\n' "$C_G" "$C_0" "$*"; }
warn(){ printf '%s[!!]%s %s\n' "$C_Y" "$C_0" "$*"; }
die() { printf '%s[XX]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
h1()  { printf '\n%s=== %s ===%s\n' "$C_B" "$*" "$C_0"; }

# ---------- 参数 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --network-name) NETWORK_NAME="$2"; shift 2;;
    --port|--et-port) ET_PORT="$2"; shift 2;;
    --frp-port) FRP_BIND_PORT="$2"; shift 2;;
    --vip) ET_VIP="$2"; shift 2;;
    --no-frp) INSTALL_FRP=0; shift;;
    --no-panel) INSTALL_PANEL=0; shift;;
    --force) FORCE=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) die "未知参数: $1（用 --help 看用法）";;
  esac
done

# ---------- 卸载 ----------
if [ "$UNINSTALL" = 1 ]; then
  h1 "卸载 mc-p2p-lan"
  for s in mc-p2p-lan-easytier mc-p2p-lan-frps; do
    systemctl stop "$s" 2>/dev/null && log "已停止 $s" || true
    systemctl disable "$s" 2>/dev/null || true
    rm -f "/etc/systemd/system/$s.service"
  done
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR"
  ok "已卸载。配置目录 $INSTALL_DIR 已删除（如需保留请提前备份 connect.txt）"
  exit 0
fi

# ---------- 前置检查 ----------
[ "$(id -u)" = 0 ] || die "请用 root 执行：sudo bash install.sh"
command -v systemctl >/dev/null || die "未检测到 systemd，本脚本只支持 systemd 发行版"
command -v curl >/dev/null || die "需要 curl，请先安装：apt install -y curl  或  yum install -y curl"
for b in unzip tar; do command -v $b >/dev/null || die "需要 $b，请先安装"; done

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   ET_ARCH="x86_64"; FRP_ARCH="amd64";;
  aarch64|arm64)  ET_ARCH="aarch64"; FRP_ARCH="arm64";;
  *) die "不支持的架构: $ARCH";;
esac
log "架构: $ARCH (EasyTier=$ET_ARCH / frp=$FRP_ARCH)"

# 公网 IP 探测（多源回退）
get_public_ip() {
  local ip=""
  for s in "https://api.ipify.org" "https://ifconfig.me/ip" "https://myip.ipip.net" "https://ip.sb"; do
    ip="$(curl -fsS --max-time 8 "$s" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)"
    [ -n "$ip" ] && { echo "$ip"; return 0; }
  done
  echo ""
}
PUBIP="$(get_public_ip)"
[ -n "$PUBIP" ] && log "公网 IP: $PUBIP" || warn "未能自动探测公网 IP，稍后请手动填写"

# ---------- 下载（多镜像回退，国内也能拉到） ----------
MIRRORS=("" "https://ghfast.top/" "https://gh-proxy.com/" "https://gh.llkk.cc/" "https://mirror.ghproxy.com/")
dl() {
  local url="$1" out="$2" m u
  for m in "${MIRRORS[@]}"; do
    u="${m}${url}"
    [ -n "$m" ] && log "  尝试镜像: $m"
    if curl -fsSL --connect-timeout 12 --max-time 300 "$u" -o "$out" 2>/dev/null && [ -s "$out" ]; then
      ok "下载完成: $(basename "$out")"
      return 0
    fi
    rm -f "$out"
  done
  die "下载失败（直连与全部镜像都不可用）: $url"
}

# ---------- 端口占用检查 ----------
check_port() {
  local p="$1"
  if (command -v ss >/dev/null && ss -lntu 2>/dev/null | grep -qE "[:.]$p\b") ||
     (command -v netstat >/dev/null && netstat -lntu 2>/dev/null | grep -qE "[:.]$p\b"); then
    warn "端口 $p 已被占用，若不是本脚本部署的服务请换一个端口后重跑"
    return 1
  fi
  return 0
}

# ---------- 主流程 ----------
h1 "1/6 准备目录与配置"
mkdir -p "$INSTALL_DIR"/{bin,etc,log}
CONF="$INSTALL_DIR/etc/env.conf"

if [ -f "$CONF" ] && [ "$FORCE" = 0 ]; then
  # shellcheck disable=SC1090
  . "$CONF"
  ok "发现已有配置，复用（要重新生成请加 --force）"
else
  NETWORK_NAME="${NETWORK_NAME:-lan-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
  ET_SECRET="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  FRP_TOKEN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  FRP_PWD="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  cat > "$CONF" <<EOF
# mc-p2p-lan 服务端配置（自动生成，请勿泄露给无关人员）
NETWORK_NAME="$NETWORK_NAME"
ET_SECRET="$ET_SECRET"
ET_PORT="$ET_PORT"
ET_VIP="$ET_VIP"
FRP_TOKEN="$FRP_TOKEN"
FRP_PWD="$FRP_PWD"
FRP_BIND_PORT="$FRP_BIND_PORT"
FRP_DASH_PORT="$FRP_DASH_PORT"
EOF
  chmod 600 "$CONF"
  ok "已生成配置: $CONF"
fi
# shellcheck disable=SC1090
. "$CONF"

h1 "2/6 下载 EasyTier v${ET_VERSION}"
if [ ! -x "$INSTALL_DIR/bin/easytier-core" ] || [ "$FORCE" = 1 ]; then
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  dl "$GH/EasyTier/EasyTier/releases/download/v${ET_VERSION}/easytier-linux-${ET_ARCH}-v${ET_VERSION}.zip" "$TMP/et.zip"
  unzip -oq "$TMP/et.zip" -d "$TMP"
  find "$TMP" -name 'easytier-core' -type f -exec install -m 0755 {} "$INSTALL_DIR/bin/easytier-core" \;
  find "$TMP" -name 'easytier-cli'  -type f -exec install -m 0755 {} "$INSTALL_DIR/bin/easytier-cli"  \; || true
else
  ok "EasyTier 已存在，跳过"
fi
"$INSTALL_DIR/bin/easytier-core" --version 2>/dev/null | head -1 || true

if [ "$INSTALL_FRP" = 1 ]; then
  h1 "3/6 下载 frp v${FRP_VERSION}"
  if [ ! -x "$INSTALL_DIR/bin/frps" ] || [ "$FORCE" = 1 ]; then
    TMP2="$(mktemp -d)"
    dl "$GH/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${FRP_ARCH}.tar.gz" "$TMP2/frp.tgz"
    tar -xzf "$TMP2/frp.tgz" -C "$TMP2"
    find "$TMP2" -name 'frps' -type f -exec install -m 0755 {} "$INSTALL_DIR/bin/frps" \;
    rm -rf "$TMP2"
  else
    ok "frps 已存在，跳过"
  fi
else
  log "3/6 跳过 frp（--no-frp）"
fi

h1 "4/6 写入 systemd 服务"
cat > /etc/systemd/system/mc-p2p-lan-easytier.service <<EOF
[Unit]
Description=mc-p2p-lan EasyTier Node ($NETWORK_NAME)
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/bin/easytier-core -i $ET_VIP --network-name "$NETWORK_NAME" --network-secret "$ET_SECRET" -l $ET_PORT
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

if [ "$INSTALL_FRP" = 1 ]; then
  cat > "$INSTALL_DIR/etc/frps.toml" <<EOF
bindPort = $FRP_BIND_PORT
auth.method = "token"
auth.token = "$FRP_TOKEN"

webServer.addr = "127.0.0.1"
webServer.port = $FRP_DASH_PORT
webServer.user = "admin"
webServer.password = "$FRP_PWD"
EOF
  chmod 600 "$INSTALL_DIR/etc/frps.toml"

  cat > /etc/systemd/system/mc-p2p-lan-frps.service <<EOF
[Unit]
Description=mc-p2p-lan frps
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/bin/frps -c $INSTALL_DIR/etc/frps.toml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable --now mc-p2p-lan-easytier >/dev/null 2>&1 && ok "EasyTier 已启动并设置开机自启"
[ "$INSTALL_FRP" = 1 ] && { systemctl enable --now mc-p2p-lan-frps >/dev/null 2>&1 && ok "frps 已启动并设置开机自启"; }

h1 "5/6 部署管理面板（联机管理台 + frp 面板）"
PANEL_OK=0
if [ "$INSTALL_PANEL" = 1 ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    warn "没有 python3，跳过面板部署（联机功能不受影响）"
  else
    if ! python3 -c "import flask" >/dev/null 2>&1; then
      log "安装 Flask（先用清华源，失败退回官方源）..."
      (pip3 install -q flask -i https://pypi.tuna.tsinghua.edu.cn/simple 2>&1 | tail -2 || \
       pip3 install -q flask 2>&1 | tail -2) || warn "Flask 安装失败"
    fi
    if python3 -c "import flask" >/dev/null 2>&1; then
      mkdir -p "$INSTALL_DIR/panel"
      dl "$RAW_BASE/panel/admin_panel.py" "$INSTALL_DIR/panel/admin_panel.py"
      dl "$RAW_BASE/panel/frp_panel.py"   "$INSTALL_DIR/panel/frp_panel.py"
      PANEL_PWD="$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      PANEL_SECRET="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      cat >> "$CONF" <<EOF
PANEL_PWD="$PANEL_PWD"
PANEL_SECRET="$PANEL_SECRET"
EOF
      LAN_NET="${ET_VIP%.*}.0/24"
      cat > /etc/systemd/system/mc-p2p-lan-panel.service <<EOF
[Unit]
Description=mc-p2p-lan 联机管理台
After=network.target

[Service]
Type=simple
Environment=PANEL_DIR=$INSTALL_DIR
Environment=PANEL_HOST=$ET_VIP
Environment=PANEL_PORT=8080
Environment=PANEL_TRUST_NET=$LAN_NET
Environment=PANEL_PWD=$PANEL_PWD
Environment=PANEL_SECRET=$PANEL_SECRET
ExecStart=/usr/bin/python3 $INSTALL_DIR/panel/admin_panel.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
      cat > /etc/systemd/system/mc-p2p-lan-frppanel.service <<EOF
[Unit]
Description=mc-p2p-lan frp 面板
After=network.target

[Service]
Type=simple
Environment=PANEL_DIR=$INSTALL_DIR
Environment=PANEL_HOST=$ET_VIP
Environment=PANEL_PORT=8090
Environment=PANEL_TRUST_NET=$LAN_NET
Environment=PANEL_PWD=$PANEL_PWD
Environment=PANEL_PUB_IP=$PUBIP
Environment=FRPS_TOML=$INSTALL_DIR/etc/frps.toml
ExecStart=/usr/bin/python3 $INSTALL_DIR/panel/frp_panel.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now mc-p2p-lan-panel     >/dev/null 2>&1 && ok "联机管理台已启动 (8080)"
      systemctl enable --now mc-p2p-lan-frppanel  >/dev/null 2>&1 && ok "frp 面板已启动 (8090)"
      PANEL_OK=1
    else
      warn "Flask 不可用，跳过面板部署（联机功能不受影响）"
    fi
  fi
else
  log "5/6 跳过面板（--no-panel）"
fi

h1 "6/6 验证"
sleep 3
ET_OK=0
systemctl is-active --quiet mc-p2p-lan-easytier && { ok "EasyTier: active"; ET_OK=1; } || warn "EasyTier 未起来，看日志: journalctl -u mc-p2p-lan-easytier -n 50"
if [ "$INSTALL_FRP" = 1 ]; then
  systemctl is-active --quiet mc-p2p-lan-frps && ok "frps: active" || warn "frps 未起来，看日志: journalctl -u mc-p2p-lan-frps -n 50"
fi

JOIN_URL="${RAW_BASE}/client/join-linux.sh"
JOIN_WIN="${RAW_BASE}/client/join-windows.ps1"
GUIDE_URL="${RAW_BASE}/main/GUIDE_FOR_PLAYERS.md"
ET_PEER="tcp://${PUBIP:-<服务器IP>}:$ET_PORT"

CARD="$INSTALL_DIR/connect.txt"
{
echo "================= mc-p2p-lan 联机邀请卡 ==================="
echo "生成时间: $(date '+%F %T')"
echo
echo "拿这张卡发给朋友 —— 他们全程只填 3 个框，不用敲任何命令"
echo "---------------------------------------------------------"
echo "第 1 步  下载 EasyTier 客户端（选自己系统的版本）"
echo "         https://easytier.cn/guide/download.html"
echo "         Windows / macOS / Linux / Android 都有"
echo
echo "第 2 步  打开客户端 -> 添加新网络，依次填："
echo "         网络名称  : $NETWORK_NAME"
echo "         网络密码  : $ET_SECRET"
echo "         公共服务器 / 中继地址 : $ET_PEER"
echo "         （虚拟 IP 一栏选 DHCP / 自动，别手填）"
echo "         然后点「运行网络」"
echo
echo "第 3 步  界面出现自己的虚拟 IP（形如 ${ET_VIP%.*}.x）即成功，"
echo "         PC 端再打开游戏 -> 多人游戏 -> 局域网，"
echo "         房主的存档会直接出现在列表里，点进去就联机完成。"
echo "---------------------------------------------------------"
echo "房主自己的虚拟 IP : $ET_VIP"
echo "朋友会拿到的网段  : ${ET_VIP%.*}.2 ~ ${ET_VIP%.*}.254"
echo
echo "捞一份更详细的零命令图文指南（可直接转发给朋友）："
echo "  $GUIDE_URL"
echo
echo "--- 打洞不快时，我的世界可用 frp 兜底直连 ---"
if [ "$INSTALL_FRP" = 1 ]; then
echo "frps 端口     : $FRP_BIND_PORT"
echo "MC 直接连接地址 : ${PUBIP:-<服务器IP>}   端口见 frp 面板里 25565 映射"
echo "（frp 面板只连虚拟局域网才能开：http://$ET_VIP:8090）"
else
echo "（本次未安装 frp，打洞失败就没有兜底通道）"
fi
echo
echo "============== 以下仅供房主排障，不用发给朋友 =============="
echo "--- EasyTier 参数 ---"
echo "网络名称      : $NETWORK_NAME"
echo "网络密钥      : $ET_SECRET"
echo "接入地址      : $ET_PEER"
echo "服务器虚拟 IP : $ET_VIP"
echo
echo "--- 命令行加入（可选，给爱折腾的朋友）---"
echo "Linux/macOS:"
echo "  curl -fsSL $JOIN_URL | sudo bash -s -- --name '$NETWORK_NAME' --secret '$ET_SECRET' --peer '$ET_PEER'"
echo "Windows (PowerShell 管理员):"
echo "  iex (irm $JOIN_WIN); Join-Lan -Name '$NETWORK_NAME' -Secret '$ET_SECRET' -Peer '$ET_PEER'"
echo
echo "--- 管理面板（只绑虚拟局域网 IP，公网访问不到）---"
if [ "$PANEL_OK" = 1 ]; then
echo "联机管理台  : http://$ET_VIP:8080   口令: $PANEL_PWD"
echo "frp 面板    : http://$ET_VIP:8090   口令: $PANEL_PWD"
echo "（先加入虚拟局域网，再用浏览器开上面地址；局域网内免密）"
else
echo "（未部署：缺 python3/Flask。修好后重跑本脚本即可补装）"
fi
echo
echo "--- 需要在云厂商安全组/防火墙放行的端口 ---"
echo "  TCP+UDP $ET_PORT   (EasyTier，必放)"
[ "$INSTALL_FRP" = 1 ] && echo "  TCP $FRP_BIND_PORT  (frps)"
echo "  TCP 25565 等        (frp 映射出去的游戏端口，按需)"
echo "============================================================="
} | tee "$CARD"
chmod 600 "$CARD"

echo
[ "$ET_OK" = 1 ] && ok "部署完成！把上面这张卡发给朋友就能联机（他们只用填 3 个框）。" || die "部署未完成，请按上面的提示看日志"
