#!/usr/bin/env bash
# =============================================================================
#  frp-p2p-lan / Linux & macOS 客户端一键加入
#  用法:
#    curl -fsSL <RAW>/client/join-linux.sh | sudo bash -s -- \
#        --name "<网络名>" --secret "<密钥>" --peer "tcp://1.2.3.4:11020"
#  可选: --ip 10.145.0.7   指定虚拟 IP（不填则自动分配，推荐不填）
#  停止: sudo bash join-linux.sh --stop
# =============================================================================
set -euo pipefail

NAME=""; SECRET=""; PEER=""; VIP=""
ET_VERSION="${ET_VERSION:-2.6.4}"
DIR="${DIR:-/opt/frp-p2p-lan-client}"
GH="https://github.com"
SVC="frp-p2p-lan-client"

while [ $# -gt 0 ]; do
  case "$1" in
    --name)   NAME="$2"; shift 2;;
    --secret) SECRET="$2"; shift 2;;
    --peer)   PEER="$2"; shift 2;;
    --ip)     VIP="$2"; shift 2;;
    --stop)   systemctl stop "$SVC" 2>/dev/null; echo "[OK] 已停止"; exit 0;;
    --uninstall) systemctl stop "$SVC" 2>/dev/null; systemctl disable "$SVC" 2>/dev/null; rm -f "/etc/systemd/system/$SVC.service"; systemctl daemon-reload; rm -rf "$DIR"; echo "[OK] 已卸载"; exit 0;;
    -h|--help) sed -n '2,14p' "$0"; exit 0;;
    *) echo "[XX] 未知参数: $1" >&2; exit 1;;
  esac
done

log(){ printf '[..] %s\n' "$*"; }
ok(){ printf '[OK] %s\n' "$*"; }
die(){ printf '[XX] %s\n' "$*" >&2; exit 1; }

{ [ -n "$NAME" ] && [ -n "$SECRET" ] && [ -n "$PEER" ]; } || die "缺少参数。需要 --name --secret --peer（--help 看用法）"

[ "$(id -u)" = 0 ] || die "请用 root 执行：sudo bash join-linux.sh ..."
command -v curl >/dev/null || die "需要 curl"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ET_ARCH="x86_64";;
  aarch64|arm64) ET_ARCH="aarch64";;
  *) die "不支持的架构: $ARCH";;
esac

log "1/3 下载 EasyTier v$ET_VERSION"
MIRRORS=("" "https://ghfast.top/" "https://gh-proxy.com/" "https://gh.llkk.cc/")
if [ "$(uname -s)" = "Darwin" ]; then
  ASSET="easytier-macos-${ET_ARCH}-v${ET_VERSION}.zip"
else
  ASSET="easytier-linux-${ET_ARCH}-v${ET_VERSION}.zip"
fi
mkdir -p "$DIR/bin"
if [ ! -x "$DIR/bin/easytier-core" ]; then
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  for m in "${MIRRORS[@]}"; do
    [ -n "$m" ] && log "  尝试镜像: $m"
    if curl -fsSL --connect-timeout 12 --max-time 300 "${m}${GH}/EasyTier/EasyTier/releases/download/v${ET_VERSION}/${ASSET}" -o "$TMP/et.zip" 2>/dev/null && [ -s "$TMP/et.zip" ]; then
      ok "下载完成"; break
    fi
  done
  [ -s "$TMP/et.zip" ] || die "下载失败"
  unzip -oq "$TMP/et.zip" -d "$TMP"
  find "$TMP" -name 'easytier-core' -type f -exec install -m 0755 {} "$DIR/bin/easytier-core" \;
  find "$TMP" -name 'easytier-cli'  -type f -exec install -m 0755 {} "$DIR/bin/easytier-cli"  \; || true
else
  ok "已存在，跳过"
fi

log "2/3 写入服务"
ARGS="--network-name \"$NAME\" --network-secret \"$SECRET\" -e \"$PEER\""
[ -n "$VIP" ] && ARGS="$ARGS -i $VIP"
cat > "/etc/systemd/system/$SVC.service" <<EOF
[Unit]
Description=frp-p2p-lan EasyTier Client ($NAME)
After=network.target

[Service]
Type=simple
ExecStart=$DIR/bin/easytier-core $ARGS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SVC" >/dev/null 2>&1

log "3/3 等待分配虚拟 IP"
sleep 4
systemctl is-active --quiet "$SVC" || die "服务未起来，看日志: journalctl -u $SVC -n 50"

VIP_GOT=""
for i in $(seq 1 15); do
  VIP_GOT="$(ip -4 addr show 2>/dev/null | grep -oE 'inet 10\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | grep -v '\.1$' | head -1 || true)"
  [ -n "$VIP_GOT" ] && break
  sleep 1
done

echo
if [ -n "$VIP_GOT" ]; then
  echo "================ 加入成功 ================"
  echo "你的虚拟 IP : $VIP_GOT"
  echo "把这个 IP 告诉朋友，或在 MC 里直接连这个 IP"
  echo "=========================================="
else
  echo "[!!] 暂未读到虚拟 IP，手动确认： ip addr | grep -E 'tun|et_'"
  echo "     日志: journalctl -u $SVC -n 50"
fi
