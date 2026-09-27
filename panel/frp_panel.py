#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frp 隧道管理面板 - 兜兜卢专用（樱花 frp 式）
只监听虚拟局域网 IP（不绑 0.0.0.0），无需 iptables 白名单，公网不可达。原实现曾 easytier 双网段（LAN_NET (mc-p2p-lan 虚拟局域网)）+ 本机，公网不可达
功能: 隧道 CRUD / frpc 配置一键生成 / frps 服务控制 / 爆破监控 / 操作审计
安全: 密码存文件(chmod 600) / 登录限流 / 动作白名单 / 审计留痕 / token 仅入下载文件不进页面
"""
import json
import ipaddress
import os
import re
import secrets
import subprocess
import time
import uuid
from datetime import timedelta
from threading import Lock

# ===== mc-p2p-lan 通用化配置（原私有实例已改为环境变量驱动）=====
import secrets as _secrets
INSTALL_DIR = os.environ.get("PANEL_DIR", "/opt/mc-p2p-lan")
LAN_IP      = os.environ.get("PANEL_HOST", "127.0.0.1")
LAN_NET     = os.environ.get("PANEL_TRUST_NET", ".".join(LAN_IP.split(".")[:3]) + ".0/24")
PANEL_PORT  = int(os.environ.get("PANEL_PORT", "8080"))
PUB_IP      = os.environ.get("PANEL_PUB_IP", "")
FRPS_TOML   = os.environ.get("FRPS_TOML", os.path.join(INSTALL_DIR, "etc", "frps.toml"))
# =================================================================

from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template_string, request, session, url_for)

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE, "config.json")
AUDIT_FILE = os.path.join(BASE, "audit.log")
TUNNELS_FILE = os.path.join(BASE, "tunnels.json")
TARGETS_FILE = os.path.join(BASE, "targets.json")
FRPS_TOML = os.environ.get("FRPS_TOML", os.path.join(INSTALL_DIR, "etc", "frps.toml"))
SERVER_ADDR = PUB_IP or LAN_IP
SERVER_PORT = 7000
ALLOWED_ACTIONS = {"start", "stop", "restart"}
TUNNEL_TYPES = {"tcp", "udp", "http"}
MAX_FAIL = 5
LOCK_SECONDS = 300

# 常见游戏/服务远程端口（新建隧道时的预选，Minecraft 在前）
PRESET_PORTS = [
    {"port": 25565, "service": "Minecraft Java"},
    {"port": 25566, "service": "Minecraft Java 备用"},
    {"port": 19132, "service": "Minecraft 基岩版"},
    {"port": 25575, "service": "Minecraft 地图/Mod"},
    {"port": 22, "service": "SSH"},
    {"port": 3389, "service": "远程桌面 RDP"},
    {"port": 5900, "service": "VNC"},
    {"port": 80, "service": "网站 HTTP"},
    {"port": 443, "service": "网站 HTTPS"},
    {"port": 5000, "service": "群晖 DSM"},
    {"port": 5001, "service": "群晖 DSM TLS"},
    {"port": 445, "service": "SMB 共享"},
    {"port": 21, "service": "FTP"},
    {"port": 9091, "service": "Transmission"},
    {"port": 8080, "service": "qBittorrent/Web"},
    {"port": 8123, "service": "Dynmap"},
]

# frps 服务器上实际在听的端口 → 用途（远程端口撞这些会被 frps 拒绝/冲突）
SYSTEM_PORTS = {
    22: "SSH", 7000: "frps 主端口", 7500: "frps 面板",
    11020: "EasyTier 节点", 8080: "联机管理台", 8090: "frp 面板",
    25565: "Minecraft",
}

# 免密信任网段：虚拟局域网内免密登录（公网仍需密码）
# 环境变量 FRP_TRUSTED_NETS 可覆盖（逗号分隔 CIDR），默认含本机管理环口
TRUSTED_NETS = []
for _cidr in os.environ.get("FRP_TRUSTED_NETS",
                            "127.0.0.0/8," + LAN_NET).split(","):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            TRUSTED_NETS.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError:
            pass

_lock = Lock()
_fail_track = {}


# ---------------- 配置 ----------------
def load_config():
    cfg = None
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = None
    if not cfg or "password" not in cfg or "secret_key" not in cfg:
        cfg = {"password": secrets.token_urlsafe(9),
               "secret_key": secrets.token_hex(32),
               "created": time.strftime("%Y-%m-%d %H:%M:%S")}
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.chmod(CONFIG_FILE, 0o600)
    return cfg


CFG = load_config()
app = Flask(__name__)
app.secret_key = CFG["secret_key"]
app.permanent_session_lifetime = timedelta(hours=12)


@app.after_request
def _no_store(resp):
    """面板数据 3 秒一变，HTML/API 一律不缓存，避免改版后浏览器拿旧页面。"""
    ct = resp.headers.get("Content-Type", "")
    if ct.startswith("text/html") or ct.startswith("application/json"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


# ---------------- 隧道存储 ----------------
def load_tunnels():
    with _lock:
        if not os.path.exists(TUNNELS_FILE):
            return []
        try:
            with open(TUNNELS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []


def save_tunnels(tunnels):
    with _lock:
        tmp = TUNNELS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(tunnels, f, ensure_ascii=False, indent=2)
        os.replace(tmp, TUNNELS_FILE)
        os.chmod(TUNNELS_FILE, 0o600)


# ---------------- 常用本地目标存储（免重复填） ----------------
def load_targets():
    with _lock:
        if not os.path.exists(TARGETS_FILE):
            return []
        try:
            with open(TARGETS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []


def save_targets(targets):
    with _lock:
        tmp = TARGETS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(targets, f, ensure_ascii=False, indent=2)
        os.replace(tmp, TARGETS_FILE)
        os.chmod(TARGETS_FILE, 0o600)


def remember_target(local_ip, local_port):
    """建/改隧道成功后把本地目标记入常用列表（最近使用优先，保留 12 个）"""
    if not local_ip or not local_port:
        return
    try:
        local_port = int(local_port)
    except Exception:
        return
    targets = [t for t in load_targets()
               if not (t.get("local_ip") == local_ip
                       and t.get("local_port") == local_port)]
    targets.insert(0, {
        "local_ip": local_ip, "local_port": local_port,
        "label": "%s:%d" % (local_ip, local_port),
        "used": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_targets(targets[:12])


def find_tunnel(tid):
    for t in load_tunnels():
        if t.get("id") == tid:
            return t
    return None


# ---------------- 工具 ----------------
def sh(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return "ERR: %s" % e


def peer_ip():
    """TCP 真实源 IP。无反向代理（Flask 直连），XFF 一律不可信：
    认证判定、限流记账、审计留痕全部以它为准（防公网伪造头绕认证）。"""
    return request.remote_addr or "?"


def is_trusted_peer():
    """虚拟局域网免密：源 IP 落在 TRUSTED_NETS 即信任。
    默认 127.0.0.1/8（本机管理）+ LAN_NET（mc-p2p-lan 虚拟局域网）；公网不信任。"""
    try:
        addr = ipaddress.ip_address(peer_ip())
    except Exception:
        return False
    return any(addr in net for net in TRUSTED_NETS)


# ---------------- frps dashboard 流量采集（frps 0.71 API） ----------------
DASH = "http://127.0.0.1:7500"
_tl_lock = Lock()
_traffic_last = {"in": -1, "out": -1, "ts": 0.0}
_pt_cache = {"ts": 0.0, "data": {}}
_pt_lock = Lock()


def _dash_creds():
    """dashboard 凭据只从本地 frps.toml 读取，绝不写日志/进 API 返回。"""
    try:
        txt = open(FRPS_TOML, encoding="utf-8").read()
        u = re.search(r'webServer\.user\s*=\s*"([^"]*)"', txt)
        p = re.search(r'webServer\.password\s*=\s*"([^"]*)"', txt)
        return (u.group(1) if u else "", p.group(1) if p else "")
    except Exception:
        return ("", "")


def _dash(path, timeout=2.5, post=None):
    """请求 frps dashboard API（本地回环）。失败返回 None，绝不影响面板其他功能。"""
    try:
        import urllib.request
        import base64
        u, p = _dash_creds()
        if not p:
            return None
        req = urllib.request.Request(DASH + path,
                                     method="POST" if post is not None else "GET")
        if post is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(post).encode()
        tok = base64.b64encode(("%s:%s" % (u, p)).encode()).decode()
        req.add_header("Authorization", "Basic " + tok)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode() or "null")
    except Exception:
        return None


def traffic_stats():
    """总流量(累计字节)+实时速率(B/s)。frps 重启后累计清零→自动重置基线。"""
    si = _dash("/api/serverinfo")
    if not isinstance(si, dict):
        return None
    tin = int(si.get("totalTrafficIn") or 0)
    tout = int(si.get("totalTrafficOut") or 0)
    now = time.time()
    rin = rout = 0
    with _tl_lock:
        if (_traffic_last["in"] >= 0 and tin >= _traffic_last["in"]
                and tout >= _traffic_last["out"]
                and now > _traffic_last["ts"]):
            dt = max(now - _traffic_last["ts"], 1.0)
            rin = max(int((tin - _traffic_last["in"]) / dt), 0)
            rout = max(int((tout - _traffic_last["out"]) / dt), 0)
        _traffic_last.update({"in": tin, "out": tout, "ts": now})
    return {"in": tin, "out": tout,
            "in_rate": rin, "out_rate": rout,
            "clients": int(si.get("clientCounts") or 0)}


# frps 0.71 dashboard 代理统计正确姿势：GET /api/proxy/{type}。
# 坑位实证（2026-09-23）：裸 /api/proxies 只注册了 DELETE，GET/POST 全 405；
# 旧代码 POST /api/proxies {client_id} 从来没采到过数据。客户端掉线也返回
# （status=offline + todayTraffic + lastStartTime），连续离线 7 天被 frps 清除。
PROXY_TYPES = ("tcp", "udp", "http", "https", "stcp", "sudp", "xtcp", "tcpmux")


def _collect_proxy_traffic():
    """单隧道今日流量 {name: {in,out,conns,status,last_start,last_close}} + dashboard 是否可达。
    按类型遍历 GET /api/proxy/{type} 汇总全部代理统计。
    返回 (data, dash_up)：只要任一类查询成功（拿到 dict），dash_up=True——
    成功的空列表是权威状态（frps 重启/无客户端时就该是空），不能供着旧数据。"""
    out = {}
    dash_up = False
    for typ in PROXY_TYPES:
        resp = _dash("/api/proxy/" + typ)
        if not isinstance(resp, dict):
            continue
        dash_up = True
        for px in (resp.get("proxies") or []):
            nm = px.get("name") or ""
            if nm:
                out[nm] = {
                    "in": int(px.get("todayTrafficIn")
                              or px.get("today_traffic_in") or 0),
                    "out": int(px.get("todayTrafficOut")
                               or px.get("today_traffic_out") or 0),
                    "conns": int(px.get("curConns") or 0),
                    "status": px.get("status") or "",
                    "last_start": px.get("lastStartTime") or "",
                    "last_close": px.get("lastCloseTime") or "",
                }
    return out, dash_up


def proxy_traffic(cache_secs=3):
    """单隧道今日流量。带短缓存防抖。
    dashboard 可达（哪怕返回空）→ 以实时结果为准；dashboard 整体不可达
    （全部查询失败）→ 沿用上次缓存不闪断。"""
    now = time.time()
    with _pt_lock:
        if now - _pt_cache["ts"] < cache_secs:
            return _pt_cache["data"]
    out, dash_up = _collect_proxy_traffic()
    with _pt_lock:
        if dash_up or not _pt_cache["data"]:
            _pt_cache.update({"ts": time.time(), "data": out})
        else:
            _pt_cache["ts"] = time.time()
        return _pt_cache["data"]


def _fetch_proxy_traffic_raw():
    """不走缓存的单隧道流量直取（采样线程用）。"""
    return _collect_proxy_traffic()[0]


def _backfill_history(db, proxy_names):
    """用 frps 近 7 天每日数组回填 total 为 0 的历史日期。
    frps DateCounter：index 0=今天，1=昨天…6=6 天前（GetLastDaysCount(ReserveDays=7)）。
    只在记录完全没有有效数据时写入，打 est 标记；仅在采样成功时调用。"""
    daily = db.get("daily") or {}
    filled = 0
    for k in range(1, 7):
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - k * 86400))
        rec = daily.get(day)
        if not isinstance(rec, dict):
            continue
        if int(rec.get("total_in") or 0) > 0 or int(rec.get("total_out") or 0) > 0:
            continue
        tin = tout = 0
        for nm in proxy_names:
            tr = _dash("/api/traffic/" + nm)
            if not isinstance(tr, dict):
                continue
            arr_in = tr.get("trafficIn") or []
            arr_out = tr.get("trafficOut") or []
            if len(arr_in) > k:
                tin += int(arr_in[k] or 0)
            if len(arr_out) > k:
                tout += int(arr_out[k] or 0)
        if tin > 0 or tout > 0:
            rec["total_in"] = tin
            rec["total_out"] = tout
            rec["est"] = True
            filled += 1
    return filled


# ---------------- 流量历史：每日/每月统计（后台采样落盘） ----------------
TRAFFIC_FILE = os.path.join(BASE, "traffic.json")
TRAFFIC_SAMPLE_SECS = 300
TRAFFIC_KEEP_DAYS = 400
_tf_db_lock = Lock()


def _load_traffic_db():
    try:
        d = json.load(open(TRAFFIC_FILE, encoding="utf-8"))
        if isinstance(d, dict) and isinstance(d.get("daily"), dict):
            return d
    except Exception:
        pass
    return {"daily": {}}


def _save_traffic_db(db):
    with _tf_db_lock:
        tmp = TRAFFIC_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False)
        os.replace(tmp, TRAFFIC_FILE)
        try:
            os.chmod(TRAFFIC_FILE, 0o600)
        except Exception:
            pass


def sample_traffic():
    """采样一次今日流量落盘。口径：
    - rec.total_in/out = frps 服务端「今日」累计（serverinfo，本地零点起算），
      单调递增取大值防 frps 重启清零回退；
    - rec.tunnels = 单隧道今日明细（GET /api/proxy/{type}），带状态与最后启动时间；
    - 历史空洞由 _backfill_history 用 frps 近 7 天数组估算回填（est 标记）。
    """
    db = _load_traffic_db()
    today = time.strftime("%Y-%m-%d")
    now_hm = time.strftime("%H:%M")
    daily = db["daily"]
    rec = daily.get(today)
    if rec is None or not isinstance(rec, dict):
        rec = {"date": today, "tunnels": {}, "total_in": 0, "total_out": 0,
               "samples": 0, "first": now_hm, "last": now_hm}
    else:
        rec.setdefault("tunnels", {})
        rec.setdefault("first", now_hm)
    pt = _fetch_proxy_traffic_raw()
    for nm, v in pt.items():
        t = rec["tunnels"].get(nm)
        if not isinstance(t, dict):
            t = {"in": 0, "out": 0}
        # todayTraffic 单调递增，取更大者防回退（frps 重启会清零）
        t["in"] = max(int(t.get("in") or 0), int(v.get("in") or 0))
        t["out"] = max(int(t.get("out") or 0), int(v.get("out") or 0))
        t["status"] = v.get("status") or ""
        t["last_start"] = v.get("last_start") or ""
        rec["tunnels"][nm] = t
    si = _dash("/api/serverinfo")
    if isinstance(si, dict):
        rec["total_in"] = max(int(rec.get("total_in") or 0),
                              int(si.get("totalTrafficIn") or 0))
        rec["total_out"] = max(int(rec.get("total_out") or 0),
                               int(si.get("totalTrafficOut") or 0))
    rec["samples"] = int(rec.get("samples") or 0) + 1
    rec["last"] = now_hm
    daily[today] = rec
    # 历史空洞回填（今日已由实时采样覆盖，只补 1~6 天前）
    if pt:
        _backfill_history(db, list(pt.keys()))
    # 清理过期
    cutoff = time.strftime("%Y-%m-%d",
                           time.localtime(time.time() - TRAFFIC_KEEP_DAYS * 86400))
    for k in [k for k in daily if k < cutoff]:
        del daily[k]
    _save_traffic_db(db)


def _day_totals(rec):
    """日流量口径：优先 frps 服务端今日累计（全量、权威）；
    老数据没有 total 字段时退回单隧道求和。"""
    tin = int(rec.get("total_in") or 0)
    tout = int(rec.get("total_out") or 0)
    if tin <= 0 and tout <= 0:
        tin = sum(int(t.get("in") or 0) for t in (rec.get("tunnels") or {}).values()
                  if isinstance(t, dict))
        tout = sum(int(t.get("out") or 0) for t in (rec.get("tunnels") or {}).values()
                   if isinstance(t, dict))
    return tin, tout


def traffic_history():
    db = _load_traffic_db()
    daily = []
    for day in sorted(db["daily"], reverse=True):
        rec = db["daily"][day]
        if not isinstance(rec, dict):
            continue
        tin, tout = _day_totals(rec)
        daily.append({
            "date": day,
            "in": tin, "out": tout,
            "tunnel_count": len(rec.get("tunnels") or {}),
            "samples": int(rec.get("samples") or 0),
            "first": rec.get("first", ""), "last": rec.get("last", ""),
            "est": bool(rec.get("est")),
        })
    mon = {}
    for d in daily:
        key = d["date"][:7]
        m = mon.setdefault(key, {"month": key, "in": 0, "out": 0,
                                 "days": 0, "tunnels": set()})
        m["in"] += d["in"]
        m["out"] += d["out"]
        if d["in"] or d["out"]:
            m["days"] += 1
        rec = db["daily"].get(d["date"]) or {}
        for nm in (rec.get("tunnels") or {}):
            m["tunnels"].add(nm)
    monthly = []
    # 环比必须在正序下计算（每月 vs 前一月），算完再倒序输出
    deltas = {}
    prev_tot = None
    for key in sorted(mon):
        tot = mon[key]["in"] + mon[key]["out"]
        deltas[key] = (tot - prev_tot) if (prev_tot is not None and prev_tot > 0) else None
        prev_tot = tot
    for key in sorted(mon, reverse=True):
        m = mon[key]
        monthly.append({
            "month": key, "in": m["in"], "out": m["out"], "days": m["days"],
            "tunnel_count": len(m["tunnels"]), "delta": deltas[key],
        })
    return {"daily": daily, "monthly": monthly}


def _sampler_loop():
    try:
        fw_reconcile()  # 启动对账：补回服务器重启丢失的封锁规则
    except Exception:
        pass
    while True:
        try:
            sample_traffic()
        except Exception:
            pass
        try:
            fw_reconcile()
        except Exception:
            pass
        time.sleep(TRAFFIC_SAMPLE_SECS)


def start_sampler():
    import threading
    t = threading.Thread(target=_sampler_loop, daemon=True)
    t.start()
    return t


def audit(action, detail):
    line = "%s ip=%s action=%s %s\n" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), peer_ip(), action, detail)
    with _lock:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def rate_remaining(ip):
    rec = _fail_track.get(ip)
    return int(rec[1] - time.time()) if rec and rec[1] > time.time() else 0


def rate_fail(ip):
    rec = _fail_track.get(ip, [0, 0])
    rec[0] += 1
    if rec[0] >= MAX_FAIL:
        rec = [0, time.time() + LOCK_SECONDS]
    _fail_track[ip] = rec
    return rec


def frps_active():
    return sh("systemctl is-active frps").strip() == "active"


# ---------------- 隧道防火墙（v5.27：停用=物理封锁远程端口） ----------------
# 「停用」从纯账本标志升级为真实封锁：对隧道 remote_port 在 INPUT 链追加
# REJECT（tcp-reset，客户端立刻收到拒绝，不用等超时）；「启用」精确 -D 同一条规则。
# 安全边界：
#   · 只动 TCP 隧道的 remote_port；SYSTEM_PORTS（frps/面板/其他服务在听的端口）
#     一律拒绝封锁，防手滑把面板自己关在门外；
#   · 规则追加在 INPUT 链尾：当前 policy ACCEPT，链上现有规则只按源 IP（爆破
#     黑名单）或 dport 8090（面板白名单）匹配，不会抢先命中这些新规则；
#   · iptables 规则不落盘持久化，服务器重启即丢——由采样循环每轮 + 启动时
#     按 tunnels.json 对账自愈（最坏空窗一个采样周期）。
FW_RULE_TAIL = "-p tcp -m tcp --dport %d -j REJECT --reject-with tcp-reset"


def _fw_run(args, timeout=5):
    """跑 iptables 子命令，返回 (ok, output)。"""
    try:
        r = subprocess.run("iptables " + args, shell=True,
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return False, "ERR: %s" % e


def fw_blocked(port):
    """该端口是否已被防火墙封锁（iptables -C 成功=规则存在）。"""
    try:
        port = int(port)
    except Exception:
        return False
    ok, _ = _fw_run("-C INPUT " + (FW_RULE_TAIL % port))
    return ok


def fw_block(port):
    """封锁端口（幂等：规则已在即成功）。SYSTEM_PORTS 拒绝。"""
    try:
        port = int(port)
    except Exception:
        return False, "端口无效"
    if port in SYSTEM_PORTS:
        return False, "端口 %d 是 frps/面板/系统服务端口，禁止封锁" % port
    if fw_blocked(port):
        return True, "规则已存在"
    ok, out = _fw_run("-A INPUT " + (FW_RULE_TAIL % port))
    return ok, (out or ("已封锁" if ok else "封锁失败"))


def fw_unblock(port):
    """删除封锁规则（幂等：规则不在即视为成功）。"""
    try:
        port = int(port)
    except Exception:
        return False, "端口无效"
    ok, out = _fw_run("-D INPUT " + (FW_RULE_TAIL % port))
    return ok, (out or ("已放行" if ok else "删除失败"))


def fw_reconcile():
    """按 tunnels.json 对账防火墙：应封锁的必须在、不该在的必须删。
    服务器重启丢规则、有人手改 iptables，都在这里自愈。返回 (blocked, removed)。"""
    blocked, removed = [], []
    want_block, want_open = {}, set()
    for t in load_tunnels():
        port = t.get("remote_port")
        if not isinstance(port, int):
            continue
        if t.get("type", "tcp") != "tcp":
            continue
        if t.get("enabled", True):
            want_open.add(port)
        else:
            want_block[port] = t.get("name", "?")
    for port in sorted(want_block):
        if port in want_open:
            continue  # 端口冲突时谨慎优先不封锁（validate_tunnel 已拦，双保险）
        if not fw_blocked(port):
            ok, _ = fw_block(port)
            if ok:
                blocked.append(port)
    for port in sorted(want_open):
        if fw_blocked(port):
            fw_unblock(port)
            removed.append(port)
    return blocked, removed


def port_open(port):
    try:
        p = int(port)
    except Exception:
        return False
    return bool(sh("ss -tln | grep -E ':%s\\b'" % p).strip())


def online_clients():
    out = sh("ss -tn state established '( sport = :%d )'" % SERVER_PORT)
    ips = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4:
            ips.append(parts[3].rsplit(":", 1)[0].strip("[]"))
    return ips


LOG_RE = re.compile(
    r"client login info: ip \[([\d.:a-fA-F]+)\] version \[([^\]]*)\] "
    r"hostname \[([^\]]*)\]")
TS_RE = re.compile(r"^(\w{3} \d{2} \d{2}:\d{2}:\d{2})")


def frp_events(limit=80):
    out = sh("journalctl -u frps --no-pager -n %d -o short" % (limit * 4))
    events = []
    for line in out.splitlines():
        if "client login info" not in line:
            continue
        m = LOG_RE.search(line)
        if not m:
            continue
        ts = TS_RE.match(line)
        events.append({"ts": ts.group(1) if ts else "?", "ip": m.group(1),
                       "ver": m.group(2), "host": m.group(3),
                       "ok": "token in login doesn't match" not in line})
        if len(events) >= limit:
            break
    return events


def attack_count_24h():
    out = sh("journalctl -u frps --since '24 hours ago' --no-pager | "
             "grep -c \"token in login doesn't match\" || true")
    try:
        return int(out.strip().splitlines()[-1] or 0)
    except Exception:
        return 0


SENSITIVE_KEY = re.compile(r"(?i)(token|secret|password|pwd|oauth)")


def frps_token():
    """从 frps.toml 读 token，仅用于生成 frpc 配置文件（不展示、不进日志）。"""
    try:
        with open(FRPS_TOML, encoding="utf-8") as f:
            for raw in f:
                m = re.match(r"""^\s*auth\.token\s*=\s*["']([^"']+)["']""",
                             raw)
                if m:
                    return m.group(1)
                m = re.match(r"""^\s*token\s*=\s*["']([^"']+)["']""", raw)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ""


def frps_config_summary():
    if not os.path.exists(FRPS_TOML):
        return []
    rows = []
    try:
        with open(FRPS_TOML, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    rows.append({"k": line, "v": "", "sec": True})
                    continue
                m = re.match(r"^([A-Za-z0-9_.]+)\s*=\s*(.+)$", line)
                if m:
                    k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
                    if SENSITIVE_KEY.search(k):
                        v = "***已设置(%d位)***" % len(v)
                    rows.append({"k": k, "v": v, "sec": False})
    except Exception:
        pass
    return rows


def recent_audit(n=15):
    if not os.path.exists(AUDIT_FILE):
        return []
    try:
        with open(AUDIT_FILE, encoding="utf-8") as f:
            lines = [l.rstrip() for l in f if l.strip()]
        return lines[-n:][::-1]
    except Exception:
        return []


def gen_frpc_toml(tunnels):
    token = frps_token()
    lines = [
        "# frpc 配置文件 - 由 frp 管理面板生成 (%s)" %
        time.strftime("%Y-%m-%d %H:%M:%S"),
        "# 用法: frpc -c frpc.toml",
        "serverAddr = \"%s\"" % SERVER_ADDR,
        "serverPort = %d" % SERVER_PORT,
        "auth.token = \"%s\"" % token,
        "",
    ]
    for t in tunnels:
        lines += [
            "[[proxies]]",
            "name = \"%s\"" % t["name"],
            "type = \"%s\"" % t["type"],
            "localIP = \"%s\"" % t["local_ip"],
            "localPort = %d" % t["local_port"],
        ]
        if t["type"] == "http":
            lines.append("customDomains = [\"%s\"]" % t.get("domain", ""))
        else:
            lines.append("remotePort = %d" % t["remote_port"])
        lines.append("")
    return "\n".join(lines)


def gen_frpc_cmd(t):
    token = frps_token()
    return ("./frpc %s -s %s:%d -f %s -n %s -i %s -l %d -r %d"
            % (t["type"], SERVER_ADDR, SERVER_PORT, token, t["name"],
               t["local_ip"], t["local_port"], t["remote_port"]))


# ---------------- 页面路由 ----------------
@app.route("/")
def index():
    if not session.get("ok"):
        if is_trusted_peer():
            session.permanent = True
            session["ok"] = True
            audit("login", "success (trusted-net 免密 source=%s)" % peer_ip())
            return render_template_string(PAGE, logged=True)
        return render_template_string(PAGE, logged=False)
    return render_template_string(PAGE, logged=True)


@app.route("/login", methods=["POST"])
def login():
    ip = peer_ip()
    remain = rate_remaining(ip)
    if remain > 0:
        return jsonify({"ok": False,
                        "msg": "密码错误过多，已锁定，剩余 %d 秒" % remain}), 429
    pwd = request.form.get("pwd", "")
    if pwd and secrets.compare_digest(pwd, CFG["password"]):
        session.permanent = True
        session["ok"] = True
        _fail_track.pop(ip, None)
        audit("login", "success source=%s" % peer_ip())
        return jsonify({"ok": True})
    if is_trusted_peer():
        session.permanent = True
        session["ok"] = True
        audit("login", "success (trusted-net 免密 source=%s)" % peer_ip())
        return jsonify({"ok": True})
    rec = rate_fail(ip)
    audit("login", "fail")
    if rec[1] > time.time():
        return jsonify({"ok": False, "msg": "密码错误过多，已锁定 5 分钟"}), 429
    return jsonify({"ok": False,
                    "msg": "密码错误，还可试 %d 次" % (5 - rec[0])}), 401


@app.route("/logout")
def logout():
    audit("logout", "")
    session.pop("ok", None)
    return redirect(url_for("index"))


# ---------------- API：概览 ----------------
@app.route("/api/status")
def api_status():
    if not session.get("ok"):
        abort(401)
    tunnels = load_tunnels()
    return jsonify({
        "active": frps_active(),
        "port_main": port_open(SERVER_PORT),
        "port_dash": port_open(7500),
        "clients": online_clients(),
        "events": frp_events(80),
        "tunnel_total": len(tunnels),
        "tunnel_online": sum(1 for t in tunnels
                             if t.get("enabled") and port_open(t["remote_port"])),
        "attack_24h": attack_count_24h(),
        "config": frps_config_summary(),
        "traffic": traffic_stats(),
        "proxy_traffic": proxy_traffic(),
        "audit": recent_audit(15),
        "now": time.strftime("%H:%M:%S"),
    })


# ---------------- API：流量历史 ----------------
@app.route("/api/traffic/history")
def api_traffic_history():
    if not session.get("ok"):
        abort(401)
    h = traffic_history()
    h["sample_secs"] = TRAFFIC_SAMPLE_SECS
    return jsonify(h)


# ---------------- API：端口实时检测 + 常用目标 ----------------
@app.route("/api/port_check")
def api_port_check():
    """填写远程端口时实时检测：系统监听 → 隧道占用，双层给原因"""
    if not session.get("ok"):
        abort(401)
    raw = request.args.get("port", "")
    editing_id = request.args.get("editing_id", "")
    try:
        port = int(raw)
    except Exception:
        return jsonify({"ok": False, "reason": "端口号不对"})
    if port < 1 or port > 65535:
        return jsonify({"ok": False, "reason": "端口范围 1-65535"})
    if port == SERVER_PORT:
        return jsonify({"ok": False, "kind": "system",
                        "reason": "frps 主端口"})
    if port == 8090:
        return jsonify({"ok": False, "kind": "system",
                        "reason": "frp 管理面板自身占用"})
    if port in SYSTEM_PORTS:
        return jsonify({"ok": False, "kind": "system",
                        "reason": SYSTEM_PORTS[port] + "正在使用"})
    # 系统实际监听（覆盖 SYSTEM_PORTS 没列到的服务）
    for line in sh("ss -tln").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3].rsplit(":", 1)[-1] == str(port):
            return jsonify({"ok": False, "kind": "system",
                            "reason": "本机有服务在监听该端口"})
    for t in load_tunnels():
        if t.get("remote_port") == port and t.get("id") != editing_id:
            return jsonify({"ok": False, "kind": "tunnel",
                            "reason": "已被隧道「%s」占用" % t.get("name")})
    return jsonify({"ok": True, "reason": None})


@app.route("/api/targets", methods=["GET"])
def api_targets_list():
    if not session.get("ok"):
        abort(401)
    return jsonify({"targets": load_targets(),
                    "presets": PRESET_PORTS})


# ---------------- frps 在线隧道导入（日志解析） ----------------
PROXY_NEW_RE = re.compile(r"new proxy \[([^\]]+)\] type \[([^\]]+)\] success")
PROXY_PORT_RE = re.compile(
    r"\] \[([^\]]+)\] (tcp|udp) proxy listen port \[(\d+)\]")


def frps_live_proxies():
    """frps 0.71 的 /api/proxies 对 GET/POST 均 405 → 解析 frps 日志拿真实隧道。
    frpc 每次注册 proxy 会打 [name] tcp/udp proxy listen port [port] +
    new proxy [name] type [type] success。倒序扫，同名取最新一次。"""
    out = sh("journalctl -u frps --no-pager -o short --since '7 days ago'")
    ports, types, order = {}, {}, []
    for line in out.splitlines():
        m = PROXY_PORT_RE.search(line)
        if m:
            name = m.group(1)
            if name not in ports:
                ports[name] = int(m.group(3))
                if name not in order:
                    order.append(name)
        m2 = PROXY_NEW_RE.search(line)
        if m2:
            types.setdefault(m2.group(1), m2.group(2))
    live = []
    for name in reversed(order):
        ttype = types.get(name, "tcp")
        if ttype not in TUNNEL_TYPES:
            ttype = "tcp"
        live.append({"name": name, "type": ttype, "remote_port": ports.get(name, 0)})
    return live


def frps_client_meta():
    """最近在线 frpc 的版本/IP（导入时写进备注）"""
    cs = _dash("/api/clients")
    if isinstance(cs, list) and cs:
        c = cs[-1]
        return c.get("version", ""), c.get("clientIP", "")
    return "", ""


@app.route("/api/tunnels/import", methods=["POST"])
def api_tunnels_import():
    """把 frps 实际在跑的 frpc 隧道收编进面板（同名/同远程端口跳过）"""
    if not session.get("ok"):
        abort(401)
    live = frps_live_proxies()
    if not live:
        return jsonify({"ok": False,
                        "errs": ["frps 日志里没找到在跑的隧道"
                                 "（frpc 需在线并注册过 proxy）"]}), 400
    version, cip = frps_client_meta()
    tunnels = load_tunnels()
    exist_names = {t.get("name") for t in tunnels}
    exist_ports = {t.get("remote_port") for t in tunnels}
    imported, skipped = [], []
    for p in live:
        if not p.get("remote_port"):
            continue
        if p["name"] in exist_names or p["remote_port"] in exist_ports:
            skipped.append("%s:%d" % (p["name"], p["remote_port"]))
            continue
        t = {"id": uuid.uuid4().hex[:8], "enabled": True,
             "created": time.strftime("%Y-%m-%d %H:%M:%S"),
             "name": p["name"], "type": p["type"], "local_ip": "127.0.0.1",
             "local_port": p["remote_port"], "remote_port": p["remote_port"],
             "note": "导入自 frps%s%s · 本地端口默认=远程，可编辑" % (
                 " · frpc %s" % version if version else "",
                 " · %s" % cip if cip else "")}
        tunnels.append(t)
        imported.append(t["name"])
    if imported:
        save_tunnels(tunnels)
        audit("tunnel_import", ",".join(imported))
    return jsonify({"ok": True, "imported": imported, "skipped": skipped})


# ---------------- API：隧道 CRUD ----------------
def validate_tunnel(data, editing_id=None):
    name = str(data.get("name", "")).strip()
    ttype = str(data.get("type", "")).strip()
    local_ip = str(data.get("local_ip", "")).strip() or "127.0.0.1"
    note = str(data.get("note", "")).strip()[:60]
    errs = []
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", name):
        errs.append("名称只能含字母/数字/_-，1-32 位")
    if ttype not in TUNNEL_TYPES:
        errs.append("类型必须是 tcp/udp/http")
    try:
        local_port = int(data.get("local_port", 0))
        if not (1 <= local_port <= 65535):
            raise ValueError
    except Exception:
        errs.append("本地端口必须是 1-65535")
        local_port = 0
    try:
        remote_port = int(data.get("remote_port", 0))
        if not (1 <= remote_port <= 65535):
            raise ValueError
    except Exception:
        errs.append("远程端口必须是 1-65535")
        remote_port = 0
    if not re.match(r"^[\d.:a-fA-F]{3,45}$", local_ip):
        errs.append("本地 IP 格式不对")
    if remote_port in (SERVER_PORT, 7500):
        errs.append("远程端口 %d 被 frps 自身占用，请换端口" % remote_port)
    if not errs:
        for t in load_tunnels():
            if t.get("id") != editing_id and t.get("remote_port") == remote_port:
                errs.append("远程端口 %d 已被隧道「%s」占用" %
                            (remote_port, t.get("name")))
                break
            if t.get("id") != editing_id and t.get("name") == name:
                errs.append("隧道名称「%s」已存在" % name)
                break
    return errs, {"name": name, "type": ttype, "local_ip": local_ip,
                  "local_port": local_port, "remote_port": remote_port,
                  "note": note}


@app.route("/api/tunnels", methods=["GET"])
def api_tunnels_list():
    if not session.get("ok"):
        abort(401)
    tunnels = load_tunnels()
    for t in tunnels:
        fwb = bool(t.get("type", "tcp") == "tcp" and fw_blocked(t["remote_port"]))
        t["fw_blocked"] = fwb
        t["online"] = bool(t.get("enabled") and not fwb
                           and port_open(t["remote_port"]))
        t["addr"] = "%s:%d" % (SERVER_ADDR, t["remote_port"])
        t["cfg_cmd"] = gen_frpc_cmd(t)
    return jsonify({"tunnels": tunnels})


@app.route("/api/tunnels", methods=["POST"])
def api_tunnels_create():
    if not session.get("ok"):
        abort(401)
    errs, fields = validate_tunnel(request.form)
    if errs:
        return jsonify({"ok": False, "errs": errs}), 400
    tunnels = load_tunnels()
    t = {"id": uuid.uuid4().hex[:8], "enabled": True,
         "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    t.update(fields)
    tunnels.append(t)
    save_tunnels(tunnels)
    remember_target(t["local_ip"], t["local_port"])
    audit("tunnel_create", t["name"])
    return jsonify({"ok": True, "tunnel": t})


@app.route("/api/tunnels/<tid>", methods=["POST", "PUT"])
def api_tunnels_edit(tid):
    if not session.get("ok"):
        abort(401)
    tunnels = load_tunnels()
    target = None
    for t in tunnels:
        if t.get("id") == tid:
            target = t
            break
    if not target:
        abort(404)
    errs, fields = validate_tunnel(request.form, editing_id=tid)
    if errs:
        return jsonify({"ok": False, "errs": errs}), 400
    target.update(fields)
    save_tunnels(tunnels)
    remember_target(target["local_ip"], target["local_port"])
    audit("tunnel_edit", target["name"])
    return jsonify({"ok": True, "tunnel": target})


@app.route("/api/tunnels/<tid>/toggle", methods=["POST"])
def api_tunnels_toggle(tid):
    if not session.get("ok"):
        abort(401)
    tunnels = load_tunnels()
    for t in tunnels:
        if t.get("id") == tid:
            new_enabled = not t.get("enabled", True)
            port = t.get("remote_port")
            tcp = t.get("type", "tcp") == "tcp"
            if new_enabled:  # 启用：精确删除 REJECT 规则
                if tcp and fw_blocked(port):
                    ok, out = fw_unblock(port)
                    if not ok:
                        return jsonify({"ok": False,
                                        "err": "删除防火墙规则失败：%s" % out[:160]}), 500
                t["enabled"] = True
                save_tunnels(tunnels)
                audit("tunnel_enable", "%s 远程端口 %s 已放行" % (t["name"], port))
            else:            # 停用：追加 REJECT 规则，端口物理不可达
                if tcp:
                    ok, out = fw_block(port)
                    if not ok:
                        return jsonify({"ok": False,
                                        "err": out[:160]}), 400
                t["enabled"] = False
                save_tunnels(tunnels)
                audit("tunnel_disable", "%s 远程端口 %s 已封锁(iptables REJECT)"
                      % (t["name"], port))
            return jsonify({"ok": True, "enabled": t["enabled"],
                            "fw_blocked": bool(tcp and fw_blocked(port))})
    abort(404)


@app.route("/api/tunnels/<tid>", methods=["DELETE"])
def api_tunnels_delete(tid):
    if not session.get("ok"):
        abort(401)
    tunnels = load_tunnels()
    name = ""
    kept = []
    for t in tunnels:
        if t.get("id") == tid:
            name = t.get("name", "")
        else:
            kept.append(t)
    if not name:
        abort(404)
    save_tunnels(kept)
    audit("tunnel_delete", name)
    return jsonify({"ok": True})


@app.route("/api/tunnels/<tid>/frpc")
def api_tunnel_frpc(tid):
    if not session.get("ok"):
        abort(401)
    t = find_tunnel(tid)
    if not t:
        abort(404)
    toml = gen_frpc_toml([t])
    audit("tunnel_export", t["name"])
    return Response(toml, mimetype="text/plain",
                    headers={"Content-Disposition":
                             "attachment; filename=frpc-%s.toml" % t["name"]})


# ---------------- API：frps 控制 ----------------
@app.route("/api/control", methods=["POST"])
def api_control():
    if not session.get("ok"):
        abort(401)
    action = request.form.get("action", "")
    if action not in ALLOWED_ACTIONS:
        abort(400)
    before = frps_active()
    sh("systemctl %s frps" % action, timeout=30)
    time.sleep(1.5)
    after = frps_active()
    audit(action, "before=%s after=%s" % (before, after))
    return jsonify({"ok": True, "action": action,
                    "before": before, "after": after})


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>frp 面板</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%23ff5c8a'/%3E%3Cpath d='M7 12h13l-3.5-3.5M25 20H12l3.5 3.5' stroke='white' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
/* ============ 樱花 frp 风：浅色白底 + 粉色点缀 + 文字优先；mobile-first，桌面 ≥860px 增强 ============ */
:root{
  --bg:#f8f7f8;--card:#ffffff;--bd:#e8e3e6;--bd2:#f2eff1;
  --tx:#262024;--t2:#82757d;--t3:#b8adb4;
  --pk:#ff5c8a;--pk-d:#e8365f;--pk-bg:#fff0f4;--pk-light:#fff8fa;
  --gn:#15803d;--gn-bg:#ecfdf3;--gn-bd:#bce5c9;
  --rd:#e11d48;--rd-bg:#fff1f3;--rd-bd:#f6ccd3;
  --amb:#b45309;--amb-bg:#fffbeb;--amb-bd:#fde68a;
  --bl:#2563eb;--bl-bg:#eff6ff;--bl-bd:#dbeafe;
  --pp:#7c3aed;--pp-bg:#f5f3ff;--pp-bd:#ede9fe;
  --cy:#0284c7;--cy-bg:#f0f9ff;--cy-bd:#e0f2fe;
  --sh:0 1px 3px rgba(43,36,41,.04), 0 4px 14px rgba(43,36,41,.025);
  --sh-card:0 4px 20px rgba(60,35,48,.035), 0 1px 2px rgba(60,35,48,.02);
  --sh-lg:0 20px 48px rgba(75,51,63,.09), 0 4px 12px rgba(75,51,63,.03);
  --radius:16px;
}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%}body.modal-open{overflow:hidden}
body{
  background:var(--bg);color:var(--tx);
  font:14px/1.6 "Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif;
  min-height:100vh;overscroll-behavior-y:none;
}
body::before{
  content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;
  background-color:#f9f7f8;
  background-image:
    radial-gradient(circle,rgba(255,92,138,.11) 1.2px,transparent 1.2px),
    radial-gradient(850px 520px at 8% -5%,rgba(255,92,138,.13),transparent 70%),
    radial-gradient(900px 550px at 95% 5%,rgba(124,58,237,.07),transparent 65%),
    radial-gradient(700px 500px at 85% 95%,rgba(255,182,193,.09),transparent 60%),
    linear-gradient(180deg,#fcfbfa 0%,#f8f7f8 100%);
  background-size:28px 28px,100% 100%,100% 100%,100% 100%,100% 100%;
}
.bg-art{position:fixed;inset:0;z-index:0;pointer-events:none;width:100%;height:100%;overflow:hidden}
.bg-art svg{width:100%;height:100%;display:block}
.layout,.loginbox{position:relative;z-index:1}
button{font-family:inherit}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:rgba(139,127,134,.22);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:rgba(139,127,134,.35)}
::-webkit-scrollbar-track{background:transparent}

/* ---------- 顶栏（手机） ---------- */
.topbar{
  position:sticky;top:0;z-index:60;display:flex;align-items:center;justify-content:space-between;
  gap:10px;padding:12px 16px;background:rgba(255,255,255,.88);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
  border-bottom:1px solid var(--bd2);padding-top:calc(12px + env(safe-area-inset-top));
}
.topbar .t{font-size:16px;font-weight:800;display:flex;align-items:center;gap:9px}
.topbar .t>span:last-child{display:flex;flex-direction:column;line-height:1.15}
.topbar .t small{font-size:10px;font-weight:600;color:var(--t2);margin-top:3px}
.topbar .clock{font-size:11px;color:var(--t3);text-align:right;line-height:1.5;max-width:44vw;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums}

/* logo 徽标（CSS 渐变方块 + 内联 SVG，替代 emoji） */
.lg-ic{width:30px;height:30px;border-radius:9px;flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,var(--pk),var(--pk-d));box-shadow:0 3px 10px rgba(255,92,138,.32)}
.lg-ic svg{display:block}
.grad{background:linear-gradient(120deg,var(--pk),var(--pk-d));-webkit-background-clip:text;background-clip:text;color:transparent}

main{padding:14px 14px calc(84px + env(safe-area-inset-bottom));max-width:1120px;margin:0 auto}

/* ---------- 底部 tabbar（手机）：纯文字 ---------- */
.tabbar{
  position:fixed;left:0;right:0;bottom:0;z-index:90;display:flex;
  background:rgba(255,255,255,.94);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-top:1px solid var(--bd2);padding:6px 4px calc(6px + env(safe-area-inset-bottom));
}
.tabbar a{
  flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px;padding:7px 0;
  color:var(--t2);font-size:11px;font-weight:600;text-decoration:none;border-radius:12px;cursor:pointer;
  transition:color .15s;min-height:48px;
}
.tabbar a.on{color:var(--pk);font-weight:800}
.tabbar a.add span{
  width:44px;height:44px;border-radius:14px;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,var(--pk),var(--pk-d));color:#fff;font-size:24px;font-weight:300;
  box-shadow:0 6px 18px rgba(255,92,138,.4);margin-top:-26px;
}
.tabbar a.add{flex:0 0 60px}

/* ---------- 桌面侧栏（默认隐藏） ---------- */
aside{display:none}

/* ---------- 通用组件 ---------- */
.card{
  background:rgba(255,255,255,.90);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border:1px solid rgba(255,255,255,.8);border-radius:14px;padding:15px;margin-bottom:14px;
  box-shadow:var(--sh);animation:fadeUp .4s ease both;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.card h2{
  font-size:13px;font-weight:800;color:var(--tx);margin-bottom:12px;
  display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;
}
.kpis{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px}
.kpi{
  background:rgba(255,255,255,.88);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border:1px solid rgba(255,255,255,.8);border-radius:14px;
  padding:13px 14px;min-width:0;box-shadow:var(--sh);animation:fadeUp .4s ease both;
}
.kpi:nth-child(2){animation-delay:.04s}.kpi:nth-child(3){animation-delay:.08s}
.kpi:nth-child(4){animation-delay:.12s}.kpi:nth-child(5){animation-delay:.16s}
.kpi .lb{font-size:11px;color:var(--t2);margin-bottom:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi .vl{font-size:19px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.25;word-break:break-word}
.kpi .sub{font-size:10px;color:var(--t3);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:20px;
  font-size:11px;font-weight:700;line-height:1.7;white-space:nowrap}
.pill .d{width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}
.p-on{background:var(--gn-bg);color:var(--gn)}
.p-off{background:var(--rd-bg);color:var(--rd)}
.p-dim{background:#f4f2f4;color:var(--t2)}
.tag{display:inline-flex;align-items:center;justify-content:center;padding:2px 7px;border-radius:6px;font-size:10px;font-weight:800;letter-spacing:.5px;line-height:1.3;font-family:Consolas,monospace}
.tag-tcp{background:var(--bl-bg);color:var(--bl);border:1px solid var(--bl-bd)}
.tag-udp{background:var(--pp-bg);color:var(--pp);border:1px solid var(--pp-bd)}
.tag-http{background:var(--gn-bg);color:var(--gn);border:1px solid var(--gn-bd)}
.st-dot{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700}
.st-dot i{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.st-on{color:var(--gn)}.st-on i{background:var(--gn);animation:pulse 2s infinite}
.st-off{color:var(--t3)}.st-off i{background:var(--t3)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
/* ---------- 状态微胶囊徽标（现代极客感） ---------- */
.st-badge{display:inline-flex;align-items:center;gap:5px;padding:3.5px 9px;border-radius:999px;font-size:11.5px;font-weight:700;line-height:1.35;white-space:nowrap;box-shadow:0 1px 2px rgba(43,36,41,.03)}
.st-badge i{width:6px;height:6px;border-radius:50%;flex-shrink:0;display:inline-block}
.st-badge.st-on{background:var(--gn-bg);color:var(--gn);border:1px solid var(--gn-bd)}
.st-badge.st-on i{background:var(--gn);box-shadow:0 0 0 3px rgba(21,128,61,.16);animation:pulseGlow 2.4s infinite}
.st-badge.st-off{background:#f6f3f5;color:var(--t2);border:1px solid #ebe5e8}
.st-badge.st-off i{background:var(--t3)}
.st-badge.st-blocked{background:#fff1f3;color:#e11d48;border:1px solid #ffd4dc;font-weight:700;letter-spacing:.2px;box-shadow:0 1px 3px rgba(225,29,72,.07)}
.st-badge.st-blocked i{background:#e11d48;border-radius:2px;box-shadow:0 0 0 2.5px rgba(225,29,72,.15)}
.st-badge.st-dis{background:#f7f4f6;color:var(--t2);border:1px solid #ece6e9}
.st-badge.st-dis i{background:var(--t3)}
.btn{
  border:1px solid var(--bd);background:#fff;color:var(--tx);border-radius:10px;
  padding:8px 15px;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;white-space:nowrap;
  display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:36px;
}
.btn:active{transform:scale(.97)}
.btn-sm{min-height:28px;padding:4px 10px;font-size:12px;border-radius:8px}
.btn-pk{background:linear-gradient(120deg,var(--pk),var(--pk-d));border-color:transparent;color:#fff;font-weight:700;box-shadow:0 2px 8px rgba(255,92,138,.25)}
.btn-go{background:var(--gn-bg);border-color:var(--gn-bd);color:var(--gn);font-weight:700}
.btn-stop{background:var(--rd-bg);border-color:var(--rd-bd);color:var(--rd);font-weight:700}
.btn-re{background:#faf8f9;border-color:var(--bd);color:var(--t2)}
.btn-sec{background:#fff;border-color:#ded8dc;color:#5a4f56;font-weight:600}
.btn-sec:hover{background:#faf7f8;border-color:#cfc6cb;color:var(--tx)}
.btn-del{background:transparent;border:1px solid transparent;color:var(--t2);font-weight:600}
.btn-del:hover{background:var(--rd-bg);border-color:var(--rd-bd);color:var(--rd)}
.ctrl{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.ctrl .btn{min-height:44px}
.hint{font-size:12px;color:var(--t2);margin-top:12px;line-height:1.9}
.hint .mono{color:var(--cy);font-family:Consolas,monospace;font-size:11px}
.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px}
.ok{color:var(--gn);font-weight:700}.bad{color:var(--rd);font-weight:700}.dim{color:var(--t2)}.t3{color:var(--t3)}
.empty{color:var(--t3);font-size:13px;padding:34px 16px;text-align:center;line-height:2}
.empty .sm{font-size:12px;color:var(--t3)}
.scrollx{overflow-x:auto;-webkit-overflow-x:touch;margin:0 -4px;padding:0 4px}
.scrollx table{min-width:480px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:#766971;font-weight:700;text-align:left;padding:12px 14px;font-size:11.5px;
  background:linear-gradient(180deg,#fcfafc 0%,#faf6f8 100%);border-bottom:1px solid #eee7ea;white-space:nowrap}
td{padding:12px 14px;border-bottom:1px solid #f2edf0;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:#fff8fa}
.tblwrap{border:1px solid #ece5ea;border-radius:16px;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:2px;background:#fff;box-shadow:var(--sh-card)}
.tblwrap table{min-width:960px}
/* 穿透管线芯片 */
.loc-code{display:inline-block;font-family:Consolas,"Cascadia Mono",monospace;font-size:11.5px;color:#574a52;background:#f7f4f6;border:1px solid #ebe4e8;padding:2.5px 8px;border-radius:6px}
.addr-code{display:inline-block;font-family:Consolas,"Cascadia Mono",monospace;font-size:11.5px;font-weight:600;color:var(--cy);background:var(--cy-bg);border:1px solid var(--cy-bd);padding:2.5px 8px;border-radius:6px}
.flow-cell{display:inline-flex;align-items:center;gap:6px;font-family:Consolas,"Cascadia Mono",monospace;font-size:11px;white-space:nowrap}
.flow-down{color:var(--gn);font-weight:700}
.flow-sep{color:var(--t3);font-weight:400}
.flow-up{color:var(--pk);font-weight:700}

/* ---------- 隧道卡片（手机默认） ---------- */
.tun-card{
  background:var(--card);border:1px solid var(--bd2);border-radius:14px;padding:13px 14px;margin-bottom:10px;
  box-shadow:var(--sh);animation:fadeUp .35s ease both;
}
.tun-card .r1{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}
.tun-card .nm{font-weight:800;font-size:15px;display:flex;align-items:center;gap:8px;min-width:0}
.tun-card .nm span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tun-card .r2{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--t2);margin-bottom:6px}
.tun-card .addr{color:var(--cy);font-family:Consolas,monospace;font-size:12px;font-weight:600}
.tun-card .note{color:var(--t3);font-size:11px;margin-bottom:8px}
.tun-card .ops{display:flex;gap:8px;border-top:1px solid var(--bd2);padding-top:10px}
.tun-card .ops .btn{flex:1;min-height:40px;padding:8px 6px}
#tlist.no-anim .tun-card,#clients.no-anim .tun-card{animation:none}

/* ---------- 模态框：手机 bottom-sheet ---------- */
.modal{position:fixed;inset:0;background:rgba(43,36,41,.4);backdrop-filter:blur(3px);
  display:none;align-items:flex-end;justify-content:center;z-index:200;animation:fadeIn .18s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal .box{
  background:#fff;border:1px solid var(--bd);border-bottom:none;border-radius:20px 20px 0 0;
  padding:20px 18px calc(20px + env(safe-area-inset-bottom));width:100%;max-height:92vh;overflow:auto;
  animation:slideUp .24s cubic-bezier(.2,1,.3,1);
}
@keyframes slideUp{from{transform:translateY(40px);opacity:0}to{transform:none;opacity:1}}
.modal h3{font-size:16px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.modal .grab{width:36px;height:4px;border-radius:2px;background:#e0dcde;margin:0 auto 14px}
.f-row{display:flex;gap:12px;margin-bottom:13px;flex-wrap:wrap}
.f-item{flex:1;min-width:140px}
.f-item label{display:block;font-size:12px;color:var(--t2);margin-bottom:6px;font-weight:700}
.f-item input,.f-item select{
  width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--bd);
  background:#fff;color:var(--tx);font-size:15px;outline:none;transition:border .15s,box-shadow .15s;
}
.f-item input:focus,.f-item select:focus{border-color:var(--pk);box-shadow:0 0 0 3px rgba(255,92,138,.12)}
/* 端口预选 / 常用目标 chips + 实时检测提示 */
.pchips{display:flex;gap:6px;overflow-x:auto;padding:1px 0 5px;scrollbar-width:none;-webkit-overflow-scrolling:touch}
.pchips::-webkit-scrollbar{display:none}
.pchip{flex:0 0 auto;padding:6px 11px;border:1px solid var(--bd);border-radius:999px;background:#fff;
  font-size:11px;color:var(--t2);white-space:nowrap;cursor:pointer;line-height:1.4;transition:border .15s,color .15s,background .15s}
.pchip:active{transform:scale(.96)}
.pchip.sel{border-color:var(--pk);color:var(--pk-d);background:#fff5f8;font-weight:700}
.pchip .pk2{color:var(--t3);margin-right:5px;font-family:var(--mono,monospace)}
.ptip{font-size:11px;margin-top:5px;min-height:15px;line-height:1.5;font-weight:600}
.ptip.ok{color:var(--gn)}
.ptip.bad{color:var(--rd)}
.ptip.wait{color:var(--t3);font-weight:400}
.f-err{color:var(--rd);font-size:12px;margin-bottom:12px;display:none;
  background:var(--rd-bg);border:1px solid var(--rd-bd);border-radius:10px;padding:10px 12px;line-height:1.8}
pre.cfg{background:#faf9fa;border:1px solid var(--bd);border-radius:12px;padding:14px;
  font-size:11px;overflow:auto;white-space:pre;margin:12px 0;line-height:1.8;color:#4b4348}
.cfgbar{display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap}
.cfgbar .btn{min-height:44px}
#toast{position:fixed;top:calc(14px + env(safe-area-inset-top));left:14px;right:14px;z-index:300;
  background:#fff;border:1px solid var(--bd);border-left:3px solid var(--gn);border-radius:12px;
  padding:12px 16px;font-size:13px;font-weight:600;display:none;box-shadow:0 8px 32px rgba(43,36,41,.16);animation:fadeIn .2s}

/* ---------- 登录页 ---------- */
.loginbox{max-width:400px;margin:10vh auto 0;padding:0 16px}
.loginbox .card{padding:34px 26px;text-align:center;border-radius:18px}
.loginbox .lg{margin-bottom:12px}
.loginbox h2{font-size:21px;font-weight:800;margin-bottom:4px;justify-content:center;color:var(--tx)}
.loginbox .st{font-size:12px;color:var(--t2);margin-bottom:22px}
.loginbox input{width:100%;padding:13px 16px;border-radius:12px;border:1px solid var(--bd);
  background:#fff;color:var(--tx);font-size:17px;margin-bottom:12px;outline:none;
  text-align:center;transition:border .15s,box-shadow .15s}
.loginbox input:focus{border-color:var(--pk);box-shadow:0 0 0 3px rgba(255,92,138,.12)}
.loginbox .btn{width:100%;padding:13px;font-size:15px;min-height:48px}
.msg{min-height:18px;font-size:13px;margin-top:10px}
.sec-row td:first-child{color:var(--pk);font-weight:800;font-size:11px;letter-spacing:1px}
.view{display:none}
.view.on{display:block}

/* ---------- 启停亮灯：停用的隧道整体压暗 ---------- */
/* v5.12：停用隧道只压暗信息区，按钮区豁免（父级 filter 无法被子级抵消，故分区压暗）*/
.tun-card.off .r1,.tun-card.off .r2,.tun-card.off .note{opacity:.55;filter:saturate(.4)}
#tun-table tr.off td{opacity:.55;filter:saturate(.4)}
#tun-table tr.off td.opc{opacity:1;filter:none}
#tun-table tr.off:hover{background:#fff}
.st-dot.st-dis{color:var(--t3)}.st-dot.st-dis i{background:var(--t3)}

/* ---------- 刷新频率 pill 组 ---------- */
.pollbar{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:14px;
  background:var(--card);border:1px solid var(--bd2);border-radius:12px;padding:9px 12px;box-shadow:var(--sh)}
.pollbar .lab{font-size:12px;color:var(--t2);font-weight:700;margin-right:2px}
.ps{border:1px solid var(--bd);background:#fff;color:var(--t2);border-radius:20px;
  padding:5px 13px;font-size:12px;font-weight:700;cursor:pointer;transition:all .15s;min-height:32px}
.ps:active{transform:scale(.96)}
.ps.on{background:linear-gradient(120deg,var(--pk),var(--pk-d));border-color:transparent;color:#fff;
  box-shadow:0 2px 8px rgba(255,92,138,.28)}
.pollbar .pst{margin-left:auto;font-size:11px;color:var(--t3);font-variant-numeric:tabular-nums;white-space:nowrap}

/* ---------- 流量监控卡 ---------- */
.tflow{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tf{border:1px solid var(--bd2);border-radius:12px;padding:13px 14px;background:#fdfcfd}
.tf .tfl{font-size:11px;color:var(--t2);font-weight:700;margin-bottom:5px}
.tf .tfv{font-size:20px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.25;word-break:break-all}
.tf .tfs{font-size:11px;font-weight:700;margin-top:3px;font-variant-numeric:tabular-nums}
.tf.tf-in .tfv{color:var(--gn)}
.tf.tf-out .tfv{color:var(--pk)}
.tf.tf-in .tfs{color:var(--gn)}
.tf.tf-out .tfs{color:var(--pk)}
.tun-card .r2 .tflab{color:var(--t3);font-weight:700}

/* ---------- 流量统计图（自绘 SVG，无外部依赖） ---------- */
.legend{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--tx);font-weight:700;margin-bottom:12px;flex-wrap:wrap}
.legend i{width:11px;height:11px;border-radius:3px;display:inline-block;flex-shrink:0}
.legend .lg-in{background:var(--gn)}
.legend .lg-out{background:var(--pk)}
.legend .lg-note{font-weight:500;font-size:12px;color:var(--t2);margin-left:auto}
.chartwrap{position:relative;margin:0 -2px;padding:2px;overflow:visible}
.chartwrap svg{display:block;width:100%;height:auto;overflow:visible}
.chartwrap .col-bg{fill:transparent;transition:fill .24s cubic-bezier(.16,1,.3,1);pointer-events:none}
.chartwrap .col-group.active .col-bg{fill:rgba(255,92,138,.10)}
body.dark .chartwrap .col-group.active .col-bg{fill:rgba(255,255,255,.08)}
.chartwrap .col-hit{cursor:pointer;pointer-events:all}
.chartwrap .col-group.active rect.bar-in{filter:brightness(1.18) drop-shadow(0 2px 6px rgba(34,197,94,.45));transition:filter .24s cubic-bezier(.16,1,.3,1)}
.chartwrap .col-group.active rect.bar-out{filter:brightness(1.18) drop-shadow(0 2px 6px rgba(255,92,138,.5));transition:filter .24s cubic-bezier(.16,1,.3,1)}

/* ---------- 悬浮数值卡片 Tooltip（深色黑曜石渐变 + 柔光浮现微动效） ---------- */
.chart-tooltip{
  position:absolute;top:0;left:0;
  opacity:0;visibility:hidden;pointer-events:none;z-index:60;
  background:linear-gradient(145deg,rgba(26,20,28,.96) 0%,rgba(16,12,18,.95) 100%);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border:1px solid rgba(255,92,138,.35);
  box-shadow:0 14px 32px -6px rgba(0,0,0,.7),0 0 18px rgba(255,92,138,.18),inset 0 1px 0 rgba(255,255,255,.1);
  border-radius:10px;padding:10px 14px;
  color:#fff;font-size:12px;line-height:1.45;white-space:nowrap;
  transform:translateY(6px) scale(0.96);
  transform-origin:center bottom;
  transition:opacity .24s cubic-bezier(.16,1,.3,1),transform .24s cubic-bezier(.16,1,.3,1),visibility .24s;
  min-width:142px;
}
.chart-tooltip.show{opacity:1;visibility:visible;transform:translateY(0) scale(1)}
/* 左右移动切换柱子时，卡片开启平滑滑行渐变动效 */
.chart-tooltip.moving{
  transition:
    opacity .24s cubic-bezier(.16,1,.3,1),
    transform .24s cubic-bezier(.16,1,.3,1),
    left .22s cubic-bezier(.16,1,.3,1),
    top .22s cubic-bezier(.16,1,.3,1),
    visibility .24s;
}
body:not(.dark) .chart-tooltip{
  background:linear-gradient(145deg,rgba(32,24,32,.96) 0%,rgba(20,15,22,.95) 100%);
  border:1px solid rgba(255,92,138,.38);
  box-shadow:0 12px 28px -4px rgba(45,15,25,.4),0 0 16px rgba(255,92,138,.14),inset 0 1px 0 rgba(255,255,255,.12);
}

/* 卡片内部文字在左右切换柱子时平滑淡入 */
.chart-tooltip .tip-inner{
  animation:tipFadeIn .2s cubic-bezier(.16,1,.3,1) both;
}
@keyframes tipFadeIn{
  from{opacity:.35;transform:translateY(2px)}
  to{opacity:1;transform:translateY(0)}
}
.chart-tooltip .tip-head{
  display:flex;align-items:center;justify-content:space-between;gap:10px;
  font-family:Consolas,"Cascadia Mono",monospace;font-weight:700;font-size:12px;
  color:#fce7ef;border-bottom:1px solid rgba(255,255,255,.12);
  padding-bottom:5px;margin-bottom:6px;
}
.chart-tooltip .tip-est{font-size:10px;font-weight:600;color:#fca5a5;background:rgba(239,68,68,.2);border-radius:4px;padding:1px 5px}
.chart-tooltip .tip-row{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:3.5px 0;font-size:11.5px}
.chart-tooltip .tip-tag{display:flex;align-items:center;gap:6px;color:#d5c7cf}
.chart-tooltip .tip-tag i{width:7.5px;height:7.5px;border-radius:2px;display:inline-block;flex-shrink:0}
.chart-tooltip .tip-tag i.in{background:#22c55e}
.chart-tooltip .tip-tag i.out{background:#ff5c8a}
.chart-tooltip .tip-tag i.tot{background:#e2e8f0}
.chart-tooltip .tip-val{font-family:Consolas,"Cascadia Mono",monospace;font-weight:700;text-align:right}
.chart-tooltip .tip-val.in{color:#4ade80}
.chart-tooltip .tip-val.out{color:#ff759f}
.chart-tooltip .tip-val.tot{color:#ffffff}
.chart-tooltip .tip-div{height:1px;background:rgba(255,255,255,.1);margin:6px 0 5px 0}

/* ---------- 流量表：数字右对齐等宽，列不裁切，字号清晰易读 ---------- */
.tbl-scroll{overflow-x:auto;-webkit-overflow-x:touch}
.tbl td,.tbl th{text-align:left;vertical-align:middle}
.tbl th{padding:12px 14px;font-size:13.5px;font-weight:700;color:var(--tx);background:#faf7f9;letter-spacing:.2px}
.tbl td{padding:12px 14px;font-size:14px;border-bottom:1px solid #f2eff1}
.tbl td.num,.tbl th.num{text-align:right;font-variant-numeric:tabular-nums;
  font-family:Consolas,"Cascadia Mono",monospace;font-size:14px;white-space:nowrap}
.tbl td.mono-l{font-family:Consolas,"Cascadia Mono",monospace;font-size:14px;white-space:nowrap;font-weight:600;color:var(--tx)}
.tbl th.num{font-size:13.5px;font-weight:700}
td.num-in{color:#15803d;font-weight:700}
td.num-out{color:#e11d48;font-weight:700}
.tbl tr:hover td{background:#fff9fb}
.badge-sub{font-size:12px;font-weight:600;color:var(--t2);background:#faf4f7;border:1px solid #f2e7ec;padding:2.5px 8px;border-radius:6px;margin-left:8px;vertical-align:middle;display:inline-block}
.traffic-grid{display:grid;grid-template-columns:1fr;gap:12px;margin-bottom:12px}
.traffic-grid .card{margin-bottom:0}

/* ============ 桌面（≥860px）：侧栏 + 表格 ============ */
@media (min-width:860px){
  body::before{
    background-color:#faf8f9;
    background-image:
      radial-gradient(circle,rgba(255,92,138,.065) 1.2px,transparent 1.2px),
      radial-gradient(700px 460px at 10% -4%,rgba(255,92,138,.06),transparent 60%),
      radial-gradient(900px 560px at 106% 8%,rgba(124,58,237,.03),transparent 60%),
      linear-gradient(180deg,#faf8f9 0%,#f6f5f6 100%);
    background-size:28px 28px,100% 100%,100% 100%,100% 100%;
  }
  .topbar{display:none}
  .tabbar{display:none}
  aside{
    display:flex;width:212px;flex-shrink:0;position:sticky;top:0;height:100vh;flex-direction:column;
    background:#fff;border-right:1px solid var(--bd2);padding:20px 12px;
  }
  .layout{display:flex;min-height:100vh;width:100%;margin:0}
  aside .logo{font-size:18px;font-weight:800;padding:2px 10px 18px;border-bottom:1px solid var(--bd2);
    margin-bottom:14px;display:flex;align-items:center;gap:10px}
  aside nav{flex:1;display:flex;flex-direction:column;gap:2px}
  aside nav a{
    display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:10px;color:var(--t2);
    text-decoration:none;font-size:14px;font-weight:600;cursor:pointer;position:relative;transition:all .16s;border:1px solid transparent;
  }
  aside nav a:hover{color:var(--tx);background:#faf8f9}
  aside nav a.on{color:var(--pk);background:var(--pk-bg);border-color:#fbdde5;font-weight:800}
  aside nav a.on::before{content:"";position:absolute;left:-12px;top:20%;bottom:20%;width:3px;border-radius:3px;
    background:linear-gradient(180deg,var(--pk),var(--pk-d))}
  aside nav a.exit:hover{color:var(--rd);background:var(--rd-bg)}
  aside .side-foot{font-size:11px;color:var(--t3);padding:10px;border-top:1px solid var(--bd2);line-height:1.9}
  main{padding:22px 32px 60px;max-width:none}
  .kpis{grid-template-columns:repeat(5,1fr);gap:14px}
  .kpi .vl{font-size:21px}
  .kpi .lb{font-size:12px}
  .kpi .sub{font-size:11px}
  .ctrl{display:flex;gap:10px;flex-wrap:wrap}
  .ctrl .btn{flex:0 0 auto;min-width:110px}
  .tun-card{display:none}
  #tun-table{display:block}
  .modal{align-items:center}
  .modal .box{
    width:520px;max-width:94vw;border-radius:18px;border:1px solid var(--bd);
    padding:26px;animation:popIn .2s cubic-bezier(.2,1.2,.4,1);
  }
  @keyframes popIn{from{transform:scale(.95) translateY(10px);opacity:0}to{transform:none;opacity:1}}
  .modal .grab{display:none}
  .modal .box.wide{width:640px}
  .card{padding:18px 20px;border-radius:16px}
  .topbar-d{display:flex;align-items:center;justify-content:space-between;gap:14px;
    padding:14px 18px;margin-bottom:20px;border-radius:14px;background:#fff;
    border:1px solid var(--bd2);position:sticky;top:0;z-index:60;box-shadow:var(--sh)}
  .topbar-d h1{font-size:17px;font-weight:800}
  .topbar-d .srv{font-size:12px;color:var(--t2);display:flex;align-items:center;gap:8px;font-variant-numeric:tabular-nums}
  .topbar-d .srv b{color:var(--pk)}
  .topbar-d .srv .dot{width:7px;height:7px;border-radius:50%;background:var(--gn);box-shadow:0 0 8px rgba(21,163,74,.5);animation:pulse 2.4s infinite}
}
/* v5.27 修复：此处原先有一行 .topbar-d{display:none} 写在桌面 @media 之后，
   同为单类选择器时源顺序后者胜，把 ≥860px 的桌面顶栏（含「＋ 新建隧道」按钮）
   一并隐藏——桌面端曾因此没有任何新建入口。移动端隐藏由上面
   @media (max-width:859px){.topbar-d{display:none!important}} 负责，默认不再隐藏。 */
@media (max-width:859px){.topbar-d{display:none!important}}

/* ============ v5.15 Apple-inspired motion：克制反馈、自然过渡 ============ */
:root{--ease-apple:cubic-bezier(.22,.61,.36,1);--ease-spring:cubic-bezier(.2,.8,.2,1)}
:focus-visible{outline:2px solid var(--pk);outline-offset:3px}
button:disabled{opacity:.48;cursor:not-allowed;transform:none!important;box-shadow:none!important}
.btn,.ps,.pchip,.tabbar a,aside nav a,.card,.kpi,.tun-card,.tf{transition:transform .24s var(--ease-apple),box-shadow .24s var(--ease-apple),background-color .24s var(--ease-apple),border-color .24s var(--ease-apple),color .24s var(--ease-apple)}
.btn:active,.ps:active,.pchip:active{transform:scale(.965)}
@media (hover:hover) and (pointer:fine){
  .card,.kpi,.tun-card{will-change:transform}
  .card:hover,.kpi:hover,.tun-card:hover{transform:translateY(-2px);box-shadow:0 12px 28px rgba(75,51,63,.09)}
}
@media (hover:hover) and (pointer:fine){
  .tf:hover{transform:translateY(-1px);border-color:#ead6dd;box-shadow:0 6px 16px rgba(75,51,63,.06)}
}
.st-on i,.side-status .dot,.topbar-d .srv .dot{animation:pulseGlow 2.6s var(--ease-apple) infinite}
@keyframes pulseGlow{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(21,163,74,0)}50%{opacity:.8;box-shadow:0 0 0 4px rgba(21,163,74,.13)}}
.view.on{animation:viewIn .32s var(--ease-apple) both}
@keyframes viewIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.kpi .vl,.tf .tfv{transition:color .22s ease,transform .22s var(--ease-apple)}
/* ---------- v5.23 流量监控翻牌（split-flap） ---------- */
.tf .tfv{position:relative;display:block;perspective:700px;min-height:1.25em}
.tf .tfv .fc{position:absolute;left:0;top:0;width:100%;transform-origin:center top;backface-visibility:hidden;white-space:nowrap;visibility:hidden}
.tf .tfv .fc.on{visibility:visible}
.tf .tfv .fc.out{animation:flipOut .19s ease-in both;z-index:2;visibility:visible}
.tf .tfv .fc.in{animation:flipIn .19s ease-out .19s both;z-index:1;visibility:visible}
@keyframes flipOut{from{transform:rotateX(0deg)}to{transform:rotateX(-90deg)}}
@keyframes flipIn{from{transform:rotateX(-90deg)}to{transform:rotateX(0deg)}}
.value-bump{animation:valueFlash .5s var(--ease-apple)}
@keyframes valueFlash{
  0%{filter:brightness(1) saturate(1)}
  15%{filter:brightness(1.5) saturate(1.35)}
  40%{filter:brightness(1.12) saturate(1.06)}
  100%{filter:brightness(1) saturate(1)}
}
.pchip.sel{animation:chipSelect .22s var(--ease-spring)}
@keyframes chipSelect{from{transform:scale(.94)}to{transform:scale(1)}}
.chart-draw{transform-origin:left bottom;animation:chartDraw .65s var(--ease-apple) both}
@keyframes chartDraw{from{opacity:.15;transform:scaleY(.08)}to{opacity:1;transform:scaleY(1)}}
.toast-in{animation:toastIn .28s var(--ease-spring) both!important}
.toast-out{animation:toastOut .24s var(--ease-apple) both!important}
@keyframes toastIn{from{opacity:0;transform:translateY(-10px) scale(.98)}to{opacity:1;transform:none}}
@keyframes toastOut{from{opacity:1;transform:none}to{opacity:0;transform:translateY(-7px) scale(.985)}}
.modal.is-closing{animation:fadeOut .2s ease both}
.modal.is-closing .box{animation:slideDown .2s var(--ease-apple) both}
@keyframes fadeOut{from{opacity:1}to{opacity:0}}
@keyframes slideDown{from{transform:none;opacity:1}to{transform:translateY(30px);opacity:0}}
.skeleton{background:linear-gradient(90deg,#faf7f8 25%,#f1e9ed 38%,#faf7f8 55%);background-size:300% 100%;animation:shimmer 1.35s ease-in-out infinite;border-radius:6px}
@keyframes shimmer{from{background-position:100% 0}to{background-position:-100% 0}}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.001ms!important}
}

/* ============ v5.14 Sakura Studio：统一视觉层 ============ */
.card,.kpi,.tun-card{position:relative;overflow:hidden}
.card{border-color:#ebe4e8;box-shadow:0 5px 20px rgba(75,51,63,.045)}
.card::after{content:"";position:absolute;left:0;top:0;width:42px;height:3px;background:linear-gradient(90deg,var(--pk),#ffb0c6);border-radius:0 0 5px 0;opacity:.9}
.card h2{letter-spacing:.1px;font-size:14px;padding-top:1px}
.card h2::first-letter{color:var(--pk)}
.kpi{border-color:#eee7eb;background:linear-gradient(145deg,#fff 0%,#fffafb 100%);box-shadow:0 5px 18px rgba(75,51,63,.045);padding:15px 16px}
.kpi::before{content:"";position:absolute;right:-18px;top:-22px;width:68px;height:68px;border-radius:50%;background:var(--pk-bg);opacity:.7}
.kpi .lb,.kpi .vl,.kpi .sub{position:relative}
.kpi .lb{font-weight:800;letter-spacing:.2px}
.kpi .vl{font-size:22px;letter-spacing:-.4px}
.pollbar{border-color:#eee5e9;background:rgba(255,255,255,.8);box-shadow:0 4px 16px rgba(75,51,63,.04)}
.pollbar .lab{color:var(--tx);letter-spacing:.2px}
.btn{box-shadow:0 1px 2px rgba(75,51,63,.03)}
@media (hover:hover) and (pointer:fine){
  .btn:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(75,51,63,.09)}
  .btn-pk:hover{box-shadow:0 6px 16px rgba(255,92,138,.28)}
}
.pill{padding:3px 10px;letter-spacing:.1px}
.pill .d{box-shadow:0 0 0 3px currentColor;opacity:.18}
.tun-card{border-color:#eee6ea;box-shadow:0 5px 18px rgba(75,51,63,.05);padding:15px}
.tun-card .r1{margin-bottom:10px}
.tun-card .ops{padding-top:12px}
.tun-card .addr{background:#f4fbfc;padding:2px 7px;border-radius:6px}
.tblwrap{border-color:#eee6ea;box-shadow:0 4px 15px rgba(75,51,63,.035)}
th{background:#fcf9fa;letter-spacing:.2px}
tbody tr{transition:background .15s}
tbody tr:hover{background:#fff6f8!important}
.empty{padding:42px 16px;background:linear-gradient(180deg,#fffafd,#fff)}
.empty::before{content:"";display:block;width:42px;height:42px;margin:0 auto 10px;border-radius:14px;background:var(--pk-bg);border:1px solid #fbdde5}
.modal .box{box-shadow:var(--sh-lg)}
.modal h3{letter-spacing:.2px}
.f-item label{color:#756a71}
.f-item input,.f-item select{border-color:#e5dfe2;background:#fffdfd}
.f-item input:hover,.f-item select:hover{border-color:#d8cbd0}
#toast{border-left-width:4px}

/* 桌面侧栏：品牌区、导航胶囊和服务器状态 */
@media (min-width:860px){
  .layout{display:flex;min-height:100vh;width:100%;margin:0}
  aside{width:256px;flex-shrink:0;position:sticky;top:0;height:100vh;padding:26px 16px;background:rgba(255,255,255,.88);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:6px 0 26px rgba(75,51,63,.028)}
  aside .logo{padding:0 8px 22px;margin-bottom:14px;border-bottom:1px solid #f1e7ec;font-size:19px;display:flex;align-items:center;gap:11px}
  .brand-sub{display:block;color:#a899a1;font-size:9.5px;font-weight:700;letter-spacing:.6px;margin-top:2px;text-transform:uppercase}
  .side-status{margin:0 2px 20px;padding:13px 14px;border:1px solid #f1e4ea;border-radius:14px;background:linear-gradient(150deg,#ffffff 0%,#fff9fb 100%);box-shadow:0 2px 8px rgba(75,51,63,.025);font-size:11px;color:var(--t2)}
  .side-status>div:first-child{display:flex;align-items:center;gap:7px;color:var(--gn);font-weight:700}
  .side-status .dot{width:7.5px;height:7.5px;border-radius:50%;display:inline-block;background:var(--gn);box-shadow:0 0 0 4px rgba(21,128,61,.12)}
  .side-status small{display:block;margin-top:4px;color:var(--t3);font:10.5px Consolas,monospace}
  .network-row{display:flex;gap:6px;margin-top:9px}
  .network-row span{padding:3px 8px;border-radius:6px;background:#fff;border:1px solid #ede3e7;color:#917f88;font-size:10.5px;font-weight:600;font-family:Consolas,monospace}
  aside nav{gap:5px}
  aside nav a{padding:12px 14px;border-radius:12px;font-size:14px;font-weight:600;letter-spacing:.1px;display:flex;align-items:center;gap:10px;transition:all .18s var(--ease-apple)}
  aside nav a:hover{color:var(--tx);background:#faf6f8}
  aside nav a::before{display:inline-flex;position:static;width:24px;height:24px;align-items:center;justify-content:center;border-radius:7px;background:#faf4f7;color:#b1a0a8;font-size:10.5px;font-weight:800;content:"·"}
  aside nav a[data-v="v-overview"]::before{content:"01"}
  aside nav a[data-v="v-tunnels"]::before{content:"02"}
  aside nav a[data-v="v-traffic"]::before{content:"03"}
  aside nav a[data-v="v-security"]::before{content:"04"}
  aside nav a.on{color:var(--pk-d);background:linear-gradient(90deg,#fff0f4 0%,#fff7f9 100%);border-color:#fcdde5;font-weight:800;box-shadow:0 2px 8px rgba(255,92,138,.06)}
  aside nav a.on::before{position:static;left:auto;top:auto;bottom:auto;width:24px;height:24px;background:#fff;color:var(--pk);box-shadow:0 1px 4px rgba(255,92,138,.15)}
  aside nav a.on::after{content:"";position:absolute;left:-16px;top:18%;bottom:18%;width:3.5px;border-radius:4px;background:linear-gradient(180deg,var(--pk),var(--pk-d))}
  .side-bottom{margin-top:auto;display:flex;flex-direction:column;gap:8px}
  .side-exit-btn{
    display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:12px;
    color:var(--t2);font-size:13.5px;font-weight:600;text-decoration:none;
    transition:all .18s var(--ease-apple);border:1px solid transparent;cursor:pointer;
  }
  .side-exit-btn svg{flex-shrink:0;transition:transform .18s var(--ease-apple)}
  .side-exit-btn:hover{color:var(--rd);background:var(--rd-bg);border-color:var(--rd-bd)}
  .side-exit-btn:hover svg{transform:translateX(3px)}
  .top-exit-m{
    display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;
    border-radius:50%;color:var(--t2);background:#fff;border:1px solid var(--bd2);
    text-decoration:none;transition:all .18s var(--ease-apple);
  }
  .top-exit-m:hover,.top-exit-m:active{color:var(--rd);background:var(--rd-bg);border-color:var(--rd-bd)}
  aside .side-foot{margin:0 -2px;padding:14px 12px;border:1px solid #f1e6eb;border-radius:12px;background:linear-gradient(150deg,#ffffff 0%,#fffafc 100%);color:#9a8991;font-size:11px}
  main{padding:24px 36px 68px;max-width:1720px;width:100%;margin:0}
  .topbar-d{max-width:1720px;width:100%;padding:16px 26px;margin-bottom:22px;border-radius:16px;border-color:#eee5ea;background:rgba(255,255,255,.86);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 4px 22px rgba(75,51,63,.038)}
  .topbar-d h1{font-size:19px;letter-spacing:-.2px;font-weight:800}
  .top-actions{display:flex;align-items:center;gap:12px}
  .top-new{min-height:36px;padding:7px 18px;font-size:13px;font-weight:700;border-radius:10px;box-shadow:0 3px 10px rgba(255,92,138,.28)}
  .topbar-d h1::after{content:" / Sakura FRP";font-size:11.5px;color:var(--t3);font-weight:600;letter-spacing:.3px}
  .topbar-d .srv{padding:6px 14px;border-radius:999px;background:#faf6f8;border:1px solid #efe4ea;font-size:12px}
  .card{padding:20px 24px}
  .kpis{gap:12px}
  .kpi{padding:16px 18px}
  .kpi .vl{font-size:28px}
  /* 桌面端表格与列宽 */
  .tblwrap{border-color:#ebe4e8;border-radius:16px;box-shadow:0 4px 22px rgba(75,51,63,.035);background:#fff}
  .tblwrap table th{padding:13px 16px;font-size:12px;letter-spacing:.3px;background:#faf7f9}
  .tblwrap table td{padding:14px 16px;font-size:13.5px}
  .tblwrap table th:nth-child(1){width:165px}
  .tblwrap table th:nth-child(2){width:120px}
  .tblwrap table th:nth-child(3){width:70px}
  .tblwrap table th:nth-child(4){width:160px}
  .tblwrap table th:nth-child(5){width:185px}
  .tblwrap table th:nth-child(6){width:175px}
  .tblwrap table th:nth-child(7){min-width:80px}
  .tblwrap table th:nth-child(8){width:150px}
  .tblwrap table th:nth-child(9){width:245px}
  .btn{min-height:30px;font-size:12px}
  .loc-code, .addr-code{font-size:12.5px;padding:3px 8px}
  .opc{display:flex;align-items:center;gap:6px;justify-content:flex-start}
  /* 隧道页安全策略提示框（桌面端 Card 化） */
  #tun-hint{
    margin-top:14px;padding:14px 18px;border-radius:14px;
    background:linear-gradient(135deg,#fffbfd 0%,#fff 100%);
    border:1px solid #f0e1e7;border-left:4px solid var(--pk);
    box-shadow:0 2px 10px rgba(75,51,63,.025);
    font-size:12px;line-height:1.85;color:#6b5d64;
  }
  /* 桌面端流量明细表放大与双栏网格 */
  #v-traffic .card{padding:22px 26px;margin-bottom:18px}
  #v-traffic .card h2{font-size:16px;font-weight:800}
  #v-traffic .tbl th{padding:13px 16px;font-size:13.5px}
  #v-traffic .tbl td{padding:14px 16px;font-size:14px}
  #v-traffic .tbl td.num,#v-traffic .tbl th.num{font-size:14px}
  #v-traffic .tbl td.mono-l{font-size:14px}
  .traffic-grid{display:grid;grid-template-columns:1fr;gap:14px;margin-bottom:14px}
  .traffic-grid .card{margin-bottom:0}
  @media (min-width:980px){
    .traffic-grid{grid-template-columns:1fr 1.16fr;gap:18px;align-items:start;margin-bottom:18px}
    .traffic-grid .tbl th{padding:11px 12px;font-size:13px}
    .traffic-grid .tbl td{padding:12px 12px;font-size:13.5px}
  }
  #v-traffic .hint{
    font-size:13px;line-height:1.85;color:#5c4d55;
    margin-top:16px;padding:12px 16px;border-radius:10px;
    background:#faf4f7;border:1px solid #f2e6eb;border-left:3px solid var(--pk);
  }
  #v-traffic .hint span{font-size:13px}
  /* 桌面端 Toast 悬浮胶囊 */
  #toast{
    left:50%!important;right:auto!important;transform:translateX(-50%)!important;
    top:22px!important;min-width:320px;max-width:520px;
    padding:12px 22px!important;border-radius:14px!important;
    background:rgba(255,255,255,.96)!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;
    box-shadow:0 14px 38px rgba(60,35,48,.12), 0 2px 8px rgba(60,35,48,.04)!important;
    border:1px solid #ebdfe5!important;border-left:4px solid var(--gn)!important;
  }
  #toast.toast-in{animation:toastInD .28s var(--ease-spring) both!important}
  #toast.toast-out{animation:toastOutD .22s var(--ease-apple) both!important}
  @keyframes toastInD{from{opacity:0;transform:translate(-50%,-10px) scale(.98)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
  @keyframes toastOutD{from{opacity:1;transform:translate(-50%,0) scale(1)}to{opacity:0;transform:translate(-50%,-8px) scale(.985)}}
}
@media (max-width:1200px) and (min-width:860px){
  aside{width:218px}
  main{padding-left:24px;padding-right:24px}
  .topbar-d{padding-left:18px;padding-right:18px}
  .topbar-d .srv b{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
}
@media (max-width:859px){
  .top-actions{gap:0}
  .top-new{display:none}
  main{padding-top:18px}
  .topbar{padding-left:18px;padding-right:18px}
  .card{border-radius:16px}
  .kpi{border-radius:16px}
  .tabbar{box-shadow:0 -6px 24px rgba(75,51,63,.06)}
  .tabbar a.on{background:#fff4f7}
}



/* ============ 暗黑夜间模式 2.0（极客黑曜石） ============ */
html.dark {
  background-color: #09080c !important;
}
html.dark, html.dark body, body.dark {
  --bg: #09080c !important;
  --card: rgba(18, 14, 23, 0.78) !important;
  --bd: rgba(255, 255, 255, 0.08) !important;
  --bd2: rgba(255, 255, 255, 0.05) !important;
  --tx: #f5f2f5 !important;
  --t2: #9e909a !important;
  --t3: #6b5f67 !important;
  --pk: #ff5c8a !important;
  --pk-d: #ff759d !important;
  --pk-bg: rgba(255, 92, 138, 0.14) !important;
  --pk-light: rgba(255, 92, 138, 0.07) !important;
  --gn: #22c55e !important;
  --gn-bg: rgba(34, 197, 94, 0.14) !important;
  --gn-bd: rgba(34, 197, 94, 0.35) !important;
  --rd: #f43f5e !important;
  --rd-bg: rgba(244, 63, 94, 0.14) !important;
  --rd-bd: rgba(244, 63, 94, 0.35) !important;
  --sh: 0 4px 20px rgba(0, 0, 0, 0.45) !important;
  --sh-card: 0 10px 32px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.06) !important;
  --sh-lg: 0 24px 64px rgba(0, 0, 0, 0.75) !important;
  color: #f5f2f5 !important;
  background-color: transparent !important;
}

body.dark::before {
  background-color: #0b090f !important;
  background-image:
    /* 1. 极其隐约纯净的极客科技坐标方格（完全静态，无任何闪烁，赋予空间秩序感） */
    linear-gradient(rgba(255, 255, 255, 0.024) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.024) 1px, transparent 1px),
    /* 2. 左上角深空极光：柔和樱粉微光晕 */
    radial-gradient(1100px 620px at 12% -8%, rgba(255, 92, 138, 0.16), transparent 72%),
    /* 3. 右上角深空极光：科技紫罗兰漫反射 */
    radial-gradient(1200px 680px at 94% 6%, rgba(139, 92, 246, 0.14), transparent 68%),
    /* 4. 中间偏右：微弱天青冷光（冷暖对比打破单调沉闷） */
    radial-gradient(850px 480px at 78% 52%, rgba(6, 182, 212, 0.045), transparent 60%),
    /* 5. 底部纵深：黑曜石自然渐变沉降 */
    linear-gradient(180deg, #120d1a 0%, #09070c 55%, #050407 100%) !important;
  background-size: 34px 34px, 34px 34px, 100% 100%, 100% 100%, 100% 100%, 100% 100% !important;
}

/* 顶栏与侧边栏：透光黑曜石磨砂玻璃（第一层级） */
body.dark .topbar-d, body.dark aside, body.dark .topbar, body.dark .tabbar {
  background: rgba(15, 12, 21, 0.76) !important;
  backdrop-filter: blur(26px) !important;
  -webkit-backdrop-filter: blur(26px) !important;
  border-color: rgba(255, 255, 255, 0.07) !important;
  box-shadow: 8px 0 36px rgba(0, 0, 0, 0.45) !important;
}

body.dark aside .logo {
  border-bottom-color: rgba(255, 255, 255, 0.07) !important;
  color: #fff !important;
}

body.dark .side-status {
  background: linear-gradient(160deg, rgba(34, 27, 43, 0.88) 0%, rgba(20, 16, 26, 0.92) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.1) !important;
  color: #bfaeb8 !important;
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.12) !important;
}

body.dark .network-row span {
  background: rgba(12, 9, 16, 0.85) !important;
  border-color: rgba(255, 255, 255, 0.08) !important;
  color: #d1c0cb !important;
}

body.dark aside nav a {
  color: #a496a0 !important;
}
body.dark aside nav a:hover {
  background: rgba(255, 255, 255, 0.06) !important;
  color: #fff !important;
}
body.dark aside nav a.on {
  background: rgba(255, 92, 138, 0.16) !important;
  color: #ff759d !important;
  border-color: rgba(255, 92, 138, 0.3) !important;
  box-shadow: 0 2px 14px rgba(255, 92, 138, 0.18) !important;
}

/* 卡片系统：黑曜石晶体微渐变 + 空间立体悬浮（第二层级） */
body.dark .card {
  background: linear-gradient(175deg, rgba(26, 21, 34, 0.86) 0%, rgba(14, 11, 19, 0.9) 100%) !important;
  backdrop-filter: blur(28px) !important;
  -webkit-backdrop-filter: blur(28px) !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  box-shadow:
    0 16px 42px -10px rgba(0, 0, 0, 0.65),
    0 2px 6px rgba(0, 0, 0, 0.4),
    inset 0 1px 0 rgba(255, 255, 255, 0.12),
    inset 0 0 0 1px rgba(255, 255, 255, 0.03) !important;
  color: #f5f2f5 !important;
}

body.dark .card::after {
  background: linear-gradient(90deg, #ff5c8a, #ff759d 60%, transparent 100%) !important;
  box-shadow: 0 0 14px rgba(255, 92, 138, 0.65) !important;
}

/* KPI 小卡：独立浮岛立体感（第三层级） */
body.dark .kpi {
  background: linear-gradient(160deg, rgba(32, 26, 41, 0.9) 0%, rgba(18, 14, 24, 0.94) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.09) !important;
  box-shadow:
    0 8px 24px -4px rgba(0, 0, 0, 0.5),
    inset 0 1px 0 rgba(255, 255, 255, 0.13) !important;
  color: #f5f2f5 !important;
}

body.dark .kpi::before {
  background: rgba(255, 92, 138, 0.1) !important;
}

body.dark .card h2 {
  color: #ffffff !important;
}

/* 按钮系统 */
body.dark .btn {
  background: rgba(255, 255, 255, 0.05) !important;
  border: 1px solid rgba(255, 255, 255, 0.1) !important;
  color: #ede5eb !important;
  backdrop-filter: blur(10px) !important;
}
body.dark .btn:hover {
  background: rgba(255, 255, 255, 0.1) !important;
  border-color: rgba(255, 92, 138, 0.4) !important;
  box-shadow: 0 0 14px rgba(255, 92, 138, 0.2) !important;
}
body.dark .btn-pk {
  background: linear-gradient(135deg, #ff5c8a, #e03368) !important;
  border-color: transparent !important;
  color: #fff !important;
  box-shadow: 0 4px 18px rgba(255, 92, 138, 0.45) !important;
}
body.dark .btn-pk:hover {
  box-shadow: 0 6px 22px rgba(255, 92, 138, 0.6) !important;
}
body.dark .btn-go {
  background: rgba(34, 197, 94, 0.16) !important;
  border-color: rgba(34, 197, 94, 0.35) !important;
  color: #4ade80 !important;
}
body.dark .btn-stop {
  background: rgba(244, 63, 94, 0.16) !important;
  border-color: rgba(244, 63, 94, 0.35) !important;
  color: #fb7185 !important;
}
body.dark .btn-sec {
  background: rgba(255, 255, 255, 0.05) !important;
  border: 1px solid rgba(255, 255, 255, 0.12) !important;
  color: #ddd4db !important;
}

/* 刷新条 */
body.dark .pollbar {
  background: linear-gradient(170deg, rgba(26, 21, 33, 0.85) 0%, rgba(16, 13, 21, 0.9) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  box-shadow: 0 4px 18px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.1) !important;
}
body.dark .ps {
  background: rgba(255, 255, 255, 0.06) !important;
  border-color: rgba(255, 255, 255, 0.1) !important;
  color: #bfaeb8 !important;
}
body.dark .ps.on {
  background: linear-gradient(120deg, #ff5c8a, #ff759d) !important;
  border-color: transparent !important;
  color: #fff !important;
  box-shadow: 0 2px 10px rgba(255, 92, 138, 0.35) !important;
}

/* 表格系统 */
body.dark .tblwrap {
  background: rgba(18, 14, 23, 0.78) !important;
  border-color: rgba(255, 255, 255, 0.07) !important;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4) !important;
}
body.dark th, body.dark .tbl th {
  background: rgba(13, 10, 17, 0.9) !important;
  color: #bfaeb9 !important;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
}
body.dark td, body.dark .tbl td {
  border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
  color: #ede6eb !important;
}
body.dark tr:hover td, body.dark tbody tr:hover td {
  background: rgba(255, 92, 138, 0.04) !important;
}
body.dark .mono-l {
  color: #f5f2f5 !important;
}

/* 概览页流量卡片 (.tf) 与底部版权 (.side-foot) */
body.dark .tf {
  background: linear-gradient(170deg, rgba(24, 18, 31, 0.92) 0%, rgba(13, 10, 17, 0.96) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.09), 0 4px 18px rgba(0, 0, 0, 0.35) !important;
}
body.dark .tf.tf-in {
  border-left: 3.5px solid #22c55e !important;
}
body.dark .tf.tf-out {
  border-left: 3.5px solid #ff5c8a !important;
}
body.dark aside .side-foot {
  background: linear-gradient(160deg, rgba(24, 19, 31, 0.85) 0%, rgba(16, 12, 22, 0.9) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.07) !important;
  color: #8a7a85 !important;
}
body.dark .empty {
  background: rgba(14, 11, 18, 0.6) !important;
  color: #9c8e98 !important;
}
body.dark .empty::before {
  background: rgba(255, 92, 138, 0.12) !important;
  border-color: rgba(255, 92, 138, 0.25) !important;
}

/* 模态弹窗 (.modal) 深度暗黑毛玻璃 */
body.dark .modal {
  background: rgba(0, 0, 0, 0.65) !important;
  backdrop-filter: blur(8px) !important;
}
body.dark .modal .box {
  background: rgba(18, 14, 24, 0.92) !important;
  backdrop-filter: blur(28px) !important;
  -webkit-backdrop-filter: blur(28px) !important;
  border: 1px solid rgba(255, 255, 255, 0.1) !important;
  box-shadow: 0 24px 64px rgba(0, 0, 0, 0.8), inset 0 1px 0 rgba(255, 255, 255, 0.08) !important;
  color: #f5f2f5 !important;
}
body.dark .f-item label {
  color: #a4949f !important;
}
body.dark .f-item input, body.dark .f-item select {
  background: rgba(12, 9, 16, 0.9) !important;
  border-color: rgba(255, 255, 255, 0.1) !important;
  color: #f5f2f5 !important;
}
body.dark .f-item input:focus, body.dark .f-item select:focus {
  border-color: #ff5c8a !important;
  box-shadow: 0 0 0 3px rgba(255, 92, 138, 0.25) !important;
}
body.dark .pchip {
  background: rgba(255, 255, 255, 0.05) !important;
  border-color: rgba(255, 255, 255, 0.09) !important;
  color: #a496a0 !important;
}
body.dark .pchip.sel {
  background: rgba(255, 92, 138, 0.18) !important;
  border-color: #ff5c8a !important;
  color: #ff759d !important;
}

/* 状态微胶囊（夜间微发光） */
body.dark .st-badge.st-on {
  background: rgba(34, 197, 94, 0.14) !important;
  color: #4ade80 !important;
  border-color: rgba(34, 197, 94, 0.35) !important;
  box-shadow: 0 0 10px rgba(34, 197, 94, 0.22) !important;
}
body.dark .st-badge.st-off {
  background: rgba(255, 255, 255, 0.05) !important;
  color: #9e919a !important;
  border-color: rgba(255, 255, 255, 0.08) !important;
}
body.dark .st-badge.st-blocked {
  background: rgba(244, 63, 94, 0.14) !important;
  color: #fb7185 !important;
  border-color: rgba(244, 63, 94, 0.38) !important;
  box-shadow: 0 0 12px rgba(244, 63, 94, 0.25) !important;
}

/* 手机端隧道卡片 */
body.dark .tun-card {
  background: rgba(18, 14, 23, 0.78) !important;
  border-color: rgba(255, 255, 255, 0.08) !important;
}
body.dark .tun-card .ops {
  border-top-color: rgba(255, 255, 255, 0.07) !important;
}

/* 提示与代码盒 */
body.dark .hint, body.dark #tun-hint, body.dark #v-traffic .hint {
  background: rgba(20, 16, 26, 0.8) !important;
  border-color: rgba(255, 255, 255, 0.07) !important;
  color: #a89aa3 !important;
}
body.dark pre.cfg {
  background: linear-gradient(180deg, rgba(11, 9, 15, 0.95) 0%, rgba(7, 5, 10, 0.98) 100%) !important;
  border: 1px solid rgba(255, 255, 255, 0.08) !important;
  box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.6) !important;
  color: #e5b9d0 !important;
}
body.dark .loc-code, body.dark .addr-code {
  background: rgba(12, 9, 17, 0.85) !important;
  border-color: rgba(255, 255, 255, 0.08) !important;
  color: #e5b9d0 !important;
}
body.dark .badge-sub {
  background: rgba(255, 255, 255, 0.06) !important;
  border-color: rgba(255, 255, 255, 0.09) !important;
  color: #a496a0 !important;
}
body.dark .crumb {
  color: #f5f2f5 !important;
}
body.dark .loginbox .card {
  background: rgba(18, 14, 23, 0.85) !important;
  border-color: rgba(255, 255, 255, 0.08) !important;
}
body.dark .loginbox input {
  background: rgba(12, 9, 16, 0.9) !important;
  border-color: rgba(255, 255, 255, 0.1) !important;
  color: #f5f2f5 !important;
}

/* 顶栏一键切换胶囊按钮 */
.theme-toggle-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 6px 14px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  background: #fff;
  border: 1px solid #ebdbe2;
  color: #826e79;
  transition: all .24s cubic-bezier(0.2, 0.9, 0.3, 1);
}
.theme-toggle-btn:hover {
  background: #fff5f8;
  border-color: #ff5c8a;
  color: #ff5c8a;
}
.theme-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 10px;
}
.theme-tag.off {
  background: #f1e9ed;
  color: #82757d;
}
.theme-tag.on {
  background: #ff5c8a;
  color: #fff;
  box-shadow: 0 0 8px rgba(255, 92, 138, 0.5);
}
body.dark .theme-toggle-btn {
  background: rgba(255, 92, 138, 0.14) !important;
  border: 1px solid rgba(255, 92, 138, 0.4) !important;
  color: #ff85a8 !important;
  box-shadow: 0 0 16px rgba(255, 92, 138, 0.28) !important;
}
body.dark .theme-toggle-btn:hover {
  background: rgba(255, 92, 138, 0.22) !important;
  box-shadow: 0 0 20px rgba(255, 92, 138, 0.45) !important;
  transform: scale(1.03);
}
.mobile-theme-btn {
  padding: 5px 9px;
  font-size: 14px;
}
body.dark .side-exit-btn {
  color: #a496a0 !important;
}
body.dark .side-exit-btn:hover {
  color: #fb7185 !important;
  background: rgba(244, 63, 94, 0.14) !important;
  border-color: rgba(244, 63, 94, 0.35) !important;
  box-shadow: 0 0 12px rgba(244, 63, 94, 0.18) !important;
}
body.dark .top-exit-m {
  background: rgba(255, 255, 255, 0.06) !important;
  border-color: rgba(255, 255, 255, 0.1) !important;
  color: #a496a0 !important;
}
body.dark .top-exit-m:hover {
  color: #fb7185 !important;
  background: rgba(244, 63, 94, 0.16) !important;
}

</style>
<script>
(function(){
  var t = localStorage.getItem('frp_theme');
  if (t === 'dark' || (!t && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
  }
})();
</script>
</head>
<body>
<script>if(document.documentElement.classList.contains('dark'))document.body.classList.add('dark');</script>
<div class="bg-art" aria-hidden="true">
  <svg viewBox="0 0 1440 900" fill="none" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">

    <!-- 穿透网络雷达扩散圈（右上角，极淡静态科技水印，不晃眼） -->
    <g transform="translate(1320, 110)" opacity="0.45">
      <circle r="180" stroke="#ff5c8a" stroke-opacity="0.06" stroke-dasharray="4 8" fill="none" stroke-width="1.2"/>
      <circle r="290" stroke="#7c3aed" stroke-opacity="0.04" stroke-dasharray="6 12" fill="none" stroke-width="1"/>
      <circle r="410" stroke="#ff5c8a" stroke-opacity="0.025" fill="none" stroke-width="1"/>
    </g>
    <!-- 穿透网络雷达扩散圈（左下角，极淡静态科技水印） -->
    <g transform="translate(70, 830)" opacity="0.4">
      <circle r="160" stroke="#ff5c8a" stroke-opacity="0.05" stroke-dasharray="4 6" fill="none" stroke-width="1"/>
      <circle r="270" stroke="#7c3aed" stroke-opacity="0.035" stroke-dasharray="5 10" fill="none" stroke-width="1"/>
    </g>
  </svg>
</div>
{% if not logged %}
<div class="loginbox">
  <div class="card">
    <div class="lg">
      <span class="lg-ic" style="width:52px;height:52px;border-radius:15px">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8h13l-3.2-3.2M20 16H7l3.2 3.2"/></svg>
      </span>
    </div>
    <h2>frp <span class="grad">面板</span></h2>
    <div class="st">虚拟局域网内可达 · 面板端口 8090</div>
    <form onsubmit="return doLogin(event)">
      <input id="pwd" type="password" placeholder="输入密码" autocomplete="current-password">
      <button class="btn btn-pk" type="submit">解 锁</button>
    </form>
    <div class="msg" id="lmsg"></div>
    <div class="hint" style="margin-top:12px">连续 5 次错误锁定 5 分钟</div>
  </div>
</div>
{% else %}
<div class="layout">
<aside id="aside">
  <div class="logo">
    <span class="lg-ic">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8h13l-3.2-3.2M20 16H7l3.2 3.2"/></svg>
    </span>
    <span><span class="grad">frp 面板</span><small class="brand-sub">Sakura tunnel studio</small></span>
  </div>
  <div class="side-status"><div><span class="dot"></span><b>节点在线</b></div><small>frps · 7000</small><div class="network-row"><span>mc-p2p-lan</span></div></div>
  <nav id="navd">
    <a href="#v-overview" class="on" data-v="v-overview" onclick="sw(this);return false">概览</a>
    <a href="#v-tunnels" data-v="v-tunnels" onclick="sw(this);return false">隧道管理</a>
    <a href="#v-traffic" data-v="v-traffic" onclick="sw(this);return false">流量表</a>
    <a href="#v-security" data-v="v-security" onclick="sw(this);return false">安全与审计</a>
  </nav>
  <div class="side-bottom">
    <a class="side-exit-btn" href="/logout" onclick="return confirm('确认退出当前登录？')" title="安全退出管理面板">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
      <span>退出登录</span>
    </a>
    <div class="side-foot">frps<br>v4.0 · Sakura Design</div>
  </div>
</aside>

<div style="flex:1;min-width:0">
  <header class="topbar-d">
    <h1 id="vtitle-d">概览</h1>
    <div class="top-actions">
      <button class="theme-toggle-btn" id="theme-btn-d" onclick="toggleTheme()" type="button" title="切换日间/夜间模式"><span id="theme-icon-d">🌙</span><span>夜间模式</span><span class="theme-tag off" id="theme-tag-d">OFF</span></button>
      <div class="srv"><span class="dot"></span><b>frps:7000</b><span id="clock-d" class="dim"></span></div>
      <button class="btn btn-pk top-new" onclick="openEdit()">＋ 新建隧道</button>
    </div>
  </header>
  <header class="topbar">
    <div class="t">
      <span class="lg-ic">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8h13l-3.2-3.2M20 16H7l3.2 3.2"/></svg>
      </span>
      <span><span class="grad">frp 面板</span><small id="vtitle-m">概览</small></span>
    </div>
    <div style="display:flex;align-items:center;gap:8px">
      <button class="theme-toggle-btn mobile-theme-btn" id="theme-btn-m" onclick="toggleTheme()" type="button" title="切换模式">🌙</button>
      <a class="top-exit-m" href="/logout" onclick="return confirm('确认退出当前登录？')" title="安全退出登录">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
      </a>
      <div class="clock" id="clock-m"></div>
    </div>
  </header>

  <main>
    <div class="view on" id="v-overview">
      <div class="pollbar">
        <span class="lab">刷新频率</span>
        <button class="ps on" onclick="setPoll(3,this)">实时 3s</button>
        <button class="ps" onclick="setPoll(6,this)">标准 6s</button>
        <button class="ps" onclick="setPoll(15,this)">省电 15s</button>
        <button class="ps" onclick="setPoll(0,this)">暂停</button>
        <span class="pst" id="pollst">自动刷新中</span>
      </div>
      <div class="kpis">
        <div class="kpi"><div class="lb">frps 服务</div><div class="vl" id="k-svc">…</div><div class="sub">systemd 托管</div></div>
        <div class="kpi"><div class="lb">隧道 在线/总</div><div class="vl" id="k-tun">…</div><div class="sub">端口监听为准</div></div>
        <div class="kpi"><div class="lb">frpc 客户端</div><div class="vl" id="k-cli">…</div><div class="sub">est. 7000</div></div>
        <div class="kpi"><div class="lb">24h 爆破</div><div class="vl" id="k-atk">…</div><div class="sub">token 拒绝</div></div>
        <div class="kpi"><div class="lb">面板端口</div><div class="vl" id="k-p2">…</div><div class="sub">frps 原生 7500</div></div>
      </div>
      <div class="card">
        <h2>流量监控 <span class="dim" style="font-weight:400;font-size:10px">frps 运行以来累计 · 实时速率</span></h2>
        <div class="tflow">
          <div class="tf tf-in"><div class="tfl">今日入站 · 下载到设备</div><div class="tfv" id="tf-in">—</div><div class="tfs" id="tf-in-r">—</div></div>
          <div class="tf tf-out"><div class="tfl">今日出站 · 从设备上传</div><div class="tfv" id="tf-out">—</div><div class="tfs" id="tf-out-r">—</div></div>
        </div>
      </div>
      <div class="card">
        <h2>frps 服务控制 <span id="ctrlmsg" class="dim" style="font-weight:400;font-size:11px"></span></h2>
        <div class="ctrl">
          <button class="btn btn-go" onclick="ctrl('start')">启动</button>
          <button class="btn btn-stop" onclick="ctrl('stop')">停止</button>
          <button class="btn btn-re" onclick="ctrl('restart')">重启</button>
        </div>
        <div class="hint">
          frps 端口 <span class="mono">7000</span>（面板与 frps 都只在虚拟局域网内可达）<br>
          frpc 跑在目标设备：建隧道 → 拿配置 → <span class="mono">frpc -c frpc.toml</span>
        </div>
      </div>
      <div class="card">
        <h2>frps 配置 <span class="dim" style="font-weight:400;font-size:10px">脱敏</span></h2>
        <div class="scrollx"><table id="cfg"></table></div>
      </div>
    </div>

    <div class="view" id="v-tunnels">
      <div class="kpis" style="grid-template-columns:repeat(2,1fr);margin-bottom:16px">
        <div class="kpi">
          <div class="lb" style="display:flex;justify-content:space-between;align-items:center">
            <span>在线隧道</span>
            <span class="st-badge st-on" style="font-size:10px;padding:2px 7px">● 活跃监听</span>
          </div>
          <div class="vl" id="k-tun2" style="color:var(--gn);font-size:26px;letter-spacing:-.5px">0</div>
          <div class="sub">远程公网端口正常代理中</div>
        </div>
        <div class="kpi">
          <div class="lb" style="display:flex;justify-content:space-between;align-items:center">
            <span>全部隧道</span>
            <span class="pill p-dim" style="font-size:10px;padding:2px 7px">含已封锁</span>
          </div>
          <div class="vl" id="k-total" style="font-size:26px;letter-spacing:-.5px">0</div>
          <div class="sub">当前面板登记的全部隧道</div>
        </div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">
        <div style="font-size:13px;font-weight:700;color:var(--tx);display:flex;align-items:center;gap:8px">
          <span>隧道映射矩阵</span>
          <span class="dim" style="font-weight:400;font-size:11px">支持 TCP / UDP 穿透与物理封锁</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn" style="min-height:34px;padding:6px 13px;font-size:12px;border-radius:9px" onclick="importFromFrps()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:2px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            从 frps 导入在线隧道
          </button>
          <button class="btn btn-pk" style="min-height:34px;padding:6px 14px;font-size:12px;border-radius:9px;box-shadow:0 3px 10px rgba(255,92,138,.3)" onclick="openEdit()">＋ 新建隧道</button>
        </div>
      </div>
      <div id="tlist"></div>
      <div id="tun-table"></div>
      <div class="hint" id="tun-hint">
        <div style="font-weight:700;color:var(--tx);margin-bottom:6px;display:flex;align-items:center;gap:7px">
          <span style="display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:6px;background:var(--pk-bg);color:var(--pk)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </span>
          <span>系统内核防火墙安全防御与端口物理封锁机制</span>
          <span class="tag" style="background:#f4edf1;color:#82737c;font-size:9.5px;padding:1px 6px">v5.27 基线</span>
        </div>
        <div style="line-height:1.9">
          • <b>停用隧道</b>：系统将对远程公网端口在内核追加 <span class="mono" style="color:var(--rd);font-weight:700;background:#fff1f3;padding:1px 5px;border-radius:4px;border:1px solid #ffd4dc">iptables REJECT（tcp-reset）</span> 规则，公网立即物理不可达，在线连接瞬间断开；<br>
          • <b>启用隧道</b>：精确删除该封锁规则，恢复公网正常路由。规则不落盘，开机自愈对账补回；系统保留端口禁止封锁。
        </div>
      </div>
    </div>

    <div class="view" id="v-traffic">
      <div class="kpis" style="grid-template-columns:repeat(2,1fr);margin-bottom:12px">
        <div class="kpi"><div class="lb">本月入站</div><div class="vl" id="k-min" style="color:var(--gn)">—</div><div class="sub">每日采样累加</div></div>
        <div class="kpi"><div class="lb">本月出站</div><div class="vl" id="k-mout" style="color:var(--pk)">—</div><div class="sub">每日采样累加</div></div>
      </div>
      <div class="card">
        <h2>流量趋势 <span class="badge-sub">近 30 天</span></h2>
        <div class="legend"><i class="lg-in"></i>入站<i class="lg-out" style="margin-left:8px"></i>出站<span class="lg-note">鼠标悬停看数值</span></div>
        <div class="chartwrap" id="chart"></div>
      </div>
      <div class="traffic-grid">
        <div class="card">
          <h2>月度汇总 <span class="badge-sub">近 12 个月</span></h2>
          <div class="tbl-scroll"><table class="tbl" id="mtable"></table></div>
        </div>
        <div class="card">
          <h2>每日明细 <span class="badge-sub">近 30 天</span></h2>
          <div class="tbl-scroll"><table class="tbl" id="dtable"></table></div>
          <div class="hint">后台每 <span id="sample-secs">5</span> 分钟采样一次 · 今日流量由 frps 按天累计 · 历史自统计之日起积累 · <span title="由 frps 近 7 天每日数据估算回填">≈ 为估算值</span></div>
        </div>
      </div>
      <div class="card">
        <h2>隧道流量明细 <span class="badge-sub">frps 今日口径 · 客户端掉线也保留</span></h2>
        <div id="ptable"></div>
        <div class="hint">由 frps 仪表盘实时读取 · 今日流量本地零点起算 · 连续离线 7 天的隧道统计会被 frps 清除</div>
      </div>
    </div>

    <div class="view" id="v-security">
      <div class="card">
        <h2>frps 登录尝试 <span class="dim" style="font-weight:400;font-size:10px">成功 / 爆破 双色标注</span></h2>
        <div id="events"></div>
      </div>
      <div class="card">
        <h2>在线 frpc 客户端</h2>
        <div id="clients"></div>
      </div>
      <div class="card">
        <h2>操作审计 <span class="dim" style="font-weight:400;font-size:10px">最近 15 条</span></h2>
        <div class="scrollx"><table id="audit"></table></div>
        <div class="hint">同步落盘 <span class="mono">INSTALL_DIR/audit.log</span></div>
      </div>
    </div>
  </main>
</div>
</div>

<nav class="tabbar">
  <a href="#v-overview" class="on" data-v="v-overview" onclick="sw(this);return false">概览</a>
  <a href="#v-tunnels" data-v="v-tunnels" onclick="sw(this);return false">隧道</a>
  <a class="add" aria-label="新建隧道" role="button" tabindex="0" onclick="openEdit()" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();openEdit();return false}"><span>＋</span></a>
  <a href="#v-traffic" data-v="v-traffic" onclick="sw(this);return false">流量</a>
  <a href="#v-security" data-v="v-security" onclick="sw(this);return false">安全</a>
</nav>
{% endif %}

<div class="modal" id="medit" role="dialog" aria-modal="true" aria-labelledby="etitle" onclick="if(event.target===this)closeEdit()">
  <div class="box">
    <div class="grab"></div>
    <h3 id="etitle">新建隧道</h3>
    <div class="f-err" id="eerr" role="alert" aria-live="assertive"></div>
    <div class="f-row">
      <div class="f-item"><label for="f-name">隧道名称 *</label><input id="f-name" placeholder="如 nas-ssh" maxlength="32"></div>
      <div class="f-item"><label for="f-type">类型 *</label><select id="f-type"><option>tcp</option><option>udp</option><option>http</option></select></div>
    </div>
    <div class="f-row">
      <div class="f-item"><label for="f-lip">本地 IP *</label><input id="f-lip" placeholder="同机填 127.0.0.1 · 跨机填设备IP" inputmode="decimal"></div>
      <div class="f-item"><label for="f-lport">本地端口 *</label><input id="f-lport" type="number" placeholder="22" inputmode="numeric"><div class="pchips" id="lport-chips" style="margin-top:7px"></div></div>
    </div>
    <div class="pchips" id="target-chips"></div>
    <div class="f-row">
      <div class="f-item"><label for="f-rport">远程端口 * <span id="port-tip" class="ptip"></span></label>
        <input id="f-rport" type="number" placeholder="公网端口，如 25565" inputmode="numeric" oninput="onPortInput()">
        <div class="pchips" id="port-chips" style="margin-top:7px"></div>
      </div>
      <div class="f-item"><label for="f-note">备注</label><input id="f-note" placeholder="选填，如 家里 NAS" maxlength="60"></div>
    </div>
    <div class="cfgbar">
      <button class="btn" onclick="closeEdit()">取消</button>
      <button class="btn btn-pk" onclick="saveTunnel()">保 存</button>
    </div>
  </div>
</div>

<div class="modal" id="mcfg" role="dialog" aria-modal="true" aria-labelledby="cfgname" onclick="if(event.target===this)closeModal('mcfg')">
  <div class="box wide">
    <div class="grab"></div>
    <h3>frpc 配置 <span class="dim" id="cfgname" style="font-size:12px;font-weight:400"></span></h3>
    <div class="hint" style="margin:0 0 4px">存为 <span class="mono">frpc.toml</span>，目标设备执行 <span class="mono">frpc -c frpc.toml</span>。token 已内置（打码显示），复制/下载拿完整文件。</div>
    <pre class="cfg" id="cfgtext"></pre>
    <div class="cfgbar">
      <button class="btn" onclick="copyCfg()">复制</button>
      <button class="btn btn-pk" onclick="dlCfg()">下载</button>
      <button class="btn" onclick="closeModal('mcfg')">关闭</button>
    </div>
  </div>
</div>

<div id="toast" role="status" aria-live="polite" aria-atomic="true"></div>

<script>
var POLL=6000, editId=null, cfgId=null, cfgFull='', timer=null, PT={}, TUN=[], portTimer=null, portOK=true;
function isNarrow(){return window.matchMedia('(max-width:859px)').matches}
function $(i){return document.getElementById(i)}
/* ---------- 日间/夜间模式 2.0 切换管理 ---------- */
function initTheme(){
  var saved=localStorage.getItem('frp_theme');
  var isDark=saved==='dark'||(!saved&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);
  if(isDark){
    document.body.classList.add('dark');
    document.documentElement.classList.add('dark');
  }else{
    document.body.classList.remove('dark');
    document.documentElement.classList.remove('dark');
  }
  updateThemeUI(isDark);
}
function toggleTheme(){
  var isDark=document.body.classList.toggle('dark');
  document.documentElement.classList.toggle('dark',isDark);
  localStorage.setItem('frp_theme',isDark?'dark':'light');
  updateThemeUI(isDark);
  chartSig='';
  if(window.__lastTrafficDays)renderChart(window.__lastTrafficDays);
}
function updateThemeUI(isDark){
  var btnD=$('theme-btn-d'), btnM=$('theme-btn-m');
  var tagD=$('theme-tag-d'), iconD=$('theme-icon-d');
  if(btnD){
    if(iconD)iconD.textContent=isDark?'🌙':'☀️';
    if(tagD){
      tagD.className='theme-tag '+(isDark?'on':'off');
      tagD.textContent=isDark?'ON':'OFF';
    }
    btnD.title=isDark?'当前为夜间模式，点击切换到日间':'当前为日间模式，点击切换到夜间';
  }
  if(btnM){
    btnM.innerHTML=isDark?'🌙':'☀️';
    btnM.title=isDark?'当前为夜间模式，点击切换到日间':'当前为日间模式，点击切换到夜间';
  }
}
initTheme();
/* ---------- 端口实时检测 + 预选/常用 chips ---------- */
function setTip(cls,txt){var e=$('port-tip');e.className='ptip '+cls;e.textContent=txt;}
function onPortInput(){
  clearTimeout(portTimer);
  var v=$('f-rport').value.trim();
  markSelChip();
  if(!v){setTip('','');portOK=true;return;}
  if(!/^\d{1,5}$/.test(v)){setTip('bad','端口只能是数字');portOK=false;return;}
  portTimer=setTimeout(function(){launchCheck(v);},400);
}
function launchCheck(v){
  if(!v||!/^\d{1,5}$/.test(v))return;
  setTip('wait','检测中…');
  fetch('/api/port_check?port='+encodeURIComponent(v)+'&editing_id='+(editId||''))
  .then(function(r){return r.json()})
  .then(function(j){
    if(j.ok){setTip('ok','端口可用');portOK=true;}
    else{setTip('bad','被占用：'+(j.reason||'不可用'));portOK=false;}
  })
  .catch(function(){setTip('wait','');portOK=true;});
}
function markSelChip(){
  var v=$('f-rport').value.trim();
  document.querySelectorAll('#port-chips .pchip').forEach(function(c){
    c.classList.toggle('sel', c.dataset.p===v);});
}
function fillPort(p){
  $('f-rport').value=p;
  /* v5.7：本地端口为空时同步同端口（同端口穿透是默认场景）*/
  if(!$('f-lport').value)$('f-lport').value=p;
  markSelChip();
  launchCheck(p);
}
function fillTarget(ip,port){
  $('f-lip').value=ip; $('f-lport').value=port;
  document.querySelectorAll('#target-chips .pchip').forEach(function(c){
    c.classList.toggle('sel', c.dataset.ip===ip&&c.dataset.port===String(port));});
  if(typeof markSelLChip==='function')markSelLChip();
}
/* v5.8：本地端口独立参考列表（与远程预选同数据，互不联动覆盖）*/
function markSelLChip(){
  var v=$('f-lport').value.trim();
  document.querySelectorAll('#lport-chips .pchip').forEach(function(c){
    c.classList.toggle('sel', c.dataset.p===v);});
}
function fillLPort(p){
  $('f-lport').value=p;
  markSelLChip();
}
function renderModalChips(){
  fetch('/api/targets').then(function(r){return r.json()}).then(function(d){
    var tc=$('target-chips');
    if(d.targets&&d.targets.length){
      tc.innerHTML='<span class="dim" style="font-size:10px;flex:0 0 auto;line-height:28px">常用</span>'
        +d.targets.map(function(t){
          return '<span class="pchip" data-ip="'+esc(t.local_ip)+'" data-port="'+esc(String(t.local_port))+'" onclick="fillTarget(\''+esc(t.local_ip)+'\','+t.local_port+')"><span class="pk2">'+esc(t.label)+'</span>一键填入</span>';}).join('');
      tc.style.display='flex';
    }else{tc.style.display='none';}
    var pc=$('port-chips');
    pc.innerHTML=(d.presets||[]).map(function(p){
      return '<span class="pchip" data-p="'+p.port+'" onclick="fillPort('+p.port+')"><span class="pk2">'+p.port+'</span>'+esc(p.service)+'</span>';}).join('');
    markSelChip();
    var lc=$('lport-chips');
    if(lc)lc.innerHTML=(d.presets||[]).map(function(p){
      return '<span class="pchip" data-p="'+p.port+'" onclick="fillLPort('+p.port+')"><span class="pk2">'+p.port+'</span>'+esc(p.service)+'</span>';}).join('');
    markSelLChip();
    /* 新建时预填本地默认值（v5.6→v5.7）*/
    if(!editId && !$('f-lip').value){
      if(d.targets && d.targets.length){
        fillTarget(d.targets[0].local_ip, d.targets[0].local_port);
      }else{
        $('f-lip').value='127.0.0.1';
      }
    }
  });
}
function fmt(n){n=+n||0;if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';
  if(n<1073741824)return (n/1048576).toFixed(1)+' MB';return (n/1073741824).toFixed(2)+' GB';}
function setPoll(s,el){
  document.querySelectorAll('.ps').forEach(function(b){b.classList.remove('on')});
  el.classList.add('on');
  if(timer){clearInterval(timer);timer=null;}
  POLL=s*1000;
  $('pollst').textContent=s>0?('每 '+s+' 秒刷新'):'已暂停';
  if(s>0){timer=setInterval(refresh,POLL);toast('已切换为每 '+s+' 秒刷新');}
  else{toast('自动刷新已暂停');}}
var toastTimer=null,modalOpener=null;
function toast(t,ok){var e=$('toast');
  clearTimeout(toastTimer);e.classList.remove('toast-out');e.textContent=t;
  e.style.borderLeftColor=ok===false?'#e11d48':'#15a34a';e.style.display='block';
  void e.offsetWidth;e.classList.add('toast-in');
  toastTimer=setTimeout(function(){e.classList.remove('toast-in');e.classList.add('toast-out');
    setTimeout(function(){e.style.display='none';e.classList.remove('toast-out')},230)},2800);}
function sw(el){
  document.querySelectorAll('.tabbar a[data-v],#navd a[data-v]').forEach(function(a){a.classList.remove('on')});
  document.querySelectorAll('.tabbar a[data-v="'+el.dataset.v+'"],#navd a[data-v="'+el.dataset.v+'"]').forEach(function(a){a.classList.add('on')});
  document.querySelectorAll('.view').forEach(function(v){v.classList.remove('on')});
  var view=$(el.dataset.v);view.classList.add('on');
  var d=$('vtitle-d'); if(d) d.textContent=el.textContent;
  var m=$('vtitle-m'); if(m) m.textContent=el.textContent;
  if(el.dataset.v==='v-traffic')loadTraffic();
  window.scrollTo({top:0,behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});}
function loadTraffic(){
  if(!$('mtable'))return;
  fetch('/api/traffic/history').then(function(r){return r.json()}).then(function(h){
    if($('sample-secs'))$('sample-secs').textContent=Math.round((h.sample_secs||300)/60);
    var mon=h.monthly||[], day=h.daily||[];
    var cm=mon.length?mon[0]:null;
    if(cm){$('k-min').textContent=fmt(cm.in);$('k-mout').textContent=fmt(cm.out);bump('k-min');bump('k-mout');}
    else{$('k-min').textContent='—';$('k-mout').textContent='—';}
    $('mtable').innerHTML=mon.length
      ?'<thead><tr><th>月份</th><th class="num" style="color:var(--gn)">入站</th><th class="num" style="color:var(--pk)">出站</th><th class="num">合计</th><th class="num">环比</th><th class="num">活跃</th></tr></thead><tbody>'
       +mon.map(function(m){
        var tot=m.in+m.out;
        var dl=(m.delta===null||m.delta===undefined)?'<span class="t3">—</span>'
          :(m.delta>=0?'<span style="color:var(--gn);font-weight:700">+'+fmt(m.delta)+'</span>'
                    :'<span style="color:var(--rd);font-weight:700">'+fmt(m.delta)+'</span>');
        return '<tr><td class="mono-l">'+esc(m.month)+'</td><td class="num num-in">'+fmt(m.in)+'</td><td class="num num-out">'+fmt(m.out)+'</td><td class="num"><b>'+fmt(tot)+'</b></td><td class="num">'+dl+'</td><td class="num t3">'+m.days+'天</td></tr>';}).join('')+'</tbody>'
      :'<tbody><tr><td class="empty" colspan="6">暂无月度数据<br><span class="sm">从今天开始积累，月初见首份汇总</span></td></tr></tbody>';
    $('dtable').innerHTML=day.length
      ?'<thead><tr><th>日期</th><th class="num" style="color:var(--gn)">入站</th><th class="num" style="color:var(--pk)">出站</th><th class="num">合计</th><th class="num">隧道</th></tr></thead><tbody>'
       +day.slice(0,30).map(function(d){
        return '<tr><td class="mono-l">'+esc(d.date)+(d.est?' <span class="dim" title="由 frps 近 7 天每日数据估算回填">≈</span>':'')+'</td><td class="num num-in">'+fmt(d.in)+'</td><td class="num num-out">'+fmt(d.out)+'</td><td class="num"><b>'+fmt(d.in+d.out)+'</b></td><td class="num t3">'+d.tunnel_count+'</td></tr>';}).join('')+'</tbody>'
      :'<tbody><tr><td class="empty" colspan="5">暂无每日数据<br><span class="sm">有 frpc 客户端连入并产生流量后开始记录</span></td></tr></tbody>';
    window.__lastTrafficDays=day;
    renderChart(day);});}
var chartSig='';
function renderChart(days){
  var el=$('chart'); if(!el)return;
  if(!days||!days.length){chartSig='';el.innerHTML='<div class="empty">暂无数据<br><span class="sm">有 frpc 客户端连入并产生流量后开始绘制</span></div>';return;}
  var isDark=document.body.classList.contains('dark');
  var latest=days[0].date;
  var p=latest.split('-').map(Number);
  var dayMap={};
  days.forEach(function(d){dayMap[d.date]=d;});
  var arr=[];
  for(var i=29;i>=0;i--){
    var dt=new Date(p[0],p[1]-1,p[2]-i);
    var ds=dt.getFullYear()+'-'+('0'+(dt.getMonth()+1)).slice(-2)+'-'+('0'+dt.getDate()).slice(-2);
    arr.push(dayMap[ds]||{date:ds,in:0,out:0,tunnel_count:0});
  }
  var cw=Math.round(el.clientWidth)||336;
  var sig=(isDark?'dark':'light')+'|'+cw+'|'+arr.map(function(d){return d.date+':'+d.in+':'+d.out}).join('|');
  if(sig===chartSig)return;
  chartSig=sig;
  var maxv=0;
  arr.forEach(function(d){maxv=Math.max(maxv,d.in,d.out);});
  if(maxv<=0)maxv=1;
  var n=30;
  var W=cw,PB=28,PT=16,H=186,area=H-PT-PB;
  var PL=10;
  var PR=(cw>700?86:(cw>480?80:76));
  var plotW=Math.max(120,W-PL-PR);
  var step=plotW/n;
  var bw=Math.max(3,Math.min(14,step*0.34));
  var gap=Math.max(1.2,Math.min(4,bw*0.25));
  var rx=Math.max(1,Math.min(3.5,bw*0.25));
  var groups='',labels='';
  arr.forEach(function(d,i){
    var slotX=PL+i*step;
    var x=slotX+(step-(bw*2+gap))/2;
    var hi=(d.in/maxv)*area, ho=(d.out/maxv)*area;
    var tot=(d.in||0)+(d.out||0);
    var grp='<g class="col-group" data-idx="'+i+'" data-date="'+d.date+'" data-in="'+d.in+'" data-out="'+d.out+'" data-tot="'+tot+'" data-est="'+(d.est?1:0)+'">';
    grp+='<rect class="col-bg" x="'+slotX.toFixed(1)+'" y="'+PT+'" width="'+step.toFixed(1)+'" height="'+area+'" rx="3"></rect>';
    if(d.in===0&&d.out===0){
      grp+='<rect class="chart-bar" x="'+x.toFixed(1)+'" y="'+(PT+area-2.5).toFixed(1)+'" width="'+(bw*2+gap).toFixed(1)+'" height="2.5" rx="1.2" fill="'+(isDark?'rgba(255,255,255,0.12)':'#e8dfe4')+'" opacity="0.85"></rect>';
    }else{
      if(d.in>0){
        var hIn=Math.max(hi,2.5);
        grp+='<rect class="chart-draw bar-in" aria-hidden="true" style="animation-delay:'+(i*12)+'ms" x="'+x.toFixed(1)+'" y="'+(PT+area-hIn).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+hIn.toFixed(1)+'" rx="'+rx.toFixed(1)+'" fill="'+(isDark?'#22c55e':'#15a34a')+'" opacity="0.95"></rect>';
      }else{
        grp+='<rect class="bar-in" x="'+x.toFixed(1)+'" y="'+(PT+area-2).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="2" rx="1" fill="'+(isDark?'rgba(34,197,94,0.18)':'#d9e6de')+'" opacity="0.65"></rect>';
      }
      if(d.out>0){
        var hOut=Math.max(ho,2.5);
        grp+='<rect class="chart-draw bar-out" aria-hidden="true" style="animation-delay:'+(i*12+6)+'ms" x="'+(x+bw+gap).toFixed(1)+'" y="'+(PT+area-hOut).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+hOut.toFixed(1)+'" rx="'+rx.toFixed(1)+'" fill="#ff5c8a" opacity="0.95"></rect>';
      }else{
        grp+='<rect class="bar-out" x="'+(x+bw+gap).toFixed(1)+'" y="'+(PT+area-2).toFixed(1)+'" width="'+bw.toFixed(1)+'" height="2" rx="1" fill="'+(isDark?'rgba(255,92,138,0.18)':'#eed9e2')+'" opacity="0.65"></rect>';
      }
    }
    grp+='<rect class="col-hit" x="'+slotX.toFixed(1)+'" y="0" width="'+step.toFixed(1)+'" height="'+H+'" fill="#000" opacity="0" pointer-events="all" style="cursor:pointer"></rect>';
    grp+='</g>';
    groups+=grp;
    var isLabel=(W>720)?(i===0||i===5||i===10||i===15||i===20||i===25||i===29):(i===0||i===7||i===14||i===21||i===29);
    if(isLabel){
      var anchor=(i===0)?'start':(i===29?'end':'middle');
      var lx=(i===0)?x:(i===29?(x+bw*2+gap):(slotX+step/2));
      labels+='<text x="'+lx.toFixed(1)+'" y="'+(H-8)+'" font-size="11" font-family="Consolas,monospace" font-weight="600" fill="'+(isDark?'#9c8e98':'#7d6e77')+'" text-anchor="'+anchor+'">'+d.date.slice(5)+'</text>';
    }
  });
  var mid=PT+area/2;
  var gridEnd=PL+plotW;
  var grid='<line x1="'+PL+'" y1="'+PT.toFixed(1)+'" x2="'+gridEnd.toFixed(1)+'" y2="'+PT.toFixed(1)+'" stroke="'+(isDark?'rgba(255,255,255,0.08)':'#f0e8ed')+'" stroke-width="1" stroke-dasharray="3,3"/>'
    +'<line x1="'+PL+'" y1="'+mid.toFixed(1)+'" x2="'+gridEnd.toFixed(1)+'" y2="'+mid.toFixed(1)+'" stroke="'+(isDark?'rgba(255,255,255,0.08)':'#eae2e7')+'" stroke-width="1" stroke-dasharray="3,3"/>'
    +'<line x1="'+PL+'" y1="'+(PT+area).toFixed(1)+'" x2="'+gridEnd.toFixed(1)+'" y2="'+(PT+area).toFixed(1)+'" stroke="'+(isDark?'rgba(255,255,255,0.14)':'#dfd6dc')+'" stroke-width="1.2"/>';
  var scaleLabels='';
  if(maxv>1){
    scaleLabels+='<text x="'+(W-4)+'" y="'+(PT+4).toFixed(1)+'" font-size="10.5" font-family="Consolas,monospace" font-weight="700" fill="'+(isDark?'#ff759f':'#e11d48')+'" text-anchor="end" dominant-baseline="middle">峰值 '+fmt(maxv)+'</text>'
      +'<text x="'+(W-4)+'" y="'+mid.toFixed(1)+'" font-size="10" font-family="Consolas,monospace" fill="'+(isDark?'#8a7b85':'#a6959f')+'" text-anchor="end" dominant-baseline="middle">'+fmt(maxv/2)+'</text>'
      +'<text x="'+(W-4)+'" y="'+(PT+area).toFixed(1)+'" font-size="9.5" font-family="Consolas,monospace" fill="'+(isDark?'#6b5f67':'#bfaeb8')+'" text-anchor="end" dominant-baseline="middle">0 B</text>';
  }
  el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="100%" height="'+H+'" role="img" aria-label="近 30 天流量趋势图">'+grid+groups+labels+scaleLabels+'</svg><div class="chart-tooltip" id="chart-tooltip"></div>';
  bindChartTooltip(el);
}
function bindChartTooltip(wrapEl){
  var tip=wrapEl.querySelector('#chart-tooltip');
  if(!tip)return;
  var groups=wrapEl.querySelectorAll('.col-group');
  var activeGrp=null;
  var hoverTimer=null;
  var HOVER_DELAY=220; // 悬停 220 毫秒（Hover Delay）后才显示，防快速滑过误触与闪烁
  var lastX=0, lastY=0;

  function renderTip(grp, clientX, clientY){
    if(activeGrp&&activeGrp!==grp){activeGrp.classList.remove('active');}
    activeGrp=grp;
    grp.classList.add('active');
    var ds=grp.getAttribute('data-date')||'';
    var vin=Number(grp.getAttribute('data-in')||0);
    var vout=Number(grp.getAttribute('data-out')||0);
    var vtot=Number(grp.getAttribute('data-tot')||0);
    var isEst=grp.getAttribute('data-est')==='1';
    tip.innerHTML='<div class="tip-inner">'
      +'<div class="tip-head"><span>'+esc(ds)+'</span>'+(isEst?'<span class="tip-est">≈ 估算</span>':'')+'</div>'
      +'<div class="tip-row"><span class="tip-tag"><i class="in"></i>入站</span><span class="tip-val in">'+fmt(vin)+'</span></div>'
      +'<div class="tip-row"><span class="tip-tag"><i class="out"></i>出站</span><span class="tip-val out">'+fmt(vout)+'</span></div>'
      +'<div class="tip-div"></div>'
      +'<div class="tip-row"><span class="tip-tag"><i class="tot"></i>合计</span><span class="tip-val tot">'+fmt(vtot)+'</span></div>'
      +'</div>';
    positionTip(grp, clientX, clientY);
    if(!tip.classList.contains('show')){
      requestAnimationFrame(function(){
        tip.classList.add('show');
        setTimeout(function(){
          if(tip.classList.contains('show')) tip.classList.add('moving');
        }, 50);
      });
    }
  }

  function positionTip(grp, clientX, clientY){
    var wrapRect=wrapEl.getBoundingClientRect();
    var hitEl=grp.querySelector('.col-hit')||grp;
    var hitRect=hitEl.getBoundingClientRect();
    var tipW=tip.offsetWidth||142;
    var tipH=tip.offsetHeight||94;
    var colCenterX=(hitRect.left+hitRect.right)/2-wrapRect.left;
    var left=colCenterX-tipW/2;
    if(left<8)left=8;
    if(left+tipW>wrapRect.width-8)left=wrapRect.width-tipW-8;
    var top=10;
    if(typeof clientY==='number'&&clientY>0){
      top=(clientY-wrapRect.top)-tipH-12;
      if(top<6)top=(clientY-wrapRect.top)+16;
      if(top+tipH>wrapRect.height-6)top=wrapRect.height-tipH-6;
    }
    tip.style.left=Math.round(left)+'px';
    tip.style.top=Math.round(top)+'px';
  }

  function hide(){
    clearTimeout(hoverTimer);
    hoverTimer=null;
    if(activeGrp){activeGrp.classList.remove('active');activeGrp=null;}
    tip.classList.remove('show', 'moving');
  }

  groups.forEach(function(grp){
    grp.addEventListener('mouseenter',function(ev){
      clearTimeout(hoverTimer);
      lastX=ev.clientX; lastY=ev.clientY;
      var delay = (tip.classList.contains('show') && activeGrp) ? 140 : HOVER_DELAY;
      hoverTimer = setTimeout(function(){
        renderTip(grp, lastX, lastY);
      }, delay);
    });
    grp.addEventListener('mousemove',function(ev){
      lastX=ev.clientX; lastY=ev.clientY;
      if(activeGrp===grp && tip.classList.contains('show')){
        positionTip(grp, lastX, lastY);
      }
    });
    grp.addEventListener('mouseleave',function(){
      clearTimeout(hoverTimer);
      if(activeGrp===grp){
        hoverTimer=setTimeout(hide, 80);
      }
    });
    grp.addEventListener('touchstart',function(ev){
      clearTimeout(hoverTimer);
      if(ev.touches&&ev.touches[0]){
        renderTip(grp, ev.touches[0].clientX, ev.touches[0].clientY);
      }
    },{passive:true});
  });

  wrapEl.addEventListener('mouseleave',hide);
  document.addEventListener('touchstart',function(ev){
    if(!wrapEl.contains(ev.target))hide();
  },{passive:true});
}
function renderProxyTraffic(){
  var el=$('ptable'); if(!el)return;
  var ks=Object.keys(PT);
  el.innerHTML=ks.length
    ?'<div class="tbl-scroll"><table class="tbl"><thead><tr><th>隧道</th><th>状态</th><th class="num" style="color:var(--gn)">入站</th><th class="num" style="color:var(--pk)">出站</th><th class="num">连接</th><th>最后启动</th></tr></thead><tbody>'
     +ks.map(function(k){var p=PT[k]||{};
       return '<tr><td class="mono-l">'+esc(k)+'</td><td>'+pill(p.status==='online','p-on','在线','p-off','离线')+'</td><td class="num num-in">'+fmt(p.in)+'</td><td class="num num-out">'+fmt(p.out)+'</td><td class="num t3">'+(p.conns||0)+'</td><td class="dim mono-l">'+esc(p.last_start||'—')+'</td></tr>';}).join('')
     +'</tbody></table></div>'
    :'<div class="empty">暂无隧道统计数据<br><span class="sm">frps dashboard 不可达，或还没有 frpc 注册过代理</span></div>';
}
function doLogin(ev){ev.preventDefault();
  var fd=new FormData();fd.append('pwd',$('pwd').value);
  fetch('/login',{method:'POST',body:fd}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(o){var m=$('lmsg');
    if(o.ok){location.reload();}else{m.textContent='密码错误：'+o.j.msg;m.style.color='#e11d48';}});return false;}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]});}
function jsq(s){return esc(JSON.stringify(String(s)));}
function pill(on,c1,t1,c2,t2){return on?'<span class="pill '+c1+'"><span class="d"></span>'+t1+'</span>':'<span class="pill '+c2+'"><span class="d"></span>'+t2+'</span>';}
function typeTag(t){return '<span class="tag tag-'+t+'">'+t.toUpperCase()+'</span>';}
function ctrl(a){if(!confirm('确认对 frps 执行 '+a+'？会断开全部 frp 隧道。'))return;
  var fd=new FormData();fd.append('action',a);
  fetch('/api/control',{method:'POST',body:fd}).then(function(r){return r.json()}).then(function(j){
    $('ctrlmsg').textContent=a+'：'+(j.before?'运行中':'停')+'→'+(j.after?'运行中':'停');refresh();});}
function openEdit(t){
  editId=t?t.id:null;
  $('etitle').textContent=t?('编辑隧道 · '+t.name):'新建隧道';
  $('eerr').style.display='none';
  $('f-name').value=t?t.name:''; $('f-type').value=t?t.type:'tcp';
  $('f-lip').value=t?t.local_ip:''; $('f-lport').value=t?t.local_port:'';
  $('f-rport').value=t?t.remote_port:''; $('f-note').value=t?(t.note||''):'';
  setTip('','');portOK=true;
  renderModalChips();
  if(t&&t.remote_port)launchCheck(t.remote_port);
  modalOpener=document.activeElement;$('medit').style.display='flex';document.body.classList.add('modal-open');setTimeout(function(){$('f-name').focus()},20);}
function closeEdit(){
  var m=$('medit');m.classList.add('is-closing');
  setTimeout(function(){m.style.display='none';m.classList.remove('is-closing');document.body.classList.remove('modal-open');if(modalOpener&&modalOpener.focus)modalOpener.focus()},190);
}
function closeModal(id){
  var m=$(id);if(!m)return;
  m.classList.add('is-closing');setTimeout(function(){m.style.display='none';m.classList.remove('is-closing')},190);
}
function saveTunnel(){
  var btn=document.querySelector('#medit .cfgbar .btn-pk');
  if($('f-rport').value&&!portOK){
    setTip('bad','端口被占用，请更换');
    $('f-rport').focus();return;}
  if(btn)btn.disabled=true;
  var fd=new FormData();
  fd.append('name',$('f-name').value); fd.append('type',$('f-type').value);
  fd.append('local_ip',$('f-lip').value); fd.append('local_port',$('f-lport').value);
  fd.append('remote_port',$('f-rport').value); fd.append('note',$('f-note').value);
  fetch(editId?('/api/tunnels/'+editId):'/api/tunnels',{method:'POST',body:fd})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(o){if(btn)btn.disabled=false;
    if(o.ok){toast('已保存');closeEdit();refresh();}
    else{var e=$('eerr');e.innerHTML=o.j.errs.join('<br>');e.style.display='block';}});}
function delTunnel(id,name){if(!confirm('确认删除隧道「'+name+'」？'))return;
  fetch('/api/tunnels/'+id,{method:'DELETE'}).then(function(r){return r.json()}).then(function(j){
    if(j.ok){toast('已删除 '+name);refresh();}});}
/* v5.9：把 frps 实际在跑的 frpc 隧道收编进面板 */
function importFromFrps(){
  if(!confirm('从 frps 导入在线 frpc 声明的隧道？\n\n· 本地 IP/端口默认填 127.0.0.1 + 同远程端口\n· 导入后请核对本地端口（frps 不知道 frpc 侧配置）\n· 面板已有的同名/同端口隧道会自动跳过'))return;
  fetch('/api/tunnels/import',{method:'POST'})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(o){
    if(o.ok){
      var n=o.j.imported.length;
      toast(n?('已导入 '+n+' 条：'+o.j.imported.join('、')):'没有新隧道可导入'+(o.j.skipped.length?'（跳过 '+o.j.skipped.join('、')+'）':''));
      refresh();
    }else{
      toast('导入失败：'+(o.j.errs||['未知']).join('；'));
    }});}
function toggleTunnel(id){
  var t=(TUN||[]).filter(function(x){return x.id===id})[0];
  var willDisable=t&&t.enabled;
  if(willDisable&&!confirm('停用后将对远程端口 '+t.remote_port+' 插入 iptables REJECT 规则——该端口从公网物理不可达，在线客户端立刻断开。\n\n确认停用「'+t.name+'」？'))return;
  fetch('/api/tunnels/'+id+'/toggle',{method:'POST'}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(o){
    if(o.ok){
      toast(o.j.enabled?'已启用，端口放行':'已停用，端口已封锁(iptables REJECT)');
      refresh();
    }else{
      toast('操作失败：'+(o.j.err||'未知错误'));
    }});}
function showCfg(id){
  cfgId=id;
  fetch('/api/tunnels/'+id+'/frpc').then(function(r){return r.text()}).then(function(txt){
    cfgFull=txt;
    $('cfgtext').textContent=txt.replace(/(auth\.token\s*=\s*")[^"]+(")/,'$1***已内置***$2');
    $('cfgname').textContent='#'+id;
    $('mcfg').style.display='flex';});}
function copyCfg(){navigator.clipboard.writeText(cfgFull).then(function(){toast('已复制（含 token）');});}
function dlCfg(){window.location='/api/tunnels/'+cfgId+'/frpc';}
var tunSig='';
function renderTunnels(tunnels){
  TUN=tunnels||[];
  var narrow=isNarrow();
  var box=$('tlist');
  var sig=(narrow?'m':'d')+'|'+tunnels.map(function(t){return t.id+':'+(t.enabled?1:0)}).join(',');
  box.classList.toggle('no-anim', sig===tunSig);tunSig=sig;
  if(!tunnels.length){
    $('tlist').innerHTML='<div class="empty">还没有隧道<br><span class="sm">点上方「＋ 新建隧道」→ 拿配置 → 设备上跑 frpc</span></div>';
    $('tun-table').innerHTML='';return;}
  if(narrow){
    $('tun-table').innerHTML='';
    $('tlist').innerHTML=tunnels.map(function(t){
      var st=t.online?'<span class="st-badge st-dot st-on"><i></i>在线</span>'
        :(!t.enabled?'<span class="st-badge st-dot '+(t.fw_blocked?'st-blocked':'st-dis')+'"><i></i>'+(t.fw_blocked?'已停用 · 端口已封锁':'已停用')+'</span>'
        :'<span class="st-badge st-dot st-off"><i></i>离线</span>');
      var pt=PT[t.name]?'<div class="r2"><span class="tflab">今日流量</span><span class="mono">↓ '+fmt(PT[t.name].in)+' · ↑ '+fmt(PT[t.name].out)+'</span></div>':'';
      return '<div class="tun-card'+(t.enabled?'':' off')+'">'
      +'<div class="r1"><div class="nm"><span>'+esc(t.name)+'</span> '+typeTag(t.type)+'</div>'+st+'</div>'
      +'<div class="r2"><span>'+esc(t.local_ip)+':'+t.local_port+'</span><span>→</span><span class="addr">'+(t.type==='http'?'需域名':esc(t.addr))+'</span></div>'
      +pt
      +(t.note?'<div class="note">'+esc(t.note)+'</div>':'')
      +'<div class="ops">'
      +'<button class="btn btn-pk" onclick="showCfg(\''+t.id+'\')">配置</button>'
      +'<button class="btn btn-sec" onclick="openEdit('+esc(JSON.stringify(t))+')">编辑</button>'
      +'<button class="btn '+(t.enabled?'btn-stop':'btn-go')+'" onclick="toggleTunnel(\''+t.id+'\')">'+(t.enabled?'停用':'启用')+'</button>'
      +'<button class="btn btn-del" style="color:var(--rd)" onclick="delTunnel(\''+t.id+'\','+jsq(t.name)+')">删除</button>'
      +'</div></div>';}).join('');
  }else{
    $('tlist').innerHTML='';
    $('tun-table').innerHTML='<div class="tblwrap"><table><thead><tr><th>状态</th><th>名称</th><th>类型</th><th>本地目标</th><th>公网地址</th><th>今日流量</th><th>备注</th><th>创建时间</th><th style="width:235px">操作</th></tr></thead><tbody>'
    +tunnels.map(function(t){
      var st=t.online?'<span class="st-badge st-dot st-on"><i></i>在线</span>'
        :(!t.enabled?'<span class="st-badge st-dot '+(t.fw_blocked?'st-blocked':'st-dis')+'"><i></i>'+(t.fw_blocked?'已停用 · 端口已封锁':'已停用')+'</span>'
        :'<span class="st-badge st-dot st-off"><i></i>离线</span>');
      var addr=t.type==='http'?'<span class="dim">需域名</span>':'<span class="addr-code">'+esc(t.addr)+'</span>';
      var tf=PT[t.name]?'<span class="flow-cell"><span class="flow-down">↓ '+fmt(PT[t.name].in)+'</span><span class="flow-sep">·</span><span class="flow-up">↑ '+fmt(PT[t.name].out)+'</span></span>':'<span class="dim">—</span>';
      return '<tr'+(t.enabled?'':' class="off"')+'>'
      +'<td>'+st+'</td><td><b>'+esc(t.name)+'</b></td><td>'+typeTag(t.type)+'</td>'
      +'<td><span class="loc-code">'+esc(t.local_ip)+':'+t.local_port+'</span></td><td>'+addr+'</td>'
      +'<td>'+tf+'</td>'
      +'<td class="dim" style="max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(t.note||'')+'">'+esc(t.note||'-')+'</td>'
      +'<td class="dim mono" style="font-size:11px;white-space:nowrap">'+esc(t.created)+'</td>'
      +'<td class="opc" style="white-space:nowrap">'
      +'<button class="btn btn-pk btn-sm" onclick="showCfg(\''+t.id+'\')">配置</button>'
      +'<button class="btn btn-sec btn-sm" onclick="openEdit('+esc(JSON.stringify(t))+')">编辑</button>'
      +'<button class="btn btn-sm '+(t.enabled?'btn-stop':'btn-go')+'" onclick="toggleTunnel(\''+t.id+'\')">'+(t.enabled?'停用':'启用')+'</button>'
      +'<button class="btn btn-del btn-sm" style="color:var(--rd)" onclick="delTunnel(\''+t.id+'\','+jsq(t.name)+')">删除</button>'
      +'</td></tr>';}).join('')+'</tbody></table></div>';}}
function bump(id){var e=$(id);if(!e)return;e.classList.remove('value-bump');void e.offsetWidth;e.classList.add('value-bump');}
/* 流量监控翻牌：旧值向下翻走（0→-90°），新值从 -90° 翻入落位，split-flap 时序 */
function flipSet(id,val){
  var box=$(id);if(!box)return;
  var faces=box.querySelectorAll('.fc');
  if(faces.length<2){
    var a=document.createElement('div');a.className='fc on';
    var b=document.createElement('div');b.className='fc';
    a.textContent=val;
    b.textContent=val;
    box.textContent='';box.appendChild(a);box.appendChild(b);
    return;}
  var cur=box.querySelector('.fc.on'),nxt=box.querySelector('.fc:not(.on)');
  if(!cur||!nxt||cur.textContent===val)return;
  nxt.textContent=val;
  cur.classList.add('out');cur.classList.remove('on');
  nxt.classList.add('on','in');
  window.setTimeout(function(c,n){return function(){c.classList.remove('out');c.textContent=val;n.classList.remove('in');}}(cur,nxt),400);
}
function refresh(){
  fetch('/api/status').then(function(r){
    if(r.status===401){
      if(timer){clearInterval(timer);timer=null;}
      if(!window.__rl){window.__rl=1;setTimeout(function(){location.reload()},1200);}
      return null;}
    return r.json();})
  .then(function(d){if(!d)return;
    var ck=d.now+' 刷新';
    if($('clock-m'))$('clock-m').textContent=ck;
    if($('clock-d'))$('clock-d').textContent='· '+ck;
    $('k-svc').innerHTML=pill(d.active,'p-on','运行中','p-off','已停止');
    if(d.traffic){
      flipSet('tf-in',fmt(d.traffic.in));
      flipSet('tf-out',fmt(d.traffic.out));
      $('tf-in-r').textContent='↓ '+fmt(d.traffic.in_rate)+'/s';
      $('tf-out-r').textContent='↑ '+fmt(d.traffic.out_rate)+'/s';
    }else{
      flipSet('tf-in','—');flipSet('tf-out','—');
      $('tf-in-r').textContent='dashboard 不可达';$('tf-out-r').textContent='';
    }
    PT=d.proxy_traffic||{};
    renderProxyTraffic();
    $('k-tun').innerHTML='<b style="color:'+(d.tunnel_online?'var(--gn)':'var(--t2)')+'">'+d.tunnel_online+'</b><span class="dim" style="font-size:13px"> / '+d.tunnel_total+'</span>';bump('k-tun');
    if($('k-tun2'))$('k-tun2').textContent=d.tunnel_online;
    if($('k-total'))$('k-total').textContent=d.tunnel_total;
    $('k-cli').innerHTML='<b>'+d.clients.length+'</b> <span class="dim" style="font-size:12px">台</span>';bump('k-cli');
    $('k-atk').innerHTML='<b style="color:'+(d.attack_24h>0?'var(--rd)':'var(--gn)')+'">'+d.attack_24h+'</b> <span class="dim" style="font-size:12px">次</span>';bump('k-atk');
    $('k-p2').innerHTML=pill(d.port_dash,'p-on','监听','p-off','未监听');
    $('cfg').innerHTML=d.config.map(function(r){
      return r.sec?'<tr class="sec-row"><td colspan="2">'+esc(r.k)+'</td></tr>'
        :'<tr><td class="mono" style="width:230px">'+esc(r.k)+'</td><td class="mono">'+esc(r.v)+'</td></tr>'}).join('')
      ||'<tr><td class="dim">未找到 frps.toml</td></tr>';
    $('audit').innerHTML=d.audit.length
      ?d.audit.map(function(l){return'<tr><td class="mono dim">'+esc(l)+'</td></tr>'}).join('')
      :'<tr><td class="empty">暂无操作记录</td></tr>';
    $('events').innerHTML=d.events.length
      ?'<div class="scrollx"><table><thead><tr><th>时间</th><th>IP</th><th>主机名</th><th>版本</th><th>结果</th></tr></thead><tbody>'
       +d.events.map(function(x){return '<tr><td class="mono dim">'+esc(x.ts)+'</td><td class="mono">'+esc(x.ip)+'</td><td>'+esc(x.host||'-')+'</td><td class="dim">'+esc(x.ver)+'</td><td>'+(x.ok?'<span class="ok">成功</span>':'<span class="bad">拒绝</span>')+'</td></tr>'}).join('')
       +'</tbody></table></div>'
      :'<div class="empty">暂无登录记录</div>';
    var cl=$('clients');if(cl)cl.classList.add('no-anim');
    cl.innerHTML=d.clients.length
      ?d.clients.map(function(ip){return'<div class="tun-card" style="margin-bottom:8px"><div class="r1"><div class="nm"><span>'+esc(ip)+'</span></div><span class="st-dot st-on"><i></i>已连接</span></div></div>'}).join('')
      :'<div class="empty">当前无 frpc 客户端在线</div>';
    return fetch('/api/tunnels');})
  .then(function(r){return r?r.json():null})
  .then(function(td){if(td)renderTunnels(td.tunnels);
    if($('v-traffic')&&$('v-traffic').classList.contains('on'))loadTraffic();});}
var _rz;
window.addEventListener('resize',function(){
  clearTimeout(_rz);_rz=setTimeout(function(){
    fetch('/api/tunnels').then(function(r){return r.json()}).then(function(td){renderTunnels(td.tunnels);});},300);});
{% if logged %}timer=setInterval(refresh,POLL);refresh();{% endif %}
</script>
</body></html>
"""


_sampler = None
if __name__ == "__main__":
    _sampler = start_sampler()
    app.run(host=LAN_IP, port=PANEL_PORT, debug=False, threaded=True)
