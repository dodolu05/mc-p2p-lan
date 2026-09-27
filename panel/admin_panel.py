#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mc-p2p-lan 联机管理面板 (仪表舱版)"""
import subprocess, json, os, re, socket, time, ipaddress
from datetime import datetime
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify

# ===== mc-p2p-lan 通用化配置（原私有实例已改为环境变量驱动）=====
import secrets as _secrets
INSTALL_DIR = os.environ.get("PANEL_DIR", "/opt/mc-p2p-lan")
LAN_IP      = os.environ.get("PANEL_HOST", "127.0.0.1")
LAN_NET     = os.environ.get("PANEL_TRUST_NET", ".".join(LAN_IP.split(".")[:3]) + ".0/24")
PANEL_PORT  = int(os.environ.get("PANEL_PORT", "8080"))
PUB_IP      = os.environ.get("PANEL_PUB_IP", "")
FRPS_TOML   = os.environ.get("FRPS_TOML", os.path.join(INSTALL_DIR, "etc", "frps.toml"))
LOG_UNIT    = os.environ.get("PANEL_LOG_UNIT", "mc-p2p-lan-easytier")
# =================================================================

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET") or _secrets.token_hex(32)
ADMIN_PWD = os.environ.get("PANEL_PWD", "mc-p2p-lan")

# 免密直达：只信 TCP 真实源 IP（request.remote_addr），绝不读 X-Forwarded-For。
# 本服务前面没有反向代理，remote_addr 即真实对端，无法伪造。
# 127/8 = 本机；LAN_NET = mc-p2p-lan 虚拟局域网网段。
TRUSTED_NETS = tuple(ipaddress.ip_network(c) for c in ("127.0.0.0/8", LAN_NET))

def trusted_peer():
    try:
        addr = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        return False
    return any(addr in net for net in TRUSTED_NETS)

def authed():
    """会话已登录，或来自可信内网且未主动退出。"""
    if session.get("ok"):
        return True
    if session.get("no_auto"):
        return False
    return trusted_peer()

SERVICES = [
    ("mc-p2p-lan-easytier", "EasyTier 虚拟局域网", "easytier"),
    ("mc-p2p-lan-frps", "frp 内网穿透", "frp"),
    ("mc-p2p-lan-panel", "联机管理面板", "panel"),
]

LINKS = [
    ("frp 面板", "http://" + LAN_IP + ":8090", "frp"),
]

def sh(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        return f"err: {e}"

def load_avg():
    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
        return {"m1": p[0], "m5": p[1], "m15": p[2]}
    except Exception:
        return {"m1": "-", "m5": "-", "m15": "-"}

def cpu_count():
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1

def _jiffy():
    try:
        with open("/proc/stat") as f:
            p = f.readline().split()[1:]
        v = [int(x) for x in p]
        idle = v[3] + (v[4] if len(v) > 4 else 0)
        return idle, sum(v)
    except Exception:
        return None

def uptime_secs():
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return None

_last_cpu_sample = {"idle": None, "total": None, "time": 0, "pct": 0}

def cpu_busy():
    """真实 CPU 占用：前后两次 /proc/stat 滑动差值，0ms 无阻塞，彻底移除 time.sleep()。"""
    curr = _jiffy()
    if not curr:
        return _last_cpu_sample["pct"]
    idle, total = curr
    now = time.time()
    last = _last_cpu_sample
    if last["idle"] is not None and (now - last["time"]) >= 0.5:
        di = idle - last["idle"]
        dt = total - last["total"]
        if dt > 0:
            last["pct"] = max(0, min(100, round((1 - di / dt) * 100)))
    last["idle"] = idle
    last["total"] = total
    last["time"] = now
    return last["pct"]

def sysinfo():
    """原生读取系统接口，减少高频子进程 Fork 损耗。"""
    mem = {"total": 0, "used": 0, "avail": 0}
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        vals = {}
        for l in lines:
            parts = l.split(":")
            if len(parts) == 2:
                vals[parts[0].strip()] = int(parts[1].strip().split()[0]) // 1024  # MB
        tot = vals.get("MemTotal", 0)
        av = vals.get("MemAvailable", vals.get("MemFree", 0))
        mem = {"total": tot, "used": max(0, tot - av), "avail": av}
    except Exception:
        for line in sh("free -m").splitlines():
            if line.startswith("Mem:"):
                p = line.split()
                mem = {"total": int(p[1]), "used": int(p[2]), "avail": int(p[6])}

    disk = {"size": "40G", "used": "11G", "avail": "29G", "percent": "28%"}
    try:
        st = os.statvfs("/")
        total_b = st.f_blocks * st.f_frsize
        free_b = st.f_bavail * st.f_frsize
        used_b = total_b - free_b
        pct = round((used_b / total_b) * 100) if total_b > 0 else 0
        disk = {
            "size": f"{total_b / (1024**3):.0f}G",
            "used": f"{used_b / (1024**3):.1f}G",
            "avail": f"{free_b / (1024**3):.1f}G",
            "percent": f"{pct}%"
        }
    except Exception:
        try:
            d = sh("df -h /").splitlines()[-1].split()
            disk = {"size": d[1], "used": d[2], "avail": d[3], "percent": d[4]}
        except Exception:
            pass

    up_sec = uptime_secs()
    up = "" if up_sec is not None else sh("uptime")
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mem": mem, "disk": disk, "uptime": up, "cpu": cpu_busy(),
        "up_secs": up_sec,
    }

def service_status(name):
    return sh(f"systemctl is-active {name}")

def services_status(names):
    """一次 systemctl 查全部服务，省掉轮询时的反复 fork。"""
    if not names:
        return {}
    out = sh("systemctl is-active " + " ".join(names), timeout=15)
    lines = [x.strip() for x in out.splitlines() if x.strip()]
    if len(lines) != len(names):
        return {n: service_status(n) for n in names}
    return dict(zip(names, lines))

def recent_logs(n=30):
    return sh(f"journalctl -u {LOG_UNIT}.service -n {n} --no-pager -o cat")

def last_logins(n=10):
    return sh(f"last -n {n} -a | grep -v wtmp")

def fail2ban_status():
    return sh("fail2ban-client status sshd")

def parse_uptime(raw):
    m = re.search(r"up\s+(\d+)\s+days?,\s+(\d+):(\d+)", raw)
    if m:
        return {"d": int(m.group(1)), "h": int(m.group(2)), "m": int(m.group(3))}
    m = re.search(r"up\s+(\d+):(\d+)", raw)
    if m:
        return {"d": 0, "h": int(m.group(1)), "m": int(m.group(2))}
    m = re.search(r"up\s+(\d+)\s+min", raw)
    if m:
        return {"d": 0, "h": 0, "m": int(m.group(1))}
    return None

def parse_fail2ban(raw):
    def g(pat):
        m = re.search(pat, raw)
        return m.group(1) if m else "-"
    return {
        "failed": g(r"Currently failed:\s*(\d+)"),
        "total_failed": g(r"Total failed:\s*(\d+)"),
        "banned": g(r"Currently banned:\s*(\d+)"),
        "total_banned": g(r"Total banned:\s*(\d+)"),
    }

LOG_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d*\s*\[(\w+)\]\s*(.*)$")

def parse_logs(raw, limit=30):
    # 最新在前：journalctl 正序输出（旧→新），截取最新 limit 条后倒序返回，
    # 使 Jinja 首屏渲染与 JS applyDetail 动态刷新两条路径都呈现「新消息在上」；
    # 行号同步按倒序位次重排（01 = 最新一条），避免残留 journalctl 窗口内旧序号
    rows = []
    for i, line in enumerate(raw.splitlines()):
        line = line.rstrip()
        if not line.strip():
            continue
        m = LOG_RE.match(line)
        if m:
            rows.append((f"{i+1:02d}", m.group(1), m.group(2), m.group(3)))
        else:
            rows.append((f"{i+1:02d}", "", "INFO", line))
    tail = rows[-limit:]
    return [(f"{n:02d}", r[1], r[2], r[3]) for n, r in enumerate(reversed(tail), 1)]

MON = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
       "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}
LOGIN_DATE_RE = re.compile(r"(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2})")

def parse_logins(raw, limit=5):
    out = []
    for line in raw.splitlines():
        line = line.rstrip()
        if not line.strip() or line.startswith(("wtmp", "btmp")):
            continue
        dm = LOGIN_DATE_RE.search(line)
        if not dm:
            out.append({"user": line[:20], "tty": "-", "src": "-", "when": "", "online": False, "note": ""})
            continue
        pre = line[:dm.start()].split()
        post = line[dm.end():].strip()
        user = pre[0] if pre else "-"
        if len(pre) >= 3 and pre[1] == "system" and pre[2] == "boot":
            tty, is_boot = "system boot", True
        else:
            tty, is_boot = (pre[1] if len(pre) > 1 else "-"), False
        mm = re.match(r"\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2})", dm.group(1))
        when = f"{MON.get(mm.group(1), '--')}-{int(mm.group(2)):02d} {mm.group(3)}" if mm else dm.group(1)
        em = re.match(r"-\s*(\d{2}:\d{2})", post)
        dur = re.search(r"\((\d+:\d+)\)", post)
        toks = [t for t in post.split() if not re.fullmatch(r"\(\d+:\d+\)", t)]
        last = toks[-1] if toks else ""
        src = last if last and re.fullmatch(r"[0-9a-fA-F.:]+", last) else "-"
        if is_boot:
            out.append({"user": user, "tty": tty, "src": "-", "when": when, "online": False, "note": "系统启动"})
        elif "still logged in" in post:
            out.append({"user": user, "tty": tty, "src": src, "when": when, "online": True, "note": "仍在线"})
        elif em:
            note = ("已登出" + (" (" + dur.group(1) + ")" if dur else "")).strip()
            out.append({"user": user, "tty": tty, "src": src, "when": f"{when} 至 {em.group(1)}", "online": False, "note": note})
        else:
            out.append({"user": user, "tty": tty, "src": src, "when": when, "online": False, "note": (post[:14] or "已登出")})
    return out[:limit]
# -*- coding: utf-8 -*-
PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#f2eee2">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20'%3E%3Crect x='3' y='3' width='14' height='14' rx='3.2' fill='%23b03426'/%3E%3Cpath d='M6.6 13.2 10 6.4l3.4 6.8' fill='none' stroke='%23f7f2e4' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<title>服务器管理台</title>
<style>
:root{
  --ink:#2e2924;
  --ink-2:#5c5347;
  --ink-3:#8d8272;
  --accent:#3c5a70;
  --accent-2:#2b4257;
  --ok:#4a7c59;
  --warn:#a97a2f;
  --stop:#b03426;
  --paper:#f2eee2;
  --glass:linear-gradient(158deg,rgba(255,253,246,.85),rgba(251,247,236,.68) 52%,rgba(255,253,246,.82));
  --edge:rgba(96,84,62,.26);
  --edge-2:rgba(96,84,62,.15);
  --pill:rgba(255,253,246,.62);
  --pill-h:rgba(255,253,246,.95);
  --r-card:18px; --r-sm:12px;
  --sh:0 22px 44px -30px rgba(84,68,44,.3),0 2px 8px -4px rgba(84,68,44,.14);
  --inset:inset 0 1px 0 rgba(255,255,255,.6);
  --fu:"Songti SC","STSong","Noto Serif CJK SC","Source Han Serif SC","SimSun",Georgia,"PingFang SC","Microsoft YaHei",serif;
  --fm:ui-monospace,"SF Mono","Cascadia Mono","JetBrains Mono",Menlo,Consolas,"Noto Sans Mono CJK SC",monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{font-family:var(--fu);font-size:14px;line-height:1.62;color:var(--ink);
  background:var(--paper);min-height:100vh;min-height:100dvh;-webkit-font-smoothing:antialiased;overflow-x:hidden}
svg{display:block}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit}
::selection{background:rgba(60,90,112,.18)}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(96,84,62,.26);border-radius:9px;border:2px solid transparent;background-clip:padding-box}
::-webkit-scrollbar-thumb:hover{background:rgba(96,84,62,.42);background-clip:padding-box}

/* 背景：宣纸底 + 淡墨远山 */
.sky{position:fixed;inset:0;z-index:-2;pointer-events:none;contain:strict;
  background:linear-gradient(178deg,#f8f4ea 0%,#f2eee2 52%,#ebe4d3 100%)}
.mts{position:fixed;left:0;right:0;bottom:0;height:44vh;min-height:240px;z-index:-1;pointer-events:none;contain:strict;
  animation:mountainBreathe 24s ease-in-out infinite alternate}
@keyframes mountainBreathe{0%{transform:translateY(0) scale(1);opacity:.95}100%{transform:translateY(-3px) scale(1.006);opacity:1}}
.mts svg{width:100%;height:100%}
.haze{position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(130% 105% at 50% 32%,transparent 52%,rgba(110,92,58,.12) 100%)}

/* 版式 */
.wrap{width:100%;max-width:1240px;margin:0 auto;padding:26px 26px 56px;position:relative;z-index:1}
.hero-h{text-align:center;margin:6px 0 20px}
.hero-h h1{font-size:30px;font-weight:700;letter-spacing:.12em;color:var(--ink)}
.seal{display:inline-grid;place-items:center;width:27px;height:27px;margin-left:13px;vertical-align:5px;border-radius:6px;
  background:#b03426;color:#f7f2e4;font-size:14px;font-weight:600;letter-spacing:0;line-height:1;transform:rotate(3deg);
  box-shadow:inset 0 0 0 1.5px rgba(247,242,228,.35);transition:transform .3s ease}
.seal:hover{transform:rotate(0deg) scale(1.08)}
.hero-h p{margin-top:7px;font-size:13px;color:var(--ink-3);letter-spacing:.14em}
.hero-h .stamp{margin-top:12px;display:inline-flex;align-items:center;gap:9px;font-family:var(--fm);font-size:12.5px;
  color:var(--ink-2);padding:6px 15px;border-radius:999px;background:rgba(96,84,62,.06);border:1px solid var(--edge-2)}
.hero-h .stamp b{color:var(--ink);font-size:14px;letter-spacing:.02em}
.pulse{position:relative;width:6px;height:6px;border-radius:50%;background:var(--ok);transition:opacity .2s}
.pulse::after{content:"";position:absolute;inset:-2px;border-radius:50%;background:var(--ok);animation:haloPulse 2.4s ease-out infinite;opacity:.6}
@keyframes haloPulse{0%{transform:scale(1);opacity:.6}60%{transform:scale(2.6);opacity:0}100%{transform:scale(2.6);opacity:0}}
.pulse.on{opacity:1}
.out-btn{position:absolute;top:28px;right:26px;z-index:5}

/* 分页 · 桌面分段控件 / 手机底部导航 */
.tabs{position:relative;display:flex;gap:2px;width:max-content;max-width:100%;margin:0 auto 20px;padding:5px;
  border-radius:999px;background:rgba(255,253,246,.78);border:1px solid var(--edge-2);
  box-shadow:var(--sh),var(--inset);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{position:relative;z-index:1;display:inline-flex;align-items:center;justify-content:center;gap:8px;flex:none;padding:10px 19px;
  border:0;background:transparent;border-radius:999px;font-size:13px;font-weight:650;letter-spacing:.08em;color:var(--ink-3);
  cursor:pointer;transition:color .2s;-webkit-tap-highlight-color:transparent}
.tab svg{width:16px;height:16px;flex:none;opacity:.85}
.tab:hover{color:var(--ink-2)}
.tab[aria-selected="true"],.tab[aria-selected="true"]:hover{color:var(--accent)}
.tab[aria-selected="true"]::before{content:"";position:absolute;z-index:-1;inset:0;border-radius:inherit;
  background:rgba(60,90,112,.1);border:1px solid rgba(60,90,112,.3)}
.tbadge{font-family:var(--fm);font-size:10px;font-weight:700;padding:2px 8px;border-radius:99px;color:var(--ink-3);
  background:rgba(96,84,62,.08);border:1px solid var(--edge-2);transition:all .2s}
.tbadge.warn{color:var(--warn);background:rgba(169,122,47,.1);border-color:rgba(169,122,47,.34)}
.tab .tdot{display:none;width:5px;height:5px;border-radius:50%;position:absolute;top:6px;right:calc(50% - 16px);
  background:var(--warn);box-shadow:0 0 6px rgba(169,122,47,.6)}
.nav-cap{display:none}

/* 页面切换 */
.panel:not(.active){display:none}
.panel.active{animation:pagein .3s cubic-bezier(.22,1,.36,1)}
@keyframes pagein{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.bento{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;align-items:start}
.b-trend{grid-column:span 2}
.span3{grid-column:1 / -1}

/* 宣纸卡 */
.card{position:relative;border-radius:var(--r-card);background:var(--glass);border:1px solid var(--edge);
  box-shadow:var(--sh),var(--inset);overflow:hidden;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  transition:transform .28s cubic-bezier(.16,1,.3,1),box-shadow .28s cubic-bezier(.16,1,.3,1)}
.card:hover{transform:translateY(-2px);box-shadow:0 28px 52px -28px rgba(84,68,44,.35),0 4px 12px -4px rgba(84,68,44,.18),var(--inset)}
.card::after{content:"";position:absolute;inset:0;pointer-events:none;border-radius:inherit;
  background:radial-gradient(90% 70% at 50% -18%,rgba(255,255,255,.5),transparent 62%)}
.chead{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:17px 20px 0}
.chead h2{font-size:13.5px;font-weight:700;letter-spacing:.14em;display:flex;align-items:center;gap:9px;color:var(--ink)}
.chead h2::before{content:"";width:8px;height:8px;border-radius:2.5px;background:#b03426}
.cnote{font-family:var(--fm);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3)}
.cbody{padding:16px 20px 20px}
.meta dl{display:flex;flex-direction:column;gap:9px;font-size:11.5px}
.meta div{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.meta dt{color:var(--ink-3);letter-spacing:.08em;white-space:nowrap}
.meta dd{font-family:var(--fm);color:var(--ink-2);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* 仪表卡（墨色条案） */
.deck{position:relative;border-radius:var(--r-card);padding:24px;overflow:hidden;
  background:linear-gradient(160deg,#332e27,#26211b 58%,#2e2921);
  border:1px solid rgba(52,44,33,.92);box-shadow:var(--sh);
  --ink:#f2ecdc;--ink-2:#cfc8b5;--ink-3:#a1977f;
  --accent:#93b8cb;--accent-2:#74a2ba;
  --ok:#84b28e;--warn:#d3a763;--stop:#d38272;
  --edge:rgba(242,236,220,.16);--edge-2:rgba(242,236,220,.1);
  --pill:rgba(242,236,220,.06);--pill-h:rgba(242,236,220,.1);
  transition:transform .28s cubic-bezier(.16,1,.3,1),box-shadow .28s cubic-bezier(.16,1,.3,1)}
.deck:hover{transform:translateY(-2px);box-shadow:0 28px 56px -24px rgba(0,0,0,.45),0 4px 14px rgba(0,0,0,.22)}
.deck::before{content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(60% 80% at 12% 0%,rgba(147,184,203,.12),transparent 60%)}
.deck-in{position:relative;display:grid;grid-template-columns:auto minmax(0,1fr) minmax(0,1fr);gap:26px;align-items:center}
.ring{position:relative;width:132px;height:132px;flex:none}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:11;stroke-linecap:round}
.ring .tr{stroke:rgba(242,236,220,.1)}
.ring .vv{stroke:var(--accent);stroke-dasharray:264;stroke-dashoffset:264;transition:stroke-dashoffset .85s cubic-bezier(.34,1.56,.64,1)}
.ring .mid{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.ring .mid b{display:block;font-size:34px;font-weight:750;letter-spacing:-.03em;line-height:1;font-variant-numeric:tabular-nums;color:var(--ink)}
.ring .mid i{font-style:normal;font-size:10px;font-weight:700;letter-spacing:.2em;opacity:.75;margin-top:5px;display:block;color:var(--ink-3)}
.dcell{min-width:0}
.dcell .k{font-size:11px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:var(--ink-3)}
.dcell .v{font-size:27px;font-weight:750;letter-spacing:-.025em;line-height:1.2;margin-top:4px;font-variant-numeric:tabular-nums;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink)}
.dcell .v small{font-size:13px;font-weight:600;opacity:.7;margin-left:2px;color:var(--ink-2)}
.dcell .s{font-size:11.5px;color:var(--ink-3);margin-top:5px;font-family:var(--fm);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar{height:6px;border-radius:99px;background:rgba(242,236,220,.1);overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;width:var(--f,0%);border-radius:99px;background:linear-gradient(90deg,var(--accent-2),var(--accent));
  transition:width .65s cubic-bezier(.22,1,.36,1)}
.deck-foot{position:relative;display:flex;align-items:center;gap:10px;margin-top:20px;padding-top:15px;border-top:1px solid var(--edge-2)}
.badge{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:650;letter-spacing:.04em;color:var(--ink-2);
  padding:6px 14px;border-radius:999px;background:var(--pill);border:1px solid var(--edge-2)}
.badge.warn{color:var(--warn);background:rgba(211,167,99,.1);border-color:rgba(211,167,99,.32)}
.lamp{width:7px;height:7px;border-radius:50%;flex:none;background:var(--ink-3)}
.lamp.ok{background:var(--ok);animation:breathe 3.2s ease-in-out infinite}
.lamp.warn{background:var(--warn);animation:blink 1.05s ease-in-out infinite}
.lamp.stop{background:var(--stop)}
@keyframes breathe{0%,100%{opacity:1}50%{opacity:.55}}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.22}}

/* 趋势 */
.trend{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px}
.tbox header{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:8px}
.tbox h3{font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3)}
.tv{font-family:var(--fm);font-size:14px;font-weight:700;color:var(--ink-2);font-variant-numeric:tabular-nums}
.spark{display:block;width:100%;height:112px}

/* 服务 · 磁贴 */
.tile-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(228px,1fr));gap:12px}
.svc{position:relative;display:flex;flex-direction:column;gap:11px;padding:16px 17px 15px 20px;border-radius:16px;
  background:var(--pill);border:1px solid var(--edge-2);overflow:hidden;transition:background .2s,border-color .2s,transform .2s}
.svc::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ok);transition:background .3s}
.svc[data-st="off"]::before{background:var(--stop)}
.svc[data-st="busy"]::before{background:var(--warn);animation:blink 1s ease-in-out infinite}
.svc:hover{background:var(--pill-h);border-color:var(--edge);transform:translateY(-2px)}
.svc-top{display:flex;align-items:flex-start;gap:12px}
.ico{width:38px;height:38px;flex:none;display:grid;place-items:center;border-radius:11px;color:var(--ink-2);
  background:rgba(255,253,246,.7);border:1px solid var(--edge-2);transition:all .3s}
.ico svg{width:19px;height:19px}
.svc[data-st="on"] .ico{color:var(--accent);border-color:rgba(60,90,112,.36);background:rgba(60,90,112,.08)}
.svc h3{font-size:14.5px;font-weight:650;letter-spacing:.02em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pkg{font-family:var(--fm);font-size:10.5px;color:var(--ink-3);margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.svc-bot{display:flex;align-items:center;justify-content:space-between;gap:10px}
.st{display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:700;padding:4px 11px 4px 9px;border-radius:999px;
  color:var(--ink-2);background:rgba(255,253,246,.66);border:1px solid var(--edge-2);white-space:nowrap;transition:all .3s}
.st.off{color:var(--stop);background:rgba(176,52,38,.07);border-color:rgba(176,52,38,.28)}
.st.warn{color:var(--warn);background:rgba(169,122,47,.08);border-color:rgba(169,122,47,.3)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;font-size:12.5px;font-weight:650;
  color:var(--ink-2);background:rgba(255,253,246,.7);border:1px solid var(--edge);border-radius:999px;padding:7px 15px;
  cursor:pointer;transition:all .18s;-webkit-tap-highlight-color:transparent}
.btn:hover{color:var(--ink);background:var(--pill-h);border-color:rgba(96,84,62,.36)}
.btn:active{transform:scale(.96)}
.btn.sm{padding:6px 13px;font-size:11.5px}
.btn.restart:hover{color:var(--accent);border-color:rgba(60,90,112,.42);background:rgba(60,90,112,.07)}
.btn[disabled]{opacity:.6;pointer-events:none}

/* 快捷入口 */
.link-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.lk{position:relative;overflow:hidden;display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:14px;align-items:center;
  padding:18px;border-radius:16px;background:var(--pill);border:1px solid var(--edge-2);transition:all .2s}
.lk:hover{border-color:rgba(60,90,112,.42);background:var(--pill-h);transform:translateY(-2px)}
.lk .ico{background:rgba(60,90,112,.06);border-color:rgba(60,90,112,.22);color:var(--accent)}
.lk h3{font-size:15px;font-weight:650;letter-spacing:.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lk .addr{font-family:var(--fm);font-size:11px;color:var(--ink-3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.lk .rt{display:flex;flex-direction:column;align-items:flex-end;gap:7px}
.pchip{font-family:var(--fm);font-size:10px;font-weight:700;letter-spacing:.04em;padding:3px 9px;border-radius:7px;
  color:var(--ink-3);background:rgba(96,84,62,.06);border:1px solid var(--edge-2)}
.probe{display:inline-flex;align-items:center;gap:7px;font-size:10.5px;font-weight:700;color:var(--ink-3);white-space:nowrap}
.probe .lamp{width:6px;height:6px}
.probe.ok{color:var(--ok)}
.probe.off{color:var(--stop)}
.lk .go{position:absolute;right:14px;bottom:12px;color:var(--ink-3);opacity:0;transform:translate(-4px,4px);transition:all .2s}
.lk .go svg{width:14px;height:14px}
.lk:hover .go{opacity:1;transform:none;color:var(--accent)}

/* 日志 */
.term{border-radius:var(--r-sm);overflow:hidden;border:1px solid rgba(52,44,33,.72);background:#26221c}
.tbar{display:flex;align-items:center;gap:8px;padding:10px 13px;border-bottom:1px solid rgba(242,236,220,.1);
  background:linear-gradient(180deg,rgba(242,236,220,.06),rgba(242,236,220,.02))}
.tdot{width:9px;height:9px;border-radius:50%;flex:none}
.tdot.r{background:#ff5f57}.tdot.y{background:#febc2e}.tdot.g{background:#28c840}
.tbar .tt{font-family:var(--fm);font-size:11px;color:#a1977f;margin-left:6px}
.tbar .rt{margin-left:auto;font-family:var(--fm);font-size:10.5px;color:#a1977f}
.log{overflow:auto;max-height:min(62vh,560px);font-family:var(--fm);font-size:12px;line-height:1.7;color:#cfc8b5}
.log-row{display:flex;align-items:flex-start;gap:13px;padding:5px 13px 5px 0;min-width:max-content}
.log-row:nth-child(odd){background:rgba(242,236,220,.025)}
.log-row:hover{background:rgba(242,236,220,.05)}
.ln{width:42px;flex:none;text-align:right;padding-right:11px;color:rgba(161,151,127,.55);font-size:10.5px;
  border-right:1px solid rgba(242,236,220,.08);user-select:none}
.ts{color:#a1977f;flex:none}
.sev{flex:none;font-size:9px;font-weight:700;letter-spacing:.1em;padding:1px 6px;border-radius:5px;margin-top:2px;
  color:#cfc8b5;background:rgba(242,236,220,.06);border:1px solid rgba(242,236,220,.12)}
.sev.WARN{color:#d3a763;background:rgba(211,167,99,.1);border-color:rgba(211,167,99,.3)}
.sev.ERROR,.sev.CRITICAL{color:#d38272;background:rgba(211,130,114,.1);border-color:rgba(211,130,114,.32)}
.msg{color:#d6d0bf;white-space:nowrap}

/* 安全 */
.f2b{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.fcell{padding:15px 16px;border-radius:var(--r-sm);background:var(--pill);border:1px solid var(--edge-2)}
.fl{display:block;font-size:10px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3)}
.fv{display:block;font-family:var(--fm);font-variant-numeric:tabular-nums;font-size:26px;font-weight:750;letter-spacing:-.03em;
  color:var(--ink);margin-top:4px;line-height:1.1}
.fv.hot{color:var(--stop)}
.rows{font-family:var(--fm);font-size:11.5px;color:var(--ink-2)}
.row-head{display:grid;grid-template-columns:56px 60px minmax(120px,1fr) minmax(110px,.9fr);gap:12px;padding-bottom:8px;
  font-family:var(--fu);font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);
  border-bottom:1px solid rgba(96,84,62,.2)}
.row-l{display:grid;grid-template-columns:56px 60px minmax(120px,1fr) minmax(110px,.9fr);gap:12px;align-items:center;
  padding:9px 0;border-bottom:1px solid rgba(96,84,62,.1)}
.row-l:last-child{border-bottom:0}
.row-l > .v{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row-l .sv{display:inline-flex;align-items:center;gap:7px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row-l .sv.muted{color:var(--ink-3)}
.chip{display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:700;padding:4px 11px 4px 9px;border-radius:999px;
  color:var(--ink-2);border:1px solid var(--edge-2);background:rgba(74,124,89,.08)}
.chip.stop{color:var(--stop);border-color:rgba(176,52,38,.28);background:rgba(176,52,38,.07)}

/* 提示 */
.toasts{position:fixed;right:20px;bottom:20px;z-index:90;display:flex;flex-direction:column;gap:10px;align-items:flex-end;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;max-width:min(340px,86vw);padding:13px 17px;border-radius:14px;font-size:12.5px;font-weight:650;
  color:#f2ecdc;background:rgba(46,41,35,.94);border:1px solid rgba(242,236,220,.16);box-shadow:var(--sh);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);animation:tin .3s cubic-bezier(.22,1,.36,1)}
.toast .lamp{width:8px;height:8px}
.toast .lamp.ok{background:#84b28e}
.toast .lamp.warn{background:#d3a763}
.toast .lamp.stop{background:#d38272}
.toast.out{animation:tout .3s ease forwards}
@keyframes tin{from{opacity:0;transform:translateY(14px) scale(.94)}to{opacity:1;transform:none}}
@keyframes tout{to{opacity:0;transform:translateY(8px) scale(.97)}}

/* 登录 */
.gate-wrap{min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:24px;position:relative;z-index:1}
.gate{position:relative;width:min(390px,100%);padding:46px 34px 34px;text-align:center;border-radius:22px;overflow:hidden;
  background:linear-gradient(158deg,rgba(255,253,246,.92),rgba(251,247,237,.82) 58%,rgba(255,253,246,.9));
  border:1px solid rgba(96,84,62,.26);box-shadow:var(--sh),var(--inset);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
.gate::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(80% 55% at 50% -12%,rgba(96,84,62,.08),transparent 62%)}
.gmark{position:relative;width:64px;height:64px;margin:0 auto 18px;border-radius:16px;display:grid;place-items:center;color:var(--accent);
  background:rgba(60,90,112,.07);border:1px solid rgba(60,90,112,.3)}
.gmark svg{width:30px;height:30px}
.gate h1{position:relative;font-size:22px;font-weight:700;letter-spacing:.1em}
.gate p{position:relative;font-size:11.5px;color:var(--ink-3);letter-spacing:.2em;margin:9px 0 24px;font-weight:700}
.gate form{position:relative}
.gate input{width:100%;padding:14px 16px;font-size:15px;font-family:var(--fm);color:var(--ink);background:rgba(255,255,255,.72);
  border:1px solid rgba(96,84,62,.28);border-radius:12px;outline:none;transition:border-color .2s,box-shadow .2s}
.gate input:focus{border-color:rgba(60,90,112,.6);box-shadow:0 0 0 4px rgba(60,90,112,.12)}
.gate input::placeholder{color:var(--ink-3)}
.gate-err{position:relative;display:flex;align-items:center;gap:9px;margin-bottom:14px;padding:10px 14px;border-radius:11px;
  font-size:12.5px;font-weight:650;letter-spacing:.04em;color:var(--stop);
  background:rgba(176,52,38,.07);border:1px solid rgba(176,52,38,.3);animation:shake .4s cubic-bezier(.36,.07,.19,.97)}
.gate-err .lamp{width:7px;height:7px;border-radius:50%;flex:none;background:var(--stop)}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(3px)}30%,50%,70%{transform:translateX(-5px)}40%,60%{transform:translateX(5px)}}
.gate input[aria-invalid="true"]{border-color:rgba(176,52,38,.55);box-shadow:0 0 0 4px rgba(176,52,38,.1)}
.gate .btn{position:relative;width:100%;margin-top:12px;padding:14px;font-size:14px;letter-spacing:.2em;border-radius:12px;color:#f7f2e4;
  background:linear-gradient(120deg,var(--accent),var(--accent-2));border-color:transparent;box-shadow:0 12px 26px -14px rgba(43,66,87,.55)}
.gate .btn:hover{color:#f7f2e4;background:linear-gradient(120deg,#4a6f89,var(--accent));border-color:transparent}

a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:10px}

/* 跳主内容 · 键盘无障碍 */
.skip{position:absolute;left:12px;top:-60px;z-index:120;display:inline-flex;align-items:center;gap:8px;
  padding:10px 18px;border-radius:999px;font-size:13px;font-weight:650;letter-spacing:.08em;
  color:var(--accent);background:rgba(255,253,246,.96);border:1px solid rgba(60,90,112,.4);
  box-shadow:var(--sh);transition:top .18s cubic-bezier(.22,1,.36,1)}
.skip:focus{top:12px}
.wrap:focus{outline:none}

/* 空态 */
.log-empty{padding:34px 16px;text-align:center;font-family:var(--fm);font-size:12px;letter-spacing:.06em;color:rgba(161,151,127,.75)}
.empty{color:var(--ink-3);font-size:12.5px;padding:26px 16px;text-align:center;letter-spacing:.08em}

/* 打印 · 运维存档 */
@media print{
  .sky,.mts,.haze,.tabs,.out-btn,.toasts,.nav-cap,.pulse,.lk .go{display:none!important}
  body{background:#fff;font-size:12px}
  .wrap{max-width:none;padding:0}
  .hero-h{margin:0 0 14px}
  .hero-h h1{font-size:22px}
  .card,.deck,.gate{box-shadow:none;backdrop-filter:none;border-color:#c9c2b2;background:#fff}
  .card::after,.deck::before{display:none}
  .deck{color:#2e2924;--ink:#2e2924;--ink-2:#5c5347;--ink-3:#8d8272;--accent:#3c5a70;--accent-2:#2b4257;
    --ok:#4a7c59;--warn:#a97a2f;--stop:#b03426;--edge:#c9c2b2;--edge-2:#ddd6c6;--pill:transparent;--pill-h:transparent}
  .term{background:#fff;border-color:#c9c2b2}
  .tbar{background:#f7f4ec}
  .tbar .tt,.tbar .rt{color:#8d8272}
  .tdot{border:1px solid rgba(0,0,0,.18)}
  .log,.log-row,.msg,.ln,.ts{color:#2e2924}
  .log-row:nth-child(odd){background:#faf8f2}
  .sev{color:#5c5347;background:#f0ede4;border-color:#c9c2b2}
  .sev.WARN{color:#a97a2f}.sev.ERROR,.sev.CRITICAL{color:#b03426}
  .lamp{box-shadow:0 0 0 1px rgba(0,0,0,.25)}
  .row-head{border-bottom-color:#c9c2b2}
  @page{margin:14mm}
}

/* 响应式 */
@media (min-width:1440px){
  .wrap{max-width:1400px;padding:32px 32px 64px}
  body{font-size:15px}
  .hero-h h1{font-size:34px}
  .hero-h p{font-size:14px}
  .tabs{margin-bottom:24px}
  .tab{font-size:14px;padding:11px 22px}
  .bento{gap:20px}
  .deck{padding:28px 30px}
  .deck-in{gap:34px}
  .ring{width:150px;height:150px}
  .ring .mid b{font-size:38px}
  .dcell .v{font-size:30px}
  .chead{padding:19px 24px 0}
  .cbody{padding:18px 24px 24px}
  .chead h2{font-size:14.5px}
  .tile-grid{grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}
  .link-grid{grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
  .svc h3,.lk h3{font-size:15.5px}
  .spark{height:124px}
  .fv{font-size:29px}
}
@media (min-width:1800px){
  .wrap{max-width:1640px}
  .ring{width:164px;height:164px}
  .tile-grid{grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
}
@media (max-width:1120px){
  .bento{grid-template-columns:minmax(0,1fr)}
  .b-trend{grid-column:auto}
  .trend{grid-template-columns:1fr 1fr}
  .tbox:nth-child(3){grid-column:1 / -1}
}
@media (max-width:820px){
  .deck-in{grid-template-columns:auto minmax(0,1fr);gap:18px}
  .deck .dcell.disk{grid-column:2}
  .trend{grid-template-columns:1fr;gap:16px}
  .tbox:nth-child(3){grid-column:auto}
  .f2b{grid-template-columns:1fr 1fr}
}
@media (max-width:640px){
  .wrap{padding:20px 14px 96px}
  .out-btn{top:16px;right:14px}
  .hero-h{margin:30px 0 18px}
  .hero-h h1{font-size:24px}
  .tabs{position:fixed;left:12px;right:12px;bottom:calc(12px + env(safe-area-inset-bottom));width:auto;margin:0;
    display:grid;grid-template-columns:repeat(5,1fr);gap:0;padding:6px 4px;border-radius:22px;z-index:80;
    background:rgba(250,246,237,.94);overflow:visible;
    backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
    box-shadow:0 -8px 28px -14px rgba(84,68,44,.4),var(--inset);border-color:var(--edge)}
  .tab{flex-direction:column;gap:4px;padding:8px 2px 7px;font-size:10.5px;letter-spacing:.06em;border-radius:15px}
  .tab svg{width:19px;height:19px}
  .tab[aria-selected="true"]::before{background:rgba(60,90,112,.1);border-color:transparent}
  .tbadge{display:none}
  .tab .tdot{display:none}
  .tab.has-warn .tdot{display:block}
  .nav-cap{display:block;text-align:center;font-family:var(--fm);font-size:9.5px;letter-spacing:.2em;
    text-transform:uppercase;color:var(--ink-3);margin:-6px 0 14px}
  .deck{padding:20px 16px}
  .deck-in{grid-template-columns:1fr 1fr;gap:14px 16px;justify-items:stretch}
  .ring{width:118px;height:118px;grid-column:1 / -1;justify-self:center}
  .ring .mid b{font-size:30px}
  .deck .dcell.disk{grid-column:auto}
  .dcell .v{font-size:22px}
  .dcell .s{font-size:10.5px}
  .deck-foot{justify-content:center;flex-wrap:wrap;gap:8px}
  .badge{font-size:11.5px;padding:5px 12px}
  .chead{padding:15px 16px 0}
  .cbody{padding:13px 16px 16px}
  .tile-grid,.link-grid{grid-template-columns:minmax(0,1fr)}
  .btn.sm{padding:8px 15px;font-size:12px}
  .log{max-height:52vh}
  .log-row{min-width:0;flex-wrap:wrap;gap:4px 12px;padding:9px 12px 9px 0}
  .ln{width:32px;padding-right:9px}
  .msg{white-space:normal;word-break:break-word;flex-basis:100%;padding-left:41px}
  .row-head{display:none}
  .row-l{grid-template-columns:none;display:flex;flex-wrap:wrap;gap:2px 12px;align-items:baseline;padding:11px 0}
  .row-l .sv{width:100%}
  .toasts{left:14px;right:14px;bottom:calc(86px + env(safe-area-inset-bottom));align-items:stretch}
  .toast{max-width:none}
}
@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}
}
</style>
</head>
<body{% if not logged %} class="login"{% endif %}>
<div class="sky" aria-hidden="true"></div>
<div class="mts" aria-hidden="true">
  <svg viewBox="0 0 1440 420" preserveAspectRatio="none">
    <path d="M0 210 C 130 150 230 118 330 156 C 430 194 500 128 615 108 C 740 86 820 160 940 150 C 1070 139 1150 84 1270 116 C 1350 137 1400 168 1440 156 L 1440 420 L 0 420 Z" fill="rgba(74,66,52,.06)"/>
    <path d="M0 288 C 150 236 280 262 400 240 C 545 213 640 258 760 246 C 900 232 1010 190 1130 222 C 1250 254 1350 242 1440 262 L 1440 420 L 0 420 Z" fill="rgba(66,58,45,.1)"/>
    <path d="M0 356 C 170 320 320 342 470 330 C 640 316 760 350 900 342 C 1060 332 1200 302 1320 330 C 1375 343 1412 352 1440 348 L 1440 420 L 0 420 Z" fill="rgba(52,45,34,.16)"/>
  </svg>
</div>
<div class="haze" aria-hidden="true"></div>
{% if not logged %}
<div class="gate-wrap">
  <div class="gate">
    <span class="gmark" aria-hidden="true"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2.6 16.4 6.3v7.4L10 17.4 3.6 13.7V6.3Z"/><circle cx="10" cy="10" r="1.6" fill="currentColor" stroke="none"/></svg></span>
    <h1>服务器管理台</h1>
    <p>请输入访问密码</p>
    <form method="post">
      {% if err %}<p class="gate-err" role="alert"><span class="lamp stop" aria-hidden="true"></span>密码不正确，请重试</p>{% endif %}
      <input type="password" name="pwd" placeholder="密码" autofocus autocomplete="current-password"{% if err %} aria-invalid="true"{% endif %}>
      <button class="btn" type="submit">进入控制台</button>
    </form>
  </div>
</div>
{% else %}
<a class="skip" href="#main">跳到主内容</a>
<svg xmlns="http://www.w3.org/2000/svg" style="display:none" aria-hidden="true">
  <symbol id="i-bot" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4.4" y="6.8" width="11.2" height="8.4" rx="2.4"/><path d="M10 6.8V4.1"/><circle cx="10" cy="3.2" r="0.9"/><path d="M8.1 10.4v1.5"/><path d="M11.9 10.4v1.5"/><path d="M8.4 13.4h3.2"/></symbol>
  <symbol id="i-frp" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3.4 10h11.9"/><path d="M13.6 8.3 15.4 10l-1.8 1.7"/><path d="M12.4 3.1v4.5"/><path d="M12.4 12.4v4.5"/></symbol>
  <symbol id="i-easytier" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="4.9" r="1.7"/><circle cx="4.9" cy="13.2" r="1.7"/><circle cx="15.1" cy="13.2" r="1.7"/><path d="M9.2 6.3 5.7 11.9"/><path d="M10.8 6.3 14.3 11.9"/><path d="M6.6 13.2h6.8"/></symbol>
  <symbol id="i-gaming" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.9" y="7.4" width="14.2" height="7.6" rx="3.6"/><path d="M6.4 9.9v2.6"/><path d="M5.1 11.2h2.6"/><circle cx="13.2" cy="10.4" r="0.55" fill="currentColor" stroke="none"/><circle cx="14.7" cy="12" r="0.55" fill="currentColor" stroke="none"/></symbol>
  <symbol id="i-files" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3.2 6.4a1.7 1.7 0 0 1 1.7-1.7h3.1l1.7 1.9h6a1.7 1.7 0 0 1 1.7 1.7v5.9a1.7 1.7 0 0 1-1.7 1.7H4.9a1.7 1.7 0 0 1-1.7-1.7Z"/></symbol>
  <symbol id="i-fail2ban" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2.9 16.1 5.3v4.4c0 3.5-2.5 5.6-6.1 7.3-3.6-1.7-6.1-3.8-6.1-7.3V5.3Z"/><path d="M7.4 9.7l1.8 1.8 3.5-3.7"/></symbol>
  <symbol id="i-gauge" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4.2 15.1a5.8 5.8 0 0 1 11.6 0"/><path d="M10 15.1l3-4.2"/><circle cx="10" cy="15.1" r="1.05"/></symbol>
  <symbol id="i-grid" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3.2" y="3.2" width="5.6" height="5.6" rx="1.4"/><rect x="11.2" y="3.2" width="5.6" height="5.6" rx="1.4"/><rect x="3.2" y="11.2" width="5.6" height="5.6" rx="1.4"/><rect x="11.2" y="11.2" width="5.6" height="5.6" rx="1.4"/></symbol>
  <symbol id="i-link" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M8.6 11.4a3.4 3.4 0 0 0 4.8 0l2.2-2.2a3.4 3.4 0 0 0-4.8-4.8l-1 1"/><path d="M11.4 8.6a3.4 3.4 0 0 0-4.8 0L4.4 10.8a3.4 3.4 0 0 0 4.8 4.8l1-1"/></symbol>
  <symbol id="i-term" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4.2" width="14" height="11.6" rx="2"/><path d="M6.4 8.2l2.1 2.1-2.1 2.1"/><path d="M10.2 12.9h3.6"/></symbol>
  <symbol id="i-shield" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2.9 16.1 5.3v4.4c0 3.5-2.5 5.6-6.1 7.3-3.6-1.7-6.1-3.8-6.1-7.3V5.3Z"/><path d="M7.4 9.7l1.8 1.8 3.5-3.7"/></symbol>
  <symbol id="i-arrow" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6.8 13.2 13.2 6.8"/><path d="M8.4 6.8h4.8v4.8"/></symbol>
  <symbol id="i-out" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12.3 3.6h2.5a1.7 1.7 0 0 1 1.7 1.7v9.4a1.7 1.7 0 0 1-1.7 1.7h-2.5"/><path d="M4.2 10h7.9"/><path d="M9.5 7.5 12 10l-2.5 2.5"/></symbol>
</svg>

<div class="wrap" id="main" tabindex="-1">
  <a class="btn out-btn" href="/logout" aria-label="退出登录"><svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true"><use href="#i-out"/></svg>退出</a>
  <header class="hero-h">
    <h1>欢迎回来<span class="seal" aria-hidden="true">印</span></h1>
    <p>{{s.host}} · 本地服务已准备就绪</p>
    <p class="stamp"><span class="pulse" id="pulse" aria-hidden="true"></span><b id="clk-hm">{{s.time_hm}}</b><span id="clk-date">{{s.time_date}}</span></p>
  </header>

  <div class="tabs" role="tablist" aria-label="控制台分区">
    <button type="button" class="tab" role="tab" id="tb-overview" data-panel="overview" aria-selected="true" aria-controls="overview"><svg viewBox="0 0 20 20" aria-hidden="true"><use href="#i-gauge"/></svg>概览</button>
    <button type="button" class="tab" role="tab" id="tb-services" data-panel="services" aria-selected="false" aria-controls="services" tabindex="-1"><svg viewBox="0 0 20 20" aria-hidden="true"><use href="#i-grid"/></svg>服务<span class="tbadge" id="tab-svc-n">{{s.n_ok}}/{{s.n_total}}</span><span class="tdot" aria-hidden="true"></span></button>
    <button type="button" class="tab" role="tab" id="tb-links" data-panel="links" aria-selected="false" aria-controls="links" tabindex="-1"><svg viewBox="0 0 20 20" aria-hidden="true"><use href="#i-link"/></svg>入口</button>
    <button type="button" class="tab" role="tab" id="tb-logs" data-panel="logs" aria-selected="false" aria-controls="logs" tabindex="-1"><svg viewBox="0 0 20 20" aria-hidden="true"><use href="#i-term"/></svg>日志</button>
    <button type="button" class="tab" role="tab" id="tb-security" data-panel="security" aria-selected="false" aria-controls="security" tabindex="-1"><svg viewBox="0 0 20 20" aria-hidden="true"><use href="#i-shield"/></svg>安全</button>
  </div>
  <p class="nav-cap" aria-hidden="true">点按切换 · 数据每 5 秒同步</p>

  <!-- 概览 -->
  <section class="panel active bento" id="overview" role="tabpanel" aria-labelledby="tb-overview">
    <div class="span3">
      <div class="deck">
        <div class="deck-in">
          <div class="ring">
            <svg viewBox="0 0 100 100" id="g-cpu" role="img" aria-label="CPU 占用 {{s.cpu_pct}}%"><circle class="tr" cx="50" cy="50" r="42"/><circle class="vv" cx="50" cy="50" r="42"/></svg>
            <p class="mid"><b id="cpu-num">{{s.cpu_pct}}</b><i>CPU</i></p>
          </div>
          <div class="dcell">
            <p class="k">内存</p>
            <p class="v"><span id="mem-num">{{s.mem.pct}}</span><small>%</small></p>
            <p class="s" id="mem-tail">{{s.mem.used}} / {{s.mem.total}} MB</p>
            <div class="bar"><i id="mem-bar" style="--f:{{s.mem.pct}}%"></i></div>
          </div>
          <div class="dcell disk">
            <p class="k">磁盘 /</p>
            <p class="v"><span id="disk-num">{{s.disk.pct}}</span><small>%</small></p>
            <p class="s" id="disk-tail">{{s.disk.used}} / {{s.disk.size}}</p>
            <div class="bar"><i id="disk-bar" style="--f:{{s.disk.pct}}%"></i></div>
          </div>
        </div>
        <div class="deck-foot">
          <span class="badge" id="top-chip"><span class="lamp ok" aria-hidden="true"></span><span id="chip-txt">{{'全部运行中' if s.all_ok else s.n_ok ~ ' / ' ~ s.n_total ~ ' 运行中'}}</span></span>
          <span class="badge" id="load-badge">负载 {{s.load.m1}} · {{s.load.m5}}</span>
          <span class="badge" id="avail-badge">可用 {{s.mem.avail}} MB</span>
        </div>
      </div>
    </div>

    <section class="card b-trend">
      <div class="chead"><h2>实时趋势</h2><span class="cnote">4 min · 5s</span></div>
      <div class="cbody">
        <div class="trend">
          <div class="tbox"><header><h3>CPU 使用率</h3><span class="tv" id="tv-cpu">{{s.cpu_pct}}%</span></header><canvas class="spark" id="sp-cpu" aria-hidden="true"></canvas></div>
          <div class="tbox"><header><h3>内存使用率</h3><span class="tv" id="tv-mem">{{s.mem.pct}}%</span></header><canvas class="spark" id="sp-mem" aria-hidden="true"></canvas></div>
          <div class="tbox"><header><h3>系统负载</h3><span class="tv" id="tv-load">{{s.load.m1}}</span></header><canvas class="spark" id="sp-load" aria-hidden="true"></canvas></div>
        </div>
      </div>
    </section>

    <aside class="card">
      <div class="chead"><h2>主机信息</h2><span class="cnote">sync <span id="sync-txt">刚刚</span></span></div>
      <div class="cbody meta">
        <dl>
          <div><dt>主机名</dt><dd>{{s.host}}</dd></div>
          <div><dt>内核</dt><dd>{{s.kernel}}</dd></div>
          <div><dt>核心</dt><dd>{{s.ncpu}} 核</dd></div>
          <div><dt>内存</dt><dd>{{s.mem.total}} MB</dd></div>
          <div><dt>运行</dt><dd id="up-val">{% if s.up %}{{s.up.d}}天{{s.up.h}}时{% else %}-{% endif %}</dd></div>
        </dl>
      </div>
    </aside>
  </section>

  <!-- 服务 -->
  <section class="panel" id="services" role="tabpanel" aria-labelledby="tb-services">
    <div class="card">
      <div class="chead">
        <h2>服务状态</h2>
        <span class="cnote"><span class="lamp {{'ok' if s.all_ok else 'warn'}}" id="svc-lamp" aria-hidden="true" style="display:inline-block;margin-right:7px"></span><span id="svc-count">{{s.n_ok}} / {{s.n_total}}</span></span>
      </div>
      <div class="cbody">
        <div class="tile-grid">
          {% for code, desc, icon in s.services %}
          <article class="svc" data-svc="{{code}}" data-st="{{'on' if s.states[code] == 'active' else ('busy' if s.states[code] == 'activating' else 'off')}}">
            <div class="svc-top">
              <span class="ico" aria-hidden="true"><svg><use href="#i-{{icon}}"/></svg></span>
              <div style="min-width:0">
                <h3>{{desc}}</h3>
                <p class="pkg">{{code}}</p>
              </div>
            </div>
            <div class="svc-bot">
              <span class="st{{'' if s.states[code] == 'active' else (' warn' if s.states[code] == 'activating' else ' off')}}" id="st-{{code}}"><span class="lamp {{'ok' if s.states[code] == 'active' else ('warn' if s.states[code] == 'activating' else 'stop')}}" aria-hidden="true"></span><span>{{s.labels[code]}}</span></span>
              <button type="button" class="btn restart sm" data-restart="{{code}}" aria-label="重启 {{desc}}">重启</button>
            </div>
          </article>
          {% endfor %}
        </div>
      </div>
    </div>
  </section>

  <!-- 入口 -->
  <section class="panel" id="links" role="tabpanel" aria-labelledby="tb-links">
    <div class="card">
      <div class="chead"><h2>快捷入口</h2><span class="cnote">浏览器实时探测</span></div>
      <div class="cbody">
        <div class="link-grid">
          {% for name, url, icon in s.links %}
          <a class="lk" href="{{url}}" target="_blank" rel="noopener" aria-label="打开 {{name}}">
            <span class="ico" aria-hidden="true"><svg><use href="#i-{{icon}}"/></svg></span>
            <div style="min-width:0">
              <h3>{{name}}</h3>
              <p class="addr">{{url|replace('http://', '')}}</p>
            </div>
            <span class="rt">
              <span class="pchip">{{url.rsplit(':', 1)[-1] if ':' in url.split('//', 1)[-1] else '80'}}</span>
              <span class="probe" id="pb-{{loop.index0}}"><span class="lamp" aria-hidden="true"></span>检测中</span>
            </span>
          </a>
          {% endfor %}
        </div>
      </div>
    </div>
  </section>

  <!-- 日志 -->
  <section class="panel" id="logs" role="tabpanel" aria-labelledby="tb-logs">
    <div class="card">
      <div class="chead"><h2>服务日志</h2><span class="cnote">tail 30 · 15s</span></div>
      <div class="cbody">
        <div class="term">
          <div class="tbar"><span class="tdot r"></span><span class="tdot y"></span><span class="tdot g"></span><span class="tt">journalctl -u 服务</span><span class="rt" id="log-meta">{{s.logs|length}} 行</span></div>
          <div class="log" id="log-box" role="log" aria-label="服务最近日志">
            {% for ln, ts, sev, msg in s.logs %}
            <div class="log-row">
              <span class="ln">{{ln}}</span>
              <span class="ts">{{ts}}</span>
              <span class="sev {{sev}}">{{sev}}</span>
              <span class="msg">{{msg}}</span>
            </div>
            {% else %}
            <div class="log-empty">暂无日志输出 · 服务可能刚启动</div>
            {% endfor %}
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- 安全 -->
  <section class="panel" id="security" role="tabpanel" aria-labelledby="tb-security">
    <div class="bento">
      <div class="card span3">
        <div class="chead"><h2>Fail2ban 防爆破</h2>
          <span class="chip{{'' if s.states['fail2ban'] == 'active' else ' stop'}}"><span class="lamp {{'ok' if s.states['fail2ban'] == 'active' else 'stop'}}" id="f2b-lamp" aria-hidden="true"></span><span id="f2b-txt">{{'防护中' if s.states['fail2ban'] == 'active' else '未运行'}}</span></span>
        </div>
        <div class="cbody">
          <div class="f2b">
            <div class="fcell"><span class="fl">当前失败</span><span class="fv" id="fb-failed">{{s.fb.failed}}</span></div>
            <div class="fcell"><span class="fl">累计失败</span><span class="fv" id="fb-total">{{s.fb.total_failed}}</span></div>
            <div class="fcell"><span class="fl">当前封禁</span><span class="fv{{ ' hot' if s.fb.banned != '0' }}" id="fb-banned">{{s.fb.banned}}</span></div>
            <div class="fcell"><span class="fl">累计封禁</span><span class="fv" id="fb-tbanned">{{s.fb.total_banned}}</span></div>
          </div>
        </div>
      </div>
      <div class="card span3">
        <div class="chead"><h2>最近登录</h2><span class="cnote">last</span></div>
        <div class="cbody">
          <div class="rows">
            <div class="row-head"><span>用户</span><span>终端</span><span>来源</span><span>时间</span></div>
            {% for r in s.logins %}
            <div class="row-l">
              <span class="v">{{r.user}}</span><span class="v">{{r.tty}}</span><span class="v">{{r.src}}</span>
              {% if r.online %}<span class="sv"><span class="lamp ok" aria-hidden="true"></span>在线</span>{% else %}<span class="sv muted">{{r.when}}</span>{% endif %}
            </div>
            {% else %}
            <div class="empty">暂无登录记录</div>
            {% endfor %}
          </div>
        </div>
      </div>
    </div>
  </section>
</div>
<div class="toasts" id="toasts" aria-live="polite" aria-atomic="false"></div>

<script>
(function(){
"use strict";
var C = 264;
var HIST = {cpu: [], mem: [], load: []};
var MAXH = 48;
var tick = 0, lastSync = Date.now();
var $ = function(id){ return document.getElementById(id); };
var num = function(v){ var n = parseFloat(v); return isNaN(n) ? 0 : n; };

function setRing(pct){
  var v = document.querySelector("#g-cpu .vv");
  if (v) v.style.strokeDashoffset = (C * (1 - Math.max(0, Math.min(100, pct)) / 100)).toFixed(1);
}

function smooth(g, pts){
  for (var i = 0; i < pts.length - 1; i++){
    var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    var c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
    var c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
    g.bezierCurveTo(c1x, c1y, c2x, c2y, p2[0], p2[1]);
  }
}

function drawSpark(id, arr, color, dec){
  var c = $(id);
  if (!c || !c.getContext) return;
  var dpr = window.devicePixelRatio || 1;
  var w = c.clientWidth, h = c.clientHeight;
  if (!w || !h) return;
  if (c.width !== Math.round(w*dpr) || c.height !== Math.round(h*dpr)){
    c.width = Math.round(w*dpr); c.height = Math.round(h*dpr);
  }
  var g = c.getContext("2d");
  g.setTransform(dpr,0,0,dpr,0,0);
  g.clearRect(0,0,w,h);
  var axisL = dec === undefined ? 26 : 30, padT = 7, padB = 5;
  var ih = h - padT - padB;
  var max = arr.length ? Math.max.apply(null, arr) : 0, min = arr.length ? Math.min.apply(null, arr) : 0;
  if (dec === undefined){
    max = Math.max(max, 10); min = Math.min(min, 0);
    if (max - min < 14) max = min + 14;
  } else {
    min = Math.max(0, min);
    if (max - min < .6){ var mid = (max + min) / 2 || .3; max = mid + .3; min = Math.max(0, mid - .3); }
  }
  var pad = (max - min) * 0.12;
  max += pad; min = Math.max(0, min - pad);
  var iw = w - axisL;
  g.strokeStyle = "rgba(96,84,62,.14)"; g.lineWidth = 1;
  g.fillStyle = "rgba(141,130,114,.85)";
  g.font = "9px " + "ui-monospace,monospace";
  g.textAlign = "right"; g.textBaseline = "middle";
  for (var k = 0; k <= 3; k++){
    var yy = Math.round(padT + ih * k / 3) + .5;
    g.beginPath(); g.moveTo(axisL, yy); g.lineTo(w, yy); g.stroke();
    var lv = Math.max(0, max - (max - min) * k / 3);
    g.fillText(dec === undefined ? String(Math.round(lv)) : lv.toFixed(dec), axisL - 7, yy);
  }
  if (arr.length < 2) return;
  var sx = iw / (arr.length - 1), sy = ih / (max - min);
  var pts = [];
  for (var i = 0; i < arr.length; i++) pts.push([axisL + i*sx, padT + ih - (arr[i] - min) * sy]);
  g.beginPath(); g.moveTo(pts[0][0], padT + ih); g.lineTo(pts[0][0], pts[0][1]);
  smooth(g, pts);
  g.lineTo(w, padT + ih); g.closePath();
  var gr = g.createLinearGradient(0, padT, 0, padT + ih);
  gr.addColorStop(0, color + "55"); gr.addColorStop(1, color + "05");
  g.fillStyle = gr; g.fill();
  g.beginPath(); g.moveTo(pts[0][0], pts[0][1]); smooth(g, pts);
  g.strokeStyle = color; g.lineWidth = 2; g.lineJoin = "round"; g.lineCap = "round"; g.stroke();
  var last = pts[pts.length - 1];
  g.beginPath(); g.arc(last[0] - 1, last[1], 6.5, 0, 6.2832); g.fillStyle = color + "2e"; g.fill();
  g.beginPath(); g.arc(last[0] - 1, last[1], 3, 0, 6.2832); g.fillStyle = color; g.fill();
}
function push(arr, v){ arr.push(v); while (arr.length > MAXH) arr.shift(); }
function renderSparks(){
  drawSpark("sp-cpu", HIST.cpu, "#3c5a70");
  drawSpark("sp-mem", HIST.mem, "#7a6f5c");
  drawSpark("sp-load", HIST.load, "#b03426", 1);
}

function toast(msg, kind){
  var box = $("toasts");
  if (!box) return;
  var t = document.createElement("div");
  t.className = "toast";
  var l = document.createElement("span"); l.className = "lamp " + (kind || "ok");
  var s = document.createElement("span"); s.textContent = msg;
  t.appendChild(l); t.appendChild(s); box.appendChild(t);
  while (box.children.length > 3) box.removeChild(box.firstChild);
  setTimeout(function(){
    t.className = "toast out";
    setTimeout(function(){ if (t.parentNode) t.parentNode.removeChild(t); }, 320);
  }, 3200);
}

var STATE_LABEL = {active:"运行中", inactive:"已停止", failed:"启动失败", activating:"重启中"};
var restarting = {};

function setSvc(code, st){
  var card = document.querySelector('.svc[data-svc="' + code + '"]');
  var pill = $("st-" + code);
  if (!card || !pill) return;
  if (restarting[code] && st !== "active") st = "activating";
  var on = st === "active", busy = st === "activating";
  card.setAttribute("data-st", on ? "on" : (busy ? "busy" : "off"));
  pill.className = "st" + (on ? "" : (busy ? " warn" : " off"));
  pill.innerHTML = '<span class="lamp ' + (on ? "ok" : (busy ? "warn" : "stop")) + '" aria-hidden="true"></span><span>' + (STATE_LABEL[st] || st) + "</span>";
}

function applySys(m){
  setRing(m.cpu_pct);
  $("cpu-num").textContent = m.cpu_pct;
  $("load-badge").textContent = "负载 " + m.load.m1 + " · " + m.load.m5;
  $("mem-num").textContent = m.mem.pct;
  $("mem-tail").textContent = m.mem.used + " / " + m.mem.total + " MB";
  $("mem-bar").style.setProperty("--f", m.mem.pct + "%");
  $("avail-badge").textContent = "可用 " + m.mem.avail + " MB";
  $("disk-num").textContent = m.disk.pct;
  $("disk-tail").textContent = m.disk.used + " / " + m.disk.size;
  $("disk-bar").style.setProperty("--f", m.disk.pct + "%");
  if (m.up) $("up-val").textContent = m.up.d + "天" + m.up.h + "时";
  $("tv-cpu").textContent = m.cpu_pct + "%";
  $("tv-mem").textContent = m.mem.pct + "%";
  $("tv-load").textContent = m.load.m1;
  push(HIST.cpu, m.cpu_pct);
  push(HIST.mem, m.mem.pct);
  push(HIST.load, num(m.load.m1));
  renderSparks();
}

function applySvcs(list){
  var okN = 0, f2 = null;
  for (var i = 0; i < list.length; i++){
    setSvc(list[i].name, list[i].state);
    if (list[i].state === "active") okN++;
    if (list[i].name === "fail2ban") f2 = list[i];
  }
  $("svc-count").textContent = okN + " / " + list.length;
  var all = okN === list.length;
  var tb = $("tab-svc-n");
  tb.textContent = okN + "/" + list.length;
  tb.className = all ? "tbadge" : "tbadge warn";
  $("tb-services").classList.toggle("has-warn", !all);
  $("chip-txt").textContent = all ? "全部运行中" : (okN + " / " + list.length + " 运行中");
  var chip = $("top-chip");
  chip.className = all ? "badge" : "badge warn";
  chip.querySelector(".lamp").className = "lamp " + (all ? "ok" : "warn");
  $("svc-lamp").className = "lamp " + (all ? "ok" : "warn");
  if (f2){
    var on2 = f2.state === "active";
    $("f2b-lamp").className = "lamp " + (on2 ? "ok" : (f2.state === "activating" ? "warn" : "stop"));
    $("f2b-txt").textContent = on2 ? "防护中" : (f2.state === "activating" ? "重启中" : "未运行");
    var pc = $("f2b-txt").parentNode;
    pc.className = "chip" + (on2 ? "" : " stop");
  }
}

function applyClock(iso){
  if (!iso) return;
  var p = iso.split(" ");
  if (p.length > 1){ $("clk-hm").textContent = p[1].slice(0,5); $("clk-date").textContent = p[0]; }
}

function fetchJSON(url, cb){
  var x = new XMLHttpRequest();
  x.open("GET", url, true);
  x.timeout = 12000;
  x.onreadystatechange = function(){
    if (x.readyState !== 4) return;
    if (x.status === 200){
      try { cb(null, JSON.parse(x.responseText)); lastSync = Date.now(); }
      catch (e){ cb(e, null); }
    } else if (x.status === 401 || x.status === 403){ cb(new Error("auth"), null); }
    else { cb(new Error("http " + x.status), null); }
  };
  x.send();
}

var prevBanned = null;
function applyDetail(d){
  if (d.logs){
    var box = $("log-box");
    if (box && d.logs.length){
      var frag = document.createDocumentFragment();
      for (var i = 0; i < d.logs.length; i++){
        var r = d.logs[i], row = document.createElement("div");
        row.className = "log-row";
        var a = document.createElement("span"); a.className = "ln"; a.textContent = r[0];
        var b = document.createElement("span"); b.className = "ts"; b.textContent = r[1];
        var c = document.createElement("span"); c.className = "sev " + r[2]; c.textContent = r[2];
        var e = document.createElement("span"); e.className = "msg"; e.textContent = r[3];
        row.appendChild(a); row.appendChild(b); row.appendChild(c); row.appendChild(e);
        frag.appendChild(row);
      }
      box.textContent = "";
      box.appendChild(frag);
      $("log-meta").textContent = d.logs.length + " 行 · " + (d.time || "").slice(11,19);
    }
  }
  if (d.fb){
    $("fb-failed").textContent = d.fb.failed;
    $("fb-total").textContent = d.fb.total_failed;
    $("fb-banned").textContent = d.fb.banned;
    $("fb-tbanned").textContent = d.fb.total_banned;
    $("fb-banned").className = "fv" + (num(d.fb.banned) > 0 ? " hot" : "");
    if (prevBanned !== null && num(d.fb.banned) > prevBanned) toast("fail2ban 新增封禁", "warn");
    prevBanned = num(d.fb.banned);
  }
  if (d.logins){
    var rows = document.querySelectorAll("#security .row-l");
    for (var j = 0; j < d.logins.length && j < rows.length; j++){
      var g = d.logins[j], cells = rows[j].children;
      cells[0].textContent = g.user; cells[1].textContent = g.tty; cells[2].textContent = g.src;
      var sv = cells[3];
      if (g.online){ sv.className = "sv"; sv.innerHTML = '<span class="lamp ok" aria-hidden="true"></span>在线'; }
      else { sv.className = "sv muted"; sv.textContent = g.when; }
    }
  }
}

function poll(){
  if (document.hidden) return;
  tick++;
  fetchJSON("/api/status", function(err, d){
    var p = $("pulse");
    if (p){ p.className = "pulse on"; setTimeout(function(){ p.className = "pulse"; }, 280); }
    if (err){ if (err.message === "auth") location.reload(); return; }
    applySys(d.sys); applySvcs(d.services); applyClock(d.sys.time);
    lastSync = Date.now();
  });
  if (tick % 3 === 1) fetchJSON("/api/detail", function(err, d){ if (!err && d) applyDetail(d); });
  for (var k in restarting){
    if (Date.now() - restarting[k] > 15000){ delete restarting[k]; toast(k + " 重启超时，请查看日志", "stop"); }
  }
}

function syncLabel(){
  var s = Math.round((Date.now() - lastSync) / 1000);
  var el = $("sync-txt");
  if (el) el.textContent = s <= 2 ? "刚刚" : (s < 60 ? s + " 秒前" : Math.floor(s/60) + " 分前");
}

function doRestart(code, btn){
  if (restarting[code]) return;
  restarting[code] = Date.now();
  btn.disabled = true; btn.textContent = "重启中";
  setSvc(code, "activating");
  var x = new XMLHttpRequest();
  x.open("POST", "/restart", true);
  x.setRequestHeader("Content-Type", "application/json");
  x.timeout = 60000;
  x.onreadystatechange = function(){
    if (x.readyState !== 4) return;
    setTimeout(function(){
      btn.disabled = false; btn.textContent = "重启";
      delete restarting[code];
      if (x.status === 200) toast(code + " 重启完成", "ok");
      else if (x.status === 0) toast("重启请求超时", "stop");
      poll();
    }, 1200);
  };
  x.ontimeout = function(){ btn.disabled = false; btn.textContent = "重启"; toast(code + " 重启耗时较长", "warn"); };
  x.send(JSON.stringify({svc: code}));
}

document.addEventListener("click", function(e){
  var b = e.target.closest ? e.target.closest("[data-restart]") : null;
  if (b) doRestart(b.getAttribute("data-restart"), b);
});
document.addEventListener("visibilitychange", function(){ if (!document.hidden) poll(); });

/* 入口连通性探测（no-cors fetch：端口通即在线，与页面内容无关） */
var LINKS = [
  {% for name, url, icon in s.links %}"{{url}}"{% if not loop.last %},{% endif %}{% endfor %}
];
function probeLinks(){
  for (var i = 0; i < LINKS.length; i++){
    (function(i){
      var el = $("pb-" + i);
      if (!el) return;
      el.className = "probe";
      el.innerHTML = '<span class="lamp" aria-hidden="true"></span>检测中';
      var done = false;
      var fin = function(ok){
        if (done) return;
        done = true;
        clearTimeout(to);
        el.className = "probe " + (ok ? "ok" : "off");
        el.innerHTML = '<span class="lamp ' + (ok ? "ok" : "stop") + '" aria-hidden="true"></span>' + (ok ? "在线" : "无响应");
      };
      var to = setTimeout(function(){ fin(false); }, 6000);
      try {
        fetch(LINKS[i] + "/", {mode: "no-cors", cache: "no-store"})
          .then(function(){ fin(true); })
          .catch(function(){ fin(false); });
      } catch (e){ fin(false); }
    })(i);
  }
}

/* 分页切换 */
var tabs = [].slice.call(document.querySelectorAll(".tab"));
var curTab = "overview";
function showPanel(name, scroll){
  if (!$(name)) return false;
  curTab = name;
  for (var i = 0; i < tabs.length; i++){
    var on = tabs[i].getAttribute("data-panel") === name;
    tabs[i].setAttribute("aria-selected", on ? "true" : "false");
    tabs[i].tabIndex = on ? 0 : -1;
    if (on && scroll) tabs[i].scrollIntoView({block: "nearest", inline: "center"});
  }
  var ps = document.querySelectorAll(".panel");
  for (var j = 0; j < ps.length; j++) ps[j].classList.toggle("active", ps[j].id === name);
  if (name === "overview") renderSparks();
  if (name === "links") probeLinks();
  return true;
}
function goTab(name, pushHash, scroll){
  if (!showPanel(name, scroll)) return;
  if (pushHash !== false){
    try { history.replaceState(null, "", "#" + name); } catch (e) { location.hash = name; }
  }
  window.scrollTo(0, 0);
}
for (var ti = 0; ti < tabs.length; ti++){
  (function(t){
    t.addEventListener("click", function(){ goTab(t.getAttribute("data-panel"), true, false); });
  })(tabs[ti]);
}
var tabBox = document.querySelector(".tabs");
if (tabBox){
  tabBox.addEventListener("keydown", function(e){
    var idx = -1;
    for (var i = 0; i < tabs.length; i++) if (tabs[i] === document.activeElement) idx = i;
    if (idx < 0) return;
    var n = null;
    if (e.key === "ArrowRight") n = (idx + 1) % tabs.length;
    else if (e.key === "ArrowLeft") n = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") n = 0;
    else if (e.key === "End") n = tabs.length - 1;
    if (n === null) return;
    e.preventDefault();
    tabs[n].focus();
    goTab(tabs[n].getAttribute("data-panel"), true, true);
  });
}
window.addEventListener("hashchange", function(){
  var h = location.hash.replace(/^#/, "");
  if (h && h !== curTab) showPanel(h, true);
});
(function(){
  var h = location.hash.replace(/^#/, "");
  if (h && h !== "overview" && $(h) && $(h).classList.contains("panel")) showPanel(h, false);
})();

HIST.cpu.push({{s.cpu_pct}});
HIST.mem.push({{s.mem.pct}});
HIST.load.push(num("{{s.load.m1}}"));
renderSparks();
window.addEventListener("resize", renderSparks);
setRing({{s.cpu_pct}});
poll();
setInterval(poll, 5000);
setInterval(syncLabel, 1000);
})();
</script>
{% endif %}
</body>
</html>"""

def build_states():
    states = services_status([n for n, _, _ in SERVICES])
    labels = {n: ("运行中" if v == "active" else {"inactive": "已停止", "failed": "启动失败", "activating": "重启中"}.get(v, v or "未知"))
              for n, v in states.items()}
    return states, labels

def build_sys():
    info = sysinfo()
    mem = info.get("mem") or {}
    disk = info.get("disk") or {}
    ld = load_avg()
    ncpu = cpu_count()

    def pct(part, whole):
        try:
            return max(0, min(100, round(part * 100 / whole)))
        except Exception:
            return 0

    mem_total = mem.get("total") or 0
    mem_pct = pct(mem.get("used") or 0, mem_total)
    try:
        disk_pct = int(str(disk.get("percent", "0")).replace("%", ""))
    except Exception:
        disk_pct = 0
    try:
        cpu_pct = max(0, min(100, int(info.get("cpu") or 0)))
    except Exception:
        cpu_pct = 0
    try:
        load_pct = max(0, min(100, round(float(ld["m1"]) * 100 / ncpu)))
    except Exception:
        load_pct = 0
    cpu_show = max(cpu_pct, load_pct)
    up = parse_uptime(info.get("uptime", ""))
    secs = info.get("up_secs")
    if secs is not None:
        up = {"d": secs // 86400, "h": (secs % 86400) // 3600, "m": (secs % 3600) // 60}

    def lv(p):
        return "stop" if p >= 90 else ("warn" if p >= 72 else "ok")

    return {
        "info": info,
        "time": info.get("time", ""),
        "up": up,
        "load": ld,
        "ncpu": ncpu,
        "cpu_pct": cpu_show,
        "cpu_lv": lv(cpu_show),
        "mem": {"used": mem.get("used", "-"), "total": mem_total or "-",
                "avail": mem.get("avail", "-"), "pct": mem_pct},
        "mem_lv": lv(mem_pct),
        "disk": {"used": str(disk.get("used", "-")).rstrip("Gg"), "size": disk.get("size", "-"),
                 "avail": disk.get("avail", "-"), "pct": disk_pct},
        "disk_lv": lv(disk_pct),
        "time_date": info.get("time", "")[:10],
        "time_hm": info.get("time", "")[11:16],
        "kernel": sh("uname -r").split("-")[0],
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if request.form.get("pwd") == ADMIN_PWD or trusted_peer():
            session["ok"] = True
            session.pop("no_auto", None)
            return redirect(url_for("index"))
        return render_template_string(PAGE, logged=False, s={}, err="pwd")
    logged = authed()
    if not logged:
        return render_template_string(PAGE, logged=False, s={})
    states, labels = build_states()
    s = build_sys()
    s.update({
        "host": socket.gethostname(),
        "services": [(n, d, ic) for n, d, ic in SERVICES],
        "states": states,
        "labels": labels,
        "links": [(n, u, ic) for n, u, ic in LINKS],
        "logs": parse_logs(recent_logs(30), 30),
        "logins": parse_logins(last_logins(10), 5),
        "fb": parse_fail2ban(fail2ban_status()),
        "n_ok": sum(1 for v in states.values() if v == "active"),
        "n_total": len(SERVICES),
        "all_ok": all(v == "active" for v in states.values()),
    })
    return render_template_string(PAGE, logged=True, s=s)

@app.route("/api/status")
def api_status():
    if not authed():
        return jsonify({"error": "unauthorized"}), 401
    states, _labels = build_states()
    sysd = build_sys()
    return jsonify({
        "ok": True,
        "time": sysd["info"]["time"],
        "host": socket.gethostname(),
        "services": [{"name": n, "desc": d, "state": states.get(n, "unknown")} for n, d, _ in SERVICES],
        "sys": {k: sysd[k] for k in ("time", "load", "ncpu", "cpu_pct", "mem", "disk", "up",
                                     "time_date", "time_hm", "kernel")},
        "n_ok": sum(1 for v in states.values() if v == "active"),
        "n_total": len(SERVICES),
        "all_ok": all(v == "active" for v in states.values()),
    })

@app.route("/api/detail")
def api_detail():
    if not authed():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "ok": True,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "logs": parse_logs(recent_logs(30), 30),
        "logins": parse_logins(last_logins(10), 5),
        "fb": parse_fail2ban(fail2ban_status()),
    })

@app.route("/restart", methods=["POST", "GET"])
def restart():
    if not authed():
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("index"))
    if request.method == "POST" and request.is_json:
        svc = (request.get_json(silent=True) or {}).get("svc", "")
    else:
        svc = request.form.get("svc", "")
    allowed = [n for n, _, _ in SERVICES]
    if svc not in allowed:
        return jsonify({"error": "bad service"}), 400
    r = subprocess.run(f"systemctl restart {svc}", shell=True, capture_output=True, text=True, timeout=90)
    state = service_status(svc)
    if request.method == "GET" and "application/json" not in request.headers.get("Accept", ""):
        return redirect(url_for("index"))
    return jsonify({"ok": r.returncode == 0, "svc": svc, "state": state,
                    "stderr": (r.stderr or "")[:300]})

@app.route("/logout")
def logout():
    session.pop("ok", None)
    if trusted_peer():
        session["no_auto"] = True   # 内网免密下也要能真退出
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host=LAN_IP, port=PANEL_PORT, debug=False)
