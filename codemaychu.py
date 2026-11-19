# -*- coding: utf-8 -*-
"""HMI máy chủ tầng 3: giám sát/điều khiển tầng 2 qua Ethernet TCP/IP, HTTP và JSON
(Chạy cổng 8080, tích hợp sẵn link Ngrok, Mã QR Máy điều khiển, Phân quyền, Bảo mật mật khẩu & Cảnh báo đồng bộ COM)."""
import os
import json
import time
import hashlib
import secrets
import threading
import socket
from datetime import datetime
from urllib.parse import urlparse
import requests
from flask import Flask, jsonify, request, render_template_string, session

HOST = "0.0.0.0"
PORT = int(os.environ.get("TIER3_PORT", "8080"))
TIER2_URL = os.environ.get("TIER2_URL", "http://127.0.0.1:5000").rstrip("/")
PUBLIC_NGROK_URL = os.environ.get("PUBLIC_NGROK_URL", "https://grit-stove-dexterous.ngrok-free.dev").rstrip("/")
LEASE_SECONDS = int(os.environ.get("CONTROL_LEASE_SECONDS", "20"))
POLL_SECONDS = float(os.environ.get("TIER2_POLL_SECONDS", "1.5"))
HTTP_TIMEOUT = float(os.environ.get("TIER3_HTTP_TIMEOUT", "4.0"))
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "hmi-tier2-tier3-secret-2026")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECURITY_FILE = os.path.join(BASE_DIR, "tier3_security.json")

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=86400 * 7
)

http = requests.Session()
http.headers.update({"X-Internal-Key": INTERNAL_API_KEY})
lock = threading.RLock()
command_lock = threading.RLock()


# ==================== QUẢN LÝ MẬT KHẨU & PHIÊN ĐĂNG NHẬP ====================
def _hash_password(raw_pass: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{raw_pass}".encode("utf-8")).hexdigest()


def _load_security_cfg() -> dict:
    default_salt = secrets.token_hex(16)
    default_admin = os.environ.get("TIER3_ADMIN_PASS", "admin123")
    default_mobile = os.environ.get("TIER3_MOBILE_PASS", "123456")
    cfg = {
        "secret_key": secrets.token_hex(32),
        "salt": default_salt,
        "admin_hash": _hash_password(default_admin, default_salt),
        "mobile_hash": _hash_password(default_mobile, default_salt),
        "auth_version": 1
    }
    if os.path.exists(SECURITY_FILE):
        try:
            with open(SECURITY_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                cfg.update(saved)
        except Exception:
            pass
    else:
        _save_security_cfg(cfg)
    return cfg


def _save_security_cfg(cfg: dict):
    try:
        with open(SECURITY_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


sec_cfg = _load_security_cfg()
app.secret_key = sec_cfg["secret_key"]

# Chống dò mật khẩu theo (IP, User-Agent)
login_attempts = {}
MAX_LOGIN_FAILS = 5
LOCKOUT_SECONDS = 60


def _client_fingerprint() -> str:
    fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    ip = fwd or request.remote_addr or "unknown"
    ua = (request.headers.get("User-Agent") or "")[:40]
    return f"{ip}|{ua}"


def _is_session_valid(required_role: str = "any") -> bool:
    role = session.get("t3_role")
    ver = session.get("t3_ver")
    if not role or ver != sec_cfg.get("auth_version", 1):
        return False
    if required_role == "admin":
        return role == "admin"
    return role in ("admin", "mobile")


@app.after_request
def add_ngrok_headers(response):
    response.headers["ngrok-skip-browser-warning"] = "true"
    return response


@app.before_request
def enforce_security():
    path = request.path or "/"
    if path in ("/api/login", "/api/logout", "/favicon.ico"):
        return None

    # Cho phép giao tiếp nội bộ giữa Tầng 2 và Tầng 3 qua khóa bí mật
    if request.headers.get("X-Internal-Key") == INTERNAL_API_KEY:
        return None

    # Phân quyền các nhóm API
    if path.startswith("/api/"):
        admin_only_prefixes = ("/api/server/", "/api/tier2/", "/api/tier3/", "/api/security/")
        if any(path.startswith(p) for p in admin_only_prefixes):
            if not _is_session_valid("admin"):
                return jsonify({"ok": False, "auth_required": True, "error": "Phiên quản trị hết hạn hoặc không có quyền"}), 401
        else:
            if not _is_session_valid("any"):
                return jsonify({"ok": False, "auth_required": True, "error": "Vui lòng đăng nhập mật khẩu để tiếp tục"}), 401
    return None


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


# Các thông số cấu hình Máy chủ Tầng 3
tier2_url = TIER2_URL
lease_seconds = LEASE_SECONDS
poll_seconds = POLL_SECONDS
http_timeout = HTTP_TIMEOUT

# Lưu cấu hình kết nối của Máy điều khiển Tầng 2
t2_conn_cfg = {
    "conn_type": "Serial Port",
    "port": "COM6",
    "baud": 9600,
    "databits": 8,
    "parity": "N",
    "stopbits": 1,
    "mode": "RTU",
    "timeout_ms": 1000,
    "delay_ms": 10,
    "ip_addr": "127.0.0.1",
    "tcp_port": 502,
    "conn_timeout_ms": 3000
}

link_enabled = False
node = {"online": False, "state": None, "error": "Chưa kết nối tầng 2", "last_seen": None}
lease = {"client_id": None, "label": None, "since": None, "last_seen": 0.0}
server_override = False
grant_all = False

# Trạng thái thanh thông báo đồng bộ khi chưa kết nối cổng COM
com_alert = {
    "active": False,
    "id": 0,
    "source": "",
    "device": "",
    "time": "",
    "message": ""
}

# ==================== TRANG ĐĂNG NHẬP BẢO MẬT ====================
LOGIN_PAGE = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Xác thực bảo mật - {{ title }}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif}
body{background:#081426;color:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}
.box{background:#12243c;border:1px solid #28415f;border-radius:14px;padding:26px 24px;width:100%;max-width:400px;box-shadow:0 18px 40px rgba(0,0,0,.55)}
.icon{font-size:38px;text-align:center;margin-bottom:10px}
h2{text-align:center;font-size:19px;margin-bottom:6px}
p.sub{text-align:center;color:#9bb0c8;font-size:13px;margin-bottom:18px;line-height:1.45}
label{display:block;font-size:12.5px;color:#cbd5e1;margin-bottom:6px;font-weight:600}
input{width:100%;padding:11px 13px;border-radius:8px;border:1px solid #334e68;background:#091526;color:#fff;font-size:15px;outline:none;margin-bottom:14px}
input:focus{border-color:#38bdf8}
button{width:100%;padding:11px;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:15px;font-weight:700;cursor:pointer;transition:.15s}
button:hover{filter:brightness(1.12)}
button:disabled{opacity:.5;cursor:not-allowed}
.err{background:rgba(239,68,68,.18);border:1px solid #f87171;color:#fecaca;padding:9px 12px;border-radius:8px;font-size:13px;margin-bottom:14px;display:none}
.hint{margin-top:14px;text-align:center;font-size:11.5px;color:#64748b}
</style></head><body>
<div class="box">
  <div class="icon">🔐</div>
  <h2>{{ title }}</h2>
  <p class="sub">{{ subtitle }}</p>
  <div id="errBox" class="err"></div>
  <form onsubmit="doLogin(event)">
    <label for="pwd">Mật khẩu truy cập</label>
    <input type="password" id="pwd" placeholder="Nhập mật khẩu..." autocomplete="current-password" autofocus required>
    <button type="submit" id="btnSubmit">Mở khóa hệ thống</button>
  </form>
  <div class="hint">Hệ thống giám sát & điều khiển công nghiệp Modbus RTU</div>
</div>
<script>
async function doLogin(e){
  e.preventDefault();
  const btn=document.getElementById('btnSubmit');
  const err=document.getElementById('errBox');
  const pwd=document.getElementById('pwd').value;
  btn.disabled=true; err.style.display='none';
  try{
    const r=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json','ngrok-skip-browser-warning':'true'},
      body:JSON.stringify({target:'{{ target }}',password:pwd})
    });
    const d=await r.json();
    if(!r.ok||!d.ok){
      err.textContent=d.error||'Mật khẩu không chính xác!';
      err.style.display='block';
      document.getElementById('pwd').select();
    }else{
      window.location.reload();
    }
  }catch(ex){
    err.textContent='Lỗi kết nối tới máy chủ!';
    err.style.display='block';
  }finally{
    btn.disabled=false;
  }
}
</script></body></html>'''

PAGE = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HMI Máy chủ tầng 3</title>
<style>
:root{color-scheme:dark;--bg:#081426;--card:#12243c;--subcard:#0d1b30;--line:#28415f;--muted:#9bb0c8;--green:#10b981;--red:#ef4444;--blue:#2563eb}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#f8fafc;font:14px Segoe UI,Arial}.wrap{max-width:1400px;margin:auto;padding:18px}.head{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:14px}.sub,.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}.card h3{margin-top:0;margin-bottom:10px}.kpi{font-size:26px;font-weight:700;margin-top:8px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:8px}.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}.cfg-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px}.cfg-item label{display:block;font-size:12px;color:var(--muted);margin-bottom:3px}button,input,select{font:inherit;border-radius:7px;padding:8px 11px;border:1px solid var(--line);background:#1d3554;color:white}select, .cfg-item input{width:100%}button{cursor:pointer;background:var(--blue);font-weight:600;transition:0.15s}button:hover:not(:disabled){filter:brightness(1.12)}button.red{background:#991b1b}button.green{background:#047857}button.orange{background:#b45309}button.dark{background:#334155}button:disabled,input:disabled,select:disabled{opacity:.4;cursor:not-allowed}.state{padding:5px 9px;border-radius:20px;background:#334155}.on{color:#34d399}.off{color:#fca5a5}.warn{color:#fbbf24}pre{white-space:pre-wrap;word-break:break-word;background:#07101e;border-radius:8px;padding:10px;max-height:220px;overflow:auto;font-size:12px}.log{max-height:220px;overflow:auto;font-size:12px}.log div{padding:6px;border-bottom:1px solid #263c56}

/* THANH THÔNG BÁO ĐỒNG BỘ CHƯA KẾT NỐI CỔNG COM */
.com-alert-bar{display:none;background:linear-gradient(90deg,#7f1d1d,#991b1b);border:1px solid #f87171;color:#fef2f2;padding:11px 16px;border-radius:10px;margin-bottom:14px;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 6px 20px rgba(239,68,68,0.3);animation:pulseBorder 1.8s infinite}
@keyframes pulseBorder{0%,100%{border-color:#f87171}50%{border-color:#fef08a}}

/* 2 KHUNG CHỨC NĂNG ĐIỀU KHIỂN MÁY CHỦ */
.sub-frame{background:var(--subcard);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:12px}
.sub-frame:last-child{margin-bottom:0}
.sub-frame-title{font-size:14px;font-weight:700;color:#38bdf8;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(40,65,95,0.6);padding-bottom:7px}
.perm-btns{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
.perm-btns button{padding:10px 12px;font-size:13.5px;border:2px solid transparent}
.perm-btns button.active-perm{border-color:#f8fafc;box-shadow:0 0 12px rgba(56,189,248,0.35)}
.ctrl-row{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;background:#12243c;border:1px solid var(--line);border-radius:8px;margin-bottom:8px}
.ctrl-row:last-child{margin-bottom:0}
.door-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:8px}

/* THANH GẠT (TOGGLE SWITCH) */
.switch{position:relative;display:inline-block;width:52px;height:28px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background-color:#334155;transition:.25s;border-radius:28px;border:1px solid #475569}
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background-color:#fff;transition:.25s;border-radius:50%}
input:checked + .slider{background-color:#10b981;border-color:#10b981}
input:checked + .slider:before{transform:translateX(24px)}

.qr-box{display:flex;gap:14px;align-items:center;background:#07101e;border:1px solid var(--line);border-radius:10px;padding:12px;flex-wrap:wrap}
.qr-img{width:136px;height:136px;border-radius:8px;border:4px solid #fff;background:#fff;flex-shrink:0}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.74);display:none;align-items:center;justify-content:center;z-index:9999;padding:16px}
.modal-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;max-width:440px;width:100%;text-align:center;box-shadow:0 18px 40px rgba(0,0,0,.6)}
@media(max-width:950px){.grid{grid-template-columns:repeat(2,1fr)}.two,.cfg-grid{grid-template-columns:1fr}}@media(max-width:480px){.grid{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<div class="head">
  <div><h2>🌡️ HMI MÁY CHỦ TẦNG 3 (PORT 8080)</h2><div class="sub">Điều phối máy điều khiển tầng 2 qua Ethernet / Ngrok · HTTP/JSON (Quạt, Bơm, Cửa)</div></div>
  <div class="row" style="margin:0;">
    <button class="green" onclick="openQrModal()">📱 Mã QR Máy điều khiển</button>
    <button class="dark" onclick="openSecModal()">🛡️ Mật khẩu & Bảo mật</button>
    <span class="state" id="net">TCP/IP: chưa kết nối</span>
    <button class="red" onclick="doLogout()">🚪 Đăng xuất</button>
  </div>
</div>

<!-- THANH THÔNG BÁO ĐỒNG BỘ Ở CÁC TẦNG KHI CHƯA KẾT NỐI CỔNG COM -->
<div id="comAlertBar" class="com-alert-bar">
  <div style="display:flex;align-items:center;gap:10px;font-weight:700;font-size:13.5px;">
    <span style="font-size:18px;">⚠️</span>
    <span id="comAlertText">Chưa kết nối cổng COM!</span>
  </div>
  <button class="dark" style="padding:5px 11px;font-size:12px;background:rgba(0,0,0,0.35);border-color:#fca5a5;" onclick="clearComAlert()">Đóng</button>
</div>

<!-- POPUP ĐỔI MẬT KHẨU & THU HỒI PHIÊN -->
<div class="modal-bg" id="secModal" onclick="if(event.target===this)closeSecModal()">
  <div class="modal-card" style="text-align:left;">
    <h3 style="margin-top:0;text-align:center;">🛡️ Quản lý Mật khẩu & Bảo mật</h3>
    <p class="muted" style="font-size:12.5px;margin-bottom:14px;text-align:center;">Bảo vệ link Ngrok/LAN khi bị lộ ra ngoài. Để trống ô mật khẩu nếu không muốn đổi mục đó.</p>
    <div style="margin-bottom:10px;">
      <label class="muted" style="font-size:12px;display:block;margin-bottom:4px;">Mật khẩu Quản trị Máy chủ Tầng 3 (mới):</label>
      <input type="password" id="newAdminPass" style="width:100%;" placeholder="Nhập mật khẩu mới (tối thiểu 4 ký tự)">
    </div>
    <div style="margin-bottom:12px;">
      <label class="muted" style="font-size:12px;display:block;margin-bottom:4px;">Mật khẩu Trạm Di Động QR /mobile-hmi (mới):</label>
      <input type="password" id="newMobilePass" style="width:100%;" placeholder="Nhập mật khẩu mới cho điện thoại">
    </div>
    <div id="secMsg" style="font-size:12.5px;margin-bottom:10px;color:#34d399;"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
      <button class="green" onclick="savePasswords()">💾 Lưu mật khẩu mới</button>
      <button class="orange" onclick="revokeAllSessions()">🚫 Đá tất cả thiết bị</button>
    </div>
    <button class="dark" style="width:100%;" onclick="closeSecModal()">Đóng</button>
  </div>
</div>

<!-- POPUP MÃ QR BIẾN ĐIỆN THOẠI THÀNH MÁY ĐIỀU KHIỂN -->
<div class="modal-bg" id="qrModal" onclick="if(event.target===this)closeQrModal()">
  <div class="modal-card">
    <h3 style="margin-top:0;">📱 Quét mã QR cho Điện thoại (Máy điều khiển)</h3>
    <p class="muted" style="font-size:13px;margin-bottom:12px;">Điện thoại sẽ yêu cầu <b>Mật khẩu Trạm Di Động</b> trước khi mở giao diện điều khiển:</p>
    <img id="qrModalImg" class="qr-img" style="width:210px;height:210px;margin:0 auto 12px auto;" alt="QR Code">
    <div style="font-weight:700;color:#38bdf8;font-size:14px;margin-bottom:10px;word-break:break-all;" id="qrModalUrlTxt">--</div>
    <div style="text-align:left;margin-bottom:12px;">
      <label class="muted" style="font-size:12px;display:block;margin-bottom:4px;">Đổi URL Ngrok hoặc IP LAN của Máy chủ:</label>
      <div style="display:flex;gap:6px;">
        <input id="customQrUrl" style="width:100%;" placeholder="https://grit-stove-dexterous.ngrok-free.dev">
        <button class="dark" onclick="updateQrCode($('customQrUrl').value)">Cập nhật</button>
      </div>
    </div>
    <button class="red" style="width:100%;" onclick="closeQrModal()">Đóng</button>
  </div>
</div>

<div class="two">
  <!-- BẢNG 1: CẤU HÌNH KẾT NỐI MÁY CHỦ TẦNG 3 -->
  <div class="card">
    <h3>⚙️ Cấu hình kết nối Máy chủ Tầng 3</h3>
    <div class="cfg-grid">
      <div class="cfg-item" style="grid-column:span 3;">
        <label>Địa chỉ máy điều khiển tầng 2 (URL HTTP/TCP)</label>
        <input id="url" placeholder="http://127.0.0.1:5000">
      </div>
      <div class="cfg-item">
        <label>Chu kỳ quét Poll (giây)</label>
        <input type="number" id="t3_poll" step="0.1" min="0.2" max="10" value="1.5">
      </div>
      <div class="cfg-item">
        <label>HTTP Timeout (giây)</label>
        <input type="number" id="t3_timeout" step="0.5" min="1" max="20" value="4.0">
      </div>
      <div class="cfg-item">
        <label>Thời gian Lease (giây)</label>
        <input type="number" id="t3_lease" step="1" min="5" max="300" value="20">
      </div>
    </div>
    <div class="row">
      <button class="green" onclick="connectT2()">Kết nối Tầng 2</button>
      <button class="red" onclick="disconnectT2()">Ngắt liên kết</button>
      <button class="dark" onclick="saveT3Config()">Lưu thông số Máy chủ</button>
      <span class="muted" id="linkmsg"></span>
    </div>
    <small class="muted">Ngắt liên kết chỉ ngắt TCP/IP tầng 3–tầng 2, không tự ngắt tiến trình RS485 tại tầng 2.</small>
  </div>

  <!-- BẢNG 2: CẤU HÌNH KẾT NỐI MÁY ĐIỀU KHIỂN TẦNG 2 -->
  <div class="card">
    <h3>🛠️ Cấu hình kết nối Máy điều khiển Tầng 2 (RS485 / Modbus)</h3>
    <div class="cfg-grid">
      <div class="cfg-item">
        <label>Connection</label>
        <select id="t2_conn" onchange="toggleT2Mode()">
          <option value="Serial Port" selected>Serial Port</option>
          <option value="Modbus TCP/IP">Modbus TCP/IP</option>
        </select>
      </div>
      <div class="cfg-item">
        <label>Cổng COM (Tầng 2)</label>
        <div style="display:flex;gap:4px;">
          <select id="t2_port">
            <option value="COM6" selected>COM6</option><option value="COM7">COM7</option><option value="COM17">COM17</option>
          </select>
          <button class="dark" style="padding:6px 10px;" onclick="scanT2Ports()" title="Quét cổng COM từ Tầng 2">↻</button>
        </div>
      </div>
      <div class="cfg-item">
        <label>Baudrate</label>
        <select id="t2_baud">
          <option value="4800">4800 Baud</option><option value="9600" selected>9600 Baud</option>
          <option value="19200">19200 Baud</option><option value="38400">38400 Baud</option>
          <option value="57600">57600 Baud</option><option value="115200">115200 Baud</option>
        </select>
      </div>
      <div class="cfg-item">
        <label>Data bits / Parity / Stop</label>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:4px;">
          <select id="t2_db"><option value="8" selected>8</option><option value="7">7</option></select>
          <select id="t2_par"><option value="N" selected>None</option><option value="E">Even</option><option value="O">Odd</option></select>
          <select id="t2_sb"><option value="1" selected>1</option><option value="2">2</option></select>
        </div>
      </div>
      <div class="cfg-item">
        <label>Mode & Timeout (ms)</label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;">
          <select id="t2_mode"><option value="RTU" selected>RTU</option><option value="ASCII">ASCII</option></select>
          <input type="number" id="t2_to" value="1000" min="50" max="10000">
        </div>
      </div>
      <div class="cfg-item">
        <label>Delay Poll (ms) / IP:Port</label>
        <div style="display:grid;grid-template-columns:65px 1fr;gap:4px;">
          <input type="number" id="t2_delay" value="10" min="5" max="5000">
          <input type="text" id="t2_tcp" value="127.0.0.1:502" disabled>
        </div>
      </div>
    </div>
    <div class="row">
      <button onclick="applyT2Config('setup_ok')">Áp dụng cấu hình sang Tầng 2</button>
      <button class="red" onclick="applyT2Config('disconnect')">Ngắt RS485 Tầng 2</button>
      <span class="muted" id="t2cfgmsg"></span>
    </div>
    <small class="muted">Điều chỉnh trực tiếp thông số cổng COM, Baudrate, Parity, Stop bit, RTU/ASCII của máy điều khiển Tầng 2.</small>
  </div>
</div>

<!-- 5 THẺ KPI -->
<div class="grid">
  <div class="card"><div class="muted">Nhiệt độ</div><div class="kpi" id="temp">-- °C</div></div>
  <div class="card"><div class="muted">Độ ẩm</div><div class="kpi" id="humi">-- %</div></div>
  <div class="card"><div class="muted">Quạt 12V (K1)</div><div class="kpi" id="fan">--</div></div>
  <div class="card"><div class="muted">Máy bơm 12V (K2)</div><div class="kpi" id="pump">--</div></div>
  <div class="card"><div class="muted">Cửa tự động (K3/K4)</div><div class="kpi" id="door" style="font-size:22px;">--</div></div>
</div>

<div class="two">
  <div class="card">
    <h3>Trạng thái và chế độ</h3>
    <p id="sensor" class="muted">Chưa có dữ liệu</p>
    <p>Chế độ: <b id="mode">--</b></p>
    <p>Ngưỡng bật quạt: <b id="tth">--</b> °C · Ngưỡng tắt quạt: <b id="hth">--</b> °C</p>
    <p>TX: <b id="tx">0</b> · RX: <b id="rx">0</b> · Lỗi: <b id="err">0</b></p>
    <p>Khung TX gần nhất</p><pre id="lasttx">--</pre>
    <p>Khung RX gần nhất</p><pre id="lastrx">--</pre>
  </div>

  <!-- KHU VỰC ĐIỀU KHIỂN MÁY CHỦ GỒM 2 KHUNG CHỨC NĂNG -->
  <div class="card">
    <h3>🎛️ Điều khiển Máy chủ Tầng 3</h3>

    <!-- KHUNG 1: QUYỀN XỬ LÝ -->
    <div class="sub-frame">
      <div class="sub-frame-title">
        <span>🔐 Khung 1: Quyền xử lý (Cấp quyền / Thu hồi quyền tầng dưới)</span>
        <span id="permBadge" style="font-size:12px;color:#fbbf24;">🔒 MÁY CHỦ GIỮ QUYỀN</span>
      </div>
      <div id="permDesc" class="muted" style="font-size:12.5px;">Máy chủ Tầng 3 luôn giữ quyền điều khiển tối cao lên mọi tầng ngay cả khi thu hồi quyền của các tầng khác.</div>
      <div class="perm-btns">
        <button class="green" id="btnGrantAll" onclick="setGrantAll(true)">✅ Cấp quyền</button>
        <button class="red active-perm" id="btnRevokeAll" onclick="revokeAll()">🔒 Thu hồi quyền</button>
      </div>
    </div>

    <!-- KHUNG 2: CHỨC NĂNG HỆ THỐNG -->
    <div class="sub-frame">
      <div class="sub-frame-title">
        <span>⚙️ Khung 2: Chức năng hệ thống (Tác động trực tiếp xuống các tầng)</span>
        <span id="sysModeTag" style="font-size:12px;color:#9bb0c8;">BẰNG TAY</span>
      </div>

      <div class="ctrl-row">
        <div>
          <div style="font-weight:600;">🤖 Chế độ tự động (Auto)</div>
          <div class="muted" style="font-size:11.5px;">Tự động bật/tắt quạt theo ngưỡng nhiệt độ</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="swSrvAuto" onchange="setMode(this.checked ? 'AUTO' : 'MANUAL')">
          <span class="slider"></span>
        </label>
      </div>

      <div class="ctrl-row">
        <div>
          <div style="font-weight:600;">☢️ Quạt 12V thủ công (K1)</div>
          <div class="muted" id="fanHint" style="font-size:11.5px;">Bật/tắt quạt bằng tay (Tự chuyển sang Bằng tay nếu đang Auto)</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="swSrvFan" onchange="setOutputVal('fan', this.checked)">
          <span class="slider"></span>
        </label>
      </div>

      <div class="ctrl-row">
        <div>
          <div style="font-weight:600;">🚿 Máy bơm 12V thủ công (K2)</div>
          <div class="muted" style="font-size:11.5px;">Bật/tắt máy bơm thủ công xuống Tầng 2</div>
        </div>
        <label class="switch">
          <input type="checkbox" id="swSrvPump" onchange="setOutputVal('pump', this.checked)">
          <span class="slider"></span>
        </label>
      </div>

      <div class="ctrl-row" style="display:block;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-weight:600;">🚪 Cửa tự động (K3 Mở / K4 Đóng)</span>
          <span id="doorSubTxt" class="warn" style="font-size:12px;font-weight:600;">Đang dừng</span>
        </div>
        <div class="door-grid">
          <button class="green" id="btnSrvDoorOpen" onclick="setDoor('open')">Mở cửa</button>
          <button class="orange" id="btnSrvDoorStop" onclick="setDoor('stop')">Dừng cửa</button>
          <button class="red" id="btnSrvDoorClose" onclick="setDoor('close')">Đóng cửa</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="two">
  <!-- KHUNG MÃ QR KẾT NỐI TRẠM DI ĐỘNG -->
  <div class="card">
    <h3>📱 Mã QR kết nối Trạm Di Động (Điện thoại)</h3>
    <div class="qr-box">
      <img id="qrInlineImg" class="qr-img" onclick="openQrModal()" style="cursor:pointer;" title="Bấm để phóng to mã QR" alt="QR">
      <div style="flex:1;min-width:190px;">
        <div style="font-weight:700;color:#34d399;margin-bottom:4px;">📲 Quét mã QR bằng Camera điện thoại:</div>
        <div id="qrInlineUrlTxt" style="font-size:13px;color:#38bdf8;font-weight:700;word-break:break-all;margin-bottom:6px;">--</div>
        <div class="muted" style="font-size:12px;line-height:1.45;">Có khóa mật khẩu bảo vệ chống lộ link. Quyền thao tác chịu sự điều phối từ <b>Khung 1: Quyền xử lý</b> ở trên.</div>
        <button class="dark" style="margin-top:10px;padding:6px 12px;font-size:12px;" onclick="openQrModal()">🔍 Phóng to / Đổi IP QR</button>
      </div>
    </div>
  </div>

  <div class="card"><h3>Nhật ký truyền thông TX/RX</h3><div class="log" id="traffic">Chưa có dữ liệu</div></div>
</div>
<div class="card"><h3>Nhật ký hệ thống tầng 2</h3><div class="log" id="logs">Chưa có dữ liệu</div></div></div>

<script>
const $=id=>document.getElementById(id);
let cid=null;
try{cid=localStorage.getItem('tier3_client_id')}catch(e){}
if(!cid){
  cid='srv_'+Date.now().toString(36)+'_'+Math.random().toString(36).substring(2,10);
  try{localStorage.setItem('tier3_client_id',cid)}catch(e){}
}
let initialized=false;
let currentQrBaseUrl="";
window.latest={};
window.isComReady=false;

function showComBanner(msg){
  $('comAlertText').textContent=msg||'Chưa kết nối cổng COM!';
  $('comAlertBar').style.display='flex';
}
function hideComBanner(){
  $('comAlertBar').style.display='none';
}
async function triggerComAlert(deviceName){
  let localMsg='Chưa kết nối cổng COM! Không thể điều khiển '+deviceName+' (Thao tác từ: Máy chủ Tầng 3)';
  showComBanner(localMsg);
  try{
    let res=await api('/api/com_alert',{source:'Máy chủ Tầng 3',device:deviceName});
    if(res&&res.com_alert&&res.com_alert.message)showComBanner(res.com_alert.message);
  }catch(e){}
}
async function clearComAlert(){
  hideComBanner();
  try{await api('/api/com_alert/clear',{});}catch(e){}
}

function updateQrCode(baseUrl){
  if(!baseUrl)return;
  baseUrl=baseUrl.trim().replace(/\/+$/,'');
  if(!baseUrl.startsWith('http://')&&!baseUrl.startsWith('https://'))baseUrl='https://'+baseUrl;
  currentQrBaseUrl=baseUrl;
  let mobileHmiUrl=baseUrl+'/mobile-hmi';
  let qrApi='https://api.qrserver.com/v1/create-qr-code/?size=240x240&margin=6&data='+encodeURIComponent(mobileHmiUrl);
  $('qrInlineImg').src=qrApi;
  $('qrModalImg').src=qrApi;
  $('qrInlineUrlTxt').textContent=mobileHmiUrl;
  $('qrModalUrlTxt').textContent=mobileHmiUrl;
  $('customQrUrl').value=baseUrl;
}

function openQrModal(){$('qrModal').style.display='flex'}
function closeQrModal(){$('qrModal').style.display='none'}
function openSecModal(){$('secMsg').textContent='';$('secModal').style.display='flex'}
function closeSecModal(){$('secModal').style.display='none'}

async function doLogout(){
  try{await fetch('/api/logout',{method:'POST'});}catch(e){}
  window.location.reload();
}

async function savePasswords(){
  let ap=$('newAdminPass').value.trim();
  let mp=$('newMobilePass').value.trim();
  if(!ap&&!mp){$('secMsg').style.color='#fbbf24';$('secMsg').textContent='Vui lòng nhập mật khẩu mới cần đổi.';return;}
  try{
    let d=await api('/api/security/update',{admin_password:ap,mobile_password:mp});
    $('newAdminPass').value='';
    $('newMobilePass').value='';
    $('secMsg').style.color='#34d399';
    $('secMsg').textContent=d.message||'Đã cập nhật mật khẩu thành công!';
  }catch(e){
    $('secMsg').style.color='#f87171';
    $('secMsg').textContent=e.message;
  }
}

async function revokeAllSessions(){
  if(!confirm('Tất cả điện thoại và trình duyệt đang mở sẽ bị đăng xuất và phải nhập lại mật khẩu. Tiếp tục?'))return;
  try{
    await api('/api/security/revoke_all',{});
    window.location.reload();
  }catch(e){alert(e.message);}
}

async function api(path,data={},method='POST'){
  let headers={'X-Client-ID':cid,'X-Client-Label':'Tier3-Server','ngrok-skip-browser-warning':'true'};
  if(method!=='GET')headers['Content-Type']='application/json';
  let r=await fetch(path,{method,headers,body:method==='GET'?undefined:JSON.stringify(data)});
  if(r.status===401){window.location.reload();throw Error('Hết phiên đăng nhập');}
  let text=await r.text();
  let d={};
  try{d=JSON.parse(text)}catch(e){throw Error('Phản hồi không hợp lệ từ máy chủ')}
  if(!r.ok||d.ok===false){
    if(d.com_disconnected&&d.com_alert&&d.com_alert.message)showComBanner(d.com_alert.message);
    throw Error(d.error||'Lỗi yêu cầu');
  }
  return d;
}

function toggleT2Mode(){
  let isTcp=$('t2_conn').value==='Modbus TCP/IP';
  $('t2_tcp').disabled=!isTcp;
  ['t2_port','t2_baud','t2_db','t2_par','t2_sb'].forEach(id=>$(id).disabled=isTcp);
}

async function saveT3Config(){
  try{
    let d=await api('/api/tier3/config',{
      url:$('url').value,
      poll_seconds:parseFloat($('t3_poll').value)||1.5,
      http_timeout:parseFloat($('t3_timeout').value)||4.0,
      lease_seconds:parseInt($('t3_lease').value)||20
    });
    $('linkmsg').textContent=d.message||'Đã lưu cấu hình máy chủ';
    refresh();
  }catch(e){$('linkmsg').textContent=e.message}
}

async function connectT2(){
  try{
    let d=await api('/api/tier2/connect',{
      url:$('url').value,
      poll_seconds:parseFloat($('t3_poll').value)||1.5,
      http_timeout:parseFloat($('t3_timeout').value)||4.0,
      lease_seconds:parseInt($('t3_lease').value)||20
    });
    $('linkmsg').textContent=d.message||'Đã kết nối';
    scanT2Ports();
    refresh();
  }catch(e){$('linkmsg').textContent=e.message}
}

async function disconnectT2(){try{await api('/api/tier2/disconnect',{});refresh()}catch(e){alert(e.message)}}

async function scanT2Ports(){
  try{
    let d=await api('/api/tier2/ports',{},'GET');
    if(d.ports&&d.ports.length){
      let sel=$('t2_port'), cur=sel.value;
      sel.innerHTML='';
      let all=[...d.ports];
      for(let i=1;i<=17;i++){let c='COM'+i;if(!all.includes(c))all.push(c);}
      all.forEach(p=>{let o=document.createElement('option');o.value=p;o.textContent=d.ports.includes(p)?p+' (Tầng 2)':p;if(p===cur)o.selected=true;sel.appendChild(o);});
    }
    $('t2cfgmsg').textContent='Đã đồng bộ danh sách cổng COM';
  }catch(e){$('t2cfgmsg').textContent='Dùng danh sách COM mặc định'}
}

async function applyT2Config(act){
  try{
    let tcpParts=($('t2_tcp').value||'127.0.0.1:502').split(':');
    let d=await api('/api/tier2/config',{
      action:act,
      conn_type:$('t2_conn').value,
      port:$('t2_port').value,
      baud:parseInt($('t2_baud').value)||9600,
      databits:parseInt($('t2_db').value)||8,
      parity:$('t2_par').value,
      stopbits:parseInt($('t2_sb').value)||1,
      mode:$('t2_mode').value,
      timeout_ms:parseInt($('t2_to').value)||1000,
      delay_ms:parseInt($('t2_delay').value)||10,
      ip_addr:tcpParts[0]||'127.0.0.1',
      tcp_port:parseInt(tcpParts[1])||502
    });
    $('t2cfgmsg').textContent=d.message||'Đã áp dụng sang tầng 2';
    refresh();
  }catch(e){$('t2cfgmsg').textContent='Lỗi: '+e.message}
}

async function setGrantAll(enable){
  try{await api('/api/server/grant_all',{enable});refresh()}catch(e){alert(e.message)}
}
async function revokeAll(){
  try{await api('/api/server/kick_phone',{});refresh()}catch(e){alert(e.message)}
}
async function setMode(mode){
  if(!window.isComReady){
    $('swSrvAuto').checked=Boolean(window.latest&&(window.latest.auto_mode||window.latest.auto));
    await triggerComAlert('Chế độ tự động (Auto)');
    return;
  }
  try{await api('/api/server/command',{action:'mode',mode});refresh()}catch(e){refresh()}
}
async function setOutputVal(name,on){
  let label=name==='fan'?'Quạt 12V (K1)':'Máy bơm 12V (K2)';
  if(!window.isComReady){
    if(name==='fan')$('swSrvFan').checked=Boolean(window.latest&&window.latest.fan);
    else $('swSrvPump').checked=Boolean(window.latest&&(window.latest.pump||window.latest.mist));
    await triggerComAlert(label);
    return;
  }
  try{
    if(name==='fan'&&window.latest&&(window.latest.auto_mode||window.latest.auto)){
      await api('/api/server/command',{action:'mode',mode:'MANUAL'});
    }
    await api('/api/server/command',{action:'output',name,on});
    refresh();
  }catch(e){refresh()}
}
async function setDoor(act){
  let label={'open':'Mở cửa','stop':'Dừng cửa','close':'Đóng cửa'}[act]||'Cửa tự động';
  if(!window.isComReady){
    await triggerComAlert(label);
    return;
  }
  try{await api('/api/server/command',{action:'output',name:'door',on:act});refresh()}catch(e){}
}
function yn(v){return v?'<span class="on">ĐANG BẬT</span>':'<span class="off">ĐANG TẮT</span>'}

async function refresh(){
  try{
    let d=await api('/api/state',{},'GET');
    window.latest=(d.node&&d.node.state)?d.node.state:{};
    let isOnline=Boolean(d.node&&d.node.online);
    let s=window.latest;
    let isComReady=isOnline&&Boolean(s&&s.is_connected);
    window.isComReady=isComReady;

    $('net').textContent=isOnline?(isComReady?'TCP/IP: ONLINE · COM ĐÃ KẾT NỐI':'TCP/IP: ONLINE · CHƯA KẾT NỐI COM'):'TCP/IP: OFFLINE';
    $('linkmsg').textContent=(d.node&&d.node.error)||('Lần nhận dữ liệu: '+((d.node&&d.node.last_seen)||'--'));

    if(d.com_alert&&d.com_alert.active&&!isComReady){
      showComBanner(d.com_alert.message);
    }else{
      hideComBanner();
    }

    if(!initialized){
      $('url').value=d.tier2_url;
      $('t3_poll').value=d.poll_seconds;
      $('t3_timeout').value=d.http_timeout;
      $('t3_lease').value=d.lease_seconds;
      if(d.qr_url&&!currentQrBaseUrl){
        updateQrCode(d.qr_url);
      }
      if(d.t2_conn_cfg){
        $('t2_conn').value=d.t2_conn_cfg.conn_type||'Serial Port';
        $('t2_port').value=d.t2_conn_cfg.port||'COM6';
        $('t2_baud').value=String(d.t2_conn_cfg.baud||9600);
        $('t2_db').value=String(d.t2_conn_cfg.databits||8);
        $('t2_par').value=d.t2_conn_cfg.parity||'N';
        $('t2_sb').value=String(d.t2_conn_cfg.stopbits||1);
        $('t2_mode').value=d.t2_conn_cfg.mode||'RTU';
        $('t2_to').value=d.t2_conn_cfg.timeout_ms||1000;
        $('t2_delay').value=d.t2_conn_cfg.delay_ms||10;
        toggleT2Mode();
      }
      initialized=true;
    }

    if(d.grant_all){
      $('permBadge').innerHTML='<span class="on">🌐 ĐÃ CẤP QUYỀN TẤT CẢ</span>';
      $('permDesc').textContent='Tất cả thiết bị (Tầng 3, Tầng 2 và Điện thoại QR) đều được phép điều khiển.';
      $('btnGrantAll').classList.add('active-perm');
      $('btnRevokeAll').classList.remove('active-perm');
    }else{
      $('permBadge').innerHTML='<span class="warn">🔒 ĐÃ THU HỒI QUYỀN TẦNG DƯỚI</span>';
      $('permDesc').textContent='Đã khóa quyền Tầng 2 và Điện thoại QR. Chỉ Máy chủ Tầng 3 được phép điều khiển hệ thống.';
      $('btnGrantAll').classList.remove('active-perm');
      $('btnRevokeAll').classList.add('active-perm');
    }

    let isAuto=Boolean(s.auto_mode||s.auto);
    let isFan=Boolean(s.fan);
    let isPump=Boolean(s.pump||s.mist);
    let doorStr=s.door_text||s.door_state||'Đang dừng';

    $('sysModeTag').textContent=isAuto?'TỰ ĐỘNG (AUTO)':'BẰNG TAY';
    $('sysModeTag').style.color=isAuto?'#34d399':'#9bb0c8';
    $('swSrvAuto').checked=isAuto;
    $('swSrvFan').checked=isFan;
    $('swSrvPump').checked=isPump;
    $('doorSubTxt').textContent=doorStr;

    if(!isOnline||!s||!Object.keys(s).length)return;
    $('temp').textContent=Number(s.temp||0).toFixed(1)+' °C';
    $('humi').textContent=Number(s.humi||s.hum||0).toFixed(1)+' %';
    $('fan').innerHTML=yn(isFan);
    $('pump').innerHTML=yn(isPump);
    $('door').innerHTML='<span class="warn">'+doorStr+'</span>';
    $('mode').textContent=isAuto?'TỰ ĐỘNG':'BẰNG TAY';
    $('tth').textContent=s.temp_th;
    $('hth').textContent=s.temp_th_low||s.humi_th;
    $('sensor').textContent='Cảm biến: '+(s.ok_sht?'hoạt động':'chưa có phản hồi')+' · Relay: '+(s.ok_rly?'phản hồi':'chưa xác nhận')+' · Kết nối Modbus: '+(s.is_connected?'đã kết nối':'mất kết nối');
    $('tx').textContent=s.tx_count||0;
    $('rx').textContent=s.rx_count||0;
    $('err').textContent=s.err_count||0;
    $('lasttx').textContent=s.last_tx||'--';
    $('lastrx').textContent=s.last_rx||'--';
    $('traffic').innerHTML=(s.txrx_logs||[]).slice(0,18).map(x=>`<div>${x.time||''} [${x.dir||''}] ${x.frame||''} ${x.desc||''}</div>`).join('')||'Chưa có dữ liệu';
    $('logs').innerHTML=(s.logs||[]).map(x=>`<div>${x.time||''} · ${x.event||''}: ${x.info||''}</div>`).join('')||'Chưa có nhật ký';
  }catch(e){$('net').textContent='Lỗi cập nhật'}
}
setInterval(refresh,1500);refresh();
</script></body></html>'''

# ================= GIAO DIỆN MÁY ĐIỀU KHIỂN DÀNH CHO ĐIỆN THOẠI KHI QUÉT QR (/mobile-hmi) =================
MOBILE_CONTROLLER_PAGE = r'''<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HMI Máy Điều Khiển (Di động) - RS485</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-main: #0b1528;
            --bg-card: #132238;
            --bg-subcard: #182a45;
            --border-card: #1e3454;
            --text-white: #f8fafc;
            --text-muted: #8ba1b7;
            --green: #10b981;
            --orange: #f97316;
            --blue: #38bdf8;
            --red: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { background-color: var(--bg-main); color: var(--text-white); display: flex; flex-direction: column; min-height: 100vh; }
        .header { display: flex; justify-content: space-between; align-items: center; padding: 12px 18px; border-bottom: 1px solid var(--border-card); flex-wrap: wrap; gap: 8px; }
        .header-title h1 { font-size: 17px; font-weight: 700; }
        .header-title p { font-size: 11.5px; color: var(--text-muted); margin-top: 2px; }
        .header-controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .txrx-pill { background: #0f1d33; border: 1px solid #284268; padding: 4px 10px; border-radius: 6px; font-size: 11.5px; font-weight: 700; display: inline-flex; align-items: center; gap: 8px; }
        .online-badge { font-size: 12px; font-weight: 700; padding: 4px 8px; border-radius: 20px; }

        .auth-bar { padding: 8px 18px; font-size: 12.5px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; border-bottom: 1px solid var(--border-card); }
        .auth-ok { background: rgba(16, 185, 129, 0.14); color: #34d399; }
        .auth-locked { background: rgba(239, 68, 68, 0.18); color: #fca5a5; }

        /* THANH THÔNG BÁO ĐỒNG BỘ CHƯA KẾT NỐI CỔNG COM */
        .com-alert-bar { display: none; background: linear-gradient(90deg, #7f1d1d, #991b1b); border-bottom: 1px solid #f87171; color: #fef2f2; padding: 10px 18px; align-items: center; justify-content: space-between; gap: 10px; font-size: 12.5px; font-weight: 700; }

        .btn { border: none; padding: 8px 12px; border-radius: 6px; font-weight: 600; font-size: 12.5px; cursor: pointer; transition: 0.2s; color: white; }
        .btn-green { background: var(--green); }
        .btn-red { background: var(--red); }
        .btn-orange { background: var(--orange); }
        .btn-blue { background: #1d4ed8; }
        .btn-dark { background: #263852; border: 1px solid #334e68; }
        .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        input[type="number"] { background: #1e293b; color: white; border: 1px solid var(--border-card); padding: 6px 10px; border-radius: 6px; font-size: 13px; outline: none; width: 80px; text-align: center; font-weight: 700; }

        .container { flex: 1; padding: 14px 18px; display: flex; flex-direction: column; gap: 14px; }
        .kpi-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
        .kpi-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 10px; padding: 14px 16px; display: flex; align-items: center; justify-content: space-between; }
        .kpi-temp { background: linear-gradient(135deg, #0d2847, #132238); border-color: #1d4ed8; }
        .kpi-humi { background: linear-gradient(135deg, #09383e, #132238); border-color: #0d9488; }
        .kpi-left { display: flex; align-items: center; gap: 12px; }
        .kpi-icon { width: 42px; height: 42px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 19px; background: rgba(255,255,255,0.08); }
        .kpi-info h3 { font-size: 12.5px; font-weight: 600; }
        .kpi-info .val { font-size: 22px; font-weight: 700; margin: 2px 0; }
        .kpi-info .sub { font-size: 11px; color: var(--text-muted); }

        .switch { position: relative; display: inline-block; width: 48px; height: 26px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #475569; transition: .25s; border-radius: 26px; }
        .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 4px; bottom: 4px; background-color: white; transition: .25s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--green); }
        input:checked + .slider:before { transform: translateX(22px); }
        input:disabled + .slider { opacity: 0.4; cursor: not-allowed; }

        .body-grid { display: grid; grid-template-columns: 65fr 35fr; gap: 14px; flex: 1; }
        .left-col, .right-col { display: flex; flex-direction: column; gap: 14px; }
        .card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 10px; padding: 14px; }
        .card-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
        .card-hdr h2 { font-size: 14.5px; font-weight: 700; }
        .chart-box { position: relative; height: 240px; width: 100%; }

        .bottom-left-grid { display: grid; grid-template-columns: 45fr 55fr; gap: 14px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { text-align: left; color: var(--text-muted); font-weight: 600; padding-bottom: 6px; border-bottom: 1px solid var(--border-card); }
        td { padding: 6px 0; border-bottom: 1px solid rgba(30, 52, 84, 0.4); }
        .dot-ok { color: var(--green); font-weight: 600; }
        .dot-off { color: var(--text-muted); font-weight: 600; }
        .dot-err { color: var(--red); font-weight: 600; }
        .quick-txrx { margin-top: 8px; padding: 7px 10px; background: #0b1528; border: 1px solid #1e3454; border-radius: 6px; font-family: Consolas, monospace; font-size: 11px; }

        .ctrl-subcard { background: var(--bg-subcard); border: 1px solid var(--border-card); border-radius: 8px; padding: 12px; margin-bottom: 10px; }
        .ctrl-top { display: flex; justify-content: space-between; align-items: center; }
        .ctrl-btns { display: flex; justify-content: flex-end; gap: 8px; margin-top: 10px; }
        .door-btns { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-top: 10px; }
        .th-row { display: flex; justify-content: space-between; align-items: center; margin: 10px 0; font-size: 13px; }
        .footer { background: #081020; border-top: 1px solid var(--border-card); padding: 8px 18px; display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); }

        @media (max-width: 1000px) {
            .kpi-grid { grid-template-columns: repeat(2, 1fr); }
            .body-grid, .bottom-left-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 520px) {
            .kpi-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

<div class="header">
    <div class="header-title">
        <h1>📱 HMI Máy Điều Khiển (Trạm Di Động)</h1>
        <p>Nhà xưởng - RS485 + Modbus RTU (Kết nối qua Máy chủ Tầng 3)</p>
    </div>
    <div class="header-controls">
        <div class="txrx-pill">
            <span>Tx: <b id="hdrTxCnt" style="color:#f59e0b;">0</b></span>
            <span>Rx: <b id="hdrRxCnt" style="color:#10b981;">0</b></span>
        </div>
        <span id="onlineBadge" class="online-badge" style="color:var(--red);">☁ Offline •</span>
        <button class="btn btn-dark" style="padding:5px 10px;font-size:11.5px;" onclick="doLogout()">🚪 Thoát</button>
    </div>
</div>

<div id="authBar" class="auth-bar auth-locked">
    <span id="authMsg">Đang kết nối tới Máy chủ Tầng 3...</span>
    <div style="display:flex;gap:6px;">
        <button id="btnClaim" class="btn btn-green" style="padding:5px 10px;font-size:12px;" onclick="claimControl()">Nhận quyền điều khiển</button>
        <button id="btnRelease" class="btn btn-red" style="padding:5px 10px;font-size:12px;display:none;" onclick="releaseControl()">Nhả quyền</button>
    </div>
</div>

<!-- THANH THÔNG BÁO ĐỒNG BỘ Ở CÁC TẦNG KHI CHƯA KẾT NỐI CỔNG COM -->
<div id="comAlertBar" class="com-alert-bar">
    <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:16px;">⚠️</span>
        <span id="comAlertText">Chưa kết nối cổng COM!</span>
    </div>
    <button class="btn" style="padding:4px 9px;font-size:11.5px;background:rgba(0,0,0,0.35);border:1px solid #fca5a5;" onclick="clearComAlert()">Đóng</button>
</div>

<div class="container">
    <div class="kpi-grid">
        <div class="kpi-card kpi-temp">
            <div class="kpi-left">
                <div class="kpi-icon" style="color:#38bdf8;">🌡️</div>
                <div class="kpi-info">
                    <h3>Nhiệt độ</h3>
                    <div class="val" id="kpiTemp">--.- °C</div>
                    <div class="sub">Cảm biến SHT20 (ID: 1)</div>
                </div>
            </div>
        </div>

        <div class="kpi-card kpi-humi">
            <div class="kpi-left">
                <div class="kpi-icon" style="color:#2dd4bf;">💧</div>
                <div class="kpi-info">
                    <h3>Độ ẩm</h3>
                    <div class="val" id="kpiHumi">--.- %</div>
                    <div class="sub">Cảm biến SHT20 (ID: 1)</div>
                </div>
            </div>
        </div>

        <div class="kpi-card">
            <div class="kpi-left">
                <div class="kpi-icon">☢️</div>
                <div class="kpi-info">
                    <h3>Quạt 12V</h3>
                    <div class="val" id="kpiFanTxt" style="font-size:18px;">Đang tắt</div>
                    <div class="sub">Func 05, Kênh 1</div>
                </div>
            </div>
            <label class="switch">
                <input type="checkbox" id="swFanTop" onchange="controlRelay('fan', this.checked)">
                <span class="slider"></span>
            </label>
        </div>

        <div class="kpi-card">
            <div class="kpi-left">
                <div class="kpi-icon">🚿</div>
                <div class="kpi-info">
                    <h3>Máy bơm 12V</h3>
                    <div class="val" id="kpiPumpTxt" style="font-size:18px;">Đang tắt</div>
                    <div class="sub">Func 05, Kênh 2</div>
                </div>
            </div>
            <label class="switch">
                <input type="checkbox" id="swPumpTop" onchange="controlRelay('pump', this.checked)">
                <span class="slider"></span>
            </label>
        </div>

        <div class="kpi-card">
            <div class="kpi-left">
                <div class="kpi-icon">🚪</div>
                <div class="kpi-info">
                    <h3>Cửa Tự động</h3>
                    <div class="val" id="kpiDoorTxt" style="font-size:17px;color:#fbbf24;">Đang dừng</div>
                    <div class="sub">K3 Mở | K4 Đóng</div>
                </div>
            </div>
        </div>
    </div>

    <div class="body-grid">
        <div class="left-col">
            <div class="card">
                <div class="card-hdr">
                    <h2>Biểu đồ nhiệt độ và độ ẩm trực tiếp</h2>
                    <div style="display:flex;gap:14px;font-size:12px;">
                        <span style="color:var(--orange);font-weight:700;">● Nhiệt độ (°C)</span>
                        <span style="color:var(--blue);font-weight:700;">● Độ ẩm (%)</span>
                    </div>
                </div>
                <div class="chart-box">
                    <canvas id="envChart"></canvas>
                </div>
            </div>

            <div class="bottom-left-grid">
                <div class="card">
                    <div class="card-hdr"><h2>Trạng thái thiết bị</h2></div>
                    <table>
                        <thead><tr><th>Thiết bị</th><th style="text-align:right;">Trạng thái</th></tr></thead>
                        <tbody>
                            <tr><td>📟 Cảm biến SHT20 (ID: 1)</td><td id="stSht" style="text-align:right;" class="dot-off">● Chưa kết nối</td></tr>
                            <tr><td>🎛️ Module Relay (ID: 255)</td><td id="stRly" style="text-align:right;" class="dot-off">● Chưa kết nối</td></tr>
                            <tr><td>☢️ Quạt 12V (Kênh 1)</td><td id="stFan" style="text-align:right;" class="dot-off">● Tắt</td></tr>
                            <tr><td>🚿 Máy bơm 12V (Kênh 2)</td><td id="stPump" style="text-align:right;" class="dot-off">● Tắt</td></tr>
                            <tr><td>🚪 Cửa tự động (K3/K4)</td><td id="stDoor" style="text-align:right;" class="dot-off">● Đang dừng</td></tr>
                        </tbody>
                    </table>
                    <div class="quick-txrx">
                        <div><span style="color:#f59e0b;font-weight:700;">Tx:</span> <span id="quickTxTxt">--</span></div>
                        <div><span style="color:#10b981;font-weight:700;">Rx:</span> <span id="quickRxTxt">--</span></div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-hdr"><h2>Nhật ký hoạt động</h2></div>
                    <table>
                        <thead><tr><th style="width:24%;">Thời gian</th><th style="width:32%;">Sự kiện</th><th>Thông tin</th></tr></thead>
                        <tbody id="logTableBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="right-col">
            <div class="card">
                <div class="card-hdr"><h2>Điều khiển thủ công (05 Write Single Coil)</h2></div>
                <div class="ctrl-subcard">
                    <div class="ctrl-top">
                        <div>
                            <div style="font-weight:700;font-size:14px;">☢️ Quạt 12V (Kênh 1)</div>
                            <div style="font-size:11px;color:var(--text-muted);">Slave ID: 255 | Func: 05 | Addr: 0</div>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="swFanMan" onchange="controlRelay('fan', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="ctrl-btns">
                        <button id="btnFanOn" class="btn btn-dark" onclick="controlRelay('fan', true)">Bật</button>
                        <button id="btnFanOff" class="btn btn-dark" onclick="controlRelay('fan', false)">Tắt</button>
                    </div>
                </div>

                <div class="ctrl-subcard">
                    <div class="ctrl-top">
                        <div>
                            <div style="font-weight:700;font-size:14px;">🚿 Máy bơm 12V (Kênh 2)</div>
                            <div style="font-size:11px;color:var(--text-muted);">Slave ID: 255 | Func: 05 | Addr: 1</div>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="swPumpMan" onchange="controlRelay('pump', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="ctrl-btns">
                        <button id="btnPumpOn" class="btn btn-dark" onclick="controlRelay('pump', true)">Bật</button>
                        <button id="btnPumpOff" class="btn btn-dark" onclick="controlRelay('pump', false)">Tắt</button>
                    </div>
                </div>

                <div class="ctrl-subcard" style="margin-bottom:0;">
                    <div class="ctrl-top">
                        <div>
                            <div style="font-weight:700;font-size:14px;">🚪 Cửa Tự Động (K3 & K4)</div>
                            <div style="font-size:11px;color:var(--text-muted);">Mở 3.7s / Đóng 3.5s - Tự ngắt</div>
                        </div>
                    </div>
                    <div class="door-btns">
                        <button id="btnDoorOpen" class="btn btn-green" onclick="controlRelay('door', 'open')">MỞ</button>
                        <button id="btnDoorStop" class="btn btn-orange" onclick="controlRelay('door', 'stop')">DỪNG</button>
                        <button id="btnDoorClose" class="btn btn-red" onclick="controlRelay('door', 'close')">ĐÓNG</button>
                    </div>
                </div>
            </div>

            <div class="card" style="flex:1;">
                <div class="card-hdr">
                    <h2>Chế độ tự động (Auto Quạt)</h2>
                    <label class="switch">
                        <input type="checkbox" id="swAuto" onchange="toggleAuto(this.checked)">
                        <span class="slider"></span>
                    </label>
                </div>
                <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Tự động bật quạt khi vượt ngưỡng cài đặt</p>
                <div class="th-row">
                    <span>🌡️ Nhiệt độ &gt;</span>
                    <div><input type="number" id="inpTempTh" step="0.5" value="30.0" disabled> °C</div>
                </div>
                <div class="th-row">
                    <span>❄️ Nhiệt độ &lt;</span>
                    <div><input type="number" id="inpHumiTh" step="0.5" value="28.0" disabled> °C</div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="footer">
    <span>HMI Máy Điều Khiển (Mobile QR)</span>
    <span>Chịu sự điều phối quyền từ Máy Chủ Tầng 3</span>
</div>

<script>
const $ = id => document.getElementById(id);

let cid = null;
try { cid = localStorage.getItem('tier3_client_id'); } catch (e) {}
if (!cid) {
    cid = 'mob_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
    try { localStorage.setItem('tier3_client_id', cid); } catch (e) {}
}

window.latestState = {};
window.isComReady = false;

async function doLogout() {
    try { await fetch('/api/logout', { method: 'POST' }); } catch (e) {}
    window.location.reload();
}

function showComBanner(msg) {
    $('comAlertText').innerText = msg || 'Chưa kết nối cổng COM!';
    $('comAlertBar').style.display = 'flex';
}
function hideComBanner() {
    $('comAlertBar').style.display = 'none';
}
async function triggerComAlert(deviceName) {
    let localMsg = 'Chưa kết nối cổng COM! Không thể điều khiển ' + deviceName + ' (Thao tác từ: Điện thoại)';
    showComBanner(localMsg);
    try {
        let res = await api('/api/com_alert', { source: 'Điện thoại (Trạm Di Động)', device: deviceName });
        if (res && res.com_alert && res.com_alert.message) showComBanner(res.com_alert.message);
    } catch (e) {}
}
async function clearComAlert() {
    hideComBanner();
    try { await api('/api/com_alert/clear', {}); } catch (e) {}
}

let envChart = null;
try {
    if (window.Chart && $('envChart')) {
        const ctx = $('envChart').getContext('2d');
        envChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Nhiệt độ (°C)', data: [], borderColor: '#f97316', yAxisID: 'yTemp', tension: 0.25, borderWidth: 2, pointRadius: 1.5 },
                    { label: 'Độ ẩm (%)', data: [], borderColor: '#38bdf8', yAxisID: 'yHumi', tension: 0.25, borderWidth: 2, pointRadius: 1.5 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false, animation: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#8ba1b7', maxTicksLimit: 8 }, grid: { color: 'rgba(30, 52, 84, 0.5)' } },
                    yTemp: { type: 'linear', position: 'left', suggestedMin: 20, suggestedMax: 42, ticks: { color: '#f97316' }, grid: { color: 'rgba(30, 52, 84, 0.5)' } },
                    yHumi: { type: 'linear', position: 'right', suggestedMin: 20, suggestedMax: 100, ticks: { color: '#38bdf8' }, grid: { drawOnChartArea: false } }
                }
            }
        });
    }
} catch (e) {}

async function api(path, data = {}, method = 'POST') {
    let headers = {
        'X-Client-ID': cid,
        'X-Client-Label': 'Phone-HMI-QR',
        'ngrok-skip-browser-warning': 'true'
    };
    if (method !== 'GET') {
        headers['Content-Type'] = 'application/json';
    }
    let r = await fetch(path, {
        method,
        headers,
        body: method === 'GET' ? undefined : JSON.stringify(data)
    });
    if (r.status === 401) {
        window.location.reload();
        throw Error('Phiên đăng nhập đã hết hạn');
    }
    let text = await r.text();
    let d = {};
    try { d = JSON.parse(text); } catch (e) { throw Error('Mất kết nối hoặc phản hồi không hợp lệ từ Máy chủ Tầng 3'); }
    if (!r.ok || d.ok === false) {
        if (d.com_disconnected && d.com_alert && d.com_alert.message) showComBanner(d.com_alert.message);
        throw Error(d.error || 'Bị từ chối quyền điều khiển');
    }
    return d;
}

async function claimControl() {
    try { await api('/api/claim', { client_id: cid, label: 'Điện thoại (HMI QR)' }); refresh(); }
    catch (e) { alert(e.message); }
}

async function releaseControl() {
    try { await api('/api/release', { client_id: cid }); refresh(); }
    catch (e) { alert(e.message); }
}

async function controlRelay(name, on) {
    let s = window.latestState || {};
    let label = name === 'fan' ? 'Quạt 12V' : (name === 'pump' ? 'Máy bơm 12V' : 'Cửa tự động');
    if (!window.isComReady) {
        ['swFanTop', 'swFanMan'].forEach(id => { if ($(id)) $(id).checked = Boolean(s.fan); });
        ['swPumpTop', 'swPumpMan'].forEach(id => { if ($(id)) $(id).checked = Boolean(s.pump || s.mist); });
        await triggerComAlert(label);
        return;
    }
    try { await api('/api/command', { action: 'output', name, on }); refresh(); }
    catch (e) { refresh(); }
}

async function toggleAuto(isAuto) {
    let s = window.latestState || {};
    if (!window.isComReady) {
        if ($('swAuto')) $('swAuto').checked = Boolean(s.auto_mode);
        await triggerComAlert('Chế độ tự động (Auto)');
        return;
    }
    try { await api('/api/command', { action: 'mode', mode: isAuto ? 'AUTO' : 'MANUAL' }); refresh(); }
    catch (e) { refresh(); }
}

async function heartbeat() {
    try { await api('/api/heartbeat', { client_id: cid }); } catch (e) {}
}

async function refresh() {
    try {
        let d = await api('/api/state', {}, 'GET');
        if (!d || typeof d !== 'object') return;

        let nodeObj = d.node || {};
        let s = (nodeObj.state && typeof nodeObj.state === 'object') ? nodeObj.state : {};
        window.latestState = s;
        let online = Boolean(nodeObj.online && s.is_connected);
        window.isComReady = online;

        let badge = $('onlineBadge');
        if (badge) {
            badge.innerText = online ? '☁ Online •' : '☁ Offline •';
            badge.style.color = online ? '#10b981' : '#ef4444';
        }

        if (d.com_alert && d.com_alert.active && !online) {
            showComBanner(d.com_alert.message);
        } else {
            hideComBanner();
        }

        let leaseObj = d.lease || {};
        let srvLocked = Boolean(d.server_override);
        let isGrantAll = Boolean(d.grant_all);
        let isMyLease = (leaseObj.client_id === cid);
        let freeLease = (!leaseObj.client_id);
        let canOperate = isGrantAll || ((!srvLocked) && (isMyLease || freeLease));

        let bar = $('authBar');
        if (bar) {
            if (isGrantAll) {
                bar.className = 'auth-bar auth-ok';
                $('authMsg').innerText = '🌐 Máy chủ Tầng 3 đã CẤP QUYỀN CHO TẤT CẢ (Tự do điều khiển)';
                $('btnClaim').style.display = 'none';
                $('btnRelease').style.display = 'none';
            } else if (srvLocked) {
                bar.className = 'auth-bar auth-locked';
                $('authMsg').innerText = '🔒 Máy chủ Tầng 3 đã thu hồi quyền (Điện thoại chỉ xem)';
                $('btnClaim').style.display = 'none';
                $('btnRelease').style.display = 'none';
            } else if (isMyLease) {
                bar.className = 'auth-bar auth-ok';
                $('authMsg').innerText = '🟢 Điện thoại đang giữ quyền Máy Điều Khiển';
                $('btnClaim').style.display = 'none';
                $('btnRelease').style.display = 'inline-block';
            } else if (freeLease) {
                bar.className = 'auth-bar auth-ok';
                $('authMsg').innerText = '🔵 Sẵn sàng điều khiển (Bấm nút để tự động nhận quyền)';
                $('btnClaim').style.display = 'inline-block';
                $('btnRelease').style.display = 'none';
            } else {
                bar.className = 'auth-bar auth-locked';
                $('authMsg').innerText = '🔒 Thiết bị khác đang giữ quyền: ' + (leaseObj.label || 'Unknown');
                $('btnClaim').style.display = 'none';
                $('btnRelease').style.display = 'none';
            }
        }

        let disableFan = Boolean(s.auto_mode) || (!canOperate);
        let disableDevice = (!canOperate);
        ['swFanTop', 'swFanMan'].forEach(id => { if ($(id)) { $(id).checked = Boolean(s.fan); $(id).disabled = disableFan; } });
        ['swPumpTop', 'swPumpMan'].forEach(id => { if ($(id)) { $(id).checked = Boolean(s.pump || s.mist); $(id).disabled = disableDevice; } });
        ['btnFanOn', 'btnFanOff'].forEach(id => { if ($(id)) $(id).disabled = disableFan; });
        ['btnPumpOn', 'btnPumpOff', 'btnDoorOpen', 'btnDoorStop', 'btnDoorClose'].forEach(id => { if ($(id)) $(id).disabled = disableDevice; });
        if ($('swAuto')) {
            $('swAuto').checked = Boolean(s.auto_mode);
            $('swAuto').disabled = !canOperate;
        }

        if (!nodeObj.online || !Object.keys(s).length) return;

        $('hdrTxCnt').innerText = Number(s.tx_count || 0);
        $('hdrRxCnt').innerText = Number(s.rx_count || 0);
        $('quickTxTxt').innerText = s.last_tx || '--';
        $('quickRxTxt').innerText = s.last_rx || '--';

        if (s.ok_sht && s.temp !== undefined) {
            $('kpiTemp').innerText = Number(s.temp).toFixed(1) + ' °C';
            $('kpiHumi').innerText = Number(s.humi || s.hum || 0).toFixed(1) + ' %';
        }

        let isPumpOn = Boolean(s.pump || s.mist);
        $('kpiFanTxt').innerText = s.fan ? 'Đang bật' : 'Đang tắt';
        $('kpiFanTxt').style.color = s.fan ? '#10b981' : '#f8fafc';
        $('kpiPumpTxt').innerText = isPumpOn ? 'Đang bật' : 'Đang tắt';
        $('kpiPumpTxt').style.color = isPumpOn ? '#10b981' : '#f8fafc';
        $('kpiDoorTxt').innerText = s.door_text || s.door_state || 'Đang dừng';

        $('btnFanOn').className = 'btn ' + (s.fan ? 'btn-green' : 'btn-dark');
        $('btnFanOff').className = 'btn ' + (!s.fan ? 'btn-red' : 'btn-dark');
        $('btnPumpOn').className = 'btn ' + (isPumpOn ? 'btn-green' : 'btn-dark');
        $('btnPumpOff').className = 'btn ' + (!isPumpOn ? 'btn-red' : 'btn-dark');

        $('inpTempTh').value = s.temp_th ?? 30.0;
        $('inpHumiTh').value = s.temp_th_low ?? 28.0;

        $('stSht').innerText = s.ok_sht ? '● Đang hoạt động' : '● Mất kết nối';
        $('stSht').className = s.ok_sht ? 'dot-ok' : 'dot-err';
        $('stRly').innerText = s.ok_rly ? '● Đang hoạt động' : '● Mất kết nối';
        $('stRly').className = s.ok_rly ? 'dot-ok' : 'dot-err';
        $('stFan').innerText = s.fan ? '● Đang bật' : '● Tắt';
        $('stFan').className = s.fan ? 'dot-ok' : 'dot-off';
        $('stPump').innerText = isPumpOn ? '● Đang bật' : '● Tắt';
        $('stPump').className = isPumpOn ? 'dot-ok' : 'dot-off';
        $('stDoor').innerText = '● ' + (s.door_text || 'Đang dừng');

        if (envChart && Array.isArray(s.chart_time)) {
            envChart.data.labels = s.chart_time;
            envChart.data.datasets[0].data = s.chart_temp || [];
            envChart.data.datasets[1].data = s.chart_humi || [];
            envChart.update('none');
        }

        let tb = $('logTableBody');
        if (tb && Array.isArray(s.logs)) {
            tb.innerHTML = '';
            s.logs.slice(0, 5).forEach(r => {
                let tr = document.createElement('tr');
                tr.innerHTML = `<td style="color:var(--text-muted)">${r.time||''}</td><td>${r.event||''}</td><td style="color:#10b981">${r.info||''}</td>`;
                tb.appendChild(tr);
            });
        }
    } catch (e) {}
}

api('/api/claim', { client_id: cid, label: 'Điện thoại (HMI QR)' }).catch(() => {});
setInterval(refresh, 1500);
setInterval(heartbeat, 5000);
refresh();
</script>
</body>
</html>'''


# ==================== ROUTE ĐĂNG NHẬP / ĐĂNG XUẤT / ĐỔI MẬT KHẨU ====================
@app.route('/api/login', methods=['POST'])
def api_login():
    fp = _client_fingerprint()
    now = time.time()
    rec = login_attempts.get(fp)
    if rec and rec.get("locked_until", 0) > now:
        remain = int(rec["locked_until"] - now)
        return jsonify({"ok": False, "error": f"Nhập sai quá nhiều lần. Vui lòng thử lại sau {remain}s"}), 429

    d = request.get_json(silent=True) or {}
    target = str(d.get("target", "admin")).strip()
    pwd = str(d.get("password", ""))

    salt = sec_cfg["salt"]
    h = _hash_password(pwd, salt)

    role_granted = None
    if target == "mobile":
        if h == sec_cfg["mobile_hash"]:
            role_granted = "mobile"
        elif h == sec_cfg["admin_hash"]:
            role_granted = "admin"
    else:
        if h == sec_cfg["admin_hash"]:
            role_granted = "admin"

    if not role_granted:
        fails = (rec.get("fails", 0) if rec else 0) + 1
        locked_until = (now + LOCKOUT_SECONDS) if fails >= MAX_LOGIN_FAILS else 0
        login_attempts[fp] = {"fails": 0 if locked_until else fails, "locked_until": locked_until}
        if locked_until:
            return jsonify({"ok": False, "error": f"Sai mật khẩu {MAX_LOGIN_FAILS} lần! Tạm khóa {LOCKOUT_SECONDS}s."}), 429
        return jsonify({"ok": False, "error": f"Mật khẩu không đúng! (Còn {MAX_LOGIN_FAILS - fails} lần thử)"}), 401

    login_attempts.pop(fp, None)
    session.permanent = True
    session["t3_role"] = role_granted
    session["t3_ver"] = sec_cfg.get("auth_version", 1)
    return jsonify({"ok": True, "role": role_granted})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route('/api/security/update', methods=['POST'])
def api_security_update():
    d = request.get_json(silent=True) or {}
    new_admin = str(d.get("admin_password", "")).strip()
    new_mobile = str(d.get("mobile_password", "")).strip()

    if new_admin and len(new_admin) < 4:
        return jsonify({"ok": False, "error": "Mật khẩu Quản trị phải có ít nhất 4 ký tự"}), 400
    if new_mobile and len(new_mobile) < 4:
        return jsonify({"ok": False, "error": "Mật khẩu Trạm Di Động phải có ít nhất 4 ký tự"}), 400

    with lock:
        salt = sec_cfg["salt"]
        if new_admin:
            sec_cfg["admin_hash"] = _hash_password(new_admin, salt)
        if new_mobile:
            sec_cfg["mobile_hash"] = _hash_password(new_mobile, salt)
        _save_security_cfg(sec_cfg)

    return jsonify({"ok": True, "message": "Đã lưu mật khẩu mới thành công!"})


@app.route('/api/security/revoke_all', methods=['POST'])
def api_security_revoke_all():
    with lock:
        sec_cfg["auth_version"] = int(sec_cfg.get("auth_version", 1)) + 1
        _save_security_cfg(sec_cfg)
    session.clear()
    return jsonify({"ok": True})


@app.route('/')
def home():
    if not _is_session_valid("admin"):
        return render_template_string(
            LOGIN_PAGE,
            target="admin",
            title="HMI Máy Chủ Tầng 3",
            subtitle="Vui lòng nhập mật khẩu Quản trị để truy cập bảng điều phối"
        )
    return render_template_string(PAGE)


@app.route('/mobile-hmi')
def mobile_hmi():
    if not _is_session_valid("any"):
        return render_template_string(
            LOGIN_PAGE,
            target="mobile",
            title="Trạm Di Động (HMI QR)",
            subtitle="Vui lòng nhập mật khẩu truy cập thiết bị điều khiển"
        )
    return render_template_string(MOBILE_CONTROLLER_PAGE)


def t2(path, data=None, method='GET', timeout=None):
    with lock:
        base = tier2_url
        to = timeout if timeout is not None else http_timeout
    if method == 'GET':
        r = http.get(base + path, timeout=to)
    else:
        r = http.post(base + path, json=data or {}, timeout=to)
    r.raise_for_status()
    return r.json()


def set_com_alert(source, device=""):
    with lock:
        now_str = datetime.now().strftime('%H:%M:%S')
        dev_txt = f" [{device}]" if device else ""
        msg = f"Chưa kết nối cổng COM! Không thể điều khiển{dev_txt} — Thao tác từ: {source} ({now_str})"
        com_alert.update({
            "active": True,
            "id": int(time.time() * 1000),
            "source": source,
            "device": device,
            "time": now_str,
            "message": msg
        })
        payload = dict(com_alert)
    try:
        t2('/api/tier3/com_alert', payload, 'POST', timeout=1.5)
    except Exception:
        pass
    return payload


def clear_com_alert_state():
    with lock:
        com_alert.update({
            "active": False,
            "source": "",
            "device": "",
            "time": "",
            "message": ""
        })
    try:
        t2('/api/tier3/com_alert', {"active": False}, 'POST', timeout=1.5)
    except Exception:
        pass


def expire():
    if lease['client_id'] and time.time() - lease['last_seen'] > lease_seconds:
        lease.update(client_id=None, label=None, since=None, last_seen=0.0)


def poll_loop():
    global server_override, grant_all
    while True:
        with lock:
            enabled = link_enabled
            wait_s = poll_seconds
        if enabled:
            try:
                try:
                    s = t2('/api/tier3/state')
                except Exception:
                    s = t2('/api/status')
                with lock:
                    node.update(online=True, state=s, error=None, last_seen=datetime.now().strftime('%H:%M:%S'))
                    if s.get('is_connected'):
                        com_alert['active'] = False
                    else:
                        t2_alert = s.get('com_alert')
                        if isinstance(t2_alert, dict) and t2_alert.get('active'):
                            if int(t2_alert.get('id', 0)) > int(com_alert.get('id', 0)):
                                com_alert.update(t2_alert)

                    t2_ov = s.get('server_override') or {}
                    if grant_all:
                        if t2_ov.get('active') or not t2_ov.get('grant_all'):
                            try:
                                t2('/api/tier3/override', {'active': False, 'grant_all': True, 'reason': 'Máy chủ Tầng 3 cấp quyền cho tất cả'}, 'POST', timeout=2.0)
                            except Exception:
                                pass
                    elif server_override:
                        if not t2_ov.get('active') or t2_ov.get('grant_all'):
                            try:
                                t2('/api/tier3/override', {'active': True, 'grant_all': False, 'reason': 'Máy chủ Tầng 3 thu hồi quyền các tầng dưới'}, 'POST', timeout=2.0)
                            except Exception:
                                pass
                    else:
                        server_override = bool(t2_ov.get('active'))
            except Exception as e:
                with lock:
                    node.update(online=False, error=str(e))
        time.sleep(max(0.2, wait_s))


@app.route('/api/com_alert', methods=['GET', 'POST'])
def api_com_alert():
    if request.method == 'GET':
        with lock:
            return jsonify({'ok': True, 'com_alert': dict(com_alert)})
    d = request.get_json(silent=True) or {}
    source = str(d.get('source', 'Thiết bị điều khiển')).strip()
    device = str(d.get('device', '')).strip()
    alert_obj = set_com_alert(source, device)
    return jsonify({'ok': True, 'com_alert': alert_obj})


@app.route('/api/com_alert/clear', methods=['POST'])
def api_com_alert_clear():
    clear_com_alert_state()
    return jsonify({'ok': True})


@app.route('/api/state')
def api_state():
    with lock:
        expire()
        lan_ip = get_local_ip()
        qr_base = PUBLIC_NGROK_URL if PUBLIC_NGROK_URL else f'http://{lan_ip}:{PORT}'
        return jsonify({
            'ok': True,
            'node': node,
            'tier2_url': tier2_url,
            'qr_url': qr_base,
            'poll_seconds': poll_seconds,
            'http_timeout': http_timeout,
            'lease_seconds': lease_seconds,
            't2_conn_cfg': t2_conn_cfg,
            'link_enabled': link_enabled,
            'lease': {k: v for k, v in lease.items() if k != 'last_seen'},
            'server_override': server_override,
            'grant_all': grant_all,
            'com_alert': dict(com_alert)
        })


@app.route('/api/tier3/config', methods=['POST'])
def config_tier3():
    global tier2_url, poll_seconds, http_timeout, lease_seconds
    d = request.get_json(silent=True) or {}
    with lock:
        if d.get('url'):
            c = str(d.get('url')).strip().rstrip('/')
            if not c.startswith(('http://', 'https://')):
                c = 'http://' + c
            tier2_url = c
        if d.get('poll_seconds'):
            poll_seconds = max(0.2, float(d.get('poll_seconds')))
        if d.get('http_timeout'):
            http_timeout = max(0.5, float(d.get('http_timeout')))
        if d.get('lease_seconds'):
            lease_seconds = max(5, int(d.get('lease_seconds')))
    return jsonify({'ok': True, 'message': f'Đã lưu (Poll {poll_seconds}s, Timeout {http_timeout}s, Lease {lease_seconds}s)'})


@app.route('/api/tier2/connect', methods=['POST'])
def connect_tier2():
    global tier2_url, link_enabled, poll_seconds, http_timeout, lease_seconds
    d = request.get_json(silent=True) or {}
    candidate = str(d.get('url') or tier2_url).strip().rstrip('/')
    if not candidate.startswith(('http://', 'https://')):
        candidate = 'http://' + candidate
    try:
        p = urlparse(candidate)
        valid = bool(p.hostname and (p.port or p.scheme == 'https') and p.path in ('', '/'))
    except ValueError:
        valid = False
    if not valid:
        return jsonify({'ok': False, 'error': 'Địa chỉ phải có dạng http://127.0.0.1:5000'}), 400
    with lock:
        tier2_url = candidate
        if d.get('poll_seconds'):
            poll_seconds = max(0.2, float(d.get('poll_seconds')))
        if d.get('http_timeout'):
            http_timeout = max(0.5, float(d.get('http_timeout')))
        if d.get('lease_seconds'):
            lease_seconds = max(5, int(d.get('lease_seconds')))
        link_enabled = True
        node.update(online=False, state=None, error='Đang kiểm tra kết nối')
    try:
        try:
            s = t2('/api/tier3/state', timeout=http_timeout)
        except Exception:
            s = t2('/api/status', timeout=http_timeout)
        with lock:
            node.update(online=True, state=s, error=None, last_seen=datetime.now().strftime('%H:%M:%S'))
            if s.get('is_connected'):
                com_alert['active'] = False
        return jsonify({'ok': True, 'message': 'Đã kết nối tầng 2 thành công', 'state': s})
    except Exception as e:
        with lock:
            node.update(online=False, error=str(e))
        return jsonify({'ok': False, 'error': 'Không kết nối được tầng 2: ' + str(e)}), 502


@app.route('/api/tier2/disconnect', methods=['POST'])
def disconnect_tier2():
    global link_enabled
    with command_lock, lock:
        link_enabled = False
        node.update(online=False, state=None, error='Đã ngắt liên kết tầng 3–tầng 2')
    return jsonify({'ok': True})


@app.route('/api/tier2/ports', methods=['GET'])
def tier2_ports():
    for ep in ('/api/tier3/ports', '/api/ports', '/api/serial/ports'):
        try:
            res = t2(ep, method='GET', timeout=2.5)
            return jsonify({'ok': True, 'ports': res.get('ports', []), 'config': res.get('config', {})})
        except Exception:
            continue
    return jsonify({'ok': True, 'ports': [], 'config': t2_conn_cfg})


@app.route('/api/tier2/config', methods=['POST'])
def tier2_config():
    d = request.get_json(silent=True) or {}
    with lock:
        t2_conn_cfg.update({
            "conn_type": d.get("conn_type", "Serial Port"),
            "port": str(d.get("port", "COM6")).split()[0].strip(),
            "baud": int(d.get("baud", 9600)),
            "databits": int(d.get("databits", 8)),
            "parity": str(d.get("parity", "N")),
            "stopbits": int(d.get("stopbits", 1)),
            "mode": str(d.get("mode", "RTU")),
            "timeout_ms": int(d.get("timeout_ms", 1000)),
            "delay_ms": int(d.get("delay_ms", 10)),
            "ip_addr": str(d.get("ip_addr", "127.0.0.1")),
            "tcp_port": int(d.get("tcp_port", 502))
        })
        payload = dict(t2_conn_cfg)
        payload["action"] = d.get("action", "setup_ok")
        payload["baudrate"] = payload["baud"]
        payload["bytesize"] = payload["databits"]
        payload["timeout"] = payload["timeout_ms"] / 1000.0

    for ep in ('/api/tier3/serial_config', '/api/connect', '/api/tier3/connect'):
        try:
            res = t2(ep, data=payload, method='POST', timeout=4.0)
            if isinstance(res, dict) and res.get('ok'):
                return jsonify({'ok': True, 'message': f"Đã áp dụng xuống Tầng 2 ({payload['port']} · {payload['baud']} bps)"})
        except Exception:
            continue

    return jsonify({'ok': False, 'error': 'Không gửi được cấu hình xuống Tầng 2 (Hãy kiểm tra kết nối Tầng 2)'}), 502


@app.route('/api/server/grant_all', methods=['POST'])
def server_grant_all():
    global grant_all, server_override
    d = request.get_json(silent=True) or {}
    enable = bool(d.get('enable', True))
    with lock:
        grant_all = enable
        if enable:
            server_override = False
            lease.update(client_id=None, label=None, since=None, last_seen=0.0)
    try:
        t2('/api/tier3/override', {
            'active': False,
            'grant_all': enable,
            'reason': 'Máy chủ Tầng 3 cấp quyền cho tất cả' if enable else 'Máy chủ Tầng 3 tắt chế độ cấp quyền tất cả'
        }, 'POST', timeout=4.0)
    except Exception:
        pass
    return jsonify({'ok': True, 'grant_all': grant_all})


@app.route('/api/claim', methods=['POST'])
def claim():
    d = request.get_json(silent=True) or {}
    cid = str(d.get('client_id', '')).strip()
    label = str(d.get('label', 'Điện thoại (HMI QR)'))
    if not cid:
        return jsonify({'ok': False, 'error': 'Thiếu client_id'}), 400
    with lock:
        expire()
        if grant_all:
            return jsonify({'ok': True, 'grant_all': True})
        if server_override:
            return jsonify({'ok': False, 'error': 'Máy chủ tầng 3 đã thu hồi quyền điều khiển'}), 423
        if lease['client_id'] in (None, cid):
            lease.update(client_id=cid, label=label, since=datetime.now().strftime('%H:%M:%S'), last_seen=time.time())
            return jsonify({'ok': True})
        return jsonify({'ok': False, 'error': 'Thiết bị khác đang giữ quyền: ' + str(lease['label'])}), 423


@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    cid = str((request.get_json(silent=True) or {}).get('client_id', ''))
    with lock:
        expire()
        if grant_all:
            return jsonify({'ok': True, 'is_owner': True, 'grant_all': True})
        if cid and lease['client_id'] == cid:
            lease['last_seen'] = time.time()
            return jsonify({'ok': True, 'is_owner': True})
        return jsonify({'ok': True, 'is_owner': False, 'owner': lease['label']})


@app.route('/api/release', methods=['POST'])
def release():
    cid = str((request.get_json(silent=True) or {}).get('client_id', ''))
    with lock:
        expire()
        if not cid or lease['client_id'] != cid:
            return jsonify({'ok': False, 'error': 'Thiết bị này không giữ quyền'}), 403
        lease.update(client_id=None, label=None, since=None, last_seen=0.0)
    return jsonify({'ok': True})


@app.route('/api/server/kick_phone', methods=['POST'])
def kick_phone():
    global server_override, grant_all
    with lock:
        lease.update(client_id=None, label=None, since=None, last_seen=0.0)
        grant_all = False
        server_override = True
    try:
        t2('/api/tier3/override', {'active': True, 'grant_all': False, 'reason': 'Máy chủ Tầng 3 thu hồi quyền của các tầng dưới'}, 'POST')
    except Exception:
        pass
    return jsonify({'ok': True})


def forward(action, d, from_server=False):
    global server_override
    with command_lock:
        with lock:
            expire()
            s_state = node.get('state') or {}
            com_ok = bool(link_enabled and node.get('online') and s_state.get('is_connected'))
            if not com_ok:
                src_name = 'Máy chủ Tầng 3' if from_server else 'Điện thoại (Trạm Di Động)'
                dev_map = {'fan': 'Quạt 12V', 'pump': 'Máy bơm 12V', 'door': 'Cửa tự động'}
                dev_name = 'Chế độ tự động (Auto)' if action == 'mode' else dev_map.get(d.get('name'), '')
                alert_obj = set_com_alert(src_name, dev_name)
                return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409

            if not from_server and not grant_all:
                cid = request.headers.get('X-Client-ID', '')
                if server_override:
                    return jsonify({'ok': False, 'error': 'Máy chủ Tầng 3 đã thu hồi quyền điều khiển'}), 423
                if lease['client_id'] is None and cid:
                    lease.update(client_id=cid, label='Điện thoại (HMI QR)',
                                 since=datetime.now().strftime('%H:%M:%S'), last_seen=time.time())
                elif not cid or lease['client_id'] != cid:
                    return jsonify({'ok': False, 'error': 'Thiết bị khác đang giữ quyền điều khiển'}), 423
                lease['last_seen'] = time.time()

        if action not in ('output', 'mode'):
            return jsonify({'ok': False, 'error': 'Lệnh không hợp lệ'}), 400
        try:
            endpoint = '/api/tier3/' + (('' if from_server else 'client-') + action)
            result = t2(endpoint, d, 'POST', timeout=5)
            with lock:
                node.update(online=True, error=None, last_seen=datetime.now().strftime('%H:%M:%S'))
                if from_server and not grant_all:
                    server_override = True
            return jsonify({'ok': True, 'result': result})
        except Exception as e:
            return jsonify({'ok': False, 'error': 'Không gửi được lệnh xuống Tầng 2: ' + str(e)}), 502


@app.route('/api/command', methods=['POST'])
def command():
    d = request.get_json(silent=True) or {}
    return forward(d.get('action'), d, False)


@app.route('/api/server/command', methods=['POST'])
def server_command():
    global server_override, grant_all
    d = request.get_json(silent=True) or {}
    if d.get('action') == 'release_override':
        try:
            t2('/api/tier3/override', {'active': False, 'grant_all': grant_all, 'reason': 'Máy chủ nhả quyền'}, 'POST')
            server_override = False
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 502
    return forward(d.get('action'), d, True)


if __name__ == '__main__':
    threading.Thread(target=poll_loop, daemon=True).start()
    ip = get_local_ip()
    print('HMI máy chủ tầng 3   : http://127.0.0.1:%s  (hoặc %s)' % (PORT, PUBLIC_NGROK_URL))
    print('HMI Điện thoại (QR)  : %s/mobile-hmi' % PUBLIC_NGROK_URL)
    print('Mật khẩu mặc định    : Quản trị = admin123 | Điện thoại = 123456')
    print('TIER2_URL            :', tier2_url)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
