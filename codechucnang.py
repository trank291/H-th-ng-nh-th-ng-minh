import os
import json
import hashlib
import secrets
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox
import time
import threading
import socket
from datetime import datetime

# === THƯ VIỆN GIAO TIẾP CỔNG COM THẬT ===
import serial
import serial.tools.list_ports

# === THƯ VIỆN WEB SERVER & CORS ===
from flask import Flask, jsonify, request, render_template_string, session
from flask_cors import CORS
import logging

# Thư viện vẽ biểu đồ Matplotlib trên Tkinter
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt

# ==================== 1. CẤU HÌNH WEB SERVER TẦNG 2 (PORT 5000) ====================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app_instance = None
TIER3_URL = os.environ.get("TIER3_URL", "http://127.0.0.1:8080").rstrip("/")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "hmi-tier2-tier3-secret-2026")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TIER2_SEC_FILE = os.path.join(BASE_DIR, "tier2_security.json")

# --- CẤU HÌNH MODBUS & NGƯỠNG MẶC ĐỊNH ---
RELAY_SLAVE_ID = 0xFF      # Địa chỉ mạch Relay (0xFF = 255)
TEMP_THRESHOLD_HIGH = 30.0
TEMP_THRESHOLD_LOW = 28.0
DOOR_OPEN_TIME_MS = 3700   # Thời gian mở cửa (K3) tự ngắt: 3700ms
DOOR_CLOSE_TIME_MS = 3500  # Thời gian đóng cửa (K4) tự ngắt: 3500ms


# ==================== QUẢN LÝ MẬT KHẨU BẢO MẬT WEB / MOBILE TẦNG 2 ====================
def _hash_pass(raw_pass: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{raw_pass}".encode("utf-8")).hexdigest()


def _load_t2_security() -> dict:
    salt = secrets.token_hex(16)
    default_pass = os.environ.get("TIER2_WEB_PASS", "3206")
    cfg = {
        "secret_key": secrets.token_hex(32),
        "salt": salt,
        "web_hash": _hash_pass(default_pass, salt),
        "default_tag": "3206",
        "user_customized": False,
        "auth_enabled": True,
        "auth_version": 1
    }
    if os.path.exists(TIER2_SEC_FILE):
        try:
            with open(TIER2_SEC_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                cfg.update(saved)
                if not cfg.get("user_customized") and cfg.get("default_tag") != "3206":
                    cfg["web_hash"] = _hash_pass(default_pass, cfg["salt"])
                    cfg["default_tag"] = "3206"
                    _save_t2_security(cfg)
        except Exception:
            pass
    else:
        _save_t2_security(cfg)
    return cfg


def _save_t2_security(cfg: dict):
    try:
        with open(TIER2_SEC_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


t2_sec = _load_t2_security()
app.secret_key = t2_sec["secret_key"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=86400 * 7
)

t2_login_attempts = {}


def _is_t2_authenticated() -> bool:
    if not t2_sec.get("auth_enabled", True):
        return True
    return bool(session.get("t2_ok") and session.get("t2_ver") == t2_sec.get("auth_version", 1))


@app.after_request
def add_ngrok_headers(response):
    response.headers["ngrok-skip-browser-warning"] = "true"
    return response


@app.before_request
def enforce_t2_security():
    path = request.path or "/"
    if path in ("/api/login", "/api/logout", "/favicon.ico"):
        return None

    # Cho phép Máy chủ Tầng 3 gọi các endpoint /api/tier3/* thông qua khóa nội bộ
    if request.headers.get("X-Internal-Key") == INTERNAL_API_KEY and path.startswith("/api/tier3/"):
        return None

    if path.startswith("/api/"):
        if not _is_t2_authenticated():
            return jsonify({"ok": False, "auth_required": True, "error": "Chưa đăng nhập mật khẩu Web Tầng 2"}), 401
    return None


def calc_crc16(data: bytes) -> bytes:
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if (crc & 1) != 0:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc.to_bytes(2, byteorder='little')


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def push_com_alert_to_tier3(payload: dict):
    """Đẩy thông báo chưa kết nối COM lên Máy chủ Tầng 3 (port 8080) 1 lần để đồng bộ các tầng."""
    def _send():
        try:
            url = f"{TIER3_URL}/api/com_alert" if payload.get("active") else f"{TIER3_URL}/api/com_alert/clear"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Internal-Key": INTERNAL_API_KEY
                },
                method="POST"
            )
            urllib.request.urlopen(req, timeout=1.2)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


# ==================== 2. GIAO DIỆN ĐĂNG NHẬP & WEB/MOBILE HMI TẦNG 2 (PORT 5000) ====================
TIER2_LOGIN_PAGE = r'''<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xác thực HMI Máy Điều Khiển Tầng 2</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Arial, sans-serif; }
        body { background: #0b132b; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 18px; }
        .card { background: #1c2541; border: 1px solid #2b3a67; border-radius: 14px; padding: 26px 22px; width: 100%; max-width: 380px; box-shadow: 0 18px 40px rgba(0,0,0,0.55); }
        .ico { font-size: 38px; text-align: center; margin-bottom: 8px; }
        h2 { text-align: center; font-size: 18px; margin-bottom: 6px; }
        p { text-align: center; color: #a0aab2; font-size: 13px; margin-bottom: 18px; line-height: 1.45; }
        label { display: block; font-size: 12.5px; color: #cbd5e1; margin-bottom: 6px; font-weight: 600; }
        input { width: 100%; padding: 11px 12px; border-radius: 8px; border: 1px solid #3a4f8a; background: #0b132b; color: #fff; font-size: 15px; outline: none; margin-bottom: 14px; }
        input:focus { border-color: #3a86ff; }
        button { width: 100%; padding: 11px; border: none; border-radius: 8px; background: #00c853; color: #fff; font-size: 15px; font-weight: 700; cursor: pointer; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .err { background: rgba(229,57,53,0.2); border: 1px solid #ff8a80; color: #ffcdd2; padding: 9px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 12px; display: none; }
    </style>
</head>
<body>
<div class="card">
    <div class="ico">🔐</div>
    <h2>HMI Máy Điều Khiển Tầng 2</h2>
    <p>Vui lòng nhập mật khẩu để mở giao diện giám sát & điều khiển thiết bị</p>
    <div id="errBox" class="err"></div>
    <form onsubmit="doLogin(event)">
        <label for="pwd">Mật khẩu truy cập</label>
        <input type="password" id="pwd" placeholder="Nhập mật khẩu..." autofocus required>
        <button type="submit" id="btnSub">Đăng nhập</button>
    </form>
</div>
<script>
async function doLogin(e) {
    e.preventDefault();
    const btn = document.getElementById('btnSub');
    const err = document.getElementById('errBox');
    btn.disabled = true; err.style.display = 'none';
    try {
        const r = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: document.getElementById('pwd').value })
        });
        const d = await r.json();
        if (!r.ok || !d.ok) {
            err.textContent = d.error || 'Sai mật khẩu!';
            err.style.display = 'block';
            document.getElementById('pwd').select();
        } else {
            window.location.reload();
        }
    } catch (ex) {
        err.textContent = 'Lỗi kết nối!';
        err.style.display = 'block';
    } finally {
        btn.disabled = false;
    }
}
</script>
</body>
</html>'''

TIER2_WEB_PAGE = r'''<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>HMI Máy Điều Khiển Tầng 2 - Modbus RTU</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        :root {
            --bg-main: #0b132b;
            --bg-card: #1c2541;
            --bg-subcard: #141d36;
            --border-card: #2b3a67;
            --text-white: #ffffff;
            --text-muted: #a0aab2;
            --green: #00c853;
            --orange: #ff9800;
            --blue: #3a86ff;
            --red: #e53935;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Arial, sans-serif; -webkit-tap-highlight-color: transparent; }
        body { background-color: var(--bg-main); color: var(--text-white); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }

        .header { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--border-card); flex-wrap: wrap; gap: 10px; }
        .header-title h1 { font-size: 17px; font-weight: 700; }
        .header-title p { font-size: 12px; color: #00e676; margin-top: 2px; }
        .header-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .pill { background: #141d36; border: 1px solid var(--border-card); padding: 5px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }

        /* THANH THÔNG BÁO ĐỒNG BỘ CHƯA KẾT NỐI CỔNG COM */
        .com-alert-bar { display: none; background: linear-gradient(90deg, #8e1919, #c62828); border-bottom: 1px solid #ff8a80; color: #ffffff; padding: 10px 16px; align-items: center; justify-content: space-between; gap: 10px; font-size: 13px; font-weight: 700; box-shadow: 0 4px 14px rgba(229, 57, 53, 0.35); }

        .lock-banner { padding: 9px 16px; font-size: 13px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-card); flex-wrap: wrap; gap: 6px; }
        .lock-free { background: rgba(58, 134, 255, 0.14); color: #60a5fa; }
        .lock-all { background: rgba(0, 200, 83, 0.16); color: #00e676; }
        .lock-busy { background: rgba(229, 57, 53, 0.2); color: #fca5a5; }

        .setup-bar { background: var(--bg-card); margin: 12px 16px 0 16px; padding: 12px 14px; border-radius: 10px; border: 1px solid var(--border-card); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
        .setup-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 13px; }
        select, input[type="number"], input[type="text"] { background: #0b132b; color: #fff; border: 1px solid var(--border-card); padding: 7px 10px; border-radius: 6px; font-size: 13px; outline: none; }
        input[type="number"] { width: 76px; text-align: center; font-weight: 700; }

        .btn { border: none; padding: 8px 14px; border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer; color: #fff; transition: 0.1s; touch-action: manipulation; user-select: none; }
        .btn:hover:not(:disabled) { filter: brightness(1.12); }
        .btn:active:not(:disabled) { transform: scale(0.98); }
        .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .btn-green { background: var(--green); }
        .btn-red { background: var(--red); }
        .btn-orange { background: var(--orange); }
        .btn-blue { background: var(--blue); }
        .btn-dark { background: #37474f; }

        .container { flex: 1; padding: 14px 16px; display: flex; flex-direction: column; gap: 14px; }
        .kpi-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
        .kpi-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 10px; padding: 14px; display: flex; align-items: center; justify-content: space-between; }
        .kpi-temp { border-color: #3a86ff; }
        .kpi-humi { border-color: #00b0ff; }
        .kpi-info h3 { font-size: 12.5px; color: var(--text-muted); font-weight: 600; }
        .kpi-info .val { font-size: 22px; font-weight: 700; margin: 4px 0; }
        .kpi-info .sub { font-size: 11px; color: #7f8c9b; }

        .switch { position: relative; display: inline-block; width: 54px; height: 30px; flex-shrink: 0; touch-action: manipulation; user-select: none; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; inset: 0; background-color: #37474f; transition: background-color .12s ease; border-radius: 30px; will-change: background-color; }
        .slider:before { position: absolute; content: ""; height: 22px; width: 22px; left: 4px; bottom: 4px; background-color: white; transition: transform .12s ease; border-radius: 50%; will-change: transform; }
        input:checked + .slider { background-color: var(--green); }
        input:checked + .slider:before { transform: translateX(24px); }
        input:disabled + .slider { opacity: 0.4; cursor: not-allowed; }

        .main-grid { display: grid; grid-template-columns: 65fr 35fr; gap: 14px; }
        .col { display: flex; flex-direction: column; gap: 14px; }
        .card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 10px; padding: 14px; }
        .card-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }
        .card-hdr h2 { font-size: 15px; font-weight: 700; }
        .chart-box { position: relative; height: 220px; width: 100%; }

        .bottom-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
        th { text-align: left; color: var(--text-muted); padding-bottom: 6px; border-bottom: 1px solid var(--border-card); }
        td { padding: 6px 0; border-bottom: 1px solid rgba(43, 58, 103, 0.45); }

        .ctrl-item { background: var(--bg-subcard); border: 1px solid var(--border-card); border-radius: 8px; padding: 12px; margin-bottom: 10px; }
        .ctrl-top { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
        .ctrl-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 10px; }
        .door-actions { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-top: 10px; }
        .th-row { display: flex; justify-content: space-between; align-items: center; margin: 10px 0; font-size: 13.5px; }

        .traffic-box { background: #0b132b; border: 1px solid var(--border-card); border-radius: 8px; padding: 10px; height: 150px; overflow-y: auto; font-family: Consolas, monospace; font-size: 11.5px; color: #00e676; }
        .traffic-line { padding: 2px 0; border-bottom: 1px solid rgba(43, 58, 103, 0.3); }

        .qr-card { display: flex; align-items: center; gap: 14px; background: #0b132b; border: 1px solid var(--border-card); border-radius: 8px; padding: 12px; flex-wrap: wrap; }
        .qr-box { background: #fff; padding: 6px; border-radius: 6px; flex-shrink: 0; }

        @media (max-width: 1024px) {
            .kpi-grid { grid-template-columns: repeat(2, 1fr); }
            .main-grid, .bottom-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 540px) {
            .kpi-grid { grid-template-columns: 1fr 1fr; gap: 8px; }
            .kpi-card { padding: 10px; }
            .kpi-info .val { font-size: 18px; }
            .btn { padding: 10px 12px; font-size: 13.5px; }
        }
    </style>
</head>
<body>

<div class="header">
    <div class="header-title">
        <h1>🎛️ HMI Máy Điều Khiển Tầng 2 - Modbus RTU</h1>
        <p>Link điện thoại LAN: <strong id="lanUrlText">{{ mobile_url }}</strong></p>
    </div>
    <div class="header-right">
        <div class="pill">TX: <span id="txCnt" style="color:#ff9800;">0</span> | RX: <span id="rxCnt" style="color:#00e676;">0</span></div>
        <div class="pill" id="connBadge" style="color:#e53935;">● Disconnected</div>
        <button class="btn btn-dark" style="padding:5px 10px;font-size:12px;" onclick="doLogout()">🚪 Đăng xuất</button>
    </div>
</div>

<!-- THANH THÔNG BÁO ĐỒNG BỘ CHƯA KẾT NỐI CỔNG COM -->
<div id="comAlertBar" class="com-alert-bar">
    <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-size:17px;">⚠️</span>
        <span id="comAlertText">Chưa kết nối cổng COM!</span>
    </div>
    <button class="btn" style="padding:4px 10px;font-size:12px;background:rgba(0,0,0,0.35);border:1px solid #ff8a80;" onclick="clearComAlert()">Đóng</button>
</div>

<div id="lockBanner" class="lock-banner lock-free">
    <span id="lockText">🔓 Quyền điều khiển cục bộ tự do (Đồng bộ Desktop & Mobile)</span>
    <span id="clockTxt" style="font-weight:400;color:#cbd5e1;">--:--:--</span>
</div>

<!-- THANH KẾT NỐI CỔNG COM MODBUS -->
<div class="setup-bar">
    <div class="setup-group">
        <strong>Modbus RS485:</strong>
        <label>Port:</label>
        <select id="selPort"><option value="COM6">COM6</option><option value="COM7">COM7</option><option value="COM17">COM17</option></select>
        <button class="btn btn-dark" onclick="scanPorts()" title="Quét lại cổng COM">↻</button>
        <label>Baud:</label>
        <select id="selBaud">
            <option value="4800">4800</option>
            <option value="9600" selected>9600</option>
            <option value="19200">19200</option>
            <option value="38400">38400</option>
            <option value="57600">57600</option>
            <option value="115200">115200</option>
        </select>
        <label>SHT20 ID:</label>
        <input type="number" id="inpShtId" value="1" min="1" max="247" style="width:58px;">
        <button id="btnComToggle" class="btn btn-green" onclick="toggleSerial()">Connect</button>
    </div>
    <div style="font-size:12px;color:var(--text-muted);" id="setupMsg">Chọn cổng USB-RS485 và bấm Connect</div>
</div>

<div class="container">
    <!-- 5 THẺ KPI -->
    <div class="kpi-grid">
        <div class="kpi-card kpi-temp">
            <div class="kpi-info">
                <h3>🌡️ Nhiệt độ</h3>
                <div class="val" id="valTemp">--.- °C</div>
                <div class="sub">SHT20</div>
            </div>
        </div>
        <div class="kpi-card kpi-humi">
            <div class="kpi-info">
                <h3>💧 Độ ẩm</h3>
                <div class="val" id="valHumi">--.- %</div>
                <div class="sub">SHT20</div>
            </div>
        </div>
        <div class="kpi-card">
            <div class="kpi-info">
                <h3>☢️ Quạt (K1)</h3>
                <div class="val" id="valFan" style="font-size:17px;">Đang tắt</div>
                <div class="sub">Làm mát</div>
            </div>
            <label class="switch">
                <input type="checkbox" id="swFanKpi" onchange="sendOutput('fan', this.checked)">
                <span class="slider"></span>
            </label>
        </div>
        <div class="kpi-card">
            <div class="kpi-info">
                <h3>🚿 Bơm (K2)</h3>
                <div class="val" id="valPump" style="font-size:17px;">Đang tắt</div>
                <div class="sub">Tưới mát</div>
            </div>
            <label class="switch">
                <input type="checkbox" id="swPumpKpi" onchange="sendOutput('pump', this.checked)">
                <span class="slider"></span>
            </label>
        </div>
        <div class="kpi-card" style="grid-column: span 1;">
            <div class="kpi-info">
                <h3>🚪 Cửa tự động</h3>
                <div class="val" id="valDoor" style="font-size:16px;color:#ff9800;">Đang dừng</div>
                <div class="sub">Mở K3 | Đóng K4</div>
            </div>
        </div>
    </div>

    <!-- THÂN CHÍNH -->
    <div class="main-grid">
        <!-- CỘT ĐIỀU KHIỂN -->
        <div class="col" style="order: 2;">
            <div class="card">
                <div class="card-hdr"><h2>🕹️ Điều khiển thủ công</h2></div>

                <div class="ctrl-item">
                    <div class="ctrl-top">
                        <div>
                            <div style="font-weight:700;">☢️ Quạt 12V (K1)</div>
                            <div style="font-size:11.5px;color:var(--text-muted);">Relay 0xFF · Kênh 1</div>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="swFanMan" onchange="sendOutput('fan', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="ctrl-actions">
                        <button id="btnFanOn" class="btn btn-dark" onclick="sendOutput('fan', true)">Bật quạt</button>
                        <button id="btnFanOff" class="btn btn-dark" onclick="sendOutput('fan', false)">Tắt quạt</button>
                    </div>
                </div>

                <div class="ctrl-item">
                    <div class="ctrl-top">
                        <div>
                            <div style="font-weight:700;">🚿 Máy bơm 12V (K2)</div>
                            <div style="font-size:11.5px;color:var(--text-muted);">Relay 0xFF · Kênh 2</div>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="swPumpMan" onchange="sendOutput('pump', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                    <div class="ctrl-actions">
                        <button id="btnPumpOn" class="btn btn-dark" onclick="sendOutput('pump', true)">Bật bơm</button>
                        <button id="btnPumpOff" class="btn btn-dark" onclick="sendOutput('pump', false)">Tắt bơm</button>
                    </div>
                </div>

                <div class="ctrl-item" style="margin-bottom:0;">
                    <div>
                        <div style="font-weight:700;">🚪 Cửa tự động (K3 & K4)</div>
                        <div style="font-size:11.5px;color:var(--text-muted);">Mở 3.7s / Đóng 3.5s - Tự động ngắt</div>
                    </div>
                    <div class="door-actions">
                        <button id="btnDoorOpen" class="btn btn-green" onclick="sendOutput('door', 'open')">MỞ</button>
                        <button id="btnDoorStop" class="btn btn-orange" onclick="sendOutput('door', 'stop')">DỪNG</button>
                        <button id="btnDoorClose" class="btn btn-red" onclick="sendOutput('door', 'close')">ĐÓNG</button>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-hdr">
                    <h2>⚙️ Chế độ tự động</h2>
                    <label class="switch">
                        <input type="checkbox" id="swAuto" onchange="sendMode(this.checked)">
                        <span class="slider"></span>
                    </label>
                </div>
                <p style="font-size:12px;color:var(--text-muted);margin-bottom:10px;">Tự động bật quạt khi vượt ngưỡng nhiệt độ</p>
                <div class="th-row">
                    <span>Nhiệt độ &gt; (Bật quạt)</span>
                    <div><input type="number" id="inpThHigh" step="0.5" value="30.0"> °C</div>
                </div>
                <div class="th-row">
                    <span>Nhiệt độ &lt; (Tắt quạt)</span>
                    <div><input type="number" id="inpThLow" step="0.5" value="28.0"> °C</div>
                </div>
                <button id="btnSaveTh" class="btn btn-blue" style="width:100%;margin-top:6px;" onclick="saveThresholds()">Lưu ngưỡng nhiệt độ</button>
            </div>

            <!-- MÃ QR MỞ TRÊN ĐIỆN THOẠI BẰNG IP LAN -->
            <div class="card">
                <div class="card-hdr"><h2>📱 Quét QR mở trên Điện thoại</h2></div>
                <div class="qr-card">
                    <div class="qr-box"><div id="qrcode"></div></div>
                    <div style="flex:1;min-width:170px;">
                        <div style="font-size:12px;color:#00e676;font-weight:700;word-break:break-all;" id="qrUrlLabel">{{ mobile_url }}</div>
                        <div style="font-size:11.5px;color:var(--text-muted);margin:6px 0;">Điện thoại & máy tính dùng chung Wi-Fi. Nếu đổi mạng, nhập IP mới bên dưới:</div>
                        <div style="display:flex;gap:6px;">
                            <input type="text" id="inpCustomIp" value="{{ lan_ip }}" style="width:125px;font-size:12px;padding:5px 8px;">
                            <button class="btn btn-blue" style="padding:5px 10px;font-size:12px;" onclick="rebuildQr()">Đổi IP</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- CỘT BIỂU ĐỒ & LOG -->
        <div class="col" style="order: 1;">
            <div class="card">
                <div class="card-hdr">
                    <h2>📈 Biểu đồ nhiệt độ & độ ẩm thời gian thực</h2>
                    <div style="font-size:12px;">
                        <span style="color:#ff5252;font-weight:700;margin-right:12px;">● Nhiệt độ (°C)</span>
                        <span style="color:#00b0ff;font-weight:700;">● Độ ẩm (%)</span>
                    </div>
                </div>
                <div class="chart-box"><canvas id="t2Chart"></canvas></div>
            </div>

            <div class="bottom-grid">
                <div class="card">
                    <div class="card-hdr"><h2>📋 Nhật ký hoạt động</h2></div>
                    <table>
                        <thead><tr><th style="width:24%;">Thời gian</th><th style="width:32%;">Sự kiện</th><th>Thông tin</th></tr></thead>
                        <tbody id="logBody"></tbody>
                    </table>
                </div>
                <div class="card">
                    <div class="card-hdr">
                        <h2>📡 Modbus TX / RX</h2>
                        <span style="font-size:11px;color:var(--text-muted);">Raw Hex RTU</span>
                    </div>
                    <div class="traffic-box" id="trafficBox">Chưa có khung truyền...</div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
const $ = id => document.getElementById(id);
let isConnected = false;
let portInitialized = false;
let chart = null;
let isRefreshing = false;
window.latestState = {};

const uiLockUntil = { fan: 0, pump: 0, auto: 0 };
const revertTimers = { fan: null, pump: null, auto: null };

async function doLogout() {
    try { await fetch('/api/logout', { method: 'POST' }); } catch (e) {}
    window.location.reload();
}

function applyFanUi(fanOn, lockFan) {
    $('valFan').textContent = fanOn ? 'Đang bật' : 'Đang tắt';
    $('valFan').style.color = fanOn ? '#00e676' : '#ffffff';
    ['swFanKpi', 'swFanMan'].forEach(id => {
        $(id).checked = fanOn;
        if (typeof lockFan === 'boolean') $(id).disabled = lockFan;
    });
    if (typeof lockFan === 'boolean') {
        ['btnFanOn', 'btnFanOff'].forEach(id => { $(id).disabled = lockFan; });
    }
    $('btnFanOn').className = 'btn ' + (fanOn ? 'btn-green' : 'btn-dark');
    $('btnFanOff').className = 'btn ' + (!fanOn ? 'btn-red' : 'btn-dark');
}

function applyPumpUi(pumpOn, lockByServer) {
    $('valPump').textContent = pumpOn ? 'Đang bật' : 'Đang tắt';
    $('valPump').style.color = pumpOn ? '#00e676' : '#ffffff';
    ['swPumpKpi', 'swPumpMan'].forEach(id => {
        $(id).checked = pumpOn;
        if (typeof lockByServer === 'boolean') $(id).disabled = lockByServer;
    });
    if (typeof lockByServer === 'boolean') {
        ['btnPumpOn', 'btnPumpOff'].forEach(id => { $(id).disabled = lockByServer; });
    }
    $('btnPumpOn').className = 'btn ' + (pumpOn ? 'btn-green' : 'btn-dark');
    $('btnPumpOff').className = 'btn ' + (!pumpOn ? 'btn-red' : 'btn-dark');
}

function applyAutoUi(autoOn, lockByServer) {
    $('swAuto').checked = autoOn;
    if (typeof lockByServer === 'boolean') $('swAuto').disabled = lockByServer;
    let fanOn = $('swFanKpi').checked;
    let lockFan = Boolean(lockByServer) || autoOn;
    ['swFanKpi', 'swFanMan'].forEach(id => { $(id).disabled = lockFan; });
    ['btnFanOn', 'btnFanOff'].forEach(id => { $(id).disabled = lockFan; });
    $('btnFanOn').className = 'btn ' + (fanOn ? 'btn-green' : 'btn-dark');
    $('btnFanOff').className = 'btn ' + (!fanOn ? 'btn-red' : 'btn-dark');
}

function showComBanner(msg) {
    $('comAlertText').textContent = msg || 'Chưa kết nối cổng COM!';
    $('comAlertBar').style.display = 'flex';
}
function hideComBanner() {
    $('comAlertBar').style.display = 'none';
}

async function triggerComAlert(deviceLabel) {
    let localMsg = `Chưa kết nối cổng COM! Không thể điều khiển [${deviceLabel}] — Thao tác từ: Web/Mobile Tầng 2`;
    showComBanner(localMsg);
    try {
        let d = await postJson('/api/local/com_alert', { device: deviceLabel });
        if (d && d.com_alert && d.com_alert.message) showComBanner(d.com_alert.message);
    } catch (e) {}
}

async function clearComAlert() {
    hideComBanner();
    try {
        await postJson('/api/local/com_alert/clear', {});
    } catch (e) {}
}

function rebuildQr() {
    let ip = ($('inpCustomIp').value || '').trim() || '{{ lan_ip }}';
    let url = `http://${ip}:5000/mobile-hmi`;
    $('qrUrlLabel').textContent = url;
    $('lanUrlText').textContent = url;
    $('qrcode').innerHTML = '';
    if (window.QRCode) {
        new QRCode($('qrcode'), { text: url, width: 104, height: 104 });
    }
}
rebuildQr();

try {
    if (window.Chart && $('t2Chart')) {
        chart = new Chart($('t2Chart').getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Nhiệt độ (°C)', data: [], borderColor: '#ff5252', yAxisID: 'yT', tension: 0.25, borderWidth: 2, pointRadius: 2 },
                    { label: 'Độ ẩm (%)', data: [], borderColor: '#00b0ff', yAxisID: 'yH', tension: 0.25, borderWidth: 2, pointRadius: 2 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false, animation: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#a0aab2', maxTicksLimit: 8 }, grid: { color: 'rgba(43,58,103,0.4)' } },
                    yT: { type: 'linear', position: 'left', suggestedMin: 20, suggestedMax: 42, ticks: { color: '#ff5252' }, grid: { color: 'rgba(43,58,103,0.4)' } },
                    yH: { type: 'linear', position: 'right', suggestedMin: 20, suggestedMax: 100, ticks: { color: '#00b0ff' }, grid: { drawOnChartArea: false } }
                }
            }
        });
    }
} catch (e) {}

async function postJson(url, body) {
    let r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (r.status === 401) {
        window.location.reload();
        throw Error('Hết phiên đăng nhập');
    }
    let d = await r.json();
    if (!r.ok || d.ok === false) {
        if (d.com_disconnected && d.com_alert && d.com_alert.message) {
            showComBanner(d.com_alert.message);
        }
        throw Error(d.error || 'Thao tác thất bại');
    }
    return d;
}

async function scanPorts() {
    try {
        let r = await fetch('/api/tier3/ports');
        if (r.status === 401) { window.location.reload(); return; }
        let d = await r.json();
        if (d.ports && d.ports.length) {
            let sel = $('selPort'), cur = sel.value;
            sel.innerHTML = '';
            d.ports.forEach(p => {
                let opt = document.createElement('option');
                opt.value = p; opt.textContent = p;
                if (p === cur) opt.selected = true;
                sel.appendChild(opt);
            });
            $('setupMsg').textContent = 'Đã cập nhật danh sách cổng COM';
        }
    } catch (e) {}
}

async function toggleSerial() {
    try {
        if (!isConnected) {
            let d = await postJson('/api/tier3/serial_config', {
                action: 'setup_ok',
                port: $('selPort').value,
                baud: parseInt($('selBaud').value) || 9600,
                sht_id: parseInt($('inpShtId').value) || 1
            });
            $('setupMsg').textContent = d.message || 'Đang kết nối...';
        } else {
            let d = await postJson('/api/tier3/serial_config', { action: 'disconnect' });
            $('setupMsg').textContent = d.message || 'Đã ngắt kết nối';
        }
        setTimeout(refresh, 150);
    } catch (e) {
        alert(e.message);
    }
}

async function sendOutput(name, on) {
    let s = window.latestState || {};
    let devMap = { fan: 'Quạt 12V (K1)', pump: 'Máy bơm 12V (K2)', door: 'Cửa tự động (K3/K4)' };
    let devLabel = devMap[name] || name;

    if (!isConnected) {
        if (name === 'fan' || name === 'pump') {
            if (revertTimers[name]) clearTimeout(revertTimers[name]);
            revertTimers[name] = setTimeout(() => {
                ['swFanKpi', 'swFanMan'].forEach(id => { $(id).checked = Boolean(s.fan); });
                ['swPumpKpi', 'swPumpMan'].forEach(id => { $(id).checked = Boolean(s.pump); });
                revertTimers[name] = null;
            }, 150);
        }
        await triggerComAlert(devLabel);
        return;
    }

    if (name === 'fan') {
        uiLockUntil.fan = Date.now() + 1500;
        applyFanUi(Boolean(on));
    } else if (name === 'pump') {
        uiLockUntil.pump = Date.now() + 1500;
        applyPumpUi(Boolean(on));
    } else if (name === 'door') {
        let txtMap = { open: 'Đang mở...', close: 'Đang đóng...', stop: 'Đang dừng' };
        let colMap = { open: '#00e676', close: '#e53935', stop: '#ff9800' };
        if (txtMap[on]) {
            $('valDoor').textContent = txtMap[on];
            $('valDoor').style.color = colMap[on];
        }
    }

    try {
        await postJson('/api/local/output', { name, on });
    } catch (e) {
        uiLockUntil[name] = 0;
        if (!e.message.includes('cổng COM')) alert(e.message);
        refresh();
    }
}

async function sendMode(isAuto) {
    let s = window.latestState || {};
    if (!isConnected) {
        if (revertTimers.auto) clearTimeout(revertTimers.auto);
        revertTimers.auto = setTimeout(() => {
            $('swAuto').checked = Boolean(s.auto_mode);
            revertTimers.auto = null;
        }, 150);
        await triggerComAlert('Chế độ tự động (Auto)');
        return;
    }

    uiLockUntil.auto = Date.now() + 1500;
    applyAutoUi(Boolean(isAuto));

    try {
        await postJson('/api/local/mode', { mode: isAuto ? 'AUTO' : 'MANUAL' });
    } catch (e) {
        uiLockUntil.auto = 0;
        if (!e.message.includes('cổng COM')) alert(e.message);
        refresh();
    }
}

async function saveThresholds() {
    try {
        let d = await postJson('/api/local/thresholds', {
            temp_high: parseFloat($('inpThHigh').value),
            temp_low: parseFloat($('inpThLow').value)
        });
        $('setupMsg').textContent = d.message || 'Đã lưu ngưỡng nhiệt độ';
        refresh();
    } catch (e) {
        alert(e.message);
    }
}

async function refresh() {
    if (isRefreshing) return;
    isRefreshing = true;
    $('clockTxt').textContent = new Date().toLocaleTimeString('vi-VN');
    try {
        let r = await fetch('/api/tier3/state');
        if (r.status === 401) { window.location.reload(); return; }
        let s = await r.json();
        if (!s || typeof s !== 'object') return;
        window.latestState = s;

        isConnected = Boolean(s.is_connected);
        let badge = $('connBadge');
        badge.textContent = isConnected ? `● Connected (${s.port || $('selPort').value})` : '● Disconnected';
        badge.style.color = isConnected ? '#00e676' : '#e53935';

        if (s.com_alert && s.com_alert.active && !isConnected) {
            showComBanner(s.com_alert.message);
        } else {
            hideComBanner();
        }

        let btnCom = $('btnComToggle');
        btnCom.textContent = isConnected ? 'Disconnect' : 'Connect';
        btnCom.className = 'btn ' + (isConnected ? 'btn-red' : 'btn-green');
        $('selPort').disabled = isConnected;
        $('selBaud').disabled = isConnected;

        if (!portInitialized && s.port) {
            $('selPort').value = s.port;
            if (s.baud) $('selBaud').value = String(s.baud);
            portInitialized = true;
        }

        $('txCnt').textContent = s.tx_count || 0;
        $('rxCnt').textContent = s.rx_count || 0;

        let ov = (s.server_override && s.server_override.active);
        let grantAll = Boolean(s.grant_all || (s.server_override && s.server_override.grant_all));
        let banner = $('lockBanner');
        if (grantAll) {
            banner.className = 'lock-banner lock-all';
            $('lockText').textContent = '🌐 Máy chủ Tầng 3 đã CẤP QUYỀN CHO TẤT CẢ (Tầng 3, Tầng 2 & Điện thoại đều được điều khiển)';
        } else if (ov) {
            banner.className = 'lock-banner lock-busy';
            $('lockText').textContent = '🔒 Máy chủ Tầng 3 đang giữ quyền ưu tiên tối cao! (Chỉ xem, không thể thao tác)';
        } else {
            banner.className = 'lock-banner lock-free';
            $('lockText').textContent = '🔓 Quyền điều khiển cục bộ tự do (Đồng bộ Desktop & Mobile)';
        }

        $('valTemp').textContent = s.ok_sht ? Number(s.temp || 0).toFixed(1) + ' °C' : '--.- °C';
        $('valHumi').textContent = s.ok_sht ? Number(s.humi || 0).toFixed(1) + ' %' : '--.- %';

        let now = Date.now();
        let lockByServer = (ov && !grantAll);
        let autoOn = (now < uiLockUntil.auto) ? $('swAuto').checked : Boolean(s.auto_mode);
        let fanOn = (now < uiLockUntil.fan) ? $('swFanKpi').checked : Boolean(s.fan);
        let pumpOn = (now < uiLockUntil.pump) ? $('swPumpKpi').checked : Boolean(s.pump);
        let lockFan = lockByServer || autoOn;

        $('valDoor').textContent = s.door_text || 'Đang dừng';
        applyFanUi(fanOn, lockFan);
        applyPumpUi(pumpOn, lockByServer);

        ['btnDoorOpen', 'btnDoorStop', 'btnDoorClose'].forEach(id => { $(id).disabled = lockByServer; });

        $('swAuto').checked = autoOn;
        $('swAuto').disabled = lockByServer;
        $('btnSaveTh').disabled = lockByServer;

        if (document.activeElement !== $('inpThHigh') && s.temp_th !== undefined) $('inpThHigh').value = s.temp_th;
        if (document.activeElement !== $('inpThLow') && s.temp_th_low !== undefined) $('inpThLow').value = s.temp_th_low;

        if (chart && Array.isArray(s.chart_time)) {
            chart.data.labels = s.chart_time;
            chart.data.datasets[0].data = s.chart_temp || [];
            chart.data.datasets[1].data = s.chart_humi || [];
            chart.update('none');
        }

        if (Array.isArray(s.logs)) {
            $('logBody').innerHTML = s.logs.slice(0, 7).map(x =>
                `<tr><td style="color:#a0aab2">${x.time||''}</td><td>${x.event||''}</td><td style="color:#00e676">${x.info||''}</td></tr>`
            ).join('');
        }

        if (Array.isArray(s.txrx_logs) && s.txrx_logs.length) {
            $('trafficBox').innerHTML = s.txrx_logs.slice(0, 20).map(x =>
                `<div class="traffic-line">[${x.time||''}] ${x.dir||''} ${x.dir==='TX'?'->':'<-'} ${x.frame||''}</div>`
            ).join('');
        }
    } catch (e) {
    } finally {
        isRefreshing = false;
    }
}

async function pollLoop() {
    await refresh();
    setTimeout(pollLoop, 1000);
}

scanPorts();
pollLoop();
</script>
</body>
</html>'''


# ==================== 3. API TẦNG 2 (ĐĂNG NHẬP, WEB/MOBILE 5000 & MÁY CHỦ TẦNG 3) ====================
@app.route('/api/login', methods=['POST'])
def t2_login():
    ip = request.remote_addr or "unknown"
    now = time.time()
    rec = t2_login_attempts.get(ip)
    if rec and rec.get("locked_until", 0) > now:
        return jsonify({"ok": False, "error": f"Sai quá nhiều lần. Thử lại sau {int(rec['locked_until'] - now)}s"}), 429

    d = request.get_json(silent=True) or {}
    pwd = str(d.get("password", ""))
    if _hash_pass(pwd, t2_sec["salt"]) != t2_sec["web_hash"]:
        fails = (rec.get("fails", 0) if rec else 0) + 1
        locked = (now + 60) if fails >= 5 else 0
        t2_login_attempts[ip] = {"fails": 0 if locked else fails, "locked_until": locked}
        return jsonify({"ok": False, "error": "Mật khẩu không chính xác!"}), 401

    t2_login_attempts.pop(ip, None)
    session.permanent = True
    session["t2_ok"] = True
    session["t2_ver"] = t2_sec.get("auth_version", 1)
    return jsonify({"ok": True})


@app.route('/api/logout', methods=['POST'])
def t2_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route('/')
@app.route('/mobile-hmi')
@app.route('/hmi')
@app.route('/mobile')
def index():
    if not _is_t2_authenticated():
        return render_template_string(TIER2_LOGIN_PAGE)
    lan_ip = get_local_ip()
    mobile_url = f"http://{lan_ip}:5000/mobile-hmi"
    return render_template_string(TIER2_WEB_PAGE, lan_ip=lan_ip, mobile_url=mobile_url)


@app.route('/api/info')
def tier2_info():
    lan_ip = get_local_ip()
    return jsonify({
        "ok": True,
        "lan_ip": lan_ip,
        "port": 5000,
        "mobile_url": f"http://{lan_ip}:5000/mobile-hmi"
    })


@app.route('/api/tier3/state')
@app.route('/api/status')
@app.route('/api/data')
def tier3_state():
    if app_instance:
        return jsonify(app_instance.get_full_state())
    return jsonify({})


@app.route('/api/tier3/ports')
@app.route('/api/ports')
@app.route('/api/serial/ports')
def tier3_ports():
    detected = [p.device for p in serial.tools.list_ports.comports()]
    all_ports = list(dict.fromkeys(detected + ["COM6", "COM7", "COM17"]))
    cfg = app_instance.serial_cfg if app_instance else {}
    return jsonify({'ok': True, 'ports': all_ports, 'config': cfg})


@app.route('/api/tier3/serial_config', methods=['POST'])
@app.route('/api/tier3/connect', methods=['POST'])
@app.route('/api/connect', methods=['POST'])
def tier3_serial_config():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa khởi tạo'}), 503

    action = d.get('action', 'setup_ok')
    if action == 'disconnect':
        app_instance.root.after(0, lambda: app_instance.disconnect_serial(source="Web / Mobile"))
        return jsonify({'ok': True, 'message': 'Đã ngắt kết nối RS485'})

    app_instance.root.after(0, lambda: app_instance.apply_tier3_serial_config(d))
    return jsonify({'ok': True, 'message': f"Đã kết nối {d.get('port', '')} @ {d.get('baud', 9600)}"})


# --- API CỤC BỘ CHO WEB/MOBILE TẦNG 2 KÍCH HOẠT CẢNH BÁO COM ---
@app.route('/api/local/com_alert', methods=['POST'])
def local_com_alert():
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    d = request.get_json(silent=True) or {}
    device = str(d.get('device', '')).strip()
    alert_obj = app_instance.build_com_alert_dict(source="Web/Mobile Tầng 2", device=device)
    app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=True))
    return jsonify({'ok': True, 'com_alert': alert_obj})


@app.route('/api/local/com_alert/clear', methods=['POST'])
def local_com_alert_clear():
    if app_instance:
        app_instance.root.after(0, lambda: app_instance.clear_com_alert(sync_t3=True))
    return jsonify({'ok': True})


# --- API NHẬN ĐỒNG BỘ CẢNH BÁO COM TỪ MÁY CHỦ TẦNG 3 ---
@app.route('/api/tier3/com_alert', methods=['GET', 'POST'])
def tier3_com_alert():
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if request.method == 'GET':
        return jsonify({'ok': True, 'com_alert': dict(app_instance.com_alert)})

    d = request.get_json(silent=True) or {}
    if not d.get('active', True):
        app_instance.root.after(0, lambda: app_instance.clear_com_alert(sync_t3=False))
        return jsonify({'ok': True, 'com_alert': dict(app_instance.com_alert)})

    source = str(d.get('source', 'Máy chủ Tầng 3')).strip()
    device = str(d.get('device', '')).strip()
    custom_msg = str(d.get('message', '')).strip()
    custom_id = int(d.get('id', 0) or 0)
    custom_time = str(d.get('time', '')).strip()

    alert_obj = app_instance.build_com_alert_dict(
        source=source,
        device=device,
        custom_msg=custom_msg,
        custom_id=custom_id,
        custom_time=custom_time
    )
    app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=False))
    return jsonify({'ok': True, 'com_alert': alert_obj})


# --- API RIÊNG CHO GIAO DIỆN WEB & MOBILE TẠI PORT 5000 ---
@app.route('/api/local/output', methods=['POST'])
def local_web_output():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if app_instance.server_override_active and not app_instance.grant_all_active:
        return jsonify({'ok': False, 'error': 'Máy chủ Tầng 3 đang giữ quyền ưu tiên tối cao!'}), 423
    if not app_instance.connected:
        dev_map = {'fan': 'Quạt 12V (K1)', 'pump': 'Máy bơm 12V (K2)', 'door': 'Cửa tự động (K3/K4)'}
        dev_name = dev_map.get(str(d.get('name', '')).lower(), 'Thiết bị')
        alert_obj = app_instance.build_com_alert_dict(source="Web/Mobile Tầng 2", device=dev_name)
        app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=True))
        return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409
    app_instance.root.after(0, lambda: app_instance.handle_local_web_output(d))
    return jsonify({'ok': True})


@app.route('/api/local/mode', methods=['POST'])
def local_web_mode():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if app_instance.server_override_active and not app_instance.grant_all_active:
        return jsonify({'ok': False, 'error': 'Máy chủ Tầng 3 đang giữ quyền ưu tiên tối cao!'}), 423
    if not app_instance.connected:
        alert_obj = app_instance.build_com_alert_dict(source="Web/Mobile Tầng 2", device="Chế độ tự động (Auto)")
        app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=True))
        return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409
    mode = str(d.get('mode', 'MANUAL')).upper()
    app_instance.root.after(0, lambda: app_instance.toggle_auto_mode(mode == 'AUTO', from_remote=True, source_name="Web/Mobile Tầng 2"))
    return jsonify({'ok': True})


@app.route('/api/local/thresholds', methods=['POST'])
def local_web_thresholds():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if app_instance.server_override_active and not app_instance.grant_all_active:
        return jsonify({'ok': False, 'error': 'Máy chủ Tầng 3 đang giữ quyền ưu tiên!'}), 423
    try:
        th_h = float(str(d.get('temp_high', TEMP_THRESHOLD_HIGH)).replace(',', '.'))
        th_l = float(str(d.get('temp_low', TEMP_THRESHOLD_LOW)).replace(',', '.'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Giá trị ngưỡng nhiệt độ không hợp lệ'}), 400
    if th_h <= th_l:
        return jsonify({'ok': False, 'error': f'Ngưỡng bật ({th_h}°C) phải lớn hơn ngưỡng tắt ({th_l}°C)!'}), 400
    app_instance.root.after(0, lambda: app_instance.update_thresholds_from_web(th_h, th_l))
    return jsonify({'ok': True, 'message': f'Đã cập nhật ngưỡng: Bật > {th_h}°C, Tắt < {th_l}°C'})


# --- API CHO MÁY CHỦ TẦNG 3 (PORT 8080) ---
@app.route('/api/tier3/override', methods=['POST'])
def tier3_override():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    active = bool(d.get('active', False))
    grant_all = bool(d.get('grant_all', False))
    reason = str(d.get('reason', 'Máy chủ Tầng 3 điều phối'))
    app_instance.root.after(0, lambda: app_instance.set_server_override(active, reason, grant_all))
    return jsonify({'ok': True})


@app.route('/api/tier3/output', methods=['POST'])
def tier3_server_output():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if not app_instance.connected:
        dev_map = {'fan': 'Quạt 12V (K1)', 'pump': 'Máy bơm 12V (K2)', 'door': 'Cửa tự động (K3/K4)'}
        dev_name = dev_map.get(str(d.get('name', '')).lower(), 'Thiết bị')
        alert_obj = app_instance.build_com_alert_dict(source="Máy chủ Tầng 3", device=dev_name)
        app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=False))
        return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409
    app_instance.root.after(0, lambda: app_instance.handle_tier3_output(d, from_server=True))
    return jsonify({'ok': True})


@app.route('/api/tier3/client-output', methods=['POST'])
def tier3_client_output():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if app_instance.server_override_active and not app_instance.grant_all_active:
        return jsonify({'ok': False, 'error': 'Máy chủ Tầng 3 đang giữ quyền ưu tiên!'}), 423
    if not app_instance.connected:
        dev_map = {'fan': 'Quạt 12V (K1)', 'pump': 'Máy bơm 12V (K2)', 'door': 'Cửa tự động (K3/K4)'}
        dev_name = dev_map.get(str(d.get('name', '')).lower(), 'Thiết bị')
        alert_obj = app_instance.build_com_alert_dict(source="Điện thoại QR (Tầng 3)", device=dev_name)
        app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=False))
        return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409
    app_instance.root.after(0, lambda: app_instance.handle_tier3_output(d, from_server=False))
    return jsonify({'ok': True})


@app.route('/api/tier3/mode', methods=['POST'])
def tier3_server_mode():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if not app_instance.connected:
        alert_obj = app_instance.build_com_alert_dict(source="Máy chủ Tầng 3", device="Chế độ tự động (Auto)")
        app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=False))
        return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409
    app_instance.root.after(0, lambda: app_instance.handle_tier3_mode(d, from_server=True))
    return jsonify({'ok': True})


@app.route('/api/tier3/client-mode', methods=['POST'])
def tier3_client_mode():
    d = request.get_json(silent=True) or {}
    if not app_instance:
        return jsonify({'ok': False, 'error': 'Tầng 2 chưa sẵn sàng'}), 503
    if app_instance.server_override_active and not app_instance.grant_all_active:
        return jsonify({'ok': False, 'error': 'Máy chủ Tầng 3 đang giữ quyền ưu tiên!'}), 423
    if not app_instance.connected:
        alert_obj = app_instance.build_com_alert_dict(source="Điện thoại QR (Tầng 3)", device="Chế độ tự động (Auto)")
        app_instance.root.after(0, lambda: app_instance.apply_com_alert_dict(alert_obj, sync_t3=False))
        return jsonify({'ok': False, 'error': alert_obj['message'], 'com_disconnected': True, 'com_alert': alert_obj}), 409
    app_instance.root.after(0, lambda: app_instance.handle_tier3_mode(d, from_server=False))
    return jsonify({'ok': True})


# ==================== 4. CÔNG TẮC GẠT (TOGGLE SWITCH) ====================
class ToggleSwitch(tk.Canvas):
    def __init__(self, parent, width=65, height=32, bg_color="#1C2541", command=None):
        super().__init__(parent, width=width, height=height, bg=bg_color, highlightthickness=0, cursor="hand2")
        self.command = command
        self.is_on = False
        self.w = width
        self.h = height

        self.rect = self.create_rounded_rect(3, 3, self.w - 3, self.h - 3, radius=12, fill="#37474F")
        self.circle = self.create_oval(5, 5, self.h - 5, self.h - 5, fill="#FFFFFF", outline="")
        self.bind("<Button-1>", self.toggle)

    def create_rounded_rect(self, x1, y1, x2, y2, radius=25, **kwargs):
        points = [
            x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
            x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
            x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1
        ]
        return self.create_polygon(points, **kwargs, smooth=True)

    def toggle(self, event=None):
        self.set_state(not self.is_on, trigger_command=True)

    def set_state(self, state, trigger_command=False):
        state = bool(state)
        if self.is_on != state:
            self.is_on = state
            if self.is_on:
                self.itemconfig(self.rect, fill="#00C853")
                self.coords(self.circle, self.w - (self.h - 5), 5, self.w - 5, self.h - 5)
            else:
                self.itemconfig(self.rect, fill="#37474F")
                self.coords(self.circle, 5, 5, self.h - 5, self.h - 5)

        if trigger_command and self.command:
            self.command(self.is_on)


# ==================== 5. GIAO DIỆN TKINTER & PHẦN CỨNG THẬT ====================
class DashboardRealApp:
    def __init__(self, root):
        global app_instance
        app_instance = self

        self.root = root
        self.root.title("Máy Điều Khiển Tầng 2 - Modbus RTU (Port 5000)")
        self.root.geometry("1340x920")
        self.root.configure(bg="#0B132B")

        self.ser = None
        self.serial_lock = threading.Lock()
        self.connected = False
        self.running = True

        self.serial_cfg = {
            "port": "COM6", "baud": 9600, "databits": 8,
            "parity": "N", "stopbits": 1, "timeout_ms": 200
        }

        self.fan_state = 0
        self.pump_state = 0
        self.door_state = "STOPPED"
        self.door_text = "Đang dừng"
        self.door_timer_id = None
        self.mode_auto = False

        self.hw_cond = threading.Condition()
        self.pending_coils = {}
        self.pending_door_action = None

        self.revert_timers = {"fan": None, "pump": None, "auto": None}

        self.server_override_active = False
        self.server_override_reason = ""
        self.grant_all_active = False

        self.com_alert = {
            "active": False,
            "id": 0,
            "source": "",
            "device": "",
            "time": "",
            "message": ""
        }
        self.last_alert_id = 0
        self.last_alert_sig = ("", 0.0)
        self.alert_hide_timer = None

        self.temp_current = 0.0
        self.hum_current = 0.0
        self.ok_sht = False
        self.ok_rly = False
        self.tx_count = 0
        self.rx_count = 0
        self.err_count = 0
        self.last_tx = "--"
        self.last_rx = "--"
        self.txrx_logs = []

        self.max_data_points = 300
        self.time_data = []
        self.temp_data = []
        self.hum_data = []
        self.view_window_points = 150

        self.setup_styles()
        self.create_header()
        self.create_com_alert_banner()
        self.create_modbus_poll_config()
        self.create_body()

        self.refresh_com_ports()

        self.relay_thread = threading.Thread(target=self.relay_worker_loop, daemon=True)
        self.relay_thread.start()

        self.data_thread = threading.Thread(target=self.update_data_loop, daemon=True)
        self.data_thread.start()

        self.web_thread = threading.Thread(
            target=lambda: app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True),
            daemon=True
        )
        self.web_thread.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('.', background="#0B132B", foreground="#FFFFFF")
        self.style.configure("Treeview", background="#1C2541", foreground="#FFFFFF", fieldbackground="#1C2541", rowheight=24)
        self.style.configure("Treeview.Heading", background="#0B132B", foreground="#3A86FF", font=('Arial', 9, 'bold'))

    def create_header(self):
        header_frame = tk.Frame(self.root, bg="#0B132B", pady=8, padx=15)
        header_frame.pack(fill="x")

        title_box = tk.Frame(header_frame, bg="#0B132B")
        title_box.pack(side="left")

        tk.Label(title_box, text="Máy Điều Khiển Tầng 2 (Quạt, Bơm, Cửa - Modbus RTU)",
                 font=("Arial", 16, "bold"), fg="#FFFFFF", bg="#0B132B").pack(anchor="w")

        lan_ip = get_local_ip()
        tk.Label(title_box, text=f"PC: http://127.0.0.1:5000  |  Điện thoại QR (LAN): http://{lan_ip}:5000/mobile-hmi  |  MK mặc định: 3206",
                 font=("Arial", 9, "bold"), fg="#00E676", bg="#0B132B").pack(anchor="w")

        status_box = tk.Frame(header_frame, bg="#0B132B")
        status_box.pack(side="right")

        tk.Button(
            status_box,
            text="🔐 Mật khẩu Web",
            bg="#1E3A8A",
            fg="#FFFFFF",
            font=("Arial", 8, "bold"),
            relief="flat",
            padx=9,
            pady=3,
            cursor="hand2",
            command=self.open_web_password_dialog
        ).pack(side="left", padx=6)

        self.lbl_override_badge = tk.Label(status_box, text="🔓 Cục bộ tự do", fg="#38BDF8", bg="#0B132B", font=("Arial", 10, "bold"))
        self.lbl_override_badge.pack(side="left", padx=8)

        self.lbl_status_online = tk.Label(status_box, text="● Disconnected", fg="#E53935", bg="#0B132B", font=("Arial", 11, "bold"))
        self.lbl_status_online.pack(side="left", padx=10)

        self.lbl_clock = tk.Label(status_box, text="", fg="#A0AAB2", bg="#0B132B", font=("Arial", 10))
        self.lbl_clock.pack(side="left")
        self.update_clock()

    def open_web_password_dialog(self):
        """Hộp thoại đổi mật khẩu & bật/tắt bảo vệ Web/Mobile Tầng 2 (Port 5000)."""
        win = tk.Toplevel(self.root)
        win.title("Bảo mật Web / Mobile Tầng 2")
        win.geometry("380x250")
        win.configure(bg="#1C2541")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="🔐 Bảo mật truy cập Web/Mobile (Port 5000)", fg="#FFFFFF", bg="#1C2541", font=("Arial", 11, "bold")).pack(pady=(12, 8))

        var_enable = tk.BooleanVar(value=bool(t2_sec.get("auth_enabled", True)))
        tk.Checkbutton(
            win,
            text="Bật yêu cầu mật khẩu khi mở Web/Mobile LAN",
            variable=var_enable,
            bg="#1C2541",
            fg="#00E676",
            selectcolor="#0B132B",
            activebackground="#1C2541",
            activeforeground="#00E676",
            font=("Arial", 9, "bold")
        ).pack(anchor="w", padx=20, pady=4)

        tk.Label(win, text="Mật khẩu mới (để trống nếu giữ nguyên):", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).pack(anchor="w", padx=20, pady=(8, 2))
        ent_new = tk.Entry(win, show="*", width=28, bg="#0B132B", fg="#FFFFFF", insertbackground="white", font=("Arial", 11))
        ent_new.pack(padx=20, fill="x")

        def save_sec():
            new_p = ent_new.get().strip()
            if new_p and len(new_p) < 4:
                messagebox.showwarning("Cảnh báo", "Mật khẩu phải có ít nhất 4 ký tự!", parent=win)
                return
            t2_sec["auth_enabled"] = bool(var_enable.get())
            if new_p:
                t2_sec["web_hash"] = _hash_pass(new_p, t2_sec["salt"])
                t2_sec["user_customized"] = True
            t2_sec["auth_version"] = int(t2_sec.get("auth_version", 1)) + 1
            _save_t2_security(t2_sec)
            self.add_log("Bảo mật Web", "Đã cập nhật mật khẩu & thu hồi phiên Web cũ")
            messagebox.showinfo("Thành công", "Đã lưu cấu hình bảo mật Web Tầng 2!", parent=win)
            win.destroy()

        btn_row = tk.Frame(win, bg="#1C2541")
        btn_row.pack(fill="x", padx=20, pady=18)
        tk.Button(btn_row, text="💾 Lưu & Đá phiên cũ", bg="#00C853", fg="white", font=("Arial", 9, "bold"), relief="flat", padx=12, pady=5, command=save_sec).pack(side="left")
        tk.Button(btn_row, text="Hủy", bg="#37474F", fg="white", font=("Arial", 9), relief="flat", padx=14, pady=5, command=win.destroy).pack(side="right")

    def create_com_alert_banner(self):
        """Thanh thông báo cảnh báo đồng bộ 1 lần trên Desktop khi chưa kết nối cổng COM."""
        self.com_alert_frame = tk.Frame(
            self.root,
            bg="#B71C1C",
            highlightbackground="#FF8A80",
            highlightthickness=1,
            padx=12,
            pady=7
        )
        self.lbl_com_alert = tk.Label(
            self.com_alert_frame,
            text="⚠️ Chưa kết nối cổng COM!",
            fg="#FFFFFF",
            bg="#B71C1C",
            font=("Arial", 10, "bold"),
            anchor="w"
        )
        self.lbl_com_alert.pack(side="left", fill="x", expand=True)

        tk.Button(
            self.com_alert_frame,
            text="Đóng",
            bg="#7F0000",
            fg="#FFFFFF",
            font=("Arial", 8, "bold"),
            relief="flat",
            padx=10,
            pady=2,
            cursor="hand2",
            command=lambda: self.clear_com_alert(sync_t3=True)
        ).pack(side="right")

    def build_com_alert_dict(self, source: str, device: str = "", custom_msg: str = "", custom_id: int = 0, custom_time: str = "") -> dict:
        t_str = custom_time or datetime.now().strftime("%H:%M:%S")
        dev_txt = f" [{device}]" if device else ""
        msg = custom_msg or f"Chưa kết nối cổng COM! Không thể điều khiển{dev_txt} — Thao tác từ: {source} ({t_str})"
        return {
            "active": True,
            "id": custom_id or int(time.time() * 1000),
            "source": source,
            "device": device,
            "time": t_str,
            "message": msg
        }

    def apply_com_alert_dict(self, alert_obj: dict, sync_t3: bool = True):
        if self.connected:
            self.clear_com_alert(sync_t3=sync_t3)
            return

        now_ts = time.time()
        aid = int(alert_obj.get("id", 0) or 0)
        sig = (alert_obj.get("device", ""), alert_obj.get("source", ""))
        if aid and aid == self.last_alert_id:
            return
        if sig == self.last_alert_sig[0] and (now_ts - self.last_alert_sig[1]) < 1.2:
            return

        self.last_alert_id = aid
        self.last_alert_sig = (sig, now_ts)
        self.com_alert.update(alert_obj)

        self.lbl_com_alert.config(text=f"⚠️  {self.com_alert['message']}")
        if not self.com_alert_frame.winfo_ismapped():
            self.com_alert_frame.pack(fill="x", padx=10, pady=(0, 6), before=self.top_modbus_frame)

        self.add_log("Cảnh báo COM", self.com_alert["message"])

        if sync_t3:
            push_com_alert_to_tier3(dict(self.com_alert))

        if self.alert_hide_timer is not None:
            self.root.after_cancel(self.alert_hide_timer)
        self.alert_hide_timer = self.root.after(3500, lambda: self.clear_com_alert(sync_t3=sync_t3))

    def trigger_com_alert(self, source: str, device: str = "", sync_t3: bool = True):
        alert_obj = self.build_com_alert_dict(source=source, device=device)
        self.apply_com_alert_dict(alert_obj, sync_t3=sync_t3)

    def clear_com_alert(self, sync_t3: bool = True):
        if self.alert_hide_timer is not None:
            self.root.after_cancel(self.alert_hide_timer)
            self.alert_hide_timer = None
        was_active = self.com_alert.get("active", False)
        self.com_alert.update({
            "active": False,
            "source": "",
            "device": "",
            "time": "",
            "message": ""
        })
        if self.com_alert_frame.winfo_ismapped():
            self.com_alert_frame.pack_forget()
        if sync_t3 and was_active:
            push_com_alert_to_tier3({"active": False})

    def create_modbus_poll_config(self):
        self.top_modbus_frame = tk.Frame(self.root, bg="#1C2541", padx=10, pady=6)
        self.top_modbus_frame.pack(fill="x", padx=10, pady=(0, 6))

        cfg_box = tk.LabelFrame(self.top_modbus_frame, text=" Modbus Connection Setup ", fg="#3A86FF", bg="#1C2541", font=("Arial", 9, "bold"))
        cfg_box.pack(side="left", fill="both", padx=(0, 10))

        f1 = tk.Frame(cfg_box, bg="#1C2541")
        f1.pack(fill="x", padx=5, pady=3)

        tk.Label(f1, text="Port:", fg="#FFFFFF", bg="#1C2541", font=("Arial", 8)).pack(side="left")
        self.cb_port = ttk.Combobox(f1, values=["COM6", "COM7", "COM17"], width=10, font=("Arial", 8))
        self.cb_port.set("COM6")
        self.cb_port.pack(side="left", padx=2)
        self.cb_port.bind("<Button-1>", lambda e: self.refresh_com_ports())

        tk.Label(f1, text="Baud:", fg="#FFFFFF", bg="#1C2541", font=("Arial", 8)).pack(side="left", padx=(5, 0))
        self.cb_baud = ttk.Combobox(f1, values=["4800", "9600", "19200", "38400", "57600", "115200"], width=6, font=("Arial", 8), state="readonly")
        self.cb_baud.set("9600")
        self.cb_baud.pack(side="left", padx=2)

        f2 = tk.Frame(cfg_box, bg="#1C2541")
        f2.pack(fill="x", padx=5, pady=3)

        tk.Label(f2, text="SHT20 ID:", fg="#FFFFFF", bg="#1C2541", font=("Arial", 8)).pack(side="left")
        self.ent_slave_id = tk.Entry(f2, width=4, bg="#0B132B", fg="#FFFFFF", insertbackground="white", font=("Arial", 8))
        self.ent_slave_id.insert(0, "1")
        self.ent_slave_id.pack(side="left", padx=2)

        self.btn_modbus_connect = tk.Button(f2, text="Connect", bg="#00C853", fg="white", font=("Arial", 8, "bold"), relief="flat", command=self.toggle_connection)
        self.btn_modbus_connect.pack(side="left", padx=(10, 0))

        traffic_box = tk.LabelFrame(self.top_modbus_frame, text=" Modbus Traffic Monitor (TX / RX Raw Frame) ", fg="#00E676", bg="#1C2541", font=("Arial", 9, "bold"))
        traffic_box.pack(side="right", fill="both", expand=True)

        t_head = tk.Frame(traffic_box, bg="#1C2541")
        t_head.pack(fill="x", padx=5, pady=2)

        tk.Label(t_head, text="Mode:", fg="#A0AAB2", bg="#1C2541", font=("Arial", 8)).pack(side="left")
        tk.Label(t_head, text="Raw Hex Bytes (RTU)", fg="#FFFFFF", bg="#1C2541", font=("Arial", 8, "bold")).pack(side="left", padx=5)
        tk.Button(t_head, text="Clear Log", bg="#37474F", fg="white", font=("Arial", 7), relief="flat", command=self.clear_traffic).pack(side="right")

        txt_frame = tk.Frame(traffic_box, bg="#0B132B")
        txt_frame.pack(fill="both", expand=True, padx=5, pady=2)

        scroll_y = tk.Scrollbar(txt_frame)
        scroll_y.pack(side="right", fill="y")

        self.txt_traffic = tk.Text(txt_frame, height=6, bg="#0B132B", fg="#00E676", font=("Consolas", 8), relief="flat", yscrollcommand=scroll_y.set)
        self.txt_traffic.pack(side="left", fill="both", expand=True)
        scroll_y.config(command=self.txt_traffic.yview)

    def create_body(self):
        body_frame = tk.Frame(self.root, bg="#0B132B", padx=10, pady=0)
        body_frame.pack(fill="both", expand=True)

        left_col = tk.Frame(body_frame, bg="#0B132B")
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right_col = tk.Frame(body_frame, bg="#0B132B", width=360)
        right_col.pack(side="right", fill="both")

        cards_frame_r1 = tk.Frame(left_col, bg="#0B132B")
        cards_frame_r1.pack(fill="x", pady=(0, 4))

        cards_frame_r2 = tk.Frame(left_col, bg="#0B132B")
        cards_frame_r2.pack(fill="x", pady=(0, 8))

        self.card_temp = tk.Frame(cards_frame_r1, bg="#1C2541", highlightbackground="#3A86FF", highlightthickness=1)
        self.card_temp.pack(side="left", fill="both", expand=True, padx=2)
        tk.Label(self.card_temp, text="Nhiệt độ", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).pack(anchor="w", padx=10, pady=(4, 0))
        self.lbl_temp_val = tk.Label(self.card_temp, text="--.- °C", fg="#FFFFFF", bg="#1C2541", font=("Arial", 18, "bold"))
        self.lbl_temp_val.pack(anchor="w", padx=10)
        tk.Label(self.card_temp, text="Cảm biến SHT20", fg="#4CAF50", bg="#1C2541", font=("Arial", 8)).pack(anchor="w", padx=10, pady=(0, 4))

        self.card_hum = tk.Frame(cards_frame_r1, bg="#1C2541")
        self.card_hum.pack(side="left", fill="both", expand=True, padx=2)
        tk.Label(self.card_hum, text="Độ ẩm", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).pack(anchor="w", padx=10, pady=(4, 0))
        self.lbl_hum_val = tk.Label(self.card_hum, text="--.- %", fg="#FFFFFF", bg="#1C2541", font=("Arial", 18, "bold"))
        self.lbl_hum_val.pack(anchor="w", padx=10)
        tk.Label(self.card_hum, text="Cảm biến SHT20", fg="#00B0FF", bg="#1C2541", font=("Arial", 8)).pack(anchor="w", padx=10, pady=(0, 4))

        card_fan_top = tk.Frame(cards_frame_r1, bg="#1C2541")
        card_fan_top.pack(side="left", fill="both", expand=True, padx=2)
        tk.Label(card_fan_top, text="Quạt 12V", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).pack(anchor="w", padx=10, pady=(4, 0))
        self.lbl_fan_top_status = tk.Label(card_fan_top, text="Đang tắt", fg="#FFFFFF", bg="#1C2541", font=("Arial", 13, "bold"))
        self.lbl_fan_top_status.pack(anchor="w", padx=10)
        tk.Label(card_fan_top, text="Thông gió - Làm mát (Kênh 1)", fg="#6C7A89", bg="#1C2541", font=("Arial", 8)).pack(anchor="w", padx=10, pady=(0, 4))

        card_pump = tk.Frame(cards_frame_r2, bg="#1C2541")
        card_pump.pack(side="left", fill="both", expand=True, padx=2)
        tk.Label(card_pump, text="Máy bơm 12V", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).pack(anchor="w", padx=10, pady=(4, 0))
        self.lbl_pump_top_status = tk.Label(card_pump, text="Đang tắt", fg="#FFFFFF", bg="#1C2541", font=("Arial", 13, "bold"))
        self.lbl_pump_top_status.pack(anchor="w", padx=10)
        tk.Label(card_pump, text="Bơm nước - Tưới mát (Kênh 2)", fg="#6C7A89", bg="#1C2541", font=("Arial", 8)).pack(anchor="w", padx=10, pady=(0, 4))

        card_door = tk.Frame(cards_frame_r2, bg="#1C2541")
        card_door.pack(side="left", fill="both", expand=True, padx=2)
        tk.Label(card_door, text="Cửa Tự động", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).pack(anchor="w", padx=10, pady=(4, 0))
        self.lbl_door_top_status = tk.Label(card_door, text="Đang dừng", fg="#FF9800", bg="#1C2541", font=("Arial", 13, "bold"))
        self.lbl_door_top_status.pack(anchor="w", padx=10)
        tk.Label(card_door, text="Mở (K3) | Đóng (K4) - Tự ngắt", fg="#6C7A89", bg="#1C2541", font=("Arial", 8)).pack(anchor="w", padx=10, pady=(0, 4))

        chart_frame = tk.Frame(left_col, bg="#1C2541")
        chart_frame.pack(fill="both", expand=True, pady=(0, 8))

        chart_head = tk.Frame(chart_frame, bg="#1C2541")
        chart_head.pack(fill="x", padx=10, pady=3)
        tk.Label(chart_head, text="Biểu đồ nhiệt độ & độ ẩm thời gian thực",
                 fg="#FFFFFF", bg="#1C2541", font=("Arial", 10, "bold")).pack(side="left")

        btn_box_time = tk.Frame(chart_head, bg="#1C2541")
        btn_box_time.pack(side="right")
        tk.Button(btn_box_time, text="1 Phút", bg="#37474F", fg="white", font=("Arial", 8), relief="flat", command=lambda: self.set_view_window(30)).pack(side="left", padx=2)
        tk.Button(btn_box_time, text="5 Phút", bg="#37474F", fg="white", font=("Arial", 8), relief="flat", command=lambda: self.set_view_window(150)).pack(side="left", padx=2)
        tk.Button(btn_box_time, text="10 Phút", bg="#37474F", fg="white", font=("Arial", 8), relief="flat", command=lambda: self.set_view_window(300)).pack(side="left", padx=2)

        self.fig, self.ax1 = plt.subplots(figsize=(5, 1.8), facecolor="#1C2541")
        self.ax1.set_facecolor("#1C2541")
        self.ax2 = self.ax1.twinx()

        self.ax1.tick_params(colors='white', labelsize=8)
        self.ax2.tick_params(colors='#00B0FF', labelsize=8)
        self.ax1.spines['bottom'].set_color('#3A86FF')
        self.ax1.spines['top'].set_visible(False)
        self.ax1.spines['left'].set_color('#FF5252')
        self.ax1.spines['right'].set_color('#00B0FF')
        self.ax2.spines['top'].set_visible(False)

        (self.line_temp,) = self.ax1.plot([], [], color='#FF5252', linewidth=1.5, label='Nhiệt độ (°C)')
        (self.line_hum,) = self.ax2.plot([], [], color='#00B0FF', linewidth=1.5, label='Độ ẩm (%)')
        self.fig.subplots_adjust(left=0.07, right=0.93, top=0.92, bottom=0.22)

        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=(0, 2))

        toolbar_frame = tk.Frame(chart_frame, bg="#1C2541")
        toolbar_frame.pack(fill="x", padx=5, pady=(0, 3))
        self.toolbar = NavigationToolbar2Tk(self.canvas, toolbar_frame)
        self.toolbar.config(background="#1C2541")
        for button in self.toolbar.winfo_children():
            button.config(background="#1C2541")
        self.toolbar.update()

        bottom_box = tk.Frame(left_col, bg="#0B132B")
        bottom_box.pack(fill="x")

        status_box = tk.Frame(bottom_box, bg="#1C2541", width=250)
        status_box.pack(side="left", fill="both", expand=True, padx=(0, 5))
        tk.Label(status_box, text="Trạng thái thiết bị", fg="#FFFFFF", bg="#1C2541", font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=3)

        self.lbl_st_sht = tk.Label(status_box, text="• Cảm biến SHT20                  : Chờ kết nối", fg="#FFB74D", bg="#1C2541", font=("Arial", 8))
        self.lbl_st_sht.pack(anchor="w", padx=10, pady=1)
        self.lbl_st_relay = tk.Label(status_box, text="• Module Relay                       : Chờ kết nối", fg="#FFB74D", bg="#1C2541", font=("Arial", 8))
        self.lbl_st_relay.pack(anchor="w", padx=10, pady=1)

        log_box = tk.Frame(bottom_box, bg="#1C2541")
        log_box.pack(side="right", fill="both", expand=True, padx=(5, 0))
        tk.Label(log_box, text="Nhật ký hoạt động SHT20 & Relay", fg="#FFFFFF", bg="#1C2541", font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=3)

        self.log_tree = ttk.Treeview(log_box, columns=("time", "event", "info"), show="headings", height=3)
        self.log_tree.heading("time", text="Thời gian")
        self.log_tree.heading("event", text="Sự kiện")
        self.log_tree.heading("info", text="Thông tin")
        self.log_tree.column("time", width=70)
        self.log_tree.column("event", width=100)
        self.log_tree.column("info", width=200)
        self.log_tree.pack(fill="both", expand=True, padx=5, pady=3)

        self.add_log("Khởi động", f"Mở Web/Mobile tại http://{get_local_ip()}:5000/mobile-hmi")

        ctrl_box = tk.Frame(right_col, bg="#1C2541", padx=15, pady=15)
        ctrl_box.pack(fill="x", pady=(0, 12))

        tk.Label(ctrl_box, text="Điều khiển thủ công", fg="#FFFFFF", bg="#1C2541", font=("Arial", 13, "bold")).pack(anchor="w", pady=(0, 12))

        fan_ctrl_frame = tk.Frame(ctrl_box, bg="#1C2541")
        fan_ctrl_frame.pack(fill="x", pady=8)
        tk.Label(fan_ctrl_frame, text="Quạt 12V (K1)\nThông gió - Làm mát", fg="#A0AAB2", bg="#1C2541", justify="left", font=("Arial", 10)).pack(side="left")
        self.switch_fan = ToggleSwitch(fan_ctrl_frame, width=65, height=32, bg_color="#1C2541", command=self.user_toggle_fan)
        self.switch_fan.pack(side="right", padx=5)

        pump_ctrl_frame = tk.Frame(ctrl_box, bg="#1C2541")
        pump_ctrl_frame.pack(fill="x", pady=8)
        tk.Label(pump_ctrl_frame, text="Máy bơm 12V (K2)\nBơm nước - Tưới mát", fg="#A0AAB2", bg="#1C2541", justify="left", font=("Arial", 10)).pack(side="left")
        self.switch_pump = ToggleSwitch(pump_ctrl_frame, width=65, height=32, bg_color="#1C2541", command=self.user_toggle_pump)
        self.switch_pump.pack(side="right", padx=5)

        door_ctrl_frame = tk.Frame(ctrl_box, bg="#1C2541")
        door_ctrl_frame.pack(fill="x", pady=8)
        tk.Label(door_ctrl_frame, text="Cửa tự động (K3 & K4)\nMở 3.7s / Đóng 3.5s", fg="#A0AAB2", bg="#1C2541", justify="left", font=("Arial", 10)).pack(side="left")

        btn_frame = tk.Frame(door_ctrl_frame, bg="#1C2541")
        btn_frame.pack(side="right")

        self.btn_door_open = tk.Button(btn_frame, text="MỞ", bg="#00C853", fg="white", font=("Arial", 8, "bold"), relief="flat", width=5, cursor="hand2", command=self.cmd_door_open)
        self.btn_door_open.pack(side="left", padx=2, ipady=3)

        self.btn_door_stop = tk.Button(btn_frame, text="DỪNG", bg="#FF9800", fg="white", font=("Arial", 8, "bold"), relief="flat", width=5, cursor="hand2", command=self.cmd_door_stop)
        self.btn_door_stop.pack(side="left", padx=2, ipady=3)

        self.btn_door_close = tk.Button(btn_frame, text="ĐÓNG", bg="#E53935", fg="white", font=("Arial", 8, "bold"), relief="flat", width=5, cursor="hand2", command=self.cmd_door_close)
        self.btn_door_close.pack(side="left", padx=2, ipady=3)

        auto_box = tk.Frame(right_col, bg="#1C2541", padx=15, pady=15)
        auto_box.pack(fill="x")

        auto_head = tk.Frame(auto_box, bg="#1C2541")
        auto_head.pack(fill="x", pady=(0, 8))

        tk.Label(auto_head, text="Chế độ tự động", fg="#FFFFFF", bg="#1C2541", font=("Arial", 13, "bold")).pack(side="left")
        self.switch_auto = ToggleSwitch(auto_head, width=65, height=32, bg_color="#1C2541", command=self.toggle_auto_mode)
        self.switch_auto.pack(side="right")

        tk.Label(auto_box, text="Tự động bật quạt khi vượt ngưỡng nhiệt", fg="#6C7A89", bg="#1C2541", font=("Arial", 9, "italic")).pack(anchor="w", pady=(0, 10))

        cfg_frame = tk.Frame(auto_box, bg="#1C2541")
        cfg_frame.pack(fill="x", pady=5)

        tk.Label(cfg_frame, text="Nhiệt độ >", fg="#FFFFFF", bg="#1C2541", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=8)
        self.ent_temp_high = tk.Entry(cfg_frame, width=7, bg="#0B132B", fg="#FFFFFF", insertbackground="white", font=("Arial", 10, "bold"), justify="center")
        self.ent_temp_high.insert(0, str(TEMP_THRESHOLD_HIGH))
        self.ent_temp_high.grid(row=0, column=1, padx=8)
        tk.Label(cfg_frame, text="°C (Bật quạt)", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).grid(row=0, column=2, sticky="w")

        tk.Label(cfg_frame, text="Nhiệt độ <", fg="#FFFFFF", bg="#1C2541", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", pady=8)
        self.ent_temp_low = tk.Entry(cfg_frame, width=7, bg="#0B132B", fg="#FFFFFF", insertbackground="white", font=("Arial", 10, "bold"), justify="center")
        self.ent_temp_low.insert(0, str(TEMP_THRESHOLD_LOW))
        self.ent_temp_low.grid(row=1, column=1, padx=8)
        tk.Label(cfg_frame, text="°C (Tắt quạt)", fg="#A0AAB2", bg="#1C2541", font=("Arial", 9)).grid(row=1, column=2, sticky="w")

        tk.Button(
            auto_box,
            text="Lưu ngưỡng nhiệt độ",
            bg="#3A86FF",
            fg="#FFFFFF",
            font=("Arial", 9, "bold"),
            relief="flat",
            pady=6,
            cursor="hand2",
            command=self.save_thresholds_desktop
        ).pack(fill="x", pady=(10, 0))

    # ==================== 6. ĐỒNG BỘ DỮ LIỆU & LỆNH ====================
    def _get_temp_thresholds(self):
        raw_h = self.ent_temp_high.get().strip().replace(",", ".")
        raw_l = self.ent_temp_low.get().strip().replace(",", ".")
        return float(raw_h), float(raw_l)

    def get_full_state(self) -> dict:
        try:
            th_h, th_l = self._get_temp_thresholds()
        except ValueError:
            th_h, th_l = TEMP_THRESHOLD_HIGH, TEMP_THRESHOLD_LOW

        recent_logs = []
        for child in self.log_tree.get_children()[:12]:
            vals = self.log_tree.item(child)["values"]
            if len(vals) >= 3:
                recent_logs.append({"time": str(vals[0]), "event": str(vals[1]), "info": str(vals[2])})

        lan_ip = get_local_ip()
        return {
            "lan_ip": lan_ip,
            "mobile_url": f"http://{lan_ip}:5000/mobile-hmi",
            "port": self.cb_port.get(),
            "baud": self.cb_baud.get(),
            "temp": self.temp_current,
            "humi": self.hum_current,
            "hum": self.hum_current,
            "fan": self.fan_state == 1,
            "pump": self.pump_state == 1,
            "mist": self.pump_state == 1,
            "door_state": self.door_state,
            "door_text": self.door_text,
            "auto_mode": self.mode_auto,
            "auto": self.mode_auto,
            "temp_th": th_h,
            "temp_th_low": th_l,
            "humi_th": th_l,
            "ok_sht": self.ok_sht,
            "ok_rly": self.ok_rly,
            "is_connected": self.connected,
            "connected": self.connected,
            "tx_count": self.tx_count,
            "rx_count": self.rx_count,
            "err_count": self.err_count,
            "last_tx": self.last_tx,
            "last_rx": self.last_rx,
            "txrx_logs": self.txrx_logs[:25],
            "logs": recent_logs,
            "chart_time": self.time_data[-20:],
            "chart_temp": self.temp_data[-20:],
            "chart_humi": self.hum_data[-20:],
            "grant_all": self.grant_all_active,
            "com_alert": dict(self.com_alert),
            "server_override": {
                "active": self.server_override_active,
                "grant_all": self.grant_all_active,
                "reason": self.server_override_reason
            }
        }

    def set_server_override(self, active: bool, reason: str = "", grant_all: bool = False):
        self.grant_all_active = grant_all
        self.server_override_active = False if grant_all else active
        self.server_override_reason = reason
        if grant_all:
            self.lbl_override_badge.config(text="🌐 Tầng 3 cấp quyền cho tất cả", fg="#00E676")
            self.add_log("Phân quyền Tầng 3", "Máy chủ Tầng 3 đã CẤP QUYỀN CHO TẤT CẢ")
        elif active:
            self.lbl_override_badge.config(text="🔒 Máy chủ Tầng 3 giữ quyền", fg="#FBBF24")
            self.add_log("Phân quyền Tầng 3", f"Máy chủ giữ quyền ưu tiên ({reason})")
        else:
            self.lbl_override_badge.config(text="🔓 Cục bộ tự do", fg="#38BDF8")
            self.add_log("Phân quyền Tầng 3", "Máy chủ đã nhả quyền ưu tiên")

    def handle_local_web_output(self, d: dict):
        self.handle_tier3_output(d, from_server=False, custom_src="Web/Mobile Tầng 2")

    def handle_tier3_output(self, d: dict, from_server: bool = False, custom_src: str = ""):
        if from_server and not self.grant_all_active:
            self.set_server_override(True, "Máy chủ Tầng 3 điều khiển thiết bị", False)

        src = custom_src if custom_src else ("Máy chủ Tầng 3" if from_server else "Điện thoại QR (Tầng 3)")
        name = str(d.get("name", "")).lower()
        on_val = d.get("on")

        if name == "fan":
            self.user_toggle_fan(bool(on_val), from_remote=True, source_name=src)
        elif name in ("pump", "mist"):
            self.user_toggle_pump(bool(on_val), from_remote=True, source_name=src)
        elif name == "door":
            act = str(on_val).lower()
            if act in ("open", "true", "1"):
                self.cmd_door_open(from_remote=True, source_name=src)
            elif act in ("close", "2"):
                self.cmd_door_close(from_remote=True, source_name=src)
            else:
                self.cmd_door_stop(auto_stop=False, from_remote=True, source_name=src)

    def handle_tier3_mode(self, d: dict, from_server: bool = False):
        if from_server and not self.grant_all_active:
            self.set_server_override(True, "Máy chủ Tầng 3 đổi chế độ", False)

        src = "Máy chủ Tầng 3" if from_server else "Điện thoại QR (Tầng 3)"
        mode = str(d.get("mode", "MANUAL")).upper()
        self.toggle_auto_mode(mode == "AUTO", from_remote=True, source_name=src)

    def save_thresholds_desktop(self):
        try:
            th_h, th_l = self._get_temp_thresholds()
        except ValueError:
            messagebox.showerror("Lỗi nhập liệu", "Ngưỡng nhiệt độ phải là số hợp lệ (ví dụ: 30.0 và 28.0)!")
            return
        if th_h <= th_l:
            messagebox.showwarning("Sai ngưỡng", f"Nhiệt độ bật quạt ({th_h}°C) phải lớn hơn nhiệt độ tắt quạt ({th_l}°C)!")
            return
        self.ent_temp_high.delete(0, tk.END)
        self.ent_temp_high.insert(0, str(th_h))
        self.ent_temp_low.delete(0, tk.END)
        self.ent_temp_low.insert(0, str(th_l))
        self.add_log("Cài đặt ngưỡng", f"Desktop: Bật > {th_h}°C, Tắt < {th_l}°C")
        if self.mode_auto:
            self.evaluate_auto_fan(announce_wait=True)

    def update_thresholds_from_web(self, th_h: float, th_l: float):
        self.ent_temp_high.delete(0, tk.END)
        self.ent_temp_high.insert(0, str(th_h))
        self.ent_temp_low.delete(0, tk.END)
        self.ent_temp_low.insert(0, str(th_l))
        self.add_log("Cài đặt ngưỡng", f"Web/Mobile: Bật > {th_h}°C, Tắt < {th_l}°C")
        if self.mode_auto:
            self.evaluate_auto_fan(announce_wait=True)

    def apply_tier3_serial_config(self, d: dict):
        port = str(d.get("port", self.cb_port.get())).split()[0].strip()
        baud = str(d.get("baud", self.cb_baud.get()))
        self.cb_port.set(port)
        self.cb_baud.set(baud)
        if d.get("sht_id"):
            self.ent_slave_id.delete(0, tk.END)
            self.ent_slave_id.insert(0, str(d.get("sht_id")))
        self.serial_cfg.update({
            "port": port,
            "baud": int(baud),
            "databits": int(d.get("databits", 8)),
            "parity": str(d.get("parity", "N")),
            "stopbits": int(d.get("stopbits", 1)),
            "timeout_ms": int(d.get("timeout_ms", 200))
        })
        if self.connected:
            self.disconnect_serial(source="Cấu hình lại COM")
        self.connect_serial(from_remote=True)

    # ==================== 7. QUẢN LÝ KẾT NỐI SERIAL THẬT ====================
    def refresh_com_ports(self):
        detected_ports = [port.device for port in serial.tools.list_ports.comports()]
        default_ports = ["COM6", "COM7", "COM17"]
        all_ports = list(dict.fromkeys(detected_ports + default_ports))
        self.cb_port['values'] = all_ports
        if not self.cb_port.get() and all_ports:
            self.cb_port.set(all_ports[0])

    def toggle_connection(self):
        if not self.connected:
            self.connect_serial(from_remote=False)
        else:
            self.disconnect_serial(source="Cục bộ")

    def connect_serial(self, from_remote=False):
        port = self.cb_port.get().strip()
        baud = int(self.cb_baud.get())
        parity_map = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}
        par = parity_map.get(self.serial_cfg.get("parity", "N"), serial.PARITY_NONE)
        db = int(self.serial_cfg.get("databits", 8))
        sb = int(self.serial_cfg.get("stopbits", 1))
        to_s = max(0.08, int(self.serial_cfg.get("timeout_ms", 200)) / 1000.0)

        try:
            self.ser = serial.Serial(port=port, baudrate=baud, bytesize=db, parity=par, stopbits=sb, timeout=to_s, write_timeout=0.3)
            self.connected = True
            self.clear_com_alert(sync_t3=True)
            self.btn_modbus_connect.config(text="Disconnect", bg="#E53935")
            self.lbl_status_online.config(text=f"● Connected ({port})", fg="#00E676")
            self.lbl_st_relay.config(text="• Module Relay                       : Đã kết nối COM", fg="#81C784")
            self.add_log("Modbus", f"Đã kết nối thành công cổng {port} @ {baud}")
        except Exception as e:
            if not from_remote:
                messagebox.showerror("Lỗi kết nối", f"Không thể mở cổng {port}:\n{e}")
            self.add_log("Lỗi COM", f"Mở cổng {port} thất bại: {e}")

    def disconnect_serial(self, source="Cục bộ"):
        self.connected = False
        self.ok_sht = False
        self.ok_rly = False
        with self.hw_cond:
            self.pending_coils.clear()
            self.pending_door_action = None
        with self.serial_lock:
            if self.ser and self.ser.is_open:
                self.ser.close()
        self.btn_modbus_connect.config(text="Connect", bg="#00C853")
        self.lbl_status_online.config(text="● Disconnected", fg="#E53935")
        self.lbl_st_sht.config(text="• Cảm biến SHT20                  : Ngắt kết nối", fg="#FFB74D")
        self.lbl_st_relay.config(text="• Module Relay                       : Ngắt kết nối", fg="#FFB74D")
        self.add_log("Modbus", f"Đã ngắt kết nối cổng COM ({source})")

    def send_modbus_frame(self, payload_without_crc: bytes, expected_rx_len: int = 8, is_relay: bool = False) -> bytes:
        if not self.connected or not self.ser or not self.ser.is_open:
            return b""

        crc = calc_crc16(payload_without_crc)
        full_frame = payload_without_crc + crc
        tx_hex = " ".join(f"{b:02X}" for b in full_frame)

        with self.serial_lock:
            try:
                self.ser.reset_input_buffer()
                self.ser.write(full_frame)
                self.tx_count += 1
                self.last_tx = tx_hex
                time.sleep(0.02)
                rx_bytes = self.ser.read(expected_rx_len)

                if rx_bytes:
                    rx_hex = " ".join(f"{b:02X}" for b in rx_bytes)
                    self.rx_count += 1
                    self.last_rx = rx_hex
                    if is_relay:
                        self.ok_rly = True
                else:
                    rx_hex = "TIMEOUT (No Response)"
                    self.err_count += 1
                    self.last_rx = rx_hex
                    if is_relay:
                        self.ok_rly = False

                # Khoảng lặng Modbus RTU giữa 2 giao dịch RS485 tránh đụng khung khi đổi Slave
                time.sleep(0.035)
                self.root.after(0, self.append_traffic, tx_hex, rx_hex)
                return rx_bytes
            except Exception as e:
                self.err_count += 1
                time.sleep(0.035)
                self.root.after(0, self.append_traffic, tx_hex, f"ERR: {e}")
                return b""

    def write_relay_coil(self, channel_idx: int, turn_on: bool) -> bool:
        val_hi = 0xFF if turn_on else 0x00
        payload = bytes([RELAY_SLAVE_ID, 0x05, 0x00, channel_idx, val_hi, 0x00])
        for _ in range(3):
            rx = self.send_modbus_frame(payload, expected_rx_len=8, is_relay=True)
            if len(rx) >= 8 and rx[0] == RELAY_SLAVE_ID and rx[1] == 0x05 and calc_crc16(rx[:-2]) == rx[-2:]:
                self.ok_rly = True
                return True
            time.sleep(0.05)
        self.ok_rly = False
        return False

    def queue_relay_coil(self, channel_idx: int, turn_on: bool):
        with self.hw_cond:
            self.pending_coils[channel_idx] = bool(turn_on)
            self.hw_cond.notify()

    def queue_door_action(self, action: str):
        with self.hw_cond:
            self.pending_door_action = action
            self.hw_cond.notify()

    def relay_worker_loop(self):
        while self.running:
            with self.hw_cond:
                while self.running and not self.pending_coils and self.pending_door_action is None:
                    self.hw_cond.wait(timeout=0.5)
                if not self.running:
                    break
                coils_batch = list(self.pending_coils.items())
                self.pending_coils.clear()
                door_act = self.pending_door_action
                self.pending_door_action = None

            for ch, state in coils_batch:
                if self.connected:
                    self.write_relay_coil(ch, state)

            if door_act and self.connected:
                if door_act == "open":
                    self._hw_door_open()
                elif door_act == "close":
                    self._hw_door_close()
                else:
                    self._hw_door_stop()

    def append_traffic(self, tx_data, rx_data):
        t = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.txrx_logs.insert(0, {"time": t, "dir": "RX", "frame": rx_data, "desc": ""})
        self.txrx_logs.insert(0, {"time": t, "dir": "TX", "frame": tx_data, "desc": ""})
        if len(self.txrx_logs) > 60:
            self.txrx_logs = self.txrx_logs[:60]

        self.txt_traffic.insert(tk.END, f"[{t}] TX -> {tx_data}\n")
        self.txt_traffic.insert(tk.END, f"[{t}] RX <- {rx_data}\n")
        self.txt_traffic.see(tk.END)
        lines = int(self.txt_traffic.index('end-1c').split('.')[0])
        if lines > 500:
            self.txt_traffic.delete('1.0', '3.0')

    def clear_traffic(self):
        self.txrx_logs.clear()
        self.txt_traffic.delete('1.0', tk.END)

    # ==================== 8. ĐIỀU KHIỂN THIẾT BỊ THẬT ====================
    def _schedule_switch_revert(self, key: str, switch_widget: ToggleSwitch, getter_fn):
        if self.revert_timers.get(key) is not None:
            self.root.after_cancel(self.revert_timers[key])
        self.revert_timers[key] = self.root.after(150, lambda: switch_widget.set_state(getter_fn()))

    def _check_local_lock(self, from_remote: bool) -> bool:
        if not from_remote and self.server_override_active and not self.grant_all_active:
            messagebox.showwarning("Khóa phân quyền", "Máy chủ Tầng 3 đang giữ quyền ưu tiên tối cao!\nHãy bấm 'Nhả quyền ưu tiên' hoặc 'Cấp quyền cho tất cả' trên Máy chủ trước.")
            return True
        return False

    def user_toggle_fan(self, is_on, from_remote=False, source_name="Máy điều khiển Tầng 2"):
        if self._check_local_lock(from_remote):
            self.switch_fan.set_state(self.fan_state == 1)
            return

        if not self.connected:
            self._schedule_switch_revert("fan", self.switch_fan, lambda: self.fan_state == 1)
            self.trigger_com_alert(source=source_name, device="Quạt 12V (K1)", sync_t3=not from_remote)
            return

        if self.mode_auto:
            if not from_remote:
                messagebox.showwarning("Cảnh báo", "Đang ở Chế độ Tự động! Vui lòng gạt Tắt Chế độ Tự động trước.")
            self.switch_fan.set_state(self.fan_state == 1)
            return

        self.fan_state = 1 if is_on else 0
        st_text = "Đang bật" if is_on else "Đang tắt"
        self.lbl_fan_top_status.config(text=st_text, fg="#00E676" if is_on else "#FFFFFF")
        self.switch_fan.set_state(is_on)

        self.queue_relay_coil(0, is_on)
        self.add_log("Quạt 12V (K1)", f"{source_name}: {st_text}")

    def user_toggle_pump(self, is_on, from_remote=False, source_name="Máy điều khiển Tầng 2"):
        if self._check_local_lock(from_remote):
            self.switch_pump.set_state(self.pump_state == 1)
            return

        if not self.connected:
            self._schedule_switch_revert("pump", self.switch_pump, lambda: self.pump_state == 1)
            self.trigger_com_alert(source=source_name, device="Máy bơm 12V (K2)", sync_t3=not from_remote)
            return

        self.pump_state = 1 if is_on else 0
        st_text = "Đang bật" if is_on else "Đang tắt"
        self.lbl_pump_top_status.config(text=st_text, fg="#00E676" if is_on else "#FFFFFF")
        self.switch_pump.set_state(is_on)

        self.queue_relay_coil(1, is_on)
        self.add_log("Máy bơm 12V (K2)", f"{source_name}: {st_text}")

    def cancel_door_timer(self):
        if self.door_timer_id is not None:
            self.root.after_cancel(self.door_timer_id)
            self.door_timer_id = None

    def _hw_door_open(self):
        self.write_relay_coil(3, False)
        time.sleep(0.03)
        self.write_relay_coil(2, True)

    def _hw_door_close(self):
        self.write_relay_coil(2, False)
        time.sleep(0.03)
        self.write_relay_coil(3, True)

    def _hw_door_stop(self):
        self.write_relay_coil(2, False)
        time.sleep(0.03)
        self.write_relay_coil(3, False)

    def cmd_door_open(self, from_remote=False, source_name="Máy điều khiển Tầng 2"):
        if self._check_local_lock(from_remote):
            return
        if not self.connected:
            self.trigger_com_alert(source=source_name, device="Mở cửa tự động (K3)", sync_t3=not from_remote)
            return
        if self.door_state == "OPENING":
            return

        self.cancel_door_timer()
        self.door_state = "OPENING"
        self.door_text = "Đang mở..."
        self.lbl_door_top_status.config(text=self.door_text, fg="#00E676")

        self.queue_door_action("open")
        self.add_log("Cửa tự động", f"{source_name}: MỞ (K3 ON) -> Tự dừng sau 3.7s")
        self.door_timer_id = self.root.after(DOOR_OPEN_TIME_MS, lambda: self.cmd_door_stop(auto_stop=True))

    def cmd_door_close(self, from_remote=False, source_name="Máy điều khiển Tầng 2"):
        if self._check_local_lock(from_remote):
            return
        if not self.connected:
            self.trigger_com_alert(source=source_name, device="Đóng cửa tự động (K4)", sync_t3=not from_remote)
            return
        if self.door_state == "CLOSING":
            return

        self.cancel_door_timer()
        self.door_state = "CLOSING"
        self.door_text = "Đang đóng..."
        self.lbl_door_top_status.config(text=self.door_text, fg="#E53935")

        self.queue_door_action("close")
        self.add_log("Cửa tự động", f"{source_name}: ĐÓNG (K4 ON) -> Tự dừng sau 3.5s")
        self.door_timer_id = self.root.after(DOOR_CLOSE_TIME_MS, lambda: self.cmd_door_stop(auto_stop=True))

    def cmd_door_stop(self, auto_stop=False, from_remote=False, source_name="Máy điều khiển Tầng 2"):
        if not auto_stop and self._check_local_lock(from_remote):
            return
        if not self.connected:
            if not auto_stop:
                self.trigger_com_alert(source=source_name, device="Dừng cửa tự động", sync_t3=not from_remote)
            return

        self.cancel_door_timer()
        prev_state = self.door_state
        self.door_state = "STOPPED"
        self.door_text = "Đã mở xong" if (auto_stop and prev_state == "OPENING") else ("Đã đóng xong" if (auto_stop and prev_state == "CLOSING") else "Đang dừng")
        self.lbl_door_top_status.config(text=self.door_text, fg="#FF9800")

        self.queue_door_action("stop")
        msg = "Tự động ngắt hành trình" if auto_stop else f"{source_name}: Bấm DỪNG KHẨN CẤP"
        self.add_log("Cửa tự động", f"{msg} (K3 & K4 OFF)")

    def toggle_auto_mode(self, is_auto, from_remote=False, source_name="Máy điều khiển Tầng 2"):
        if self._check_local_lock(from_remote):
            self.switch_auto.set_state(self.mode_auto)
            return
        if not self.connected:
            self._schedule_switch_revert("auto", self.switch_auto, lambda: self.mode_auto)
            self.trigger_com_alert(source=source_name, device="Chế độ tự động (Auto)", sync_t3=not from_remote)
            return

        self.mode_auto = bool(is_auto)
        self.switch_auto.set_state(self.mode_auto)
        mode_str = "TỰ ĐỘNG" if self.mode_auto else "BẰNG TAY"
        self.add_log("Chế độ quạt", f"{source_name}: Chuyển sang {mode_str}")

        if self.mode_auto:
            self.evaluate_auto_fan(announce_wait=True)

    def evaluate_auto_fan(self, temp=None, announce_wait=False):
        if not self.mode_auto:
            return
        if temp is None:
            if not self.ok_sht:
                if announce_wait:
                    self.add_log("Auto Quạt", "Đang chờ cảm biến SHT20 đọc nhiệt độ hợp lệ...")
                return
            temp = self.temp_current

        try:
            t_high, t_low = self._get_temp_thresholds()
        except ValueError:
            if announce_wait:
                self.add_log("Lỗi ngưỡng", "Ngưỡng nhiệt độ không hợp lệ!")
            return

        if t_high <= t_low:
            if announce_wait:
                self.add_log("Lỗi ngưỡng", f"Ngưỡng bật ({t_high}°C) phải lớn hơn ngưỡng tắt ({t_low}°C)!")
            return

        if temp > t_high:
            self.auto_set_fan(True)
        elif temp < t_low:
            self.auto_set_fan(False)
        elif announce_wait:
            self.add_log("Auto Quạt", f"Nhiệt độ hiện tại {temp:.1f}°C (Bật > {t_high}°C, Tắt < {t_low}°C)")

    def auto_set_fan(self, state_on):
        target = 1 if state_on else 0
        if self.fan_state != target or not self.ok_rly:
            was_changed = (self.fan_state != target)
            self.fan_state = target
            self.switch_fan.set_state(state_on)
            st_text = "Đang bật (Auto)" if state_on else "Đang tắt (Auto)"
            self.lbl_fan_top_status.config(text=st_text, fg="#00E676" if state_on else "#FFFFFF")
            self.queue_relay_coil(0, state_on)
            if was_changed:
                self.add_log("Auto Quạt", f"Nhiệt độ đạt ngưỡng -> {st_text}")

    # ==================== 9. VÒNG LẶP ĐỌC CẢM BIẾN SHT20 THẬT ====================
    def update_data_loop(self):
        while self.running:
            if self.connected:
                try:
                    sht_id = int(self.ent_slave_id.get())
                except ValueError:
                    sht_id = 1

                req_payload = bytes([sht_id, 0x04, 0x00, 0x01, 0x00, 0x02])
                rx = self.send_modbus_frame(req_payload, expected_rx_len=9, is_relay=False)

                if len(rx) >= 9 and rx[0] == sht_id and rx[1] == 0x04 and rx[2] == 0x04:
                    calc_c = calc_crc16(rx[:-2])
                    if calc_c == rx[-2:]:
                        raw_temp = (rx[3] << 8) | rx[4]
                        raw_hum = (rx[5] << 8) | rx[6]
                        if raw_temp & 0x8000:
                            raw_temp -= 0x10000
                        temp_c = round(raw_temp / 10.0, 1)
                        hum_pct = round(raw_hum / 10.0, 1)

                        self.temp_current = temp_c
                        self.hum_current = hum_pct
                        self.ok_sht = True
                        self.root.after(0, self.update_sensor_ui, temp_c, hum_pct, True)
                    else:
                        self.err_count += 1
                        self.ok_sht = False
                        self.root.after(0, self.update_sensor_ui, 0, 0, False)
                else:
                    self.ok_sht = False
                    self.root.after(0, self.update_sensor_ui, 0, 0, False)

            time.sleep(1.5)

    def update_sensor_ui(self, temp, hum, is_ok):
        if is_ok:
            self.lbl_temp_val.config(text=f"{temp:.1f} °C")
            self.lbl_hum_val.config(text=f"{hum:.1f} %")
            self.lbl_st_sht.config(text="• Cảm biến SHT20                  : Đang hoạt động", fg="#81C784")

            if self.mode_auto:
                self.evaluate_auto_fan(temp=temp)

            now_str = datetime.now().strftime("%H:%M:%S")
            self.time_data.append(now_str)
            self.temp_data.append(temp)
            self.hum_data.append(hum)
            if len(self.time_data) > self.max_data_points:
                self.time_data.pop(0)
                self.temp_data.pop(0)
                self.hum_data.pop(0)
            self.redraw_chart()
        else:
            self.lbl_st_sht.config(text="• Cảm biến SHT20                  : Lỗi / Không phản hồi", fg="#E53935")

    def set_view_window(self, num_points):
        self.view_window_points = num_points
        self.redraw_chart()

    def redraw_chart(self):
        if not self.time_data:
            return
        t_slice = self.time_data[-self.view_window_points:]
        temp_slice = self.temp_data[-self.view_window_points:]
        hum_slice = self.hum_data[-self.view_window_points:]
        x_idx = list(range(len(t_slice)))

        self.line_temp.set_data(x_idx, temp_slice)
        self.line_hum.set_data(x_idx, hum_slice)

        self.ax1.set_xlim(0, max(1, len(t_slice) - 1))
        if temp_slice:
            self.ax1.set_ylim(min(temp_slice) - 2, max(temp_slice) + 2)
        if hum_slice:
            self.ax2.set_ylim(max(0, min(hum_slice) - 5), min(100, max(hum_slice) + 5))

        if len(t_slice) > 1:
            step = max(1, len(t_slice) // 5)
            ticks = list(range(0, len(t_slice), step))
            self.ax1.set_xticks(ticks)
            self.ax1.set_xticklabels([t_slice[i] for i in ticks])

        self.canvas.draw_idle()

    def add_log(self, event, info):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_tree.insert("", 0, values=(t, event, info))
        if len(self.log_tree.get_children()) > 30:
            self.log_tree.delete(self.log_tree.get_children()[-1])

    def update_clock(self):
        self.lbl_clock.config(text=datetime.now().strftime("%H:%M:%S %d/%m/%Y"))
        self.root.after(1000, self.update_clock)

    def on_closing(self):
        self.running = False
        self.cancel_door_timer()
        with self.hw_cond:
            self.hw_cond.notify_all()
        if self.connected and self.ser and self.ser.is_open:
            try:
                self._hw_door_stop()
                self.ser.close()
            except Exception:
                pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app_ui = DashboardRealApp(root)
    root.mainloop()
