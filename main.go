package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	serverIP         string
	authToken        string
	port             string
	mu               sync.Mutex
	liveLogs         []string
	isListening      bool
	currentConnState = "DISCONNECTED"
)

func addLiveLog(msg string) {
	mu.Lock()
	defer mu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", timestamp, msg)
	if len(liveLogs) > 120 {
		liveLogs = liveLogs[1:]
	}
	liveLogs = append(liveLogs, line)
}

type TestRequest struct {
	TargetIP    string `json:"target_ip"`
	SpoofIP     string `json:"spoof_ip"`
	RemoteToken string `json:"remote_token"`
	TestType    string `json:"test_type"` // "icmp" or "udp"
}

type TestResponse struct {
	Log            string `json:"log"`
	LocalSuccess   bool   `json:"local_success"`
	RemoteVerified bool   `json:"remote_verified"`
	PacketsSent    int    `json:"packets_sent"`
	RemoteReceived int    `json:"remote_received"`
	StatusClass    string `json:"status_class"`
	ResultTitle    string `json:"result_title"`
	ResultMessage  string `json:"result_message"`
}

type PrepareRequest struct {
	ExpectedSourceIP string `json:"expected_source_ip"`
	DurationSec      int    `json:"duration_sec"`
	TestType         string `json:"test_type"`
}

type PrepareResponse struct {
	Status        string `json:"status"`
	ReceivedCount int    `json:"received_count"`
	Log           string `json:"log"`
}

type PageData struct {
	ServerIP       string
	Port           string
	Iface          string
	ConnectionCode string
	ConnState      string
}

const htmlPage = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CheckSpoof — سامانه پیشرفته تحلیل IP Spoofing</title>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <style>
        :root {
            --bg-dark: #070b14;
            --bg-card: rgba(15, 23, 42, 0.85);
            --bg-input: #090e1a;
            --border: #1e293b;
            --border-hover: #334155;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.2);
            --primary-grad: linear-gradient(135deg, #0284c7 0%, #2563eb 100%);
            --emerald-grad: linear-gradient(135deg, #059669 0%, #10b981 100%);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success-bg: rgba(20, 83, 45, 0.45);
            --success-border: #22c55e;
            --success-fg: #4ade80;
            --warning-bg: rgba(113, 63, 18, 0.45);
            --warning-border: #eab308;
            --warning-fg: #facc15;
            --danger-bg: rgba(127, 29, 29, 0.45);
            --danger-border: #ef4444;
            --danger-fg: #f87171;
        }

        * { box-sizing: border-box; }

        body {
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, rgba(14, 165, 233, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(37, 99, 235, 0.1) 0px, transparent 50%);
            color: var(--text-main);
            font-family: 'Vazirmatn', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 24px 16px;
            min-height: 100vh;
        }

        .wrapper {
            max-width: 1180px;
            margin: 0 auto;
        }

        /* Top Navbar */
        .navbar {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 18px 24px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            gap: 15px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: var(--primary-grad);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 20px rgba(2, 132, 199, 0.4);
        }

        .brand-text h1 {
            margin: 0;
            font-size: 20px;
            font-weight: 800;
            color: #fff;
            letter-spacing: -0.3px;
        }

        .brand-text p {
            margin: 2px 0 0 0;
            font-size: 12px;
            color: var(--text-muted);
        }

        .nav-pills {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
        }

        .pill {
            background: var(--bg-input);
            border: 1px solid var(--border);
            padding: 7px 14px;
            border-radius: 999px;
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .pill strong {
            color: var(--accent);
            font-family: monospace;
            font-size: 13px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #64748b;
            display: inline-block;
        }

        .status-dot.connected {
            background: #22c55e;
            box-shadow: 0 0 10px #22c55e;
            animation: pulse 1.8s infinite;
        }

        .status-dot.error {
            background: #ef4444;
            box-shadow: 0 0 10px #ef4444;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); opacity: 0.8; }
            50% { transform: scale(1.2); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.8; }
        }

        /* Token Banner */
        .token-banner {
            background: linear-gradient(90deg, rgba(15, 23, 42, 0.9) 0%, rgba(2, 132, 199, 0.12) 100%);
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 14px;
            padding: 14px 20px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }

        .token-label {
            font-size: 13px;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .token-value-wrap {
            display: flex;
            align-items: center;
            gap: 10px;
            background: #050811;
            padding: 8px 12px;
            border-radius: 10px;
            border: 1px solid var(--border);
            direction: ltr;
            flex: 1;
            max-width: 580px;
            justify-content: space-between;
        }

        .token-value-wrap code {
            color: #4ade80;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
        }

        .btn-copy {
            background: #1e293b;
            color: #f8fafc;
            border: 1px solid #334155;
            padding: 6px 12px;
            border-radius: 7px;
            font-family: inherit;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s;
            white-space: nowrap;
        }

        .btn-copy:hover {
            background: #334155;
            border-color: var(--accent);
        }

        /* Main Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1.15fr;
            gap: 20px;
        }

        @media (max-width: 920px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
        }

        .card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 22px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.35);
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
        }

        .card-title {
            margin: 0;
            font-size: 16px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }

        label {
            font-size: 12.5px;
            font-weight: 500;
            color: var(--text-muted);
        }

        input, select {
            width: 100%;
            padding: 11px 14px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: #fff;
            border-radius: 10px;
            font-family: inherit;
            font-size: 13.5px;
            transition: 0.2s;
            outline: none;
        }

        input:focus, select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        .ltr-input {
            direction: ltr;
            text-align: left;
            font-family: monospace;
        }

        .connect-group {
            display: flex;
            gap: 10px;
        }

        .btn-connect {
            background: var(--emerald-grad);
            color: #fff;
            border: none;
            padding: 0 18px;
            border-radius: 10px;
            font-family: inherit;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            white-space: nowrap;
            transition: 0.2s;
            box-shadow: 0 4px 14px rgba(16, 185, 129, 0.3);
        }

        .btn-connect:hover {
            filter: brightness(1.1);
            transform: translateY(-1px);
        }

        .btn-primary {
            background: var(--primary-grad);
            color: #fff;
            border: none;
            padding: 14px 20px;
            border-radius: 12px;
            font-family: inherit;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            width: 100%;
            transition: 0.2s;
            box-shadow: 0 6px 20px rgba(2, 132, 199, 0.35);
            margin-top: 4px;
        }

        .btn-primary:hover:not(:disabled) {
            filter: brightness(1.1);
            transform: translateY(-1px);
        }

        .btn-primary:disabled {
            background: #1e293b;
            color: #64748b;
            box-shadow: none;
            cursor: not-allowed;
            border: 1px solid #334155;
        }

        /* Quick Chips */
        .Preset-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 2px;
        }

        .chip {
            background: #131c31;
            border: 1px solid var(--border);
            color: #cbd5e1;
            padding: 5px 11px;
            border-radius: 8px;
            font-size: 11.5px;
            cursor: pointer;
            transition: 0.15s;
            font-family: monospace;
        }

        .chip:hover {
            border-color: var(--accent);
            color: var(--accent);
            background: rgba(56, 189, 248, 0.08);
        }

        /* Metrics Bar */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
        }

        .metric-box {
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px;
            text-align: center;
        }

        .metric-box .m-title {
            font-size: 11px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .metric-box .m-val {
            font-size: 18px;
            font-weight: 800;
            font-family: monospace;
            color: #fff;
        }

        /* Alerts */
        .alert-box {
            padding: 14px 16px;
            border-radius: 12px;
            font-size: 13px;
            line-height: 1.6;
            display: none;
        }

        .alert-box.show { display: block; }
        .alert-box strong { display: block; font-size: 14px; margin-bottom: 3px; }

        .alert-box.success {
            background: var(--success-bg);
            border: 1px solid var(--success-border);
            color: var(--success-fg);
        }

        .alert-box.warning {
            background: var(--warning-bg);
            border: 1px solid var(--warning-border);
            color: var(--warning-fg);
        }

        .alert-box.failure {
            background: var(--danger-bg);
            border: 1px solid var(--danger-border);
            color: var(--danger-fg);
        }

        /* Terminal Window */
        .terminal-window {
            background: #03060c;
            border: 1px solid #1e293b;
            border-radius: 12px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            flex: 1;
            min-height: 360px;
        }

        .terminal-bar {
            background: #0b1324;
            padding: 9px 14px;
            border-bottom: 1px solid #1e293b;
            display: flex;
            justify-content: space-between;
            align-items: center;
            direction: ltr;
        }

        .mac-dots {
            display: flex;
            gap: 6px;
        }

        .mac-dot {
            width: 11px;
            height: 11px;
            border-radius: 50%;
        }

        .mac-dot.red { background: #ef4444; }
        .mac-dot.yellow { background: #f59e0b; }
        .mac-dot.green { background: #10b981; }

        #terminal {
            padding: 16px;
            color: #34d399;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12.5px;
            line-height: 1.65;
            overflow-y: auto;
            flex: 1;
            max-height: 390px;
            white-space: pre-wrap;
            direction: ltr;
            text-align: left;
        }

        .listener-badge {
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 11.5px;
            font-weight: 600;
            background: #1e293b;
            color: #94a3b8;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .listener-badge.active {
            background: rgba(220, 38, 38, 0.25);
            color: #f87171;
            border: 1px solid #ef4444;
            animation: pulse 1.2s infinite;
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <!-- Top Navigation Bar -->
        <header class="navbar">
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div class="brand-text">
                    <h1>CheckSpoof Enterprise</h1>
                    <p>سامانه دوطرفه ارزیابی IP Spoofing و فیلترینگ BCP 38</p>
                </div>
            </div>
            <div class="nav-pills">
                <div class="pill">
                    <span>آدرس سرور:</span>
                    <strong>{{.ServerIP}}:{{.Port}}</strong>
                </div>
                <div class="pill">
                    <span>کارت شبکه:</span>
                    <strong>{{.Iface}}</strong>
                </div>
                <div class="pill">
                    <span id="conn_dot" class="status-dot"></span>
                    <span>وضعیت:</span>
                    <strong id="state_badge">{{.ConnState}}</strong>
                </div>
            </div>
        </header>

        <!-- Security Token Banner -->
        <div class="token-banner">
            <div class="token-label">
                <span>🔑</span>
                <span><strong>توکن امنیتی این سرور:</strong> (این کد را کپی کرده و در سرور مقابل وارد نمایید)</span>
            </div>
            <div class="token-value-wrap">
                <code id="my_token">{{.ConnectionCode}}</code>
                <button class="btn-copy" onclick="copyToken()" id="copy_btn">کپی توکن</button>
            </div>
        </div>

        <!-- Main 2-Column Grid -->
        <div class="dashboard-grid">
            <!-- Right Column: Configuration & Controls -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">⚙️ تنظیمات اتصال و پارامترهای تست</h2>
                </div>

                <div class="form-group">
                    <label>🔗 توکن سرور مقابل (گیرنده):</label>
                    <div class="connect-group">
                        <input type="text" id="remote_token" class="ltr-input" placeholder="198.55.102.149:{{.Port}}|a1b2c3..." oninput="extractTargetIP(this.value)">
                        <button class="btn-connect" onclick="testConnection()" id="conn_btn">تایید و اتصال</button>
                    </div>
                    <div id="connection_status" class="alert-box"></div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>🛠️ متد تست پروتکل:</label>
                        <select id="test_type">
                            <option value="icmp">ICMP SNAT (پینگ استاندارد)</option>
                            <option value="udp">UDP Spoofing (پورت ۵۵۵۵)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>🎯 آدرس IP سرور مقصد (گیرنده):</label>
                        <input type="text" id="target_ip" class="ltr-input" placeholder="مثال: 198.55.102.149">
                    </div>
                </div>

                <div class="form-group">
                    <label>🎭 آدرس IP جعلی (Spoofed Source IP):</label>
                    <input type="text" id="spoof_ip" class="ltr-input" value="8.8.8.8">
                    <div class="Preset-chips">
                        <span class="chip" onclick="setSpoofIP('8.8.8.8')">Google DNS (8.8.8.8)</span>
                        <span class="chip" onclick="setSpoofIP('1.1.1.1')">Cloudflare (1.1.1.1)</span>
                        <span class="chip" onclick="setSpoofIP('9.9.9.9')">Quad9 (9.9.9.9)</span>
                        <span class="chip" onclick="setSpoofIP('31.56.48.200')">Subnet Test (31.56.48.200)</span>
                    </div>
                </div>

                <button id="run_btn" class="btn-primary" onclick="runTest()">
                    🚀 شروع تست و ارزیابی دوطرفه
                </button>

                <div id="status_result" class="alert-box"></div>
            </div>

            <!-- Left Column: Live Telemetry & Terminal -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">📡 مانیتورینگ زنده و لاگ شبکه</h2>
                    <span id="listener_badge" class="listener-badge">⚪ آماده به کار</span>
                </div>

                <div class="metrics-grid">
                    <div class="metric-box">
                        <div class="m-title">پکت‌های ارسالی</div>
                        <div class="m-val" id="metric_sent">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">دریافتی در سرور دوم</div>
                        <div class="m-val" id="metric_recv" style="color: #4ade80;">0</div>
                    </div>
                    <div class="metric-box">
                        <div class="m-title">وضعیت SNAT محلی</div>
                        <div class="m-val" id="metric_local" style="font-size: 14px;">—</div>
                    </div>
                </div>

                <div class="terminal-window">
                    <div class="terminal-bar">
                        <div class="mac-dots">
                            <span class="mac-dot red"></span>
                            <span class="mac-dot yellow"></span>
                            <span class="mac-dot green"></span>
                        </div>
                        <span style="font-size: 11px; color: #64748b; font-family: monospace;">root@checkspoof:~# live-stream</span>
                        <button onclick="clearLogs()" style="background:transparent; border:1px solid #334155; color:#94a3b8; border-radius:5px; font-size:11px; padding:2px 8px; cursor:pointer;">Clear</button>
                    </div>
                    <div id="terminal">System initialized. Waiting for commands...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function setSpoofIP(ip) {
            document.getElementById('spoof_ip').value = ip;
        }

        function copyToken() {
            let token = document.getElementById('my_token').innerText;
            navigator.clipboard.writeText(token);
            let btn = document.getElementById('copy_btn');
            btn.innerText = "کپی شد ✓";
            btn.style.borderColor = "#22c55e";
            btn.style.color = "#4ade80";
            setTimeout(() => {
                btn.innerText = "کپی توکن";
                btn.style.borderColor = "#334155";
                btn.style.color = "#f8fafc";
            }, 2000);
        }

        function extractTargetIP(val) {
            val = val.trim();
            if(val.includes('|') && val.includes(':')) {
                let ip = val.split('|')[0].split(':')[0];
                document.getElementById('target_ip').value = ip;
            }
        }

        function clearLogs() {
            fetch('/api/clear-logs', {method: 'POST'});
            document.getElementById('terminal').innerText = "Logs cleared.\n";
        }

        // Poll live logs every 1.2 seconds
        setInterval(() => {
            fetch('/api/logs')
            .then(res => res.json())
            .then(data => {
                if(data.logs && data.logs.length > 0) {
                    let term = document.getElementById('terminal');
                    let joined = data.logs.join("\n");
                    if (term.innerText !== joined) {
                        term.innerText = joined;
                        term.scrollTop = term.scrollHeight;
                    }
                }
                let badge = document.getElementById('listener_badge');
                if(data.is_listening) {
                    badge.className = "listener-badge active";
                    badge.innerText = "🔴 در حال شنود پکت‌های ورودی...";
                } else {
                    badge.className = "listener-badge";
                    badge.innerText = "⚪ آماده به کار";
                }

                let stateBadge = document.getElementById('state_badge');
                let connDot = document.getElementById('conn_dot');
                if(data.conn_state) {
                    stateBadge.innerText = data.conn_state;
                    if(data.conn_state === "CONNECTED" || data.conn_state === "READY_TO_RECEIVE") {
                        connDot.className = "status-dot connected";
                    } else if(data.conn_state === "ERROR") {
                        connDot.className = "status-dot error";
                    } else {
                        connDot.className = "status-dot";
                    }
                }
            }).catch(() => {});
        }, 1200);

        function testConnection() {
            let remoteToken = document.getElementById('remote_token').value.trim();
            let connBox = document.getElementById('connection_status');
            let connBtn = document.getElementById('conn_btn');
            if(!remoteToken) {
                alert('لطفاً ابتدا توکن سرور مقابل را وارد کنید.');
                return;
            }

            extractTargetIP(remoteToken);
            connBtn.disabled = true;
            connBtn.innerText = "در حال بررسی...";
            connBox.className = "alert-box warning show";
            connBox.innerHTML = "<strong>⏳ در حال برقراری ارتباط...</strong>در حال احراز هویت و بررسی آمادگی سرور دوم.";

            fetch('/api/handshake', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({remote_token: remoteToken})
            })
            .then(async res => {
                if (!res.ok) throw new Error(await res.text());
                return res.json();
            })
            .then(() => {
                connBox.className = "alert-box success show";
                connBox.innerHTML = "<strong>✅ اتصال دوطرفه برقرار شد!</strong>سرور مقابل آنلاین، احراز هویت شده و آماده دریافت پکت‌های تست است.";
            })
            .catch(err => {
                connBox.className = "alert-box failure show";
                connBox.innerHTML = "<strong>❌ خطا در اتصال به سرور مقابل</strong>" + err.message;
            })
            .finally(() => {
                connBtn.disabled = false;
                connBtn.innerText = "تایید و اتصال";
            });
        }

        function runTest() {
            let target = document.getElementById('target_ip').value.trim();
            let spoof = document.getElementById('spoof_ip').value.trim();
            let remoteToken = document.getElementById('remote_token').value.trim();
            let testType = document.getElementById('test_type').value;

            if(!target) {
                alert('لطفاً آدرس IP سرور مقصد را وارد کنید.');
                return;
            }
            
            let btn = document.getElementById('run_btn');
            let resBox = document.getElementById('status_result');
            
            btn.disabled = true;
            btn.innerText = "⏳ در حال ارسال پکت‌های تست و تحلیل شبکه...";
            resBox.className = "alert-box";
            
            fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    target_ip: target,
                    spoof_ip: spoof,
                    remote_token: remoteToken,
                    test_type: testType
                })
            })
            .then(async res => {
                if (!res.ok) throw new Error(await res.text());
                return res.json();
            })
            .then(data => {
                document.getElementById('metric_sent').innerText = data.packets_sent || 3;
                document.getElementById('metric_recv').innerText = data.remote_received || 0;
                document.getElementById('metric_local').innerText = data.local_success ? "OK (تغییر یافت)" : "FAILED";
                document.getElementById('metric_local').style.color = data.local_success ? "#4ade80" : "#f87171";

                resBox.className = "alert-box show " + (data.status_class || "failure");
                resBox.innerHTML = "<strong>" + data.result_title + "</strong>" + data.result_message;
            })
            .catch(err => {
                resBox.className = "alert-box show failure";
                resBox.innerHTML = "<strong>❌ خطا در اجرای تست</strong>" + err.message;
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerText = "🚀 شروع تست و ارزیابی دوطرفه";
            });
        }
    </script>
</body>
</html>
`

var tmpl = template.Must(template.New("index").Parse(htmlPage))

func generateToken() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getOutboundIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	if err == nil {
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).IP.String()
	}
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err == nil {
		defer resp.Body.Close()
		ip, err := io.ReadAll(resp.Body)
		if err == nil {
			return strings.TrimSpace(string(ip))
		}
	}
	return "127.0.0.1"
}

func getDefaultInterface(targetIP string) string {
	out, err := exec.Command("ip", "route", "get", targetIP).Output()
	if err == nil {
		parts := strings.Fields(string(out))
		for i, word := range parts {
			if word == "dev" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	outDef, errDef := exec.Command("ip", "route", "show", "default").Output()
	if errDef == nil {
		parts := strings.Fields(string(outDef))
		for i, word := range parts {
			if word == "dev" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return "eth0"
}

func isValidIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

func setConnState(state string) {
	mu.Lock()
	defer mu.Unlock()
	currentConnState = state
}

func listenForPackets(testType, expectedIP string, duration time.Duration) (int, string) {
	mu.Lock()
	isListening = true
	currentConnState = "READY_TO_RECEIVE"
	mu.Unlock()

	defer func() {
		mu.Lock()
		isListening = false
		currentConnState = "CONNECTED"
		mu.Unlock()
	}()

	var logB strings.Builder
	count := 0

	if testType == "udp" {
		addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:5555")
		if err != nil {
			return 0, err.Error()
		}
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			msg := fmt.Sprintf("[-] UDP port 5555 bind error: %v", err)
			addLiveLog(msg)
			return 0, msg
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(duration))
		addLiveLog(fmt.Sprintf("🔴 [Receiver] Listening on UDP :5555 for spoofed IP %s (%v)...", expectedIP, duration))

		buf := make([]byte, 1024)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if n > 0 && remoteAddr.IP.String() == expectedIP {
				count++
				pktMsg := fmt.Sprintf("🎯 [Receiver] VERIFIED! Captured UDP Packet #%d from Spoofed IP %s (%d bytes)", count, remoteAddr.IP.String(), n)
				addLiveLog(pktMsg)
				logB.WriteString(pktMsg + "\n")
			}
		}
	} else {
		conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			msg := fmt.Sprintf("[-] Raw ICMP socket error (Run with sudo/root!): %v", err)
			addLiveLog(msg)
			return 0, msg
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(duration))
		addLiveLog(fmt.Sprintf("🔴 [Receiver] Listening on Raw ICMP for spoofed IP %s (%v)...", expectedIP, duration))

		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			if n > 0 && addr.String() == expectedIP {
				if buf[0] == 8 { // ICMP Echo Request
					count++
					pktMsg := fmt.Sprintf("🎯 [Receiver] VERIFIED! Captured ICMP Echo Request #%d from Spoofed IP %s (%d bytes)", count, addr.String(), n)
					addLiveLog(pktMsg)
					logB.WriteString(pktMsg + "\n")
				}
			}
		}
	}

	addLiveLog(fmt.Sprintf("🏁 [Receiver] Listener finished. Total spoofed packets captured: %d", count))
	return count, logB.String()
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":         liveLogs,
		"is_listening": isListening,
		"conn_state":   currentConnState,
	})
}

func handleClearLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	liveLogs = []string{}
	mu.Unlock()
	addLiveLog("Logs cleared by user.")
	w.WriteHeader(http.StatusOK)
}

func handleHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RemoteToken string `json:"remote_token"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	parts := strings.SplitN(strings.TrimSpace(req.RemoteToken), "|", 2)
	if len(parts) != 2 {
		http.Error(w, "فرمت توکن نامعتبر است (فرمت صحیح: IP:PORT|TOKEN)", http.StatusBadRequest)
		return
	}
	remoteAddr, remoteSecret := parts[0], parts[1]

	payload, _ := json.Marshal(PrepareRequest{
		ExpectedSourceIP: "1.1.1.1",
		DurationSec:      1,
		TestType:         "icmp",
	})
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://%s/api/prepare-receiver", remoteAddr), bytes.NewBuffer(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Spoof-Token", remoteSecret)

	client := http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		setConnState("ERROR")
		http.Error(w, "عدم امکان برقراری ارتباط با سرور دوم (پورت یا فایروال را بررسی کنید): "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		setConnState("ERROR")
		http.Error(w, "احراز هویت ناموفق بود؛ توکن سرور مقابل اشتباه است.", http.StatusUnauthorized)
		return
	}

	setConnState("CONNECTED")
	addLiveLog(fmt.Sprintf("[Handshake] Successfully paired with remote server at %s", remoteAddr))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"connected"}`))
}

func handlePrepareReceiver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientToken := r.Header.Get("X-Spoof-Token")
	if clientToken == "" || clientToken != authToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req PrepareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !isValidIPv4(req.ExpectedSourceIP) {
		http.Error(w, "Invalid IP", http.StatusBadRequest)
		return
	}
	if req.DurationSec <= 0 || req.DurationSec > 10 {
		req.DurationSec = 4
	}
	if req.TestType != "udp" {
		req.TestType = "icmp"
	}

	count, logStr := listenForPackets(req.TestType, req.ExpectedSourceIP, time.Duration(req.DurationSec)*time.Second)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PrepareResponse{
		Status:        "READY",
		ReceivedCount: count,
		Log:           logStr,
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		ServerIP:       serverIP,
		Port:           port,
		Iface:          getDefaultInterface("8.8.8.8"),
		ConnectionCode: fmt.Sprintf("%s:%s|%s", serverIP, port, authToken),
		ConnState:      currentConnState,
	}
	tmpl.Execute(w, data)
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "درخواست نامعتبر است.", http.StatusBadRequest)
		return
	}

	req.TargetIP = strings.TrimSpace(req.TargetIP)
	req.SpoofIP = strings.TrimSpace(req.SpoofIP)
	req.RemoteToken = strings.TrimSpace(req.RemoteToken)
	if req.TestType != "udp" {
		req.TestType = "icmp"
	}

	if !isValidIPv4(req.TargetIP) || !isValidIPv4(req.SpoofIP) {
		http.Error(w, "آدرس IP مقصد یا جعلی معتبر نیست (فقط IPv4 مجاز است).", http.StatusBadRequest)
		return
	}

	iface := getDefaultInterface(req.TargetIP)
	addLiveLog(fmt.Sprintf("🚀 [Sender] Starting %s Spoof Test -> Target: %s | Spoofed IP: %s | Interface: %s", strings.ToUpper(req.TestType), req.TargetIP, req.SpoofIP, iface))

	var wg sync.WaitGroup
	var remoteResp PrepareResponse
	var remoteErr error
	remoteVerified := false

	if req.RemoteToken != "" {
		parts := strings.SplitN(req.RemoteToken, "|", 2)
		if len(parts) == 2 {
			remoteAddr, remoteSecret := parts[0], parts[1]
			remoteVerified = true

			addLiveLog(fmt.Sprintf("[Sender] Requesting Receiver (%s) to open %s listener...", remoteAddr, strings.ToUpper(req.TestType)))
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload, _ := json.Marshal(PrepareRequest{
					ExpectedSourceIP: req.SpoofIP,
					DurationSec:      4,
					TestType:         req.TestType,
				})
				httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://%s/api/prepare-receiver", remoteAddr), bytes.NewBuffer(payload))
				if err != nil {
					remoteErr = err
					return
				}
				httpReq.Header.Set("Content-Type", "application/json")
				httpReq.Header.Set("X-Spoof-Token", remoteSecret)

				client := http.Client{Timeout: 8 * time.Second}
				resp, err := client.Do(httpReq)
				if err != nil {
					remoteErr = err
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					bodyB, _ := io.ReadAll(resp.Body)
					remoteErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyB))
					return
				}
				json.NewDecoder(resp.Body).Decode(&remoteResp)
			}()
			time.Sleep(450 * time.Millisecond)
		}
	}

	localSuccess := false
	packetsSent := 3

	if req.TestType == "udp" {
		ruleArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "udp", "--dport", "5555", "-j", "SNAT", "--to-source", req.SpoofIP}
		addLiveLog(fmt.Sprintf("[Sender] Adding UDP SNAT rule: iptables %s", strings.Join(ruleArgs, " ")))
		if out, err := exec.Command("iptables", ruleArgs...).CombinedOutput(); err != nil {
			addLiveLog(fmt.Sprintf("[-] iptables error: %v (%s)", err, strings.TrimSpace(string(out))))
		} else {
			defer func() {
				delArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "udp", "--dport", "5555", "-j", "SNAT", "--to-source", req.SpoofIP}
				exec.Command("iptables", delArgs...).Run()
			}()

			// Native Go UDP transmission
			raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:5555", req.TargetIP))
			if err == nil {
				conn, err := net.DialUDP("udp4", nil, raddr)
				if err == nil {
					for i := 1; i <= packetsSent; i++ {
						msg := fmt.Sprintf("CHECKSPOOF-UDP-SEQ-%d-%d", i, time.Now().UnixNano())
						conn.Write([]byte(msg))
						time.Sleep(350 * time.Millisecond)
					}
					conn.Close()
					addLiveLog(fmt.Sprintf("[Sender] Dispatched %d UDP packets to %s:5555", packetsSent, req.TargetIP))
				}
			}

			statOut, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "-x").CombinedOutput()
			if err == nil {
				for _, line := range strings.Split(string(statOut), "\n") {
					if strings.Contains(line, req.TargetIP) && strings.Contains(line, "to:"+req.SpoofIP) {
						fields := strings.Fields(line)
						if len(fields) > 0 && fields[0] != "0" {
							localSuccess = true
							break
						}
					}
				}
			}
		}
	} else {
		ruleArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "icmp", "-j", "SNAT", "--to-source", req.SpoofIP}
		addLiveLog(fmt.Sprintf("[Sender] Adding ICMP SNAT rule: iptables %s", strings.Join(ruleArgs, " ")))
		if out, err := exec.Command("iptables", ruleArgs...).CombinedOutput(); err != nil {
			addLiveLog(fmt.Sprintf("[-] iptables error: %v (%s)", err, strings.TrimSpace(string(out))))
		} else {
			defer func() {
				delArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "icmp", "-j", "SNAT", "--to-source", req.SpoofIP}
				exec.Command("iptables", delArgs...).Run()
			}()

			addLiveLog(fmt.Sprintf("[Sender] Sending 3 ICMP Echo Requests to %s...", req.TargetIP))
			exec.Command("ping", "-c", "3", "-i", "0.4", "-W", "1", req.TargetIP).CombinedOutput()

			statOut, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "-x").CombinedOutput()
			if err == nil {
				for _, line := range strings.Split(string(statOut), "\n") {
					if strings.Contains(line, req.TargetIP) && strings.Contains(line, "to:"+req.SpoofIP) {
						fields := strings.Fields(line)
						if len(fields) > 0 && fields[0] != "0" {
							localSuccess = true
							break
						}
					}
				}
			}
		}
	}

	if remoteVerified {
		wg.Wait()
		if remoteErr != nil {
			addLiveLog(fmt.Sprintf("[-] Remote verification error: %v", remoteErr))
			remoteVerified = false
		}
	}

	addLiveLog("[Sender] Cleaned up temporary iptables SNAT rules.")

	var statusClass, resultTitle, resultMessage string
	if remoteVerified {
		if remoteResp.ReceivedCount > 0 {
			statusClass = "success"
			resultTitle = "✅ تست موفقیت‌آمیز بود (اسپوفینگ در این شبکه فعال است)"
			resultMessage = fmt.Sprintf("پکت‌ها با آدرس جعلی (%s) با موفقیت از دیتاسنتر خارج شدند و سرور دوم %d پکت را به صورت کامل دریافت و تایید کرد.", req.SpoofIP, remoteResp.ReceivedCount)
		} else if localSuccess {
			statusClass = "failure"
			resultTitle = "❌ مسدود شده توسط روتر بالادست دیتاسنتر (فیلترینگ BCP 38)"
			resultMessage = "پکت‌های اسپوف‌شده از کارت شبکه سرور شما خارج شدند، اما توسط فایروال یا روتر دیتاسنتر فیلتر شده و هیچ پکتی (۰ پکت) به سرور دوم نرسید."
		} else {
			statusClass = "failure"
			resultTitle = "❌ خطا در ارسال محلی پکت‌ها"
			resultMessage = "هیچ پکتی از قانون SNAT در سیستم‌عامل عبور نکرد. دسترسی root و وضعیت فایروال محلی را بررسی کنید."
		}
	} else {
		if localSuccess {
			statusClass = "warning"
			resultTitle = "⚠️ ارسال محلی انجام شد (بدون تایید سرور دوم)"
			resultMessage = "پکت‌ها در لایه iptables تغییر آدرس داده و از کارت شبکه خارج شدند؛ اما برای اطمینان ۱۰۰٪ از عدم مسدودسازی در دیتاسنتر، توکن سرور دوم را وارد کنید."
		} else {
			statusClass = "failure"
			resultTitle = "❌ عدم موفقیت در اعمال قوانین SNAT محلی"
			resultMessage = "تغییر آدرس مبدا در سیستم‌عامل انجام نشد. مطمئن شوید برنامه با دسترسی sudo اجرا شده است."
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TestResponse{
		LocalSuccess:   localSuccess,
		RemoteVerified: remoteVerified,
		PacketsSent:    packetsSent,
		RemoteReceived: remoteResp.ReceivedCount,
		StatusClass:    statusClass,
		ResultTitle:    resultTitle,
		ResultMessage:  resultMessage,
	})
}

func resolvePort() string {
	cliPort := flag.String("port", "", "Port to run the web dashboard on (e.g., 8085)")
	flag.Parse()

	if *cliPort != "" {
		return strings.TrimSpace(*cliPort)
	}
	if envPort := os.Getenv("PORT"); envPort != "" {
		return strings.TrimSpace(envPort)
	}

	// Interactive prompt if running in terminal
	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		fmt.Print("🌐 Enter port for Web UI [Press Enter for default 8085]: ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			if p, err := strconv.Atoi(input); err == nil && p > 0 && p < 65536 {
				return input
			}
			fmt.Println("⚠️ Invalid port number, using default 8085.")
		}
	}
	return "8085"
}

func bindAvailableListener(preferredPort string) (net.Listener, string) {
	basePort, err := strconv.Atoi(preferredPort)
	if err != nil || basePort <= 0 || basePort > 65535 {
		basePort = 8085
	}

	for i := 0; i < 20; i++ {
		tryPort := strconv.Itoa(basePort + i)
		ln, err := net.Listen("tcp", "0.0.0.0:"+tryPort)
		if err == nil {
			if i > 0 {
				fmt.Printf("⚠️ Port %d was busy! Automatically switched to free port %s.\n", basePort, tryPort)
			}
			return ln, tryPort
		}
	}
	fmt.Printf("[-] Error: Could not find any free port starting from %d\n", basePort)
	os.Exit(1)
	return nil, ""
}

func main() {
	preferredPort := resolvePort()
	listener, activePort := bindAvailableListener(preferredPort)
	port = activePort

	serverIP = getOutboundIP()
	authToken = generateToken()
	setConnState("DISCONNECTED")

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/test", handleTest)
	http.HandleFunc("/api/prepare-receiver", handlePrepareReceiver)
	http.HandleFunc("/api/handshake", handleHandshake)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/clear-logs", handleClearLogs)

	addLiveLog(fmt.Sprintf("CheckSpoof initialized on %s:%s", serverIP, port))

	fmt.Println("==========================================================")
	fmt.Printf("🚀 CheckSpoof Enterprise Edition is running!\n")
	fmt.Printf("🌐 Web Dashboard  : http://%s:%s\n", serverIP, port)
	fmt.Printf("🔑 Security Token : %s:%s|%s\n", serverIP, port, authToken)
	fmt.Println("==========================================================")

	if err := http.Serve(listener, nil); err != nil {
		fmt.Printf("[-] Server error: %v\n", err)
	}
}
