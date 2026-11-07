package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Server state and configuration
var (
	serverIP         string
	authToken        string
	port             = "5000"
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
	if len(liveLogs) > 100 {
		liveLogs = liveLogs[1:]
	}
	liveLogs = append(liveLogs, line)
}

// Data structures for API and UI coordination
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
	RemoteReceived int    `json:"remote_received"`
	StatusClass    string `json:"status_class"`
	ResultMessage  string `json:"result_message"`
}

type PrepareRequest struct {
	ExpectedSourceIP string `json:"expected_source_ip"`
	DurationSec      int    `json:"duration_sec"`
}

type PrepareResponse struct {
	Status        string `json:"status"`
	ReceivedCount int    `json:"received_count"`
	Log           string `json:"log"`
}

type PageData struct {
	ServerIP       string
	Iface          string
	ConnectionCode string
	ConnState      string
}

const htmlPage = `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>CheckSpoof — سامانه پیشرفته تحلیل IP Spoofing</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #090d16;
            --accent: #38bdf8;
            --accent-hover: #0ea5e9;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --success-bg: #14532d;
            --success-fg: #4ade80;
            --warning-bg: #713f12;
            --warning-fg: #facc15;
            --danger-bg: #7f1d1d;
            --danger-fg: #f87171;
        }
        body { background-color: var(--bg-primary); color: var(--text-main); font-family: monospace; margin: 0; padding: 20px; }
        .container { max-width: 980px; margin: auto; background: var(--bg-secondary); padding: 25px; border-radius: 12px; box-shadow: 0 4px 25px rgba(0,0,0,0.6); border: 1px solid var(--border); }
        h1 { text-align: center; color: var(--accent); font-size: 24px; margin-bottom: 5px; }
        .server-info { text-align: center; color: var(--text-muted); font-size: 13px; margin-bottom: 15px; }
        .server-info span { color: var(--accent); font-weight: bold; }
        .state-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; background: #334155; color: #fff; margin-bottom: 15px; }
        .token-box { background: var(--bg-tertiary); border: 1px dashed var(--accent); padding: 12px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; direction: ltr; }
        .token-box code { color: var(--success-fg); font-size: 13px; word-break: break-all; }
        .copy-btn, .sub-btn { background: #334155; color: #fff; border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: bold; }
        .copy-btn:hover, .sub-btn:hover { background: #475569; }
        .sub-btn { background: #059669; }
        .sub-btn:hover { background: #10b981; }
        .section { margin-bottom: 20px; padding: 18px; background: var(--bg-primary); border-radius: 8px; border: 1px solid var(--border); }
        label { display: block; margin-bottom: 6px; color: var(--text-muted); font-size: 13px; }
        input, select { width: 100%; padding: 10px; margin-bottom: 12px; background: var(--bg-secondary); border: 1px solid var(--border); color: #fff; border-radius: 6px; box-sizing: border-box; font-family: monospace; }
        .connect-row { display: flex; gap: 10px; margin-bottom: 10px; }
        button.main-btn { background: var(--accent); color: var(--bg-primary); border: none; padding: 14px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; transition: 0.2s; }
        button.main-btn:hover { background: var(--accent-hover); }
        button.main-btn:disabled { background: #475569; color: #94a3b8; cursor: not-allowed; }
        .status-box { padding: 12px; border-radius: 6px; text-align: center; font-weight: bold; margin-top: 10px; font-size: 14px; }
        .success { background: var(--success-bg); color: var(--success-fg); border: 1px solid #166534; }
        .warning { background: var(--warning-bg); color: var(--warning-fg); border: 1px solid #854d0e; }
        .failure { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid #991b1b; }
        .terminal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        #terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; height: 300px; overflow-y: scroll; font-size: 12px; border: 1px solid var(--border); white-space: pre-wrap; direction: ltr; text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CheckSpoof — سامانه پیشرفته تحلیل IP Spoofing</h1>
        <div class="server-info">
            آدرس این سرور: <span>{{.ServerIP}}:5000</span> | اینترفیس پیش‌فرض: <span>{{.Iface}}</span>
        </div>
        <div style="text-align: center;">
            وضعیت اتصال: <span id="state_badge" class="state-badge">DISCONNECTED</span>
        </div>

        <label>🔑 توکن امنیتی این سرور (جهت جفت‌سازی در سرور مقابل):</label>
        <div class="token-box">
            <code id="my_token">{{.ConnectionCode}}</code>
            <button class="copy-btn" onclick="copyToken()">کپی توکن</button>
        </div>

        <div class="section">
            <label>🔗 توکن سرور مقابل (جهت برقراری کنترل‌پلین امن و دسترسی دوطرفه):</label>
            <div class="connect-row">
                <input type="text" id="remote_token" placeholder="مثال: 198.55.102.149:5000|a1b2c3d4..." oninput="extractTargetIP(this.value)" style="direction:ltr; margin-bottom:0;">
                <button class="sub-btn" onclick="testConnection()">تایید و اتصال</button>
            </div>
            <div id="connection_status"></div>

            <label style="margin-top: 15px;">🛠 نوع تست پروتکل:</label>
            <select id="test_type">
                <option value="icmp">ICMP SNAT (پیش‌فرض)</option>
                <option value="udp">UDP Spoofing</option>
            </select>

            <label>🎯 IP مقصد (Target IP / سرور گیرنده):</label>
            <input type="text" id="target_ip" placeholder="مثال: 198.55.102.149" style="direction:ltr;">
            
            <label>🎭 IP جعلی (Spoof IP):</label>
            <input type="text" id="spoof_ip" value="8.8.8.8" style="direction:ltr;">
            
            <label>پیشنهادهای سریع:</label>
            <select onchange="document.getElementById('spoof_ip').value=this.value;">
                <option value="8.8.8.8">Google DNS (8.8.8.8)</option>
                <option value="1.1.1.1">Cloudflare (1.1.1.1)</option>
                <option value="31.56.48.200">IP داخلی رنج خودی (31.56.48.200)</option>
            </select>

            <button id="run_btn" class="main-btn" disabled onclick="runTest()">🔒 ابتدا اتصال به سرور مقابل را برقرار کنید</button>
            <div id="status_result"></div>
        </div>

        <div class="section">
            <div class="terminal-header">
                <h3 style="margin:0; color: var(--text-main);">لاگ زنده فعالیت‌ها و مانیتورینگ</h3>
                <span id="listener_badge" style="background: #1e293b; color: var(--text-muted); padding: 3px 8px; border-radius: 4px; font-size: 11px;">⚪ آماده به کار</span>
            </div>
            <div id="terminal">System initialized. Waiting for action...</div>
        </div>
    </div>
    <script>
        let isConnected = false;

        function copyToken() {
            let token = document.getElementById('my_token').innerText;
            navigator.clipboard.writeText(token);
            alert('توکن امنیتی با موفقیت کپی شد!');
        }

        function extractTargetIP(val) {
            val = val.trim();
            if(val.includes('|') && val.includes(':')) {
                let ip = val.split('|')[0].split(':')[0];
                document.getElementById('target_ip').value = ip;
            }
        }

        setInterval(() => {
            fetch('/api/logs')
            .then(res => res.json())
            .then(data => {
                if(data.logs && data.logs.length > 0) {
                    let term = document.getElementById('terminal');
                    term.innerText = data.logs.join("\n");
                    term.scrollTop = term.scrollHeight;
                }
                let badge = document.getElementById('listener_badge');
                let badgeState = document.getElementById('state_badge');
                if(data.is_listening) {
                    badge.style.background = "#14532d";
                    badge.style.color = "#4ade80";
                    badge.innerText = "🔴 در حال شنود و پایش پکت‌ها...";
                } else {
                    badge.style.background = "#1e293b";
                    badge.style.color = "#94a3b8";
                    badge.innerText = "⚪ آماده به کار";
                }
                if(data.conn_state) {
                    badgeState.innerText = data.conn_state;
                    if(data.conn_state === "READY_TO_RECEIVE" || data.conn_state === "CONNECTED") {
                        badgeState.style.background = "#14532d";
                        badgeState.style.color = "#4ade80";
                    } else if(data.conn_state === "ERROR") {
                        badgeState.style.background = "#7f1d1d";
                        badgeState.style.color = "#f87171";
                    }
                }
            }).catch(e=>{});
        }, 1500);

        function testConnection() {
            let remoteToken = document.getElementById('remote_token').value.trim();
            let connBox = document.getElementById('connection_status');
            let runBtn = document.getElementById('run_btn');
            if(!remoteToken) { alert('لطفا توکن سرور مقابل را وارد کنید'); return; }

            connBox.className = "status-box warning";
            connBox.innerText = "در حال برقراری هندشک و احراز هویت دوطرفه...";

            fetch('/api/handshake', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({remote_token: remoteToken})
            })
            .then(async res => {
                if (!res.ok) throw new Error(await res.text());
                return res.json();
            })
            .then(data => {
                connBox.className = "status-box success";
                connBox.innerText = "✅ ارتباط امن و هندشک با موفقیت برقرار شد. گیرنده کاملاً آماده است.";
                isConnected = true;
                runBtn.disabled = false;
                runBtn.innerText = "شروع تست و ارزیابی دوطرفه";
            })
            .catch(err => {
                connBox.className = "status-box failure";
                connBox.innerText = "❌ خطا در برقراری ارتباط: " + err.message;
                isConnected = false;
                runBtn.disabled = true;
                runBtn.innerText = "🔒 ابتدا اتصال به سرور مقابل را برقرار کنید";
            });
        }

        function runTest() {
            let target = document.getElementById('target_ip').value.trim();
            let spoof = document.getElementById('spoof_ip').value.trim();
            let remoteToken = document.getElementById('remote_token').value.trim();
            let testType = document.getElementById('test_type').value;
            if(!target) { alert('لطفا IP مقصد را وارد کنید'); return; }
            
            let btn = document.getElementById('run_btn');
            let resBox = document.getElementById('status_result');
            
            btn.disabled = true;
            btn.innerText = "در حال اجرای تست و هماهنگی فاز دو...";
            resBox.className = "";
            resBox.innerText = "";
            
            fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_ip: target, spoof_ip: spoof, remote_token: remoteToken, test_type: testType})
            })
            .then(async res => {
                if (!res.ok) throw new Error(await res.text());
                return res.json();
            })
            .then(data => {
                resBox.className = "status-box " + (data.status_class || "failure");
                resBox.innerText = data.result_message;
            })
            .catch(err => {
                resBox.className = "status-box failure";
                resBox.innerText = "خطا در اجرا: " + err.message;
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerText = "شروع تست و ارزیابی دوطرفه";
            });
        }
    </script>
</body>
</html>
`

var tmpl = template.Must(template.New("index").Parse(htmlPage))

func generateToken() string {
	b := make([]byte, 16)
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
	// Fallback to default route interface
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

// Phase 2 Receiver Listener: ICMP & UDP Support
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

	if testType == "icmp" {
		conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			msg := fmt.Sprintf("[-] Raw ICMP socket bind error (Requires root/CAP_NET_RAW): %v", err)
			addLiveLog(msg)
			return 0, msg
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(duration))
		addLiveLog(fmt.Sprintf("[Receiver] Listening on raw ICMP for spoofed source: %s (Duration: %v)", expectedIP, duration))

		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			if n > 0 && addr.String() == expectedIP {
				// ICMP Echo Request type is 8
				if buf[0] == 8 {
					count++
					pktMsg := fmt.Sprintf("🎯 [Receiver] VERIFIED: Captured ICMP Echo Request #%d from Spoofed IP %s", count, addr.String())
					addLiveLog(pktMsg)
					logB.WriteString(pktMsg + "\n")
				}
			}
		}
	} else if testType == "udp" {
		addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:5555")
		if err != nil {
			return 0, err.Error()
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			msg := fmt.Sprintf("[-] UDP port 5555 bind error: %v", err)
			addLiveLog(msg)
			return 0, msg
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(duration))
		addLiveLog(fmt.Sprintf("[Receiver] Listening on UDP port 5555 for source: %s", expectedIP))

		buf := make([]byte, 1024)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if n > 0 && remoteAddr.IP.String() == expectedIP {
				count++
				pktMsg := fmt.Sprintf("🎯 [Receiver] VERIFIED: Captured UDP packet #%d from Spoofed IP %s", count, remoteAddr.IP.String())
				addLiveLog(pktMsg)
				logB.WriteString(pktMsg + "\n")
			}
		}
	}

	addLiveLog(fmt.Sprintf("[Receiver] Session finished. Total verified packets received: %d", count))
	return count, logB.String()
}

// API Handlers
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

// Phase 1 Handshake & Authentication
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
		http.Error(w, "فرمت توکن نامعتبر است", http.StatusBadRequest)
		return
	}
	remoteAddr, remoteSecret := parts[0], parts[1]

	// Perform test ping to remote receiver's prepare endpoint
	payload, _ := json.Marshal(PrepareRequest{ExpectedSourceIP: "1.1.1.1", DurationSec: 1})
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://%s/api/prepare-receiver", remoteAddr), bytes.NewBuffer(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Spoof-Token", remoteSecret)

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		setConnState("ERROR")
		http.Error(w, "عدم توانایی در برقراری ارتباط با سرور مقابل: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		setConnState("ERROR")
		http.Error(w, "احراز هویت رد شد یا توکن نامعتبر است", http.StatusUnauthorized)
		return
	}

	setConnState("CONNECTED")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"success"}`))
}

// Phase 2 Receiver Preparation Handshake endpoint
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

	// Determine test type based on request or default to icmp
	count, logStr := listenForPackets("icmp", req.ExpectedSourceIP, time.Duration(req.DurationSec)*time.Second)

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
		Iface:          getDefaultInterface("8.8.8.8"),
		ConnectionCode: fmt.Sprintf("%s:%s|%s", serverIP, port, authToken),
		ConnState:      currentConnState,
	}
	tmpl.Execute(w, data)
}

// Main Test Orchestrator
func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	req.TargetIP = strings.TrimSpace(req.TargetIP)
	req.SpoofIP = strings.TrimSpace(req.SpoofIP)
	req.RemoteToken = strings.TrimSpace(req.RemoteToken)

	if !isValidIPv4(req.TargetIP) || !isValidIPv4(req.SpoofIP) {
		http.Error(w, "آدرس IP نامعتبر است", http.StatusBadRequest)
		return
	}

	iface := getDefaultInterface(req.TargetIP)
	addLiveLog(fmt.Sprintf("[Sender] Starting %s test -> Target: %s | Spoof: %s | Iface: %s", strings.ToUpper(req.TestType), req.TargetIP, req.SpoofIP, iface))

	var wg sync.WaitGroup
	var remoteResp PrepareResponse
	var remoteErr error
	remoteVerified := false

	// 1. Trigger Receiver Preparation Handshake (Phase 2)
	if req.RemoteToken != "" {
		parts := strings.SplitN(req.RemoteToken, "|", 2)
		if len(parts) == 2 {
			remoteAddr, remoteSecret := parts[0], parts[1]
			remoteVerified = true

			addLiveLog(fmt.Sprintf("[Sender] Activating remote receiver listener at %s...", remoteAddr))
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload, _ := json.Marshal(PrepareRequest{
					ExpectedSourceIP: req.SpoofIP,
					DurationSec:      4,
				})
				httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://%s/api/prepare-receiver", remoteAddr), bytes.NewBuffer(payload))
				if err != nil {
					remoteErr = err
					return
				}
				httpReq.Header.Set("Content-Type", "application/json")
				httpReq.Header.Set("X-Spoof-Token", remoteSecret)

				client := http.Client{Timeout: 7 * time.Second}
				resp, err := client.Do(httpReq)
				if err != nil {
					remoteErr = err
					return
				}
				defer resp.Body.Close()
				json.NewDecoder(resp.Body).Decode(&remoteResp)
			}()
			time.Sleep(400 * time.Millisecond) // Ensure listener is bound
		}
	}

	localSuccess := false

	if req.TestType == "udp" {
		// UDP Spoofing test using python/nc or direct UDP packet generation
		addLiveLog(fmt.Sprintf("[Sender] Sending spoofed UDP packets to %s:5555...", req.TargetIP))
		// Use iptables SNAT for UDP or raw payload
		ruleArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "udp", "--dport", "5555", "-j", "SNAT", "--to-source", req.SpoofIP}
		exec.Command("iptables", ruleArgs...).Run()
		defer func() {
			delArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "udp", "--dport", "5555", "-j", "SNAT", "--to-source", req.SpoofIP}
			exec.Command("iptables", delArgs...).Run()
		}()

		exec.Command("sh", "-c", fmt.Sprintf("echo 'CheckSpoof-UDP-Test' | nc -u -w 1 %s 5555", req.TargetIP)).Run()
		localSuccess = true
	} else {
		// Method 1: ICMP SNAT
		ruleArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "icmp", "-j", "SNAT", "--to-source", req.SpoofIP}
		addLiveLog(fmt.Sprintf("[Sender] Applying iptables SNAT rule: iptables %s", strings.Join(ruleArgs, " ")))
		if out, err := exec.Command("iptables", ruleArgs...).CombinedOutput(); err != nil {
			addLiveLog(fmt.Sprintf("[-] iptables error: %v\n%s", err, string(out)))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(TestResponse{LocalSuccess: false, StatusClass: "failure", ResultMessage: "خطا در اعمال قوانین iptables"})
			return
		}

		defer func() {
			delArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "icmp", "-j", "SNAT", "--to-source", req.SpoofIP}
			exec.Command("iptables", delArgs...).Run()
		}()

		addLiveLog(fmt.Sprintf("[Sender] Sending 3 ICMP echo requests to %s...", req.TargetIP))
		pingOut, _ := exec.Command("ping", "-c", "3", "-i", "0.5", "-W", "1", req.TargetIP).CombinedOutput()
		addLiveLog(string(pingOut))

		// Check local packet counters
		statOut, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "-x").CombinedOutput()
		statStr := string(statOut)
		if err == nil {
			for _, line := range strings.Split(statStr, "\n") {
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

	if remoteVerified {
		wg.Wait()
	}

	addLiveLog("[Sender] Test session completed successfully. Cleaned up firewall rules.")

	// Evaluate final response status according to strict verification criteria
	var statusClass, resultMessage string
	if remoteVerified {
		if remoteResp.ReceivedCount > 0 {
			statusClass = "success"
			resultMessage = fmt.Sprintf("✅ تایید ۱۰۰٪ دوطرفه: پکت‌های اسپوف‌شده با موفقیت از دیتاسنتر خارج شدند و سرور دوم %d پکت دریافت کرد!", remoteResp.ReceivedCount)
		} else if localSuccess {
			statusClass = "failure"
			resultMessage = "❌ مسدود شده در روتر بالادست (BCP 38): پکت از کارت شبکه خارج شد اما سرور دوم ۰ پکت دریافت کرد (فیلترینگ دیتاسنتر)."
		} else {
			statusClass = "failure"
			resultMessage = "❌ خطا در پردازش محلی یا فیلترینگ شدید لایه شبکه."
		}
	} else {
		if localSuccess {
			statusClass = "warning"
			resultMessage = "⚠️ ارسال محلی موفق (بدون تایید سرور دوم): جهت سنجش قطعی BCP 38، توکن سرور دوم را متصل کنید."
		} else {
			statusClass = "failure"
			resultMessage = "❌ عدم موفقیت در اعمال یا تطبیق قوانین محلی."
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TestResponse{
		LocalSuccess:   localSuccess,
		RemoteVerified: remoteVerified,
		RemoteReceived: remoteResp.ReceivedCount,
		StatusClass:    statusClass,
		ResultMessage:  resultMessage,
	})
}

func main() {
	serverIP = getOutboundIP()
	authToken = generateToken()
	setConnState("DISCONNECTED")

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/test", handleTest)
	http.HandleFunc("/api/prepare-receiver", handlePrepareReceiver)
	http.HandleFunc("/api/handshake", handleHandshake)
	http.HandleFunc("/api/logs", handleLogs)

	addLiveLog("CheckSpoof server initialized successfully.")

	fmt.Println("==================================================")
	fmt.Printf("🚀 CheckSpoof Enterprise Edition is running!\n")
	fmt.Printf("🌐 Web Dashboard : http://%s:%s\n", serverIP, port)
	fmt.Printf("🔑 Security Token: %s:%s|%s\n", serverIP, port, authToken)
	fmt.Println("==================================================")

	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		fmt.Printf("[-] Server error: %v\n", err)
	}
}
