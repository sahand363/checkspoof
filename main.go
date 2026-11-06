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
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	serverIP             string
	authToken            string
	port                 = "5000"
	mu                   sync.Mutex
	liveLogs             []string
	isCurrentlyListening bool
)

func addLiveLog(msg string) {
	mu.Lock()
	defer mu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s", timestamp, msg)
	if len(liveLogs) > 50 {
		liveLogs = liveLogs[1:]
	}
	liveLogs = append(liveLogs, line)
}

type TestRequest struct {
	TargetIP    string `json:"target_ip"`
	SpoofIP     string `json:"spoof_ip"`
	RemoteToken string `json:"remote_token"`
}

type TestResponse struct {
	Log            string `json:"log"`
	LocalSuccess   bool   `json:"local_success"`
	RemoteVerified bool   `json:"remote_verified"`
	RemoteReceived int    `json:"remote_received"`
}

type ListenRequest struct {
	ExpectedSourceIP string `json:"expected_source_ip"`
	DurationSec      int    `json:"duration_sec"`
}

type ListenResponse struct {
	ReceivedCount int    `json:"received_count"`
	Log           string `json:"log"`
}

type PageData struct {
	ServerIP       string
	Iface          string
	ConnectionCode string
}

const htmlPage = `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ابزار دوطرفه تحلیل IP Spoofing</title>
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: monospace; margin: 0; padding: 20px; }
        .container { max-width: 950px; margin: auto; background: #1e293b; padding: 20px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        h1 { text-align: center; color: #38bdf8; font-size: 22px; margin-bottom: 5px; }
        .server-info { text-align: center; color: #94a3b8; font-size: 13px; margin-bottom: 15px; }
        .server-info span { color: #38bdf8; font-weight: bold; }
        .token-box { background: #090d16; border: 1px dashed #38bdf8; padding: 12px; border-radius: 8px; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center; direction: ltr; }
        .token-box code { color: #4ade80; font-size: 14px; word-break: break-all; }
        .copy-btn { background: #334155; color: #fff; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .copy-btn:hover { background: #475569; }
        .section { margin-bottom: 20px; padding: 15px; background: #0f172a; border-radius: 8px; border: 1px solid #334155; }
        label { display: block; margin-bottom: 5px; color: #94a3b8; }
        input, select { width: 100%; padding: 10px; margin-bottom: 10px; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 6px; box-sizing: border-box; }
        .connect-row { display: flex; gap: 10px; margin-bottom: 10px; }
        button.main-btn { background: #0284c7; color: white; border: none; padding: 12px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; transition: 0.2s; }
        button.main-btn:hover { background: #0ea5e9; }
        button.main-btn:disabled { background: #475569; cursor: not-allowed; }
        button.sub-btn { background: #059669; color: white; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; white-space: nowrap; }
        button.sub-btn:hover { background: #10b981; }
        .status-box { padding: 12px; border-radius: 6px; text-align: center; font-weight: bold; margin-top: 10px; }
        .success { background: #14532d; color: #4ade80; border: 1px solid #166534; }
        .warning { background: #713f12; color: #facc15; border: 1px solid #854d0e; }
        .failure { background: #7f1d1d; color: #f87171; border: 1px solid #991b1b; }
        .terminal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; }
        #terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; height: 280px; overflow-y: scroll; font-size: 13px; border: 1px solid #334155; white-space: pre-wrap; direction: ltr; text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ابزار دوطرفه تحلیل IP Spoofing</h1>
        <div class="server-info">
            آدرس این سرور: <span>{{.ServerIP}}:5000</span> | اینترفیس شبکه: <span>{{.Iface}}</span>
        </div>

        <label>🔑 توکن اتصال این سرور (کد زیر را کپی کرده و در سرور دیگر وارد کنید):</label>
        <div class="token-box">
            <code id="my_token">{{.ConnectionCode}}</code>
            <button class="copy-btn" onclick="copyToken()">Copy Token</button>
        </div>

        <div class="section">
            <label>🔗 توکن سرور مقابل (برای اتصال دوطرفه و تایید ۱۰۰٪ پکت‌ها):</label>
            <div class="connect-row">
                <input type="text" id="remote_token" placeholder="مثال: 198.55.102.149:5000|a1b2c3d4..." oninput="extractTargetIP(this.value)" style="direction:ltr; margin-bottom:0;">
                <button class="sub-btn" onclick="testConnection()">اتصال و تست لینک</button>
            </div>
            <div id="connection_status"></div>

            <label style="margin-top: 12px;">🎯 IP مقصد (Target IP):</label>
            <input type="text" id="target_ip" placeholder="مثال: 198.55.102.149" style="direction:ltr;">
            
            <label>🎭 IP جعلی (Spoof IP):</label>
            <input type="text" id="spoof_ip" value="8.8.8.8" style="direction:ltr;">
            
            <label>پیشنهادهای سریع:</label>
            <select onchange="document.getElementById('spoof_ip').value=this.value;">
                <option value="8.8.8.8">Google DNS (8.8.8.8)</option>
                <option value="1.1.1.1">Cloudflare (1.1.1.1)</option>
                <option value="31.56.48.200">IP داخلی رنج خودی (31.56.48.200)</option>
            </select>

            <button id="run_btn" class="main-btn" onclick="runTest()">شروع تست و بررسی دوطرفه</button>
            <div id="status_result"></div>
        </div>
        <div class="section">
            <div class="terminal-header">
                <h3 style="margin:0;">لاگ زنده و وضعیت گوش‌به‌زنگی (Live Activity)</h3>
                <span id="listener_badge" style="background: #1e293b; color: #94a3b8; padding: 3px 8px; border-radius: 4px; font-size: 11px;">⚪ حالت عادی</span>
            </div>
            <div id="terminal">System ready. Waiting for action...</div>
        </div>
    </div>
    <script>
        function copyToken() {
            let token = document.getElementById('my_token').innerText;
            navigator.clipboard.writeText(token);
            alert('توکن اتصال کپی شد!');
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
                if(data.is_listening) {
                    badge.style.background = "#14532d";
                    badge.style.color = "#4ade80";
                    badge.innerText = "🔴 در حال شنود پکت‌های ICMP...";
                } else {
                    badge.style.background = "#1e293b";
                    badge.style.color = "#94a3b8";
                    badge.innerText = "⚪ آماده به کار";
                }
            }).catch(e=>{});
        }, 1500);

        function testConnection() {
            let remoteToken = document.getElementById('remote_token').value.trim();
            let connBox = document.getElementById('connection_status');
            if(!remoteToken) { alert('لطفا ابتدا توکن سرور مقابل را وارد کنید'); return; }

            connBox.className = "status-box warning";
            connBox.innerText = "در حال اتصال به سرور مقابل...";

            fetch('/api/ping-remote', {
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
                connBox.innerText = "✅ ارتباط با موفقیت برقرار شد! سرور مقابل آنلاین و آماده است.";
            })
            .catch(err => {
                connBox.className = "status-box failure";
                connBox.innerText = "❌ خطا در اتصال به سرور مقابل: " + err.message;
            });
        }

        function runTest() {
            let target = document.getElementById('target_ip').value.trim();
            let spoof = document.getElementById('spoof_ip').value.trim();
            let remoteToken = document.getElementById('remote_token').value.trim();
            if(!target) { alert('لطفا IP مقصد را وارد کنید'); return; }
            
            let btn = document.getElementById('run_btn');
            let resBox = document.getElementById('status_result');
            
            btn.disabled = true;
            btn.innerText = "در حال اجرای تست و هماهنگی دوطرفه...";
            resBox.className = "";
            resBox.innerText = "";
            
            fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_ip: target, spoof_ip: spoof, remote_token: remoteToken})
            })
            .then(async res => {
                if (!res.ok) throw new Error(await res.text());
                return res.json();
            })
            .then(data => {
                let resBox = document.getElementById('status_result');
                if (data.remote_verified) {
                    if (data.remote_received > 0) {
                        resBox.className = "status-box success";
                        resBox.innerText = "✅ تایید ۱۰۰٪ دوطرفه: پکت‌های اسپوف‌شده از دیتاسنتر خارج شدند و سرور دوم " + data.remote_received + " پکت با IP جعلی دریافت کرد!";
                    } else if (data.local_success) {
                        resBox.className = "status-box failure";
                        resBox.innerText = "❌ مسدود شده در روتر بالادست (BCP 38): پکت از کارت شبکه شما خارج شد اما سرور دوم ۰ پکت دریافت کرد (فیلترینگ دیتاسنتر).";
                    } else {
                        resBox.className = "status-box failure";
                        resBox.innerText = "❌ خطا در لایه محلی: هیچ پکتی ارسال نشد.";
                    }
                } else {
                    if (data.local_success) {
                        resBox.className = "status-box warning";
                        resBox.innerText = "⚠️ ارسال محلی موفق (بدون سرور دوم): پکت‌ها تغییر یافتند، اما برای تایید ۱۰۰٪، توکن سرور دوم را متصل کنید.";
                    } else {
                        resBox.className = "status-box failure";
                        resBox.innerText = "❌ عدم موفقیت در اعمال قوانین محلی.";
                    }
                }
            })
            .catch(err => {
                resBox.className = "status-box failure";
                resBox.innerText = "خطا: " + err.message;
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerText = "شروع تست و بررسی دوطرفه";
            });
        }
    </script>
</body>
</html>
`

var tmpl = template.Must(template.New("index").Parse(htmlPage))

func generateToken() string {
	b := make([]byte, 8)
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

func getDefaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	parts := strings.Fields(string(out))
	for i, word := range parts {
		if word == "dev" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "eth0"
}

func isValidIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

func listenForSpoofedICMP(expectedIP string, duration time.Duration) (int, string) {
	mu.Lock()
	isCurrentlyListening = true
	mu.Unlock()

	defer func() {
		mu.Lock()
		isCurrentlyListening = false
		mu.Unlock()
	}()

	var logB strings.Builder
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		errMsg := fmt.Sprintf("[-] Raw ICMP socket error (Run app as root!): %v", err)
		addLiveLog(errMsg)
		return 0, errMsg
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(duration))
	msg := fmt.Sprintf("🔴 [Receiver] Started listening on ip4:icmp for spoofed source: %s (Duration: %v)", expectedIP, duration)
	addLiveLog(msg)
	logB.WriteString(msg + "\n")

	count := 0
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if n > 0 && addr.String() == expectedIP {
			if buf[0] == 8 {
				count++
				packetMsg := fmt.Sprintf("🎯 [Receiver] SUCCESS! Captured ICMP Echo Request #%d from Spoofed IP: %s (%d bytes)", count, addr.String(), n)
				addLiveLog(packetMsg)
				logB.WriteString(packetMsg + "\n")
			}
		}
	}
	finishMsg := fmt.Sprintf("🏁 [Receiver] Listener closed. Total captured packets from %s: %d", expectedIP, count)
	addLiveLog(finishMsg)
	logB.WriteString(finishMsg + "\n")
	return count, logB.String()
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":         liveLogs,
		"is_listening": isCurrentlyListening,
	})
}

func handlePingRemote(w http.ResponseWriter, r *http.Request) {
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

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://%s/api/listen", remoteAddr), bytes.NewBuffer([]byte(`{"expected_source_ip":"1.1.1.1","duration_sec":1}`)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Spoof-Token", remoteSecret)

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		http.Error(w, "عدم توانایی در ارتباط با سرور مقابل: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "توکن یا احراز هویت نامعتبر است", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"connected"}`))
}

func handleListen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientToken := r.Header.Get("X-Spoof-Token")
	if clientToken == "" || clientToken != authToken {
		http.Error(w, "Unauthorized: Invalid Connection Token", http.StatusUnauthorized)
		return
	}

	var req ListenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !isValidIPv4(req.ExpectedSourceIP) {
		http.Error(w, "Invalid expected IPv4", http.StatusBadRequest)
		return
	}
	if req.DurationSec <= 0 || req.DurationSec > 10 {
		req.DurationSec = 4
	}

	count, logStr := listenForSpoofedICMP(req.ExpectedSourceIP, time.Duration(req.DurationSec)*time.Second)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ListenResponse{
		ReceivedCount: count,
		Log:           logStr,
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		ServerIP:       serverIP,
		Iface:          getDefaultInterface(),
		ConnectionCode: fmt.Sprintf("%s:%s|%s", serverIP, port, authToken),
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
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	req.TargetIP = strings.TrimSpace(req.TargetIP)
	req.SpoofIP = strings.TrimSpace(req.SpoofIP)
	req.RemoteToken = strings.TrimSpace(req.RemoteToken)

	if !isValidIPv4(req.TargetIP) || !isValidIPv4(req.SpoofIP) {
		http.Error(w, "Invalid IPv4 address provided", http.StatusBadRequest)
		return
	}

	var logBuilder strings.Builder
	iface := getDefaultInterface()
	addLiveLog(fmt.Sprintf("[Sender] Starting test -> Target: %s | Spoof: %s", req.TargetIP, req.SpoofIP))

	var wg sync.WaitGroup
	var remoteResp ListenResponse
	var remoteErr error
	remoteVerified := false

	if req.RemoteToken != "" {
		parts := strings.SplitN(req.RemoteToken, "|", 2)
		if len(parts) != 2 {
			http.Error(w, "فرمت توکن نامعتبر است", http.StatusBadRequest)
			return
		}
		remoteAddr, remoteSecret := parts[0], parts[1]
		remoteVerified = true

		addLiveLog(fmt.Sprintf("[Sender] Contacting remote server at %s to activate listener...", remoteAddr))
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, _ := json.Marshal(ListenRequest{
				ExpectedSourceIP: req.SpoofIP,
				DurationSec:      4,
			})
			httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://%s/api/listen", remoteAddr), bytes.NewBuffer(payload))
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

			if resp.StatusCode != http.StatusOK {
				bodyBytes, _ := io.ReadAll(resp.Body)
				remoteErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
				return
			}
			json.NewDecoder(resp.Body).Decode(&remoteResp)
		}()

		time.Sleep(400 * time.Millisecond)
	}

	ruleArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "icmp", "-j", "SNAT", "--to-source", req.SpoofIP}
	addLiveLog(fmt.Sprintf("[Sender] Applying iptables SNAT rule for %s...", req.SpoofIP))
	if out, err := exec.Command("iptables", ruleArgs...).CombinedOutput(); err != nil {
		addLiveLog(fmt.Sprintf("[-] iptables error: %v", err))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TestResponse{Log: logBuilder.String(), LocalSuccess: false})
		return
	}

	defer func() {
		delArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-p", "icmp", "-j", "SNAT", "--to-source", req.SpoofIP}
		exec.Command("iptables", delArgs...).Run()
	}()

	addLiveLog(fmt.Sprintf("[Sender] Sending 3 ICMP pings to %s...", req.TargetIP))
	pingOut, _ := exec.Command("ping", "-c", "3", "-i", "0.5", "-W", "1", req.TargetIP).CombinedOutput()
	addLiveLog(string(pingOut))

	statOut, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "-x").CombinedOutput()
	statStr := string(statOut)

	localSuccess := false
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

	if remoteVerified {
		wg.Wait()
		if remoteErr != nil {
			addLiveLog(fmt.Sprintf("[-] Remote verification failed: %v", remoteErr))
			remoteVerified = false
		} else {
			addLiveLog("[Sender] Remote verification report received successfully.")
		}
	}

	addLiveLog("[Sender] Test finished. Cleaning up iptables rule.")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TestResponse{
		Log:            logBuilder.String(),
		LocalSuccess:   localSuccess,
		RemoteVerified: remoteVerified,
		RemoteReceived: remoteResp.ReceivedCount,
	})
}

func main() {
	serverIP = getOutboundIP()
	authToken = generateToken()
	connectionCode := fmt.Sprintf("%s:%s|%s", serverIP, port, authToken)

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/test", handleTest)
	http.HandleFunc("/api/listen", handleListen)
	http.HandleFunc("/api/logs", handleLogs)
	http.HandleFunc("/api/ping-remote", handlePingRemote)

	addLiveLog("Server started successfully.")

	fmt.Println("==================================================")
	fmt.Printf("🚀 Two-Way Spoof Analyzer is running!\n")
	fmt.Printf("🌐 Web UI Address   : http://%s:%s\n", serverIP, port)
	fmt.Printf("🔑 Connection Token : %s\n", connectionCode)
	fmt.Println("==================================================")

	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		fmt.Printf("[-] Server error: %v\n", err)
	}
}
