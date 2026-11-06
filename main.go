package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type TestRequest struct {
	TargetIP string `json:"target_ip"`
	SpoofIP  string `json:"spoof_ip"`
}

type TestResponse struct {
	Log     string `json:"log"`
	Success bool   `json:"success"`
}

type PageData struct {
	ServerIP string
	Iface    string
}

const htmlPage = `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ابزار تحلیل سریع IP Spoofing (Go Native)</title>
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: monospace; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background: #1e293b; padding: 20px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        h1 { text-align: center; color: #38bdf8; font-size: 22px; margin-bottom: 5px; }
        .server-info { text-align: center; color: #94a3b8; font-size: 13px; margin-bottom: 20px; }
        .server-info span { color: #38bdf8; font-weight: bold; }
        .section { margin-bottom: 20px; padding: 15px; background: #0f172a; border-radius: 8px; border: 1px solid #334155; }
        label { display: block; margin-bottom: 5px; color: #94a3b8; }
        input, select { width: 100%; padding: 10px; margin-bottom: 10px; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 6px; box-sizing: border-box; }
        button { background: #0284c7; color: white; border: none; padding: 12px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; transition: 0.2s; }
        button:hover { background: #0ea5e9; }
        button:disabled { background: #475569; cursor: not-allowed; }
        .status-box { padding: 12px; border-radius: 6px; text-align: center; font-weight: bold; margin-top: 10px; }
        .success { background: #14532d; color: #4ade80; border: 1px solid #166534; }
        .failure { background: #7f1d1d; color: #f87171; border: 1px solid #991b1b; }
        #terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; height: 280px; overflow-y: scroll; font-size: 13px; border: 1px solid #334155; white-space: pre-wrap; direction: ltr; text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ابزار تحلیل سریع IP Spoofing (مبتنی بر Go)</h1>
        <div class="server-info">
            آدرس سرور: <span>{{.ServerIP}}</span> | اینترفیس پیش‌فرض: <span>{{.Iface}}</span>
        </div>
        <div class="section">
            <label>IP مقصد (Target IP):</label>
            <input type="text" id="target_ip" placeholder="مثال: 198.55.102.149">
            
            <label>IP جعلی (Spoof IP):</label>
            <input type="text" id="spoof_ip" value="8.8.8.8">
            
            <label>پیشنهادهای سریع:</label>
            <select onchange="document.getElementById('spoof_ip').value=this.value;">
                <option value="8.8.8.8">Google DNS (8.8.8.8)</option>
                <option value="1.1.1.1">Cloudflare (1.1.1.1)</option>
                <option value="31.56.48.200">IP داخلی رنج خودی (31.56.48.200)</option>
            </select>

            <button id="run_btn" onclick="runTest()">شروع تست آنی</button>
            <div id="status_result"></div>
        </div>
        <div class="section">
            <h3>لاگ زنده ترمینال (محیط شبیه PuTTY)</h3>
            <div id="terminal">Ready...</div>
        </div>
    </div>
    <script>
        function runTest() {
            let target = document.getElementById('target_ip').value.trim();
            let spoof = document.getElementById('spoof_ip').value.trim();
            if(!target) { alert('لطفا IP مقصد را وارد کنید'); return; }
            
            let btn = document.getElementById('run_btn');
            let term = document.getElementById('terminal');
            let resBox = document.getElementById('status_result');
            
            btn.disabled = true;
            btn.innerText = "در حال اجرای تست...";
            resBox.className = "";
            resBox.innerText = "";
            term.innerText = "[+] Starting OS command execution...\n";
            
            fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_ip: target, spoof_ip: spoof})
            })
            .then(async res => {
                if (!res.ok) {
                    throw new Error(await res.text());
                }
                return res.json();
            })
            .then(data => {
                term.innerText += data.log + "\n";
                term.scrollTop = term.scrollHeight;
                if(data.success) {
                    resBox.className = "status-box success";
                    resBox.innerText = "نتیجه: پکت اسپوف‌شده با موفقیت در لایه SNAT پردازش و ارسال شد.";
                } else {
                    resBox.className = "status-box failure";
                    resBox.innerText = "نتیجه: اسپوف مسدود شد یا پکتی از قوانین عبور نکرد.";
                }
            })
            .catch(err => {
                term.innerText += "[-] Error: " + err.message + "\n";
                resBox.className = "status-box failure";
                resBox.innerText = "خطا در اجرای درخواست: " + err.message;
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerText = "شروع تست آنی";
            });
        }
    </script>
</body>
</html>
`

var tmpl = template.Must(template.New("index").Parse(htmlPage))

// getOutboundIP gets the primary outbound IP of this machine
func getOutboundIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}

	// Fallback: check public IP via HTTP if UDP dial fails
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		ServerIP: getOutboundIP(),
		Iface:    getDefaultInterface(),
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
		http.Error(w, "فرمت درخواست نامعتبر است", http.StatusBadRequest)
		return
	}

	req.TargetIP = strings.TrimSpace(req.TargetIP)
	req.SpoofIP = strings.TrimSpace(req.SpoofIP)

	// Validate IPs to prevent command injection
	if !isValidIPv4(req.TargetIP) || !isValidIPv4(req.SpoofIP) {
		http.Error(w, "آدرس IP وارد شده معتبر نیست (فقط IPv4 مجاز است)", http.StatusBadRequest)
		return
	}

	var logBuilder strings.Builder
	iface := getDefaultInterface()
	logBuilder.WriteString(fmt.Sprintf("[+] Detected Network Interface: %s\n", iface))

	// Add specific iptables SNAT rule (without flushing existing rules)
	ruleArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-j", "SNAT", "--to-source", req.SpoofIP}
	logBuilder.WriteString(fmt.Sprintf("[+] Adding Rule: iptables %s\n", strings.Join(ruleArgs, " ")))
	if out, err := exec.Command("iptables", ruleArgs...).CombinedOutput(); err != nil {
		logBuilder.WriteString(fmt.Sprintf("[-] Failed to add iptables rule: %v\n%s\n", err, string(out)))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TestResponse{Log: logBuilder.String(), Success: false})
		return
	}

	// Ensure rule is deleted even if something panics
	defer func() {
		delArgs := []string{"-t", "nat", "-D", "POSTROUTING", "-o", iface, "-d", req.TargetIP, "-j", "SNAT", "--to-source", req.SpoofIP}
		exec.Command("iptables", delArgs...).Run()
	}()

	// Send 3 pings with a 1-second timeout per ping
	logBuilder.WriteString(fmt.Sprintf("[+] Sending 3 ICMP echo requests to %s (Spoofed as %s)...\n", req.TargetIP, req.SpoofIP))
	pingOut, _ := exec.Command("ping", "-c", "3", "-W", "1", req.TargetIP).CombinedOutput()
	logBuilder.WriteString(string(pingOut))

	// Check iptables counters
	logBuilder.WriteString("\n--- iptables POSTROUTING Counters ---\n")
	statOut, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "-x").CombinedOutput()
	statStr := string(statOut)
	logBuilder.WriteString(statStr)

	// Verify if packets hit the SNAT rule (packets > 0 for our target/spoof rule)
	success := false
	if err == nil {
		for _, line := range strings.Split(statStr, "\n") {
			if strings.Contains(line, req.TargetIP) && strings.Contains(line, "to:"+req.SpoofIP) {
				fields := strings.Fields(line)
				if len(fields) > 0 && fields[0] != "0" {
					success = true
					break
				}
			}
		}
	}

	logBuilder.WriteString("\n[+] Removed temporary SNAT rule.")

	resp := TestResponse{
		Log:     logBuilder.String(),
		Success: success,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	port := "5000"
	serverIP := getOutboundIP()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/test", handleTest)

	fmt.Println("==================================================")
	fmt.Printf("🚀 Server is running!\n")
	fmt.Printf("🌐 Web UI Address : http://%s:%s\n", serverIP, port)
	fmt.Printf("🏠 Local Address  : http://127.0.0.1:%s\n", port)
	fmt.Println("==================================================")

	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		fmt.Printf("[-] Server error: %v\n", err)
	}
}
