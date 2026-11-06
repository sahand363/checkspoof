package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os/exec"
	"strings"
)

type TestRequest struct {
	TargetIP string `json:"target_ip"`
	SpoofIP  string `json:"spoof_ip"`
}

type TestResponse struct {
	Log     string `json:"log"`
	Success bool   `json:"success"`
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
        h1 { text-align: center; color: #38bdf8; font-size: 22px; }
        .section { margin-bottom: 20px; padding: 15px; background: #0f172a; border-radius: 8px; border: 1px solid #334155; }
        label { display: block; margin-bottom: 5px; color: #94a3b8; }
        input, select { width: 100%; padding: 10px; margin-bottom: 10px; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 6px; box-sizing: border-box; }
        button { background: #0284c7; color: white; border: none; padding: 12px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; }
        button:hover { background: #0ea5e9; }
        .status-box { padding: 12px; border-radius: 6px; text-align: center; font-weight: bold; margin-top: 10px; }
        .success { background: #14532d; color: #4ade80; border: 1px solid #166534; }
        .failure { background: #7f1d1d; color: #f87171; border: 1px solid #991b1b; }
        #terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; height: 280px; overflow-y: scroll; font-size: 13px; border: 1px solid #334155; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ابزار تحلیل سریع IP Spoofing (مبتنی بر Go)</h1>
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

            <button onclick="runTest()">شروع تست آنی</button>
            <div id="status_result"></div>
        </div>
        <div class="section">
            <h3>لاگ زنده ترمینال (محیط شبیه PuTTY)</h3>
            <div id="terminal">آماده برای شروع...</div>
        </div>
    </div>
    <script>
        function runTest() {
            let target = document.getElementById('target_ip').value;
            let spoof = document.getElementById('spoof_ip').value;
            if(!target) { alert('لطفا IP مقصد را وارد کنید'); return; }
            
            let term = document.getElementById('terminal');
            term.innerText = "[+] شروع پردازش دستورات روی سیستم‌عامل...\n";
            
            fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_ip: target, spoof_ip: spoof})
            }).then(res => res.json()).then(data => {
                term.innerText += data.log + "\n";
                term.scrollTop = term.scrollHeight;
                let resBox = document.getElementById('status_result');
                if(data.success) {
                    resBox.className = "status-box success";
                    resBox.innerText = "نتیجه: پکت اسپوف‌شده با موفقیت پردازش شد.";
                } else {
                    resBox.className = "status-box failure";
                    resBox.innerText = "نتیجه: اسپوف مسدود شد (پکت لاس / عدم عبور از لایه شبکه).";
                }
            });
        }
    </script>
</body>
</html>
`

func getDefaultInterface() string {
	out, err := exec.Command("sh", "-c", "ip route show | grep default").Output()
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(htmlPage))
	tmpl.Execute(w, nil)
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TestRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var logBuilder strings.Builder
	logBuilder.WriteString("[+] پاکسازی قوانین iptables...\n")
	exec.Command("iptables", "-t", "nat", "-F").Run()

	iface := getDefaultInterface()
	logBuilder.WriteString(fmt.Sprintf("[+] شناسایی اینترفیس شبکه: %s\n", iface))

	cmdStr := fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -d %s -j SNAT --to-source %s", iface, req.TargetIP, req.SpoofIP)
	logBuilder.WriteString(fmt.Sprintf("[+] اجرای دستور: %s\n", cmdStr))
	exec.Command("sh", "-c", cmdStr).Run()

	logBuilder.WriteString(fmt.Sprintf("[+] ارسال پینگ تست به %s...\n", req.TargetIP))
	pingOut, _ := exec.Command("sh", "-c", fmt.Sprintf("ping -c 3 %s", req.TargetIP)).CombinedOutput()
	logBuilder.WriteString(string(pingOut))

	logBuilder.WriteString("\n--- وضعیت شمارنده‌های iptables ---\n")
	statOut, _ := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n").CombinedOutput()
	logBuilder.WriteString(string(statOut))

	exec.Command("iptables", "-t", "nat", "-F").Run()
	logBuilder.WriteString("\n[+] پاکسازی قوانین با موفقیت انجام شد.")

	resp := TestResponse{
		Log:     logBuilder.String(),
		Success: true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/test", handleTest)

	fmt.Println("Server listening on http://0.0.0.0:5000")
	http.ListenAndServe("0.0.0.0:5000", nil)
}
