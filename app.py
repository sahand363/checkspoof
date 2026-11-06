from flask import Flask, render_template_string, request, jsonify
import subprocess
import threading
import queue
import time
import os

app = Flask(__name__)

# صف برای ارسال لاگ‌ها به ترمینال وب (شبیه‌ساز PuTTY)
log_queue = queue.Queue()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ابزار تحلیل و بررسی IP Spoofing</title>
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: monospace; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: auto; background: #1e293b; padding: 20px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        h1 { text-align: center; color: #38bdf8; font-size: 24px; }
        .section { margin-bottom: 20px; padding: 15px; background: #0f172a; border-radius: 8px; border: 1px solid #334155; }
        label { display: block; margin-bottom: 5px; color: #94a3b8; }
        input, select { width: 100%; padding: 10px; margin-bottom: 10px; background: #1e293b; border: 1px solid #475569; color: #fff; border-radius: 6px; box-sizing: border-box; }
        button { background: #0284c7; color: white; border: none; padding: 10px 20px; font-size: 16px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; }
        button:hover { background: #0ea5e9; }
        .status-box { padding: 10px; border-radius: 6px; text-align: center; font-weight: bold; margin-top: 10px; }
        .success { background: #14532d; color: #4ade80; border: 1px solid #166534; }
        .failure { background: #7f1d1d; color: #f87171; border: 1px solid #991b1b; }
        #terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; height: 300px; overflow-y: scroll; font-size: 13px; border: 1px solid #334155; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ابزار پیشرفته بررسی و تحلیل IP Spoofing</h1>
        
        <div class="section">
            <h3>تنظیمات تست</h3>
            <label>آدرس IP مقصد (Target IP):</label>
            <input type="text" id="target_ip" placeholder="مثال: 198.55.102.149">
            
            <label>آدرس IP جعلی (Spoof IP):</label>
            <input type="text" id="spoof_ip" value="8.8.8.8" placeholder="مثال: 8.8.8.8 یا 1.1.1.1">
            
            <label>پیشنهادهای سریع IP:</label>
            <select id="preset_ips" onchange="document.getElementById('spoof_ip').value=this.value;">
                <option value="8.8.8.8">Google DNS (8.8.8.8)</option>
                <option value="1.1.1.1">Cloudflare (1.1.1.1)</option>
                <option value="31.56.48.200">IP داخلی رنج خودی (31.56.48.200)</option>
                <option value="192.168.1.100">IP محلی ساختگی (192.168.1.100)</option>
            </select>

            <button onclick="startTest()">شروع تست اسپوف</button>
            <div id="status_result"></div>
        </div>

        <div class="section">
            <h3>شبیه‌ساز ترمینال (PuTTY Live Log)</h3>
            <div id="terminal">منتظر اجرای تست...</div>
        </div>
    </div>

    <script>
        function startTest() {
            let target = document.getElementById('target_ip').value;
            let spoof = document.getElementById('spoof_ip').value;
            if(!target) { alert('لطفا IP مقصد را وارد کنید'); return; }

            document.getElementById('terminal').innerText = "در حال ارسال دستورات به کرنل و تنظیم iptables...\\n";
            
            fetch('/run-test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_ip: target, spoof_ip: spoof})
            }).then(res => res.json()).then(data => {
                let resBox = document.getElementById('status_result');
                if(data.success) {
                    resBox.className = "status-box success";
                    resBox.innerText = "نتیجه: قابلیت اسپوف فعال است و پکت با موفقیت ارسال شد!";
                } else {
                    resBox.className = "status-box failure";
                    resBox.innerText = "نتیجه: اسپوف مسدود شد (دیتاسنتر یا uRPF اجازه نداد یا پکت لاس شد).";
                }
            });

            let evtSource = new EventSource("/stream-logs");
            evtSource.onmessage = function(event) {
                let term = document.getElementById('terminal');
                term.innerText += event.data + "\\n";
                term.scrollTop = term.scrollHeight;
                if(event.data.includes("TEST_FINISHED")) {
                    evtSource.close();
                }
            };
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/run-test', methods=['POST'])
def run_test():
    data = request.json
    target_ip = data.get('target_ip')
    spoof_ip = data.get('spoof_ip')
    
    def worker():
        try:
            log_queue.put(f"[+] پاکسازی قوانین قبلی iptables...")
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            
            log_queue.put(f"[+] اعمال قانون SNAT: تغییر مبدأ به {spoof_ip} برای مقصد {target_ip}")
            # پیدا کردن اینترفیس پیش‌فرض
            route_res = subprocess.run("ip route show | grep default", shell=True, capture_output=True, text=True)
            interface = "eth0"
            for word in route_res.stdout.split():
                if word == "dev":
                    # کلمه بعد از dev اینترفیس است
                    parts = route_res.stdout.split()
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        interface = parts[idx + 1]
                        break
            
            log_queue.put(f"[+] شناسایی اینترفیس شبکه: {interface}")
            
            cmd = f"iptables -t nat -A POSTROUTING -o {interface} -d {target_ip} -j SNAT --to-source {spoof_ip}"
            subprocess.run(cmd, shell=True, capture_output=True)
            
            log_queue.put(f"[+] ارسال پینگ تست به {target_ip} (تعداد 4 پکت)...")
            ping_proc = subprocess.run(f"ping -c 4 {target_ip}", shell=True, capture_output=True, text=True)
            log_queue.put(ping_proc.stdout)
            
            # بررسی شمارنده‌ها
            stat_proc = subprocess.run("iptables -t nat -L POSTROUTING -v -n", shell=True, capture_output=True, text=True)
            log_queue.put("--- وضعیت شمارنده‌های iptables ---")
            log_queue.put(stat_proc.stdout)
            
            # پاکسازی بعد از تست
            subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
            log_queue.put("[+] پاکسازی انجام شد. TEST_FINISHED")
        except Exception as e:
            log_queue.put(f"[-] خطا در اجرا: {str(e)}")
            log_queue.put("TEST_FINISHED")

    threading.Thread(target=worker).start()
    return jsonify({"status": "started"})

@app.route('/stream-logs')
def stream_logs():
    def generate():
        while True:
            try:
                msg = log_queue.get(timeout=1.0)
                yield f"data: {msg}\\n\\n"
                if "TEST_FINISHED" in msg:
                    break
            except queue.Empty:
                continue
    return app.response_class(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
