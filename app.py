'''
MIT License

Copyright (c) 2026 Noisyboy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

import threading
import queue
import requests
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw
from flask import Flask, render_template, jsonify

# --- System State ---
app = Flask(__name__)

# Expanded counters dictionary
counters = {
    "IP": 0, "TCP": 0, "UDP": 0, 
    "HTTP": 0, "FTP": 0, "SMTP": 0, 
    "SSH": 0, "Telnet": 0
}

logs = []  
MAX_LOGS = 50  

# Threat logic state
syn_scan_tracker = {}
SCAN_THRESHOLD = 20
WHITELISTED_IPS = {"127.0.0.1"} 
SENSITIVE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet"}

# AI integration
llm_analysis_queue = queue.Queue()
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "deepseek-r1"

def add_log(message, log_type="alert"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    logs.append({"timestamp": timestamp, "message": message, "type": log_type})
    if len(logs) > MAX_LOGS:
        logs.pop(0)

# --- Background Threads ---
def llm_worker():
    while True:
        packet_info, payload = llm_analysis_queue.get() 
        prompt = f"Analyze the following network payload for malicious intent. Output only 'SAFE' or 'MALICIOUS: [Reason]'. Payload: {payload}"
        try:
            response = requests.post(OLLAMA_ENDPOINT, json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            })
            result = response.json().get("response", "").strip()
            if "MALICIOUS" in result.upper():
                add_log(f"AI DETECTION ({packet_info['src_ip']}:{packet_info['dst_port']}) -> {result}", "ai")
        except Exception:
            pass
        llm_analysis_queue.task_done()

def analyze_packet(packet):
    if packet.haslayer(IP):
        counters["IP"] += 1
        src_ip = packet[IP].src
        
        if packet.haslayer(TCP):
            counters["TCP"] += 1
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport
            tcp_flags = packet[TCP].flags
            
            # --- Threat Checks ---
            if dst_port in SENSITIVE_PORTS and tcp_flags == 'S' and src_ip not in WHITELISTED_IPS:
                add_log(f"Unauthorized {SENSITIVE_PORTS[dst_port]} attempt from {src_ip}", "alert")

            if tcp_flags == 'S':
                if src_ip not in syn_scan_tracker:
                    syn_scan_tracker[src_ip] = set()
                syn_scan_tracker[src_ip].add(dst_port)
                if len(syn_scan_tracker[src_ip]) > SCAN_THRESHOLD:
                    add_log(f"SYN Port Scan detected from {src_ip}", "alert")
            
            # --- Hybrid Protocol Counting ---
            
            # 1. Port-Based Volumetric Counting for Encrypted/Stream/Standard Protocols
            if dst_port == 22 or src_port == 22:
                counters["SSH"] += 1
            elif dst_port == 23 or src_port == 23:
                counters["Telnet"] += 1
            elif dst_port == 21 or src_port == 21 or dst_port == 20 or src_port == 20:
                # Catches FTP Control (21) and Active Data (20) traffic
                counters["FTP"] += 1

            # 2. Payload-Based Counting & AI Inspection
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                
                # HTTP Payload parsing
                if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                    counters["HTTP"] += 1
                    packet_info = {"src_ip": src_ip, "dst_port": dst_port}
                    llm_analysis_queue.put((packet_info, payload.decode('utf-8', errors='ignore')))
                
                # SMTP Payload parsing
                elif payload.startswith(b"HELO ") or payload.startswith(b"EHLO "):
                    counters["SMTP"] += 1
                
                # Telnet AI Queuing
                elif dst_port == 23 or src_port == 23:
                    packet_info = {"src_ip": src_ip, "dst_port": dst_port}
                    llm_analysis_queue.put((packet_info, payload.decode('utf-8', errors='ignore')))

        elif packet.haslayer(UDP):
            counters["UDP"] += 1

def start_sniffer():
    sniff(prn=analyze_packet, store=False)

# --- Web Server Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def api_data():
    return jsonify({
        "counters": counters,
        "queue_size": llm_analysis_queue.qsize(),
        "logs": list(reversed(logs)) 
    })

if __name__ == "__main__":
    threading.Thread(target=llm_worker, daemon=True).start()
    threading.Thread(target=start_sniffer, daemon=True).start()
    
    print("Dashboard live at http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
