

# SSTATS: Deep Packet Analyzer

## Overview
SSTATS is a lightweight, asynchronous deep packet inspection (DPI) and network threat analysis tool. Built for bare-metal performance and real-time monitoring, it captures network traffic at the interface level, performs heuristic state-tracking for threat detection, and queues application-layer payloads for semantic analysis using a local Large Language Model (LLM).

## Features
* Protocol Classification: Real-time volumetric tracking for IP, TCP, UDP, HTTP, FTP, SMTP, SSH, and Telnet.
* Threat Detection Engine:
  * Identifies Nmap stealth (SYN) port scans through stateful connection tracking.
  * Alerts on unauthorized connection attempts to sensitive ports (21, 22, 23) via IP whitelisting.
* Asynchronous AI Triage: Offloads unencrypted Layer 7 payloads (HTTP, Telnet) to a local Ollama instance (DeepSeek-R1) via a non-blocking queue for zero-day malicious intent analysis.
* Live Dashboard: A dark-themed, terminal-inspired web interface served via Flask, updating in real-time without page reloads.

## Architecture
The architecture separates the packet capture engine from the analysis and visualization layers to prevent OS buffer overflows and dropped packets during high-volume traffic:
1. Scapy Sniffer: Runs in a dedicated background thread, parsing OSI Layer 2-4 headers at wire-speed.
2. LLM Worker: An asynchronous queue consumes interesting L7 payloads and queries the local LLM, preventing inference latency from blocking the main capture thread.
3. Flask Backend: Serves a lightweight REST API mapping the global state to the frontend.

## Prerequisites
* Linux environment (e.g., Arch Linux) with root access for raw socket binding.
* Python 3.x
* Scapy, Flask, Requests
* Local Ollama instance running the `deepseek-r1` model.

## Installation
1. Clone the repository:
   git clone https://github.com/noisyboy/sstats.git
   cd sstats

2. Install the required Python dependencies:
   pip install scapy flask requests

3. Ensure Ollama is running locally:
   systemctl start ollama
   ollama run deepseek-r1

## Usage
1. Configure your environment variables or edit `app.py` to set your target network interface and trusted IP whitelist.
2. Execute the application with elevated privileges to allow promiscuous mode and raw socket access:
   sudo python app.py
3. Open a web browser and navigate to the dashboard:
   http://127.0.0.1:5000

## Author
noisyboy

## License
MIT License
