<div align="center">

```text
██╗  ██╗███████╗███████╗    ███████╗██╗      █████╗ ██╗   ██╗███████╗██████╗
╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
 ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
██╔╝ ██╗███████║███████║    ███████║███████╗██║  ██║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
The Ultimate High-Performance Asynchronous DOM-based XSS Discovery Engine
```

<p align="center">
<video src="https://github.com/alisalive/XSSSlayer/releases/download/v1.0.0/XSSSLAYERV1.0.0.mp4" width="100%" controls autoplay muted loop>
Your browser does not support the video tag.
</video>
</p>

</div>

## 🚀 Overview

XSSSlayer is a real-browser XSS scanner built on Python asyncio and Microsoft Playwright. Unlike static regex-based tools, XSSSlayer executes JavaScript inside a full Chromium instance — making it 100% accurate with zero false positives.

## 🔍 Interface & Deep Analysis

<p align="center">
<img src="assets/start.jpeg" width="32%" alt="Initial Reconnaissance" />
<img src="assets/scanning.jpeg" width="32%" alt="Real-time Payload Injection" />
<img src="assets/results.jpeg" width="32%" alt="Final Vulnerability Report" />
</p>

## ✨ Key Features

| Category | Capabilities |
|---|---|
| Detection Engine | Dialog-only XSS confirmation, DOM XSS via MutationObserver, URL fragment (#) SPA testing |
| Context Analysis | 12 injection contexts (HTML_BODY, ATTR_DQ/SQ/BARE, SCRIPT, STYLE, etc.) |
| AI Heuristic | Dynamic payload generation based on fuzzing results and character allowlists |
| WAF Bypass | UA rotation, X-Forwarded-For spoofing, double URL encode, base64 eval, hex/unicode escape |
| Stealth | Playwright fingerprint masking: navigator.webdriver, hardwareConcurrency, WebGL masking |

## 🛠️ Quick Start

### Linux / Kali (One-Shot Setup)

```bash
git clone https://github.com/alisalive/XSSSlayer.git
cd XSSSlayer
chmod +x setup_kali.sh
./setup_kali.sh
source venv/bin/activate
```

### Windows

```powershell
git clone https://github.com/alisalive/XSSSlayer.git
cd XSSSlayer
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium
```

## 📑 Power User Guide

### 💡 Common Usage Modes

**Mode 1: Single Target (Fast)**
```bash
python xss_slayer.py -u "https://target.com/search?q=test" --max-pages 1
```

**Mode 2: Full God Mode**
```bash
python xss_slayer.py -u "https://target.com" --cookie "session=TOKEN" --screenshot --show-browser
```

**Mode 3: Stealth Mode**
```bash
python xss_slayer.py -u "https://target.com" --concurrency 3 --jitter 1.5 4.0
```

### 🚩 Flag Reference

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | Required | Target URL |
| `-p`, `--param` | Auto | Parameter to inject (omit for full auto-discovery) |
| `-c`, `--concurrency` | 20 | Max parallel browser tabs |
| `--timeout` | 15 | Navigation timeout in seconds |
| `--cookie` | None | Session cookies ("name=value") |
| `--proxy` | None | HTTP proxy (e.g. http://127.0.0.1:8080) |
| `--screenshot` | Off | Save PNG of confirmed XSS |
| `-o`, `--output` | None | Save JSON results to file |

## 🧠 How It Works

1. **Recon:** BFS Crawler discovers forms, inputs, and hidden parameters.
2. **Context Analysis:** Batch fuzzing identifies 12 different injection contexts.
3. **Execution:** Playwright orchestrates Chromium tabs to test mutated payloads.
4. **Validation:** Confirms execution via native browser dialog interception (`alert()`, `confirm()`).

## ⚖️ Legal & Ethics

For authorized penetration testing and security research only. Using this tool against systems without explicit written permission is illegal and unethical.

---

Developed with ❤️ by alisalive
