<div align="center">

<img src="https://capsule-render.vercel.app/api?type=venom&color=0:0d1117,50:1a1400,100:0d1117&height=160&section=header&text=XSSSlayer&fontSize=60&fontColor=e3b341&fontAlignY=60&desc=The%20Ultimate%20XSS%20Hunter&descSize=13&descAlignY=78&descColor=484f58&animation=fadeIn" width="100%"/>

</div>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-161b22?style=flat-square&logo=python&logoColor=e3b341)
![Playwright](https://img.shields.io/badge/Playwright-Chromium-161b22?style=flat-square&logo=playwright&logoColor=e3b341)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-161b22?style=flat-square&logo=linux&logoColor=e3b341)
![License](https://img.shields.io/badge/License-MIT-161b22?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0.0-161b22?style=flat-square)

</div>

<br/>

XSSSlayer is a real-browser XSS scanner built on Python asyncio and Microsoft Playwright. Unlike regex-based or proxy-based tools, it executes JavaScript inside a full Chromium instance — every finding is confirmed by a real `alert()` / `confirm()` / `prompt()` dialog caught by the browser's native event system, not by string matching. Zero false positives by design.

<br/>

---

## Why XSSSlayer

Most XSS scanners work by injecting payloads and checking if the string appears in the response. XSSSlayer actually runs the payload in a browser and waits for the dialog to fire. If it doesn't execute, it doesn't count. This eliminates false positives entirely and catches DOM-based XSS that proxy-based tools miss completely.

<br/>

---

## Detection Engine

```
Target URL
    │
    ├── BFS Crawler          same-origin, configurable page limit
    │       └── Form / Input Discovery
    │               └── Parameter Mining    hidden inputs, JS hints, JSON body
    │
    ├── Context Analysis     Batch fuzz probe → 12 injection contexts
    │       └── Allowed / Blocked char detection
    │
    ├── Payload Selection
    │       ├── 15 Universal Polyglots
    │       ├── Context-Specific Escapes   HTML_BODY, ATTR_DQ/SQ, SCRIPT_STRING, COMMENT, STYLE...
    │       ├── AI Heuristic               novel payloads generated from fuzz results
    │       └── 100+ WAF Bypass Encodings  base64, hex, unicode, comment junk, case randomizer
    │
    └── Real Browser Execution (Playwright Chromium)
            ├── page.on("dialog")    → XSS Confirmed
            ├── MutationObserver     → DOM XSS Confirmed
            └── HTML Report + Screenshot (optional)
```

<br/>

---

## Features

| Category | Capabilities |
|---|---|
| **Detection** | Dialog-confirmed XSS (0 false positives), DOM XSS via MutationObserver, URL fragment SPA testing |
| **Context Analysis** | 12 injection contexts: HTML\_BODY, ATTR\_DQ/SQ/BARE, SCRIPT\_STRING, COMMENT, STYLE, and more |
| **Fuzzing** | 22-char batch probe, allowed/blocked char analysis, context-escape prefix generation |
| **AI Heuristic** | Generates novel payloads on-the-fly based on char allowlist from fuzz results |
| **WAF Bypass** | UA rotation, X-Forwarded-For spoofing, 403/429 backoff, double URL encode, base64 `eval(atob())`, hex `\xNN`, unicode `\uNNNN`, comment junk, case randomizer |
| **Stealth** | Playwright fingerprint masking: `navigator.webdriver`, WebGL, plugins, screen dimensions |
| **Auto-Discovery** | Form/input discovery, parameter mining, BFS same-origin crawler |
| **Blind / OOB** | `--xss-report` injects callback URLs for out-of-band detection |
| **Output** | Dark-theme HTML report with risk levels, screenshots, payload detail |
| **Auth Support** | `--cookie` for authenticated panel testing |
| **Proxy** | `--proxy` for Burp Suite integration |

<br/>

---

## Installation

### Kali Linux (One-Shot)

```bash
git clone https://github.com/alisalive/XSSSlayer.git
cd XSSSlayer
chmod +x setup_kali.sh && ./setup_kali.sh
source venv/bin/activate
```

### Windows

```bash
git clone https://github.com/alisalive/XSSSlayer.git
cd XSSSlayer
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium
```

<br/>

---

## Usage

```bash
# Fast single-target scan
python xss_slayer.py -u "https://target.com/" --max-pages 1

# Full God Mode — maximum coverage
python xss_slayer.py -u "https://target.com" \
    --cookie "session=YOUR_TOKEN" \
    --xss-report YOUR_CALLBACK_ID \
    --show-browser --screenshot \
    --proxy http://127.0.0.1:8080 \
    --max-pages 60 --timeout 20 \
    --jitter 0.5 2.0 \
    --concurrency 25 \
    -o results.json

# Stealth Mode — low and slow
python xss_slayer.py -u "https://target.com" \
    --concurrency 3 \
    --jitter 1.5 4.0 \
    --timeout 30

# Authenticated panel scan
python xss_slayer.py -u "https://target.com/admin/users?id=1" \
    -p id \
    --cookie "session=abc123; csrf_token=xyz" \
    --screenshot
```

### Flag Reference

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | Required | Target URL |
| `-p`, `--param` | Auto | Parameter to inject. Omit for full auto-discovery |
| `-c`, `--concurrency` | 20 | Max parallel browser tabs |
| `--timeout` | 15 | Navigation timeout in seconds |
| `--jitter MIN MAX` | 0.5 2.0 | Random delay range between requests |
| `--max-pages` | 30 | Max pages to crawl |
| `--proxy` | None | HTTP proxy (e.g. Burp Suite) |
| `--cookie` | None | Session cookies |
| `--xss-report` | None | Blind/OOB XSS callback ID |
| `--screenshot` | Off | Save PNG screenshots of confirmed XSS |
| `--show-browser` | Off | Open visible browser on XSS confirmation |
| `-o`, `--output` | None | Save JSON results to file |

<br/>

---

## Output

- **Terminal** — Rich-colored live feed with context detection, WAF status, hit alerts
- **HTML Report** — `results/report_YYYYMMDD_HHMMSS.html` — dark-theme, risk levels, payload detail, screenshot thumbnails
- **JSON** — `-o output.json` for pipeline integration

<br/>

---

## Legal

> For authorized penetration testing and security research only.
> Always obtain explicit written permission before scanning any target.
> The author assumes no liability for misuse.

<br/>

---

<div align="center">

Built by **[alisalive](https://github.com/alisalive)**

</div>
