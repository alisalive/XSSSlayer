```
██╗  ██╗███████╗███████╗    ███████╗██╗      █████╗ ██╗   ██╗███████╗██████╗
╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
 ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
██╔╝ ██╗███████║███████║    ███████║███████╗██║  ██║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

<p align="center">
  <strong>The Ultimate XSS Hunter — Context-Aware · AI Heuristic · DOM/SPA · Stealth · OOB</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/engine-Playwright%20Chromium-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" />
</p>

---

## What is XSSSlayer?

XSSSlayer is a **real-browser XSS scanner** built on Python asyncio and Microsoft Playwright. Unlike regex-based tools, XSSSlayer executes JavaScript inside a full Chromium instance — making it **zero false positives**.

Every finding is confirmed by a real `alert()` / `confirm()` / `prompt()` dialog caught by the browser's native event system. No guessing. No noise.

---

## Interface & Deep Analysis

| | | |
|--|--|--|
| ![Startup Screen](assets/start.jpeg) <br>*Clean CLI launch with target config — get scanning in seconds.* | ![Scanning in Progress](assets/scanning.jpeg) <br>*Live payload injection feed — context detection and WAF bypass in real time.* | ![Results Report](assets/results.jpeg) <br>*Dark-theme HTML report with confirmed XSS hits, risk levels and screenshots.* |

---

## Features

| Category | Capabilities |
|---|---|
| **Detection Engine** | Dialog-only XSS confirmation (0 false positives), DOM XSS via MutationObserver, URL fragment (`#`) SPA testing |
| **Context Analysis** | 12 injection contexts: `HTML_BODY`, `ATTR_DQ/SQ/BARE`, `SCRIPT_STRING`, `COMMENT`, `STYLE`, and more |
| **Fuzzing Engine** | 22-char batch probe, allowed/blocked char analysis, context-escape prefix generation |
| **AI Heuristic** | Generates novel payloads on-the-fly based on char allowlist from fuzz results |
| **WAF Bypass** | UA rotation, X-Forwarded-For spoofing, 403/429 backoff, double URL encode, base64 `eval(atob())`, hex `\xNN`, unicode `\uNNNN`, comment junk (`scr/**/ipt`), case randomizer (`OnErRoR`) |
| **Stealth** | Playwright fingerprint masking: `navigator.webdriver`, `hardwareConcurrency`, WebGL, plugins, chrome object, screen dimensions |
| **Auto-Discovery** | Form/input discovery, parameter mining (hidden inputs, JS hints, JSON body), BFS same-origin crawler |
| **Blind / OOB XSS** | `--xss-report` injects callback URLs for out-of-band detection |
| **Output** | Dark-theme HTML report with risk levels, screenshots, elapsed time, payload detail |
| **Session Support** | `--cookie` for authenticated panel testing |
| **Proxy Support** | `--proxy` for Burp Suite integration |

---

## Installation

### 🐧 Linux / Kali — One-Shot Setup

```bash
git clone https://github.com/alisalive/XSSSlayer.git
cd XSSSlayer
chmod +x setup_kali.sh
./setup_kali.sh
```

`setup_kali.sh` does everything automatically:

- Installs all system dependencies (smart package resolution for Kali 2024+, Ubuntu 24.04+, Debian 12+)
- Creates Python virtual environment
- Installs all Python packages
- Installs Playwright Chromium browser
- Registers `xssslayer` as a **global command** — works from any directory

> ⚠️ **If you already have XSSSlayer cloned**, just pull and re-run setup:
> ```bash
> cd XSSSlayer && git pull origin main && ./setup_kali.sh
> ```

**After setup — use from anywhere:**

```bash
xssslayer -u "https://target.com"
xssslayer --help
```

---

### 🪟 Windows — Setup

**Step 1 — Clone and install:**

```cmd
git clone https://github.com/alisalive/XSSSlayer.git
cd XSSSlayer
python -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\python -m playwright install chromium
venv\Scripts\pip install -e .
```

**Step 2 — Make `xssslayer` available from any directory (run once in CMD):**

```cmd
setx PATH "%PATH%;C:\Users\%USERNAME%\XSSSlayer"
```

> ⚠️ After running `setx`, **open a new CMD window** — the old one won't see the updated PATH.

The `xssslayer.bat` launcher included in the repo handles venv activation automatically — you never need to activate the venv manually.

**After setup — use from anywhere:**

```cmd
xssslayer -u "https://target.com"
xssslayer --help
```

---

## Usage

### Mode 1 — Auto-Discovery (Default)

Crawls the entire target, discovers all forms and parameters, scans everything automatically.

```bash
xssslayer -u "https://target.com"
```

### Mode 2 — Single Parameter (Fast)

Target a specific URL and parameter directly. No crawling — straight to injection.

```bash
xssslayer -u "https://target.com/search?q=x" -p q --max-pages 1
```

### Mode 3 — Full God Mode

Maximum coverage: crawler + screenshots + Burp proxy + OOB + visible PoC browser.

```bash
xssslayer -u "https://target.com" \
    --cookie "session=YOUR_TOKEN" \
    --xss-report YOUR_XSS_REPORT_ID \
    --show-browser --screenshot \
    --proxy http://127.0.0.1:8080 \
    --max-pages 60 --timeout 20 \
    --jitter 0.5 2.0 \
    --concurrency 25 \
    -o results.json
```

### Mode 4 — Stealth Mode

Low-and-slow with human-like delays to evade WAFs and rate limiters.

```bash
xssslayer -u "https://target.com" \
    --concurrency 3 \
    --jitter 1.5 4.0 \
    --timeout 30
```

### Mode 5 — Authenticated Panel Scan

Pass session cookies to scan protected pages and admin panels.

```bash
xssslayer -u "https://target.com/admin/users?id=1" \
    -p id \
    --cookie "session=abc123; csrf_token=xyz" \
    --screenshot
```

---

## Flag Reference

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | **Required** | Target URL |
| `-p`, `--param` | Auto | Parameter to inject. Omit for full auto-discovery |
| `-c`, `--concurrency` | `20` | Max parallel browser tabs |
| `--timeout` | `15` | Navigation timeout in seconds |
| `--jitter MIN MAX` | `0.3 1.5` | Random delay range between requests (seconds) |
| `--max-pages` | `30` | Max pages to crawl in auto-discovery mode |
| `--proxy` | None | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--cookie` | None | Session cookies (`"name=value; name2=value2"`) |
| `--xss-report` | None | Blind/OOB XSS callback ID |
| `--screenshot` | Off | Save PNG screenshots of confirmed XSS |
| `--show-browser` | Off | Open visible Chromium window on XSS confirmation |
| `--no-mine` | Off | Disable parameter mining |
| `-o`, `--output` | None | Save confirmed results to JSON file |

---

## How It Works

```
Target URL
    │
    ├─► Step 1: WAF Detection
    │       └─► Signature matching against headers & body
    │
    ├─► Step 2: BFS Crawler (same-origin, --max-pages)
    │       └─► Form / Input Discovery
    │               └─► Parameter Mining (hidden fields, JS hints, JSON body)
    │
    └─► Step 3: God Mode Scan
            ├─► Context Analysis (Batch Fuzz → 12 context types)
            │       └─► Allowed/Blocked char detection
            ├─► Payload Selection
            │       ├─► 15 Universal Polyglots
            │       ├─► Context-Specific Escapes
            │       ├─► AI Heuristic (on-the-fly from fuzz results)
            │       └─► 2769 payloads from file + WAF Bypass Encodings
            └─► Real Browser Execution (Playwright Chromium)
                    ├─► page.on("dialog") → XSS Confirmed ✓
                    ├─► MutationObserver  → DOM XSS Confirmed ✓
                    └─► HTML Report + Screenshot (optional)
```

---

## Output

**Terminal** — Rich-colored live feed with timestamps, context tags, WAF status, and confirmed hit alerts.

**HTML Report** — Auto-saved to `results/report_YYYYMMDD_HHMMSS.html`. Dark theme, risk badges, full payload detail, screenshot thumbnails.

**JSON** — Use `-o output.json` for pipeline integration or custom reporting.

---

## Requirements

| Dependency | Version |
|---|---|
| Python | 3.10+ |
| playwright | ≥ 1.51.0 |
| rich | ≥ 13.7.1 |
| aiohttp | ≥ 3.11.0 |
| beautifulsoup4 | ≥ 4.12.0 |
| Chromium | Auto-installed via `playwright install chromium` |

> ⚠️ **Python 3.13 users:** Playwright < 1.51.0 hangs on `new_page()` due to a Python 3.13 asyncio incompatibility. This repo requires `playwright>=1.51.0` which fixes it.

---

## Troubleshooting

### Tool hangs at "Step 1 — WAF Detection" on Kali/Linux

**Cause:** Playwright < 1.51.0 is incompatible with Python 3.13.

**Fix:**
```bash
cd XSSSlayer
source venv/bin/activate
pip install --upgrade playwright
python -m playwright install chromium
```

Verify versions:
```bash
python --version                  # must be 3.10+
python -m playwright --version    # must be 1.51.0+
```

---

### `xssslayer: command not found` after setup on Linux

**Fix — re-run setup** (it auto-creates `/usr/local/bin/xssslayer`):
```bash
./setup_kali.sh
```

**Or create the launcher manually:**
```bash
XSSSLAYER_DIR="$(pwd)"
sudo tee /usr/local/bin/xssslayer > /dev/null << EOF
#!/usr/bin/env bash
source "$XSSSLAYER_DIR/venv/bin/activate"
exec python "$XSSSLAYER_DIR/xss_slayer.py" "\$@"
EOF
sudo chmod +x /usr/local/bin/xssslayer
```

---

### `xssslayer` not recognized on Windows

**Cause:** XSSSlayer directory is not in your PATH.

**Fix — run once in CMD:**
```cmd
setx PATH "%PATH%;C:\Users\%USERNAME%\XSSSlayer"
```
Open a **new** CMD window after running this command.

---

### `libasound2` package not found (Kali 2024+ / Ubuntu 24.04+)

The package was renamed to `libasound2t64`. The `setup_kali.sh` handles this automatically. If needed manually:
```bash
sudo apt-get install libasound2t64
```

---

### `ModuleNotFoundError: No module named 'playwright'`

You ran `python xss_slayer.py` directly outside the venv. Use the global command instead:
```bash
xssslayer -u "https://target.com"
```
Or activate the venv first:
```bash
source venv/bin/activate
python xss_slayer.py -u "https://target.com"
```

---

### A system dependency failed to install

Run Playwright's built-in dependency installer:
```bash
sudo python -m playwright install-deps chromium
```

---

### Brave Browser repository warnings during `apt-get update`

Lines like `N: Skipping acquire of configured file ... brave-browser` are **harmless**. They come from a duplicate Brave repository entry and do not affect XSSSlayer.

---

### `TargetClosedError` spam after pressing Ctrl+C

**Normal behavior.** When you interrupt a scan with Ctrl+C, all concurrent browser tabs close simultaneously and each logs a `TargetClosedError`. The scan stopped cleanly — this is not a bug.

---

## Legal & Ethics

> **For authorized penetration testing and security research only.**
> Using this tool against systems without explicit written permission is illegal and unethical.
> The author assumes no liability for misuse. Always obtain proper authorization before scanning any target.

---

## Support

If XSSSlayer helped you find a bug bounty or level up your security research:

- ⭐ Star this repository
- 🐛 Open an issue for bugs or feature requests
- 🔗 Share it with the community

---

<p align="center">
  Developed by <strong>alisalive.exe</strong> &nbsp;|&nbsp; GitHub: <a href="https://github.com/alisalive">alisalive</a>
  <br><br>
  <strong>XSSSlayer v1.0.0 — The Ultimate XSS Hunter</strong>
</p>
