"""Static signals in extension code.

Nothing here is a verdict on its own. Plenty of honest extensions spawn
processes or talk to the network. The checks module decides what
combination of signals is worth reporting.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

# A signal is a regex plus a name. Patterns are deliberately literal-ish:
# minified code keeps string literals intact, which is where the tells are.
_SIGNALS = {
    "child_process": r"""require\(\s*["'](?:node:)?child_process["']\s*\)|from\s*["'](?:node:)?child_process["']""",
    "authorized_keys": r"authorized_keys",
    "ssh_private_key": r"\.ssh[/\\\\]+id_(?:rsa|ed25519|ecdsa|dsa)\b|[\"']id_(?:rsa|ed25519|ecdsa)[\"']",
    "reverse_tunnel": (r"""["'\s]-R["'\s,]+["']?\*?:?\d*:?(?:localhost|127\.0\.0\.1):22\b|\bautossh\b|"""
                       r"""["'`]\*:\d+:(?:localhost|127\.0\.0\.1):22["'`]"""),
    "ssh_no_hostcheck": r"StrictHostKeyChecking[=\s]*no|UserKnownHostsFile[=\s]*/dev/null",
    "launch_agent": r"Library/LaunchAgents|Library/LaunchDaemons|launchctl\s+(?:load|bootstrap)",
    "crontab": r"@reboot|crontab\s+-[l\-]|\|\s*crontab\b",
    "win_startup": r"""Start Menu[/\\\\]+Programs[/\\\\]+Startup|schtasks(?:\.exe)?\s+/create|CurrentVersion\\\\+Run\b""",
    "systemd_user": r"systemctl\s+--user\s+enable|\.config/systemd/user",
    "shell_rc": r"""\.(?:bashrc|zshrc|bash_profile|profile)["']""",
    "cred_files": (r"\.aws[/\\\\]+credentials|\.npmrc[\"']|\.pypirc|\.docker[/\\\\]+config\.json|"
                   r"\.kube[/\\\\]+config|\.git-credentials|\.netrc[\"']|gcloud[/\\\\]+credentials|"
                   r"application_default_credentials\.json|azure[/\\\\]+accessTokens"),
    "browser_data": r"Login Data|Local State[\"']|Cookies[\"'].{0,40}(?:Chrome|Chromium|Brave|Edge)|Default[/\\\\]+Cookies|key4\.db|logins\.json",
    "keychain": r"security\s+find-(?:generic|internet)-password|login\.keychain",
    "env_harvest": r"Object\.keys\(\s*process\.env\s*\)[\s\S]{0,160}?(?:/[^/\n]{0,40}(?:KEY|TOKEN|SECRET|PASS)[^/\n]{0,40}/|[\"'](?:KEY|TOKEN|SECRET|PASS)[\"'])",
    "env_dump": r"JSON\.stringify\(\s*process\.env\s*\)",
    "eval_decode": (r"eval\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\s*\(|"
                    r"(?:new\s+)?Function\(\s*(?:atob|Buffer\.from)\s*\(|"
                    r"eval\(\s*[\w$.]+\.toString\(\s*[\"'](?:base64|hex)?[\"']?\s*\)\s*\)|"
                    r"vm\.runInNewContext\(\s*(?:atob|Buffer\.from)"),
    "big_base64": r"[\"'][A-Za-z0-9+/]{3000,}={0,2}[\"']",
    "charcode_blob": r"String\.fromCharCode\((?:\s*\d{2,3}\s*,){40,}",
    "shell_pipe": r"(?:curl|wget)\s[^\"'\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\biex\s*\(|Invoke-Expression|powershell(?:\.exe)?\s+[^\"']{0,40}-(?:e|enc|encodedcommand)\s",
    "exfil_service": (r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/api|"
                      r"webhook\.site|\.ngrok(?:-free)?\.(?:io|app)|transfer\.sh|pipedream\.net|"
                      r"requestbin|interact\.sh|oast\.(?:pro|live|fun|site)|burpcollaborator"),
    "public_ip_ip": r"\b(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!169\.254\.)(?:\d{1,3}\.){3}\d{1,3}\b",
    "ip_lookup": r"ifconfig\.me|api\.ipify\.org|ipinfo\.io|icanhazip\.com|checkip\.amazonaws",
    "write_fn": r"(?:append|write)File(?:Sync)?\s*\(|createWriteStream\s*\(",
    "read_fn": r"readFile(?:Sync)?\s*\(|createReadStream\s*\(",
    "net_send": r"https?\.request\s*\(|fetch\s*\(|XMLHttpRequest|axios\.post|\.post\s*\(|net\.connect|new\s+WebSocket",
    "detached": r"detached\s*:\s*(?:!0|true)",
    "hidden_window": r"windowsHide\s*:\s*(?:!0|true)",
}
# Cheap substring checks: if none of these appear, the regex can't match,
# so it's skipped.
_HINTS = {
    "child_process": ("child_process",), "authorized_keys": ("authorized_keys",), "ssh_private_key": ("id_",),
    "reverse_tunnel": (":22", "autossh"), "ssh_no_hostcheck": ("stricthostkeychecking", "userknownhostsfile"),
    "launch_agent": ("launchagents", "launchdaemons", "launchctl"), "crontab": ("@reboot", "crontab"),
    "win_startup": ("startup", "schtasks", "currentversion"), "systemd_user": ("systemctl", "systemd/user"),
    "shell_rc": ("rc\"", "rc'", "profile"),
    "cred_files": (".aws", ".npmrc", ".pypirc", ".docker", ".kube", "git-credentials", ".netrc", "gcloud",
                   "application_default_credentials", "accesstokens"),
    "browser_data": ("login data", "local state", "cookies", "key4.db", "logins.json"),
    "keychain": ("security find-", "keychain"), "env_harvest": ("process.env",), "env_dump": ("process.env",),
    "eval_decode": ("eval(", "function(", "runinnewcontext"), "charcode_blob": ("fromcharcode",),
    "shell_pipe": ("curl", "wget", "iex", "invoke-expression", "powershell"),
    "exfil_service": ("discord", "telegram", "pastebin", "webhook.site", "ngrok", "transfer.sh", "pipedream",
                      "requestbin", "interact.sh", "oast.", "burpcollaborator"),
    "ip_lookup": ("ifconfig.me", "ipify", "ipinfo", "icanhazip", "checkip"),
}
_CASE_SENSITIVE = {"public_ip_ip", "env_harvest"}
SIGNALS = {k: re.compile(v, 0 if k in _CASE_SENSITIVE else re.I) for k, v in _SIGNALS.items()}

# Bundler headers. Anything significant before these was not put there by the bundler.
_BUNDLE_HEADERS = re.compile(
    r"var __create\s*=\s*Object\.create|var __defProp\s*=\s*Object\.defineProperty|"
    r"/\*{6}/|webpackBootstrap|__webpack_require__|__webpack_modules__|"
    r"\(\(\)\s*=>\s*\{\s*(?:[\"']use strict[\"'];?\s*)?var\s+\w+\s*=\s*\{\s*\d+\s*[:(]|"
    r"\(\s*function\s*\(\s*\)\s*\{\s*(?:[\"']use strict[\"'];?\s*)?var\s+\w+\s*=\s*\{\s*\d+\s*[:(]|"
    r"[\"']use strict[\"'];\s*var \w+\s*=\s*Object\.create|"
    r"System\.register\(|define\(\s*\[|Object\.defineProperty\(\s*exports\s*,\s*[\"']__esModule"
)
_PREFIX_NOISE = re.compile(r"\A(?:\s|#![^\n]*\n|/\*[\s\S]*?\*/|//[^\n]*\n|[\"']use strict[\"'];?)*")
_BUNDLER_MARKS = re.compile(r"__webpack_require__|__esModule|webpackBootstrap|__commonJS|__toESM|__defProp")
MAX_INJECTED = 150_000  # the Oct 2026 implant was ~5 KB; real bundles that start late are rare

@dataclass
class Hit:
    signal: str
    offset: int
    snippet: str


def _snip(text: str, start: int, end: int, pad: int = 30) -> str:
    s = text[max(0, start - pad): min(len(text), end + pad)]
    return " ".join(s.split())[:110]


def scan_text(text: str) -> Dict[str, List[Hit]]:
    out: Dict[str, List[Hit]] = {}
    lower = text.lower()
    for name, rx in SIGNALS.items():
        hints = _HINTS.get(name)
        if hints and not any(h in lower for h in hints):
            continue
        hits = []
        for m in rx.finditer(text):
            if name == "public_ip_ip" and not _plausible_ip(m.group(0), text, m.start()):
                continue
            hits.append(Hit(name, m.start(), _snip(text, m.start(), m.end())))
            if len(hits) >= 20:
                break
        if hits:
            out[name] = hits
    return out


def _plausible_ip(ip: str, text: str, pos: int) -> bool:
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts) or parts[0] in ("0", "255"):
        return False
    before = text[max(0, pos - 12):pos]
    after = text[pos + len(ip): pos + len(ip) + 3]
    # versions like 1.2.3.4 inside semver-ish strings, or part of a longer dotted number
    if re.search(r"[\d.]$", before) or after[:1] in (".",) or re.match(r"^\.\d", after):
        return False
    if re.search(r"version|ver[\"']?\s*[:=]|\bv$", before, re.I):
        return False
    # an IP used as a host: inside a URL, after host:/@, or quoted next to network words
    e = re.escape(ip)
    ctx = text[max(0, pos - 10): pos + len(ip) + 8]
    if re.search(r"https?://" + e + r"|host(?:name)?[\"']?\s*[:=]\s*[\"'`]?" + e + r"|@" + e + r"\b", text[max(0, pos - 20): pos + len(ip) + 2]):
        return True
    if not re.search(r"[\"'`]" + e + r"(?::\d+)?[\"'`/]", ctx):
        return False
    wide = text[max(0, pos - 80): pos + len(ip) + 80]
    if re.search(r"\b(?:oid|OID|RSA|Encryption|sha\d+|ecdsa|EdDSA|curve|x509|asn1|coerce|semver)\b", wide):
        return False
    return bool(re.search(r"\b(?:host|connect|request|socket|port|ssh|tcp|udp|server|endpoint|beacon|url)\b", wide, re.I))


def near(hits_a: List[Hit], hits_b: List[Hit], window: int = 400) -> Optional[Hit]:
    """First hit in a that has a hit from b within `window` characters."""
    for a in hits_a:
        for b in hits_b:
            if abs(a.offset - b.offset) <= window:
                return a
    return None


def injected_prefix(text: str) -> Optional[str]:
    """Code that sits in front of the bundler's own header.

    The October 2026 Claude Code extension backdoor was an IIFE pasted in
    front of an otherwise normal esbuild bundle, so it ran before activate().
    """
    lead = _PREFIX_NOISE.match(text)
    start = lead.end() if lead else 0
    first = _BUNDLE_HEADERS.match(text, start)
    if first:
        return None  # the file starts with the bundle itself
    m = _BUNDLE_HEADERS.search(text, start, start + MAX_INJECTED)
    if not m:
        return None
    code = text[start:m.start()]
    if len(code.strip()) < 40 or _BUNDLER_MARKS.search(code):
        return None
    if re.search(r"""require\(\s*["'](?:node:)?(?:child_process|fs|net|http|https|os|crypto)["']""", code):
        return code
    return None


def is_minified(text: str) -> bool:
    if len(text) < 20_000:
        return False
    lines = text.count("\n") + 1
    return len(text) / lines > 500
