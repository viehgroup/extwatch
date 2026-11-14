"""Look for what a malicious extension leaves behind on the machine.

Uninstalling a backdoored extension doesn't undo what it already did.
These checks look at the usual persistence spots for signs of an implant.
Read-only: nothing is changed or removed.
"""

import base64
import glob
import hashlib
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import time
from typing import Iterator, List, Optional

from .checks import HIGH, LOW, MEDIUM, Finding
from .data import known_bad

HIDDEN_SCRIPT = re.compile(r"(?:^|[\s/'\"])(?:~|/(?:Users|home)/[^/\s]+|\$HOME)?/?\.(?!local\b|nvm\b|cargo\b|bun\b|deno\b|pyenv\b|rbenv\b|volta\b|asdf\b|sdkman\b|orbstack\b|docker\b|npm\b)[\w.-]+/(?:\.[\w.-]+|[\w.-]+\.(?:sh|py|js|cmd|bat|ps1))\b")


def _home(*parts: str) -> str:
    return os.path.join(os.path.expanduser("~"), *parts)


def _finding(rule, sev, where, msg, fix="") -> Finding:
    return Finding(rule, sev, "this machine", where, msg, fix)


# ------------------------------------------------------------------ ssh keys

def ssh_fingerprint(line: str) -> Optional[str]:
    parts = line.split()
    for i, p in enumerate(parts):
        if p.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            try:
                raw = base64.b64decode(parts[i + 1], validate=True)
            except ValueError:
                return None
            digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            return "SHA256:" + digest
    return None


def check_authorized_keys(path: Optional[str] = None) -> Iterator[Finding]:
    path = path or _home(".ssh", "authorized_keys")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        mtime = os.path.getmtime(path)
    except OSError:
        return
    bad_fps = known_bad()["ssh_key_fingerprints"]
    bad_strings = [s for s in known_bad()["strings"] if s["context"] in ("ssh", "any")]
    flagged = False
    for n, line in enumerate(lines, 1):
        fp = ssh_fingerprint(line)
        if fp in bad_fps:
            flagged = True
            yield _finding("EW020", HIGH, path, f"key {n} is a known attacker key: {bad_fps[fp]} ({fp})",
                           "Remove this key, then follow the incident's remediation steps and rotate credentials.")
            continue
        for s in bad_strings:
            if s["value"] in line:
                flagged = True
                yield _finding("EW020", HIGH, path, f"key {n} carries the comment '{s['value']}': {s['name']}",
                               "Remove this key, then follow the incident's remediation steps and rotate credentials.")
    age_days = (time.time() - mtime) / 86400
    if lines and not flagged and age_days < 14:
        comments = ", ".join(sorted({ln.split()[-1] for ln in lines if len(ln.split()) >= 3})[:5]) or "no comments"
        yield _finding("EW021", LOW, path,
                       f"{len(lines)} authorized key(s), file changed {age_days:.0f} day(s) ago ({comments})",
                       "If you don't run an SSH server on purpose, check you recognise every key here.")


# ------------------------------------------------------------------ known files

def check_known_artifacts() -> Iterator[Finding]:
    tmp = os.environ.get("TMPDIR") or tempfile.gettempdir()
    for art in known_bad()["host_artifacts"]:
        if "path" in art:
            p = os.path.expanduser(art["path"])
            if os.path.exists(p):
                yield _finding("EW022", HIGH, p, f"known backdoor file present: {art['name']}",
                               "Treat this machine as compromised: isolate it and follow incident response.")
        elif "glob" in art:
            for p in glob.glob(art["glob"].replace("$TMP", tmp)):
                yield _finding("EW022", HIGH, p, f"known backdoor file present: {art['name']}",
                               "Treat this machine as compromised: isolate it and follow incident response.")


# ------------------------------------------------------------------ macOS

def check_launch_agents(directory: Optional[str] = None) -> Iterator[Finding]:
    directory = directory or _home("Library", "LaunchAgents")
    for path in sorted(glob.glob(os.path.join(directory, "*.plist"))):
        try:
            with open(path, "rb") as fh:
                data = plistlib.load(fh)
        except Exception:
            continue
        label = str(data.get("Label", ""))
        args = data.get("ProgramArguments") or ([data["Program"]] if data.get("Program") else [])
        cmd = " ".join(str(a) for a in args)
        name = os.path.basename(path)
        if label.startswith("com.apple.") or name.startswith("com.apple."):
            yield _finding("EW023", HIGH, path,
                           f"user LaunchAgent pretends to be Apple ('{label}') and runs: {cmd[:100]}",
                           "Apple doesn't install agents here. Unload it with launchctl and investigate.")
        elif re.search(r"(?:^|/)(?:ba|z)?sh$", str(args[0]) if args else "") and HIDDEN_SCRIPT.search(cmd):
            yield _finding("EW024", MEDIUM, path, f"LaunchAgent '{label}' runs a hidden script: {cmd[:100]}",
                           "Check what the script does and which app installed it.")


# ------------------------------------------------------------------ Linux

def _crontab() -> str:
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        return out.stdout if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def check_crontab(text: Optional[str] = None) -> Iterator[Finding]:
    text = _crontab() if text is None else text
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("@reboot") and (HIDDEN_SCRIPT.search(s) or re.search(r"\bssh\b.*-R\b|autossh", s)):
            yield _finding("EW025", HIGH, f"crontab line {n}", f"runs at boot: {s[:120]}",
                           "Remove the entry with 'crontab -e' if you didn't add it, then investigate.")


def check_systemd_user(directory: Optional[str] = None) -> Iterator[Finding]:
    directory = directory or _home(".config", "systemd", "user")
    for path in sorted(glob.glob(os.path.join(directory, "*.service"))):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = re.search(r"^ExecStart=(.+)$", text, re.M)
        if m and (HIDDEN_SCRIPT.search(m.group(1)) or re.search(r"\bssh\b.*-R\b|autossh", m.group(1))):
            yield _finding("EW025", MEDIUM, path, f"user service runs: {m.group(1)[:120]}",
                           "Check which app created this service.")


# ------------------------------------------------------------------ Windows

def check_windows_startup(directory: Optional[str] = None) -> Iterator[Finding]:
    appdata = os.environ.get("APPDATA")
    directory = directory or (os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
                              if appdata else None)
    if not directory or not os.path.isdir(directory):
        return
    for path in sorted(glob.glob(os.path.join(directory, "*"))):
        if path.lower().endswith((".cmd", ".bat", ".vbs", ".ps1", ".js")):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(4000)
            except OSError:
                text = ""
            sev = HIGH if re.search(r"\bssh\b.*-R\b|autossh|iex|Invoke-Expression|-enc\b", text, re.I) else LOW
            yield _finding("EW026", sev, path, f"script in your Startup folder: {os.path.basename(path)}",
                           "Startup scripts run at every login. Make sure you know where this came from.")


# ------------------------------------------------------------------ processes

def check_tunnels(ps_output: Optional[str] = None) -> Iterator[Finding]:
    if ps_output is None:
        if sys.platform == "win32":
            return
        try:
            ps_output = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                       text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return
    for line in ps_output.splitlines():
        if re.search(r"\b(?:auto)?ssh\b", line) and re.search(r"-R\s*['\"]?\*?:?0?:?(?:localhost|127\.0\.0\.1):22\b", line):
            yield _finding("EW027", HIGH, "running process",
                           f"reverse SSH tunnel exposing this machine's SSH port: {line.strip()[:140]}",
                           "Unless you set this up, kill it and treat the machine as compromised.")


def run_all() -> List[Finding]:
    checks = [check_authorized_keys, check_known_artifacts, check_tunnels]
    if sys.platform == "darwin":
        checks.append(check_launch_agents)
    elif sys.platform == "win32":
        checks.append(check_windows_startup)
    else:
        checks += [check_crontab, check_systemd_user]
    out: List[Finding] = []
    for fn in checks:
        out.extend(fn())
    return out
