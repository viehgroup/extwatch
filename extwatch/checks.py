"""Turn raw signals into findings people can act on.

Single signals are weak: Git, Docker and Python extensions all spawn
processes. What gives a backdoor away is a combination, like code that
writes to ~/.ssh/authorized_keys, or a raw IP next to a process spawn.
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .analyze import Hit, injected_prefix, near, scan_text
from .data import known_bad, popular
from .discover import Extension

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITY_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

RULES = {
    "EW001": ("Plants SSH keys", "Code writes to ~/.ssh/authorized_keys, which lets someone log in to this machine."),
    "EW002": ("Sets up persistence", "Code creates a LaunchAgent, cron job, startup script or service so it survives reboots."),
    "EW003": ("Reverse SSH tunnel", "Code opens a tunnel that exposes this machine's SSH port to a remote server."),
    "EW004": ("Reads credentials", "Code reads credential stores such as ~/.aws/credentials, browser logins or the keychain."),
    "EW005": ("Runs hidden code", "Code decodes and executes an encoded payload at runtime."),
    "EW006": ("Talks to a raw IP address", "Code connects to a hard-coded public IP instead of a domain."),
    "EW007": ("Code injected before the bundle", "Code sits in front of the bundler's header, so it runs before the extension activates."),
    "EW008": ("Downloads and runs a script", "Code pipes a download straight into a shell."),
    "EW009": ("Known exfiltration service", "Code references a service commonly used to receive stolen data."),
    "EW010": ("Collects secret environment variables", "Code gathers environment variables named like keys, tokens or passwords."),
    "EW011": ("Host fingerprinting", "Code looks up this machine's public IP, often the first step of a check-in beacon."),
    "EW012": ("Differs from the official release", "Files differ from the package the official marketplace serves for this version."),
    "EW013": ("Version not on official marketplaces", "This version can't be found on the VS Marketplace or Open VSX; it may have been pulled."),
    "EW014": ("Not on any public marketplace", "The extension isn't listed on the VS Marketplace or Open VSX."),
    "EW015": ("Known malicious", "Matches a published indicator of compromise."),
    "EW016": ("Impersonates a popular extension", "Name or ID imitates a well-known extension from a different publisher."),
    "EW017": ("Installed from a file", "Installed manually from a .vsix rather than from a marketplace."),
    "EW018": ("Recently installed or updated", "Installed or updated in the last few days."),
    "EW020": ("Known attacker SSH key", "authorized_keys contains a key from a published incident."),
    "EW021": ("Recently changed authorized_keys", "authorized_keys changed recently; worth a look."),
    "EW022": ("Known backdoor file", "A file from a published incident exists on this machine."),
    "EW023": ("Fake Apple LaunchAgent", "A user LaunchAgent uses an Apple-style name."),
    "EW024": ("LaunchAgent runs a hidden script", "A LaunchAgent runs a script from a hidden folder."),
    "EW025": ("Suspicious boot task", "A cron job or user service runs a hidden script or SSH tunnel at boot."),
    "EW026": ("Startup folder script", "A script runs at every Windows login."),
    "EW027": ("Active reverse SSH tunnel", "A running process is forwarding this machine's SSH port to a remote host."),
}

CODE_FILES = (".js", ".cjs", ".mjs")
MAX_SCAN = 30 * 1024 * 1024
# public resolvers and documentation ranges show up in honest code all the time
BENIGN_IPS = re.compile(r"^(?:8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112|"
                        r"208\.67\.22[02]\.22[02]|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+|"
                        r"100\.100\.100\.200|224\.\d+\.\d+\.\d+|239\.\d+\.\d+\.\d+)$")
PERSIST = ("launch_agent", "crontab", "win_startup", "systemd_user")


@dataclass
class Finding:
    rule: str
    severity: str
    target: str     # extension id@version (editor), or "this machine"
    location: str   # file inside the extension, or path on disk
    message: str
    fix: str = ""


def _target(ext: Extension) -> str:
    return f"{ext.id}@{ext.version}" + (f" ({ext.editor})" if ext.editor else "")


def _ips(hits: List[Hit]) -> List[Hit]:
    out = []
    for h in hits:
        m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", h.snippet)
        ip = m.group(0) if m else ""
        if ip and not BENIGN_IPS.match(ip):
            out.append(h)
    return out


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------- per file

def check_code(ext: Extension, rel: str, text: str) -> List[Finding]:
    t, f = _target(ext), []
    s: Dict[str, List[Hit]] = scan_text(text)
    g = s.get
    entry = rel in ext.entry_points
    where = rel

    def add(rule, sev, hit: Optional[Hit], msg, fix):
        snippet = f' near: "{hit.snippet}"' if hit else ""
        f.append(Finding(rule, sev, t, where + (f" @{hit.offset}" if hit else ""), msg + snippet, fix))

    # The October 2026 pattern: code pasted ahead of the real bundle
    if entry or len(text) > 200_000:
        prefix = injected_prefix(text)
        if prefix:
            ps = scan_text(prefix)
            risky = sorted(k for k in ps if k in ("child_process", "authorized_keys", "reverse_tunnel", "public_ip_ip",
                                                  "launch_agent", "crontab", "win_startup", "env_harvest", "eval_decode"))
            f.append(Finding("EW007", HIGH, t, where + " @0",
                             f"{len(prefix):,} characters of code run before the bundler's own header"
                             + (f" and use: {', '.join(risky)}" if risky else ""),
                             "Compare this file with the official release. This is how the Oct 2026 Claude Code "
                             "extension backdoor was inserted."))

    if g("authorized_keys") and g("write_fn"):
        hit = near(g("authorized_keys"), g("write_fn"), 600)
        if hit:
            add("EW001", HIGH, hit, "writes to ~/.ssh/authorized_keys",
                "Unless this is an SSH management tool you trust, remove the extension and check authorized_keys.")

    if g("reverse_tunnel"):
        add("EW003", HIGH, g("reverse_tunnel")[0], "starts a reverse SSH tunnel",
            "Remove the extension and run `extwatch --hunt` to look for leftovers.")
    elif g("ssh_no_hostcheck") and g("child_process") and g("detached"):
        add("EW003", MEDIUM, g("ssh_no_hostcheck")[0], "runs ssh in the background with host-key checks turned off",
            "Check what host it connects to and why.")

    persist_hits = [h for k in PERSIST for h in g(k, [])]
    if persist_hits:
        actors = g("write_fn", []) + g("child_process", [])
        hit = near(persist_hits, actors, 800)
        if hit:
            alarming = any(g(k) for k in ("reverse_tunnel", "ssh_no_hostcheck", "eval_decode", "exfil_service")) or _ips(g("public_ip_ip", []))
            add("EW002", HIGH if alarming else MEDIUM, hit,
                f"creates a {hit.signal.replace('_', ' ')} entry so code keeps running after a restart",
                "Check what it registers. Persistence is rarely needed by an editor extension.")

    if g("eval_decode"):
        add("EW005", HIGH, g("eval_decode")[0], "decodes a payload and executes it",
            "Legitimate extensions don't need to hide their code. Treat as suspicious.")

    if g("shell_pipe"):
        hit = near(g("shell_pipe"), g("child_process", []), 2000) if g("child_process") else None
        add("EW008", HIGH if hit else LOW, g("shell_pipe")[0],
            "pipes a download into a shell" + ("" if hit else " (may only be shown as an install hint)"),
            "Check whether this runs automatically or is only displayed to you.")

    ips = _ips(g("public_ip_ip", []))
    exfil = g("exfil_service", [])
    harvest = g("env_harvest", [])
    creds = [h for k in ("cred_files", "browser_data", "keychain") for h in g(k, [])]
    sends = bool(g("net_send"))

    if ips:
        hot = bool(g("child_process") and near(ips, g("child_process"), 3000)) or harvest or g("authorized_keys")
        add("EW006", HIGH if hot else MEDIUM, ips[0], "connects to a hard-coded public IP address",
            "Find out who owns the address. Honest services almost always use domain names.")

    if exfil:
        add("EW009", HIGH if (harvest or creds) else MEDIUM, exfil[0],
            "references a service often used to collect stolen data",
            "Check what is sent there.")

    if harvest:
        add("EW010", HIGH if (ips or exfil) and sends else MEDIUM, harvest[0],
            "collects environment variable names or values that look like secrets",
            "Rotate secrets exposed in the editor's environment if the extension is untrusted.")

    if creds:
        read_hit = near(creds, g("read_fn", []), 500) if g("read_fn") else None
        if read_hit:
            leaving = sends and (ips or exfil)
            kind = read_hit.signal
            sev = HIGH if leaving else (MEDIUM if kind in ("browser_data", "keychain") else LOW)
            add("EW004", sev, read_hit, f"reads {kind.replace('_', ' ')}",
                "Expected for cloud or Docker tooling; suspicious for anything else.")

    if g("ip_lookup") and (ips or exfil):
        add("EW011", MEDIUM, g("ip_lookup")[0], "looks up this machine's public IP and reports to a remote host",
            "A beacon like this usually precedes remote access.")

    return f


# --------------------------------------------------------------- per extension

def check_known_bad(ext: Extension, files: Dict[str, bytes]) -> List[Finding]:
    out, t, kb = [], _target(ext), known_bad()
    for entry in kb["versions"]:
        if ext.id == entry["id"] and ext.version in entry["versions"] and (
                not entry.get("editors") or ext.editor in entry["editors"]):
            out.append(Finding("EW015", HIGH, t, ext.location, f"{entry['name']}. See {entry['source']}",
                               "Remove it, then run `extwatch --hunt` and follow the advisory's remediation steps."))
    for rel, data in files.items():
        info = kb["file_sha256"].get(_sha256(data))
        if info:
            out.append(Finding("EW015", HIGH, t, rel, f"file matches {info['name']}. See {info['source']}",
                               "Remove it, then run `extwatch --hunt` and follow the advisory's remediation steps."))
    strings = [s for s in kb["strings"] if s["context"] == "any"]
    for rel, data in files.items():
        if not rel.endswith(CODE_FILES):
            continue
        for s in strings:
            if s["value"].encode() in data:
                out.append(Finding("EW015", HIGH, t, rel, f"contains {s['value']}: {s['name']}. See {s['source']}",
                                   "Remove it, then run `extwatch --hunt`."))
    return out


def _edit1(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def check_identity(ext: Extension) -> List[Finding]:
    pop = popular()
    if ext.id in pop:
        return []
    t, out = _target(ext), []
    name = ext.id.split(".", 1)[1]
    disp = (ext.display_name or "").strip().lower()
    for pid, pname in pop.items():
        ppub, pn = pid.split(".", 1)
        if disp and disp == pname.lower():
            out.append(Finding("EW016", HIGH, t, "package.json",
                               f"uses the display name '{pname}' of {pid}, but comes from publisher '{ext.publisher}'",
                               f"Make sure you meant to install this instead of {pid}."))
            break
        if name == pn and len(pn) > 3:
            out.append(Finding("EW016", MEDIUM, t, "package.json",
                               f"same extension name as {pid} from a different publisher",
                               f"Make sure you meant to install this instead of {pid}."))
            break
        if len(pid) > 8 and _edit1(ext.id, pid):
            out.append(Finding("EW016", MEDIUM, t, "package.json", f"ID is one character away from {pid}",
                               f"Make sure you meant to install this instead of {pid}."))
            break
    return out


def check_official(ext: Extension, verdict) -> List[Finding]:
    t = _target(ext)
    if verdict is None:
        return []
    best = verdict.best
    if best and not verdict.matched:
        out = []
        if best.modified:
            files = ", ".join(best.modified[:5]) + (f" and {len(best.modified) - 5} more" if len(best.modified) > 5 else "")
            out.append(Finding("EW012", HIGH, t, best.modified[0],
                               f"{len(best.modified)} file(s) differ from the {best.marketplace} release of this version: {files}",
                               "Someone changed this code after it was published, or it came from somewhere else. "
                               "Remove it and reinstall from the official marketplace."))
        if best.added_code:
            files = ", ".join(best.added_code[:5])
            out.append(Finding("EW012", MEDIUM, t, best.added_code[0],
                               f"{len(best.added_code)} code file(s) not in the {best.marketplace} release: {files}",
                               "Some extensions download helpers at runtime; check these are expected."))
        return out
    if not verdict.comparisons and verdict.found_on:
        return [Finding("EW013", MEDIUM, t, ext.location,
                        f"listed on {', '.join(verdict.found_on)} but version {ext.version} isn't",
                        "Versions disappear when they're pulled for security reasons. Update or reinstall it.")]
    if not verdict.found_on and not verdict.errors:
        return [Finding("EW014", LOW, t, ext.location, "not listed on the VS Marketplace or Open VSX",
                        "Fine for private or company extensions; otherwise check where it came from.")]
    return []


def check_extension(ext: Extension, verdict=None, now: Optional[datetime] = None) -> List[Finding]:
    now = now or datetime.now(timezone.utc)
    files = ext.read_files()
    findings: List[Finding] = []
    findings += check_known_bad(ext, files)
    findings += check_identity(ext)
    for rel, data in files.items():
        if rel.endswith(CODE_FILES) and len(data) <= MAX_SCAN and "/test/" not in f"/{rel}" and not rel.endswith(".map"):
            findings += check_code(ext, rel, data.decode("utf-8", "replace"))
    findings += check_official(ext, verdict)

    # A clean match with a verified publisher's release turns weak behavioural
    # hints into noise. High-severity behaviour still shows: a publisher's own
    # pipeline can be compromised too.
    if verdict is not None and verdict.matched and verdict.matched.verified_publisher:
        findings = [x for x in findings if x.severity == HIGH or x.rule in ("EW015", "EW016")]

    if ext.source == "vsix" and not ext.is_vsix:
        findings.append(Finding("EW017", LOW, _target(ext), ext.location, "installed manually from a .vsix file",
                                "Make sure you know where the file came from."))

    if ext.installed and findings and any(x.severity != LOW for x in findings):
        days = (now - ext.installed).days
        if days <= 7:
            findings.append(Finding("EW018", LOW, _target(ext), ext.location,
                                    f"installed or updated {days} day(s) ago",
                                    "Recent changes deserve a closer look."))
    return _dedupe(findings)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen, out = set(), []
    for x in findings:
        key = (x.rule, x.target, x.location.split(" @")[0])
        if key in seen:
            continue
        seen.add(key)
        out.append(x)
    return out
