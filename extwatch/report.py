import json
import shutil
import textwrap
from collections import OrderedDict
from typing import List

from . import __version__
from .checks import HIGH, LOW, MEDIUM, RULES, SEVERITY_ORDER, Finding

_C = {HIGH: "31", MEDIUM: "33", LOW: "36", "dim": "2", "bold": "1", "ok": "32"}


def _p(on: bool):
    return lambda s, k: f"\033[{_C[k]}m{s}\033[0m" if on else s


def text(findings: List[Finding], scanned: int, verified: int, color: bool, notes: List[str]) -> str:
    p = _p(color)
    width = min(100, shutil.get_terminal_size((80, 24)).columns)
    groups: "OrderedDict[str, List[Finding]]" = OrderedDict()
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.target)):
        groups.setdefault(f.target, []).append(f)

    out = []
    for target, items in groups.items():
        out.append(p(target, "bold"))
        for f in sorted(items, key=lambda x: -SEVERITY_ORDER[x.severity]):
            out.append(f"  {p(f'{f.severity:<6}', f.severity)} {f.rule}  {RULES[f.rule][0]}")
            for line in textwrap.wrap(f"{f.message} [{f.location}]", width - 4, break_on_hyphens=False):
                out.append("    " + line)
            if f.fix:
                for i, line in enumerate(textwrap.wrap(f.fix, width - 9, break_on_hyphens=False)):
                    out.append(("    fix: " if i == 0 else "         ") + p(line, "dim"))
        out.append("")

    for n in notes:
        out.append(p(n, "dim"))
    counts = [f"{sum(1 for x in findings if x.severity == s)} {s}" for s in (HIGH, MEDIUM, LOW)
              if any(x.severity == s for x in findings)]
    summary = f"{scanned} extension{'s' if scanned != 1 else ''} scanned"
    if verified:
        summary += f", {verified} checked against the official release"
    out.append(summary + (": " + ", ".join(counts) if counts else ". " + p("Nothing suspicious found.", "ok")))
    return "\n".join(out)


def as_json(findings: List[Finding], scanned: int) -> str:
    return json.dumps({"version": __version__, "scanned": scanned,
                       "findings": [f.__dict__ for f in findings]}, indent=2)


def sarif(findings: List[Finding]) -> str:
    level = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
    used = sorted({f.rule for f in findings})
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "extwatch", "version": __version__,
                "informationUri": "https://github.com/viehgroup/extwatch",
                "rules": [{"id": r, "name": RULES[r][0].replace(" ", ""),
                           "shortDescription": {"text": RULES[r][0]},
                           "fullDescription": {"text": RULES[r][1]}} for r in used],
            }},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": f"{f.target}: {f.message}" + (f" Fix: {f.fix}" if f.fix else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location.split(" @")[0]}}}],
            } for f in findings],
        }],
    }, indent=2)


def github(findings: List[Finding]) -> str:
    kind = {HIGH: "error", MEDIUM: "warning", LOW: "notice"}

    def esc(s):
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def prop(s):
        return esc(s).replace(":", "%3A").replace(",", "%2C")

    return "\n".join(
        f"::{kind[f.severity]} title={prop(f.rule + ' ' + RULES[f.rule][0])}::{esc(f.target + ': ' + f.message)}"
        for f in findings)
