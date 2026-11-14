import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List

from . import __version__, report
from .checks import RULES, SEVERITY_ORDER, check_extension
from .discover import EDITORS, installed, open_path


def build_parser():
    p = argparse.ArgumentParser(
        prog="extwatch",
        description="Catch backdoored VS Code, Cursor and Windsurf extensions.",
        epilog="With no paths, scans every editor's installed extensions.",
    )
    p.add_argument("paths", nargs="*", help=".vsix files or extension folders to scan instead")
    p.add_argument("--verify", action="store_true",
                   help="compare each extension with the official VS Marketplace / Open VSX release (downloads packages)")
    p.add_argument("--hunt", action="store_true",
                   help="also look for backdoor leftovers on this machine (SSH keys, startup items, tunnels)")
    p.add_argument("--editor", action="append", metavar="NAME",
                   help="only scan this editor (repeatable): " + ", ".join(e for e, _ in EDITORS))
    p.add_argument("--only", action="append", metavar="ID", help="only scan this extension ID (repeatable)")
    p.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE")
    p.add_argument("-j", "--jobs", type=int, default=4, help="parallel downloads with --verify (default 4)")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"extwatch {__version__}")
    return p


def main(argv=None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130


def _main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        for rid, (title, desc) in RULES.items():
            print(f"{rid}  {title}\n       {desc}")
        return 0

    if args.paths:
        exts = []
        for path in args.paths:
            e = open_path(path)
            if not e:
                print(f"extwatch: {path}: not a .vsix file or extension folder", file=sys.stderr)
                return 2
            exts.append(e)
    else:
        exts = list(installed(editors=args.editor))
    if args.only:
        want = {i.lower() for i in args.only}
        exts = [e for e in exts if e.id in want]

    show_progress = args.format == "text" and not args.output and sys.stderr.isatty()
    verdicts = {}
    notes: List[str] = []
    if args.verify and exts:
        from .official import verify
        done = 0

        def run(e):
            nonlocal done
            v = verify(e)
            done += 1
            if show_progress:
                print(f"\rchecking official releases {done}/{len(exts)}", end="", file=sys.stderr, flush=True)
            return e, v

        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            for e, v in pool.map(run, exts):
                verdicts[id(e)] = v
        if show_progress:
            print("\r" + " " * 40 + "\r", end="", file=sys.stderr)
        failed = sum(1 for v in verdicts.values() if v.errors and not v.comparisons)
        if failed:
            notes.append(f"Could not reach the marketplaces for {failed} extension(s); those were checked offline only.")

    ignore = {r.upper() for r in args.ignore}
    findings = []
    for e in exts:
        findings += check_extension(e, verdicts.get(id(e)))
        e.files = {}  # free memory as we go
    if args.hunt:
        from .hunt import run_all
        findings += run_all()
    findings = [f for f in findings if f.rule not in ignore]

    verified_ok = sum(1 for v in verdicts.values() if v.matched)
    if args.format == "json":
        out = report.as_json(findings, len(exts))
    elif args.format == "sarif":
        out = report.sarif(findings)
    elif args.format == "github":
        out = report.github(findings)
    else:
        if not exts and not args.paths:
            notes.append("No editor extensions found in the usual places.")
        if not args.verify and exts:
            notes.append("Tip: add --verify to compare each extension with its official release.")
        color = not args.output and sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        out = report.text(findings, len(exts), verified_ok, color, notes)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    elif out:
        print(out)

    if args.fail_on == "never":
        return 0
    t = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= t for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
