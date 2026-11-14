"""Compare an installed extension with the copy the official marketplaces serve.

A file that differs from the published package is the clearest signal there
is: it means someone changed the code after the publisher shipped it, or the
copy came from somewhere else.
"""

import gzip
import hashlib
import json
import os
import platform as _platform
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import __version__
from .discover import Extension, vsix_files_from_bytes

UA = f"extwatch/{__version__} (+https://github.com/viehgroup/extwatch)"
VSM_QUERY = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
OPENVSX = "https://open-vsx.org/api"
MAX_DOWNLOAD = 200 * 1024 * 1024

# Files the editor itself creates or rewrites on install
IGNORE = {".vsixmanifest", "extension.vsixmanifest", "[Content_Types].xml"}
CODE_EXT = (".js", ".cjs", ".mjs", ".node", ".sh", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".so", ".dylib", ".py")


class OfficialError(Exception):
    pass


@dataclass
class Comparison:
    marketplace: str                    # where the reference copy came from
    verified_publisher: Optional[bool] = None
    modified: List[str] = field(default_factory=list)
    added_code: List[str] = field(default_factory=list)
    added_other: int = 0
    missing: int = 0

    @property
    def identical(self) -> bool:
        return not self.modified and not self.added_code


@dataclass
class Verdict:
    """Result of checking one extension against every marketplace we know."""
    comparisons: List[Comparison] = field(default_factory=list)
    found_on: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def matched(self) -> Optional[Comparison]:
        return next((c for c in self.comparisons if c.identical), None)

    @property
    def best(self) -> Optional[Comparison]:
        if not self.comparisons:
            return None
        return min(self.comparisons, key=lambda c: (len(c.modified), len(c.added_code)))


def _cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "extwatch")


def _http(url: str, data: Optional[bytes] = None, headers: Optional[dict] = None, timeout: float = 30) -> bytes:
    h = {"User-Agent": UA, "Accept-Encoding": "gzip"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_DOWNLOAD + 1)
            if len(body) > MAX_DOWNLOAD:
                raise OfficialError(f"{url}: download too large")
            if body[:2] == b"\x1f\x8b":
                body = gzip.decompress(body)
            return body
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return b""
        raise OfficialError(f"{url}: HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise OfficialError(f"{url}: {e}") from e


def _cached_vsix(key: str, url: str) -> bytes:
    path = os.path.join(_cache_dir(), hashlib.sha256(key.encode()).hexdigest() + ".vsix")
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        pass
    data = _http(url, timeout=120)
    if data:
        try:
            os.makedirs(_cache_dir(), exist_ok=True)
            with open(path + ".tmp", "wb") as fh:
                fh.write(data)
            os.replace(path + ".tmp", path)
        except OSError:
            pass
    return data


def current_platform() -> str:
    machine = _platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "armhf" if machine.startswith("arm") else "x64"
    osname = {"darwin": "darwin", "win32": "win32"}.get(sys.platform, "linux")
    return f"{osname}-{arch}"


# --------------------------------------------------------------- marketplaces

def vs_marketplace(ext: Extension) -> Optional[tuple]:
    """(vsix bytes, verified publisher) from the Visual Studio Marketplace."""
    body = json.dumps({
        "filters": [{"criteria": [{"filterType": 7, "value": ext.id}], "pageNumber": 1, "pageSize": 1}],
        "flags": 0x1 | 0x2 | 0x80,  # versions, files, asset URIs
    }).encode()
    raw = _http(VSM_QUERY, body, {"Content-Type": "application/json",
                                  "Accept": "application/json;api-version=3.0-preview.1"})
    try:
        exts = json.loads(raw)["results"][0]["extensions"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    if not exts:
        return None
    meta = exts[0]
    verified = bool((meta.get("publisher") or {}).get("isDomainVerified"))
    for v in meta.get("versions") or []:
        if v.get("version") != ext.version:
            continue
        tp = v.get("targetPlatform")
        if tp and tp != (ext.platform or current_platform()):
            continue
        pkg = next((f for f in v.get("files") or [] if f.get("assetType", "").endswith("VSIXPackage")), None)
        if pkg and pkg.get("source"):
            data = _cached_vsix(f"vsm:{ext.id}:{ext.version}:{tp}", pkg["source"])
            return (data, verified) if data else None
    return "no-version", verified


def open_vsx(ext: Extension) -> Optional[tuple]:
    pub, name = ext.id.split(".", 1)
    q = urllib.parse.quote
    plat = ext.platform or current_platform()
    paths = [f"{OPENVSX}/{q(pub)}/{q(name)}/{q(plat)}/{q(ext.version)}",
             f"{OPENVSX}/{q(pub)}/{q(name)}/{q(ext.version)}"]
    for url in paths:
        raw = _http(url)
        if not raw:
            continue
        try:
            meta = json.loads(raw)
        except ValueError:
            continue
        if meta.get("error") or meta.get("targetPlatform") not in (None, "universal", plat):
            continue  # a build for a different OS would never match
        dl = (meta.get("files") or {}).get("download")
        if dl:
            data = _cached_vsix(f"ovsx:{ext.id}:{ext.version}:{meta.get('targetPlatform')}", dl)
            if data:
                return data, bool(meta.get("verified"))
    # does the extension exist at all?
    raw = _http(f"{OPENVSX}/{q(pub)}/{q(name)}")
    try:
        if raw and not json.loads(raw).get("error"):
            return "no-version", None
    except ValueError:
        pass
    return None


# --------------------------------------------------------------- comparison

def _norm_manifest(data: bytes) -> Optional[dict]:
    try:
        d = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(d, dict):
        d.pop("__metadata", None)  # older VS Code builds write install metadata here
    return d


def compare_files(installed: Dict[str, bytes], official: Dict[str, bytes], marketplace: str) -> Comparison:
    c = Comparison(marketplace)
    for rel, data in installed.items():
        if rel in IGNORE or rel.endswith("/.DS_Store") or rel == ".DS_Store":
            continue
        ref = official.get(rel)
        if ref is None:
            if rel.lower().endswith(CODE_EXT):
                c.added_code.append(rel)
            else:
                c.added_other += 1
            continue
        if data == ref:
            continue
        if rel == "package.json" and _norm_manifest(data) == _norm_manifest(ref):
            continue
        c.modified.append(rel)
    c.missing = sum(1 for rel in official if rel not in installed and rel not in IGNORE)
    return c


def verify(ext: Extension, retries: int = 1) -> Verdict:
    v = Verdict()
    installed = ext.read_files()
    for label, fn in (("VS Marketplace", vs_marketplace), ("Open VSX", open_vsx)):
        res = None
        for attempt in range(retries + 1):
            try:
                res = fn(ext)
                break
            except OfficialError as e:
                if attempt == retries:
                    v.errors.append(f"{label}: {e}")
                else:
                    time.sleep(1)
        if res is None:
            continue
        data, verified = res
        v.found_on.append(label)
        if data == "no-version":
            continue
        try:
            official = vsix_files_from_bytes(data)
        except Exception as e:  # corrupt download, not the user's problem
            v.errors.append(f"{label}: could not read package ({e})")
            continue
        comp = compare_files(installed, official, label)
        comp.verified_publisher = verified
        v.comparisons.append(comp)
        if comp.identical:
            break  # one exact match is enough
    return v
