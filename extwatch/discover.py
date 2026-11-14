"""Find installed editor extensions, or open a .vsix / extension folder."""

import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

# (editor name, extensions dir relative to home)
EDITORS = [
    ("VS Code", ".vscode/extensions"),
    ("VS Code Insiders", ".vscode-insiders/extensions"),
    ("VSCodium", ".vscode-oss/extensions"),
    ("Cursor", ".cursor/extensions"),
    ("Windsurf", ".windsurf/extensions"),
    ("Trae", ".trae/extensions"),
    ("Kiro", ".kiro/extensions"),
    ("Positron", ".positron/extensions"),
    ("VS Code Server", ".vscode-server/extensions"),
    ("Cursor Server", ".cursor-server/extensions"),
]

KNOWN_PLATFORMS = ("win32-x64", "win32-arm64", "linux-x64", "linux-arm64", "linux-armhf",
                   "alpine-x64", "alpine-arm64", "darwin-x64", "darwin-arm64", "web")

TEXT_EXT = (".js", ".cjs", ".mjs", ".ts", ".json", ".sh", ".ps1", ".bat", ".cmd", ".py")
MAX_FILE = 25 * 1024 * 1024


@dataclass
class Extension:
    id: str                       # publisher.name, lower-case
    version: str
    display_name: str = ""
    publisher: str = ""
    editor: str = ""
    location: str = ""            # folder or .vsix path
    platform: Optional[str] = None
    source: Optional[str] = None  # "gallery", "vsix", ... from extensions.json
    installed: Optional[datetime] = None
    manifest: dict = field(default_factory=dict)
    files: Dict[str, bytes] = field(default_factory=dict, repr=False)  # loaded lazily
    is_vsix: bool = False

    @property
    def entry_points(self) -> List[str]:
        out = []
        for key in ("main", "browser"):
            v = self.manifest.get(key)
            if isinstance(v, str):
                p = os.path.normpath(v).replace(os.sep, "/")
                out.append(p)
                if not p.endswith((".js", ".cjs", ".mjs")):
                    out.append(p + ".js")
        return out

    @property
    def activation(self) -> List[str]:
        ev = self.manifest.get("activationEvents") or []
        return [e for e in ev if isinstance(e, str)]

    @property
    def runs_at_startup(self) -> bool:
        return any(e in ("*", "onStartupFinished") for e in self.activation)

    def read_files(self) -> Dict[str, bytes]:
        if self.files:
            return self.files
        if self.is_vsix:
            self.files = _vsix_files(self.location)
        else:
            self.files = _dir_files(self.location)
        return self.files


def _dir_files(root: str) -> Dict[str, bytes]:
    out = {}
    for dirpath, _dirs, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                if os.path.getsize(full) > MAX_FILE:
                    continue
                with open(full, "rb") as fh:
                    out[rel] = fh.read()
            except OSError:
                continue
    return out


def _vsix_files(path_or_bytes) -> Dict[str, bytes]:
    src = io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, (bytes, bytearray)) else path_or_bytes
    out = {}
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith("extension/"):
                continue
            if info.file_size > MAX_FILE:
                continue
            out[info.filename[len("extension/"):]] = zf.read(info)
    return out


def vsix_files_from_bytes(data: bytes) -> Dict[str, bytes]:
    return _vsix_files(data)


def _folder_platform(folder: str, version: str) -> Optional[str]:
    tail = folder.rsplit(version, 1)[-1].lstrip("-") if version and version in folder else ""
    return tail if tail in KNOWN_PLATFORMS else None


def _load_manifest(text: bytes) -> dict:
    try:
        data = json.loads(text.decode("utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _ext_from_manifest(manifest: dict, **kw) -> Optional[Extension]:
    pub, name = manifest.get("publisher"), manifest.get("name")
    if not isinstance(pub, str) or not isinstance(name, str):
        return None
    disp = manifest.get("displayName") if isinstance(manifest.get("displayName"), str) else ""
    if disp.startswith("%"):
        disp = ""  # localised placeholder like %displayName%
    return Extension(id=f"{pub}.{name}".lower(), version=str(manifest.get("version", "")),
                     display_name=disp or name, publisher=pub, manifest=manifest, **kw)


def open_folder(path: str, editor: str = "", meta: Optional[dict] = None) -> Optional[Extension]:
    try:
        with open(os.path.join(path, "package.json"), "rb") as fh:
            manifest = _load_manifest(fh.read())
    except OSError:
        return None
    meta = meta or {}
    ext = _ext_from_manifest(manifest, editor=editor, location=path)
    if not ext:
        return None
    ext.platform = meta.get("targetPlatform") or _folder_platform(os.path.basename(path), ext.version)
    if ext.platform in ("undefined", "universal"):
        ext.platform = None
    ext.source = meta.get("source")
    ts = meta.get("installedTimestamp")
    if isinstance(ts, (int, float)) and ts > 0:
        ext.installed = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
    return ext


def open_vsix(path: str) -> Optional[Extension]:
    try:
        with zipfile.ZipFile(path) as zf:
            manifest = _load_manifest(zf.read("extension/package.json"))
            platform = None
            try:
                vsm = zf.read("extension.vsixmanifest").decode("utf-8", "replace")
                m = re.search(r'TargetPlatform="([^"]+)"', vsm)
                platform = m.group(1) if m else None
            except KeyError:
                pass
    except (OSError, KeyError, zipfile.BadZipFile):
        return None
    ext = _ext_from_manifest(manifest, editor="vsix file", location=path)
    if ext:
        ext.is_vsix = True
        ext.platform = platform
        ext.source = "vsix"
    return ext


def _read_registry(ext_dir: str) -> Dict[str, dict]:
    """extensions.json maps folders to install metadata (source, timestamp, platform)."""
    try:
        with open(os.path.join(ext_dir, "extensions.json"), encoding="utf-8") as fh:
            entries = json.load(fh)
    except (OSError, ValueError):
        return {}
    out = {}
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        rel = e.get("relativeLocation")
        if not rel:
            loc = e.get("location") or {}
            p = loc.get("fsPath") or loc.get("path") if isinstance(loc, dict) else None
            rel = os.path.basename(p) if p else None
        if rel:
            out[rel] = e.get("metadata") or {}
    return out


def installed(home: Optional[str] = None, editors: Optional[List[str]] = None) -> Iterator[Extension]:
    home = home or os.path.expanduser("~")
    wanted = {e.lower() for e in editors} if editors else None
    for editor, rel in EDITORS:
        if wanted and editor.lower() not in wanted and editor.split()[0].lower() not in wanted:
            continue
        ext_dir = os.path.join(home, rel)
        if not os.path.isdir(ext_dir):
            continue
        registry = _read_registry(ext_dir)
        obsolete = _read_obsolete(ext_dir)
        for folder in sorted(os.listdir(ext_dir)):
            full = os.path.join(ext_dir, folder)
            if folder.startswith(".") or folder in obsolete or not os.path.isdir(full):
                continue
            ext = open_folder(full, editor, registry.get(folder))
            if ext:
                yield ext


def _read_obsolete(ext_dir: str) -> set:
    # extensions VS Code has uninstalled but not yet deleted
    try:
        with open(os.path.join(ext_dir, ".obsolete"), encoding="utf-8") as fh:
            data = json.load(fh)
        return {k for k, v in data.items() if v} if isinstance(data, dict) else set()
    except (OSError, ValueError):
        return set()


def open_path(path: str) -> Optional[Extension]:
    if os.path.isdir(path):
        return open_folder(path, "folder")
    if path.lower().endswith(".vsix"):
        return open_vsix(path)
    return None
