"""Bundled reference data: known-bad indicators and popular extensions."""

import json
from functools import lru_cache
from importlib import resources
from typing import Dict


@lru_cache(maxsize=None)
def known_bad() -> dict:
    return json.loads(resources.files(__package__).joinpath("known_bad.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def popular() -> Dict[str, str]:
    """id -> display name"""
    out = {}
    text = resources.files(__package__).joinpath("popular.txt").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip() and not line.startswith("#") and "\t" in line:
            ext_id, name = line.split("\t", 1)
            out[ext_id.strip().lower()] = name.strip()
    return out
