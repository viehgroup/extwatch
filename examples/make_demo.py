"""Build two demo extensions to try extwatch on.

    python examples/make_demo.py
    extwatch demo-clean.vsix demo-backdoored.vsix

The backdoored one copies the structure of the October 2026 Claude Code
extension compromise, but it is inert: it throws on its first line, the SSH
key is a dummy and the address is in a reserved test range.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tests.fixtures import backdoored_files, clean_files, make_vsix  # noqa: E402

out = sys.argv[1] if len(sys.argv) > 1 else "."
for name, files in (("demo-clean.vsix", clean_files()), ("demo-backdoored.vsix", backdoored_files())):
    path = os.path.join(out, name)
    with open(path, "wb") as fh:
        fh.write(make_vsix(files))
    print("wrote", path)
