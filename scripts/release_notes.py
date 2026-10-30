"""Print the CHANGELOG.md section for a version, for use as GitHub release notes.

Usage: python scripts/release_notes.py v0.1.1 > release-notes.md
Exits with an error if the changelog has no non-empty section for that version.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def section(changelog: str, version: str) -> str:
    version = version.removeprefix("v")
    pattern = rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|^\[Unreleased\]:|\Z)"
    match = re.search(pattern, changelog, re.S | re.M)
    if not match or not match.group(1).strip():
        raise SystemExit(f"CHANGELOG.md has no section for {version}")
    return match.group(1).strip() + "\n"


if __name__ == "__main__":
    text = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text(encoding="utf-8")
    sys.stdout.write(section(text, sys.argv[1]))
