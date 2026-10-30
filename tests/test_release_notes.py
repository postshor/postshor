import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts" / "release_notes.py")
release_notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_notes)
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("tag", ["v0.1.0", "v0.1.1", "0.1.1"])
def test_every_released_version_has_notes(tag):
    notes = release_notes.section(CHANGELOG, tag)
    assert notes.startswith("###")
    assert "## [" not in notes and "[Unreleased]:" not in notes


def test_missing_version_fails_loudly():
    with pytest.raises(SystemExit):
        release_notes.section(CHANGELOG, "v9.9.9")
