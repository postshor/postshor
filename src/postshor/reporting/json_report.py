"""Native JSON report: the complete, lossless output format."""

from __future__ import annotations

import json

from postshor import __version__
from postshor.models import ScanResult
from postshor.score import Score

SCHEMA_VERSION = "1"


def to_dict(result: ScanResult, score: Score) -> dict:
    return {
        "tool": {"name": "postshor", "version": __version__},
        "schema_version": SCHEMA_VERSION,
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "files_scanned": result.files_scanned,
        "suppressed": result.suppressed,
        "errors": result.errors,
        "score": {**score.to_dict(), "scope": result.target, "test_adjustment": result.test_adjustment},
        "findings": [f.to_dict() for f in result.findings],
    }


def render(result: ScanResult, score: Score) -> str:
    return json.dumps(to_dict(result, score), indent=2)
