"""Human-readable terminal output."""

from __future__ import annotations

import os
import sys

from postshor.models import ScanResult, Severity
from postshor.score import Score

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
_GRADE_COLORS = {"A": "\033[1;32m", "B": "\033[32m", "C": "\033[33m", "D": "\033[1;33m", "F": "\033[1;31m"}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def render(result: ScanResult, score: Score, verbose: bool = False, color: bool | None = None, limit: int = 50) -> str:
    color = _use_color(sys.stdout) if color is None else color

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out: list[str] = []
    out.append(c(_BOLD, "PostShor") + c(_DIM, f"  quantum-readiness scan of {result.target}"))
    out.append("")
    shown = 0
    for sev, items in result.by_severity().items():
        if not items or (sev == Severity.INFO and not verbose):
            continue
        for f in items:
            if shown >= limit and not verbose:
                break
            tag = c(_COLORS[sev], f" {sev.label.upper():8} ")
            out.append(f"{tag} {c(_BOLD, f.title)}  {c(_DIM, f.rule_id)}")
            out.append(f"           {f.location}" + (c(_DIM, f"  {f.location.snippet[:90]}") if f.location.snippet and f.location.line else ""))
            if verbose:
                out.append(f"           {f.message}")
            out.append(f"           {c(_DIM, 'fix:')} {f.remediation}")
            out.append("")
            shown += 1
    hidden = sum(1 for f in result.findings if f.severity > Severity.INFO) - shown
    if hidden > 0:
        out.append(c(_DIM, f"... {hidden} more findings. Use --verbose or write a report with -o report.html"))
        out.append("")

    counts = "  ".join(
        c(_COLORS[s], f" {n} {s.label} ") if n else c(_DIM, f"0 {s.label}")
        for s in sorted(Severity, reverse=True)
        for n in [score.counts[s.label]]
    )
    out.append(c(_BOLD, "Summary"))
    out.append(f"  Files scanned:  {result.files_scanned}" + (f"   suppressed: {result.suppressed}" if result.suppressed else ""))
    out.append(f"  Findings:       {counts}")
    grade = c(_GRADE_COLORS[score.grade], f"{score.grade} ({score.value}/100)")
    out.append(f"  Quantum Readiness Score (QRS v{score.version}): {grade}")
    if score.counts["critical"]:
        out.append(c(_COLORS[Severity.HIGH], "  Harvest-now-decrypt-later exposure detected: fix CRITICAL findings first."))
    for e in result.errors[:5]:
        out.append(c(_DIM, f"  warning: {e}"))
    return "\n".join(out) + "\n"
