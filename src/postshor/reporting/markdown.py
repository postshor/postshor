"""Markdown report, sized for pull-request comments and CI job summaries."""

from __future__ import annotations

from postshor.models import ScanResult, Severity
from postshor.reporting.plan import build_plan, inventory
from postshor.score import Score

_ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪"}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render(result: ScanResult, score: Score, limit: int = 30) -> str:
    out = [
        "## PostShor: quantum-readiness report",
        "",
        f"{score.badge_markdown}",
        "",
        f"**Quantum Readiness Score (QRS v{score.version}): {score.grade} ({score.value}/100)** · "
        f"{result.files_scanned} files scanned",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    out += [f"| {_ICON[s]} {s.label} | {score.counts[s.label]} |" for s in sorted(Severity, reverse=True)]

    phases = [p for p in build_plan(result.findings) if p.findings]
    if phases:
        out += ["", "### Migration plan", ""]
        for p in phases:
            out.append(f"- **{p.title}** ({p.deadline}): {len(p.findings)} findings. {p.why}")

    rows = [f for f in result.findings if f.severity > Severity.INFO][:limit]
    if rows:
        out += ["", "### Top findings", "", "| | Finding | Location | Fix |", "|---|---|---|---|"]
        for f in rows:
            out.append(f"| {_ICON[f.severity]} | {_cell(f.title)} | `{_cell(str(f.location))}` | {_cell(f.remediation)} |")
        remaining = sum(1 for f in result.findings if f.severity > Severity.INFO) - len(rows)
        if remaining > 0:
            out.append(f"\n_{remaining} more findings in the full report._")

    inv = inventory(result.findings)
    if inv:
        out += ["", "<details><summary>Cryptographic inventory</summary>", "", "| Algorithm | Occurrences | Files |", "|---|---|---|"]
        out += [f"| {name} | {n} | {files} |" for name, n, files in inv]
        out += ["", "</details>"]
    return "\n".join(out) + "\n"
