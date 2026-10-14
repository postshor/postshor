"""Report writers. Each module exposes ``render(result, score) -> str``."""

from __future__ import annotations

from postshor.reporting import cbom, html_report, json_report, markdown, sarif

FORMATS = {
    "json": json_report.render,
    "sarif": sarif.render,
    "cbom": cbom.render,
    "html": html_report.render,
    "markdown": markdown.render,
}


def format_for_path(path: str) -> str:
    p = path.lower()
    if p.endswith((".sarif", ".sarif.json")):
        return "sarif"
    if p.endswith((".cdx.json", ".cbom.json", ".cdx")):
        return "cbom"
    if p.endswith(".json"):
        return "json"
    if p.endswith((".html", ".htm")):
        return "html"
    if p.endswith((".md", ".markdown")):
        return "markdown"
    raise ValueError(f"cannot infer report format from {path!r}; use --format or a known extension (.html .json .sarif .cdx.json .md)")
