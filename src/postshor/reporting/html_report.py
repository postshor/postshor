"""Self-contained HTML report for executives and auditors (no external assets)."""

from __future__ import annotations

import html
import json

from postshor import __version__
from postshor.models import ScanResult, Severity
from postshor.reporting.plan import build_plan, inventory
from postshor.score import Score

e = html.escape

_CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#16181d;--muted:#5d6370;--line:#e3e3df;--accent:#2f5bd3;
--crit:#b3261e;--high:#d0531c;--med:#a87b00;--low:#2b7a9b;--info:#7a7f8a;--ok:#1f7a4d;--chip:#f0f0ec}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1115;--panel:#171a21;--ink:#e8e9ec;--muted:#9aa0ab;
--line:#2a2f3a;--accent:#7c9cff;--crit:#ff6b5e;--high:#ff9a5c;--med:#e6c14d;--low:#6cc0e0;--info:#8a909b;--ok:#4cc38a;--chip:#20242d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:40px 16px 80px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:20px}
.brand{font-weight:700;letter-spacing:.02em;font-size:13px;text-transform:uppercase;color:var(--accent)}
h1{font-size:28px;margin:4px 0 0;letter-spacing:-.01em}h2{font-size:19px;margin:44px 0 14px}
.meta{color:var(--muted);font-size:13px;text-align:right}
.hero{display:grid;grid-template-columns:220px 1fr;gap:24px;margin-top:28px}
@media (max-width:720px){.hero{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.grade{font-size:84px;font-weight:800;line-height:1}.score{color:var(--muted);margin-top:6px}
.g-A{color:var(--ok)}.g-B{color:var(--ok)}.g-C{color:var(--med)}.g-D{color:var(--high)}.g-F{color:var(--crit)}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
@media (max-width:720px){.counts{grid-template-columns:repeat(3,1fr)}}
.count b{display:block;font-size:30px;font-variant-numeric:tabular-nums}.count span{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.callout{margin-top:14px;padding:12px 14px;border-left:3px solid var(--crit);background:var(--chip);border-radius:6px;font-size:14px}
.timeline{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}@media (max-width:720px){.timeline{grid-template-columns:1fr 1fr}}
.tl b{display:block;font-size:20px}.tl span{color:var(--muted);font-size:13px}
.phase{margin-bottom:14px}.phase h3{margin:0 0 4px;font-size:16px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.phase .when{color:var(--muted);font-weight:500;font-size:13px}.phase p{margin:4px 0 8px;color:var(--muted)}
.phase ul{margin:0;padding-left:18px}.phase li{margin:2px 0}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;background:var(--chip);font-size:12px;font-weight:600}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.toolbar button{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:99px;padding:5px 12px;font:inherit;font-size:13px;cursor:pointer}
.toolbar button[aria-pressed=true]{background:var(--ink);color:var(--panel);border-color:var(--ink)}
.toolbar input{flex:1;min-width:180px;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:8px;padding:6px 10px;font:inherit;font-size:13px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}td code{font-size:12.5px;word-break:break-all}td:last-child code{white-space:nowrap;word-break:normal}
.fix{color:var(--muted);margin-top:4px}details summary{cursor:pointer;color:var(--accent)}
footer{margin-top:56px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
"""

_JS = """
const rows=[...document.querySelectorAll('#findings tbody tr')];let sev='all';
function apply(){const q=document.getElementById('q').value.toLowerCase();
rows.forEach(r=>{const ok=(sev==='all'||r.dataset.sev===sev)&&(!q||r.textContent.toLowerCase().includes(q));r.hidden=!ok;});}
document.querySelectorAll('.toolbar button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.toolbar button').forEach(x=>x.setAttribute('aria-pressed','false'));
b.setAttribute('aria-pressed','true');sev=b.dataset.sev;apply();}));
document.getElementById('q').addEventListener('input',apply);
"""

_TIMELINE = [
    ("Now", "Harvest-now-decrypt-later: recorded traffic is already exposed"),
    ("2026", "EU: national PQC roadmaps due; migrations start"),
    ("2030", "NIST: RSA/ECC deprecated · EU: high-risk systems migrated"),
    ("2035", "NIST: RSA/ECC disallowed · EU & NSA CNSA 2.0: migration complete"),
]


def render(result: ScanResult, score: Score) -> str:
    sev_counts = "".join(
        f'<div class="count"><b class="sev-{s.label}">{score.counts[s.label]}</b><span>{s.label}</span></div>'
        for s in sorted(Severity, reverse=True)
    )
    callout = (
        '<div class="callout"><b>Harvest-now-decrypt-later exposure.</b> Critical findings protect data with key exchange or '
        "encryption that a future quantum computer can break. Adversaries can record it today.</div>"
        if score.counts["critical"] else ""
    )
    timeline = "".join(f'<div class="card tl"><b>{e(y)}</b><span>{e(t)}</span></div>' for y, t in _TIMELINE)

    phases_html = ""
    for p in build_plan(result.findings):
        n = len(p.findings)
        actions = "".join(f"<li>{e(a)}</li>" for a in p.actions)
        phases_html += (
            f'<div class="card phase"><h3><span>{e(p.title)} <span class="pill">{n} finding{"s" if n != 1 else ""}</span></span>'
            f'<span class="when">{e(p.deadline)}</span></h3><p>{e(p.why)}</p><ul>{actions}</ul></div>'
        )

    rows = ""
    for f in result.findings:
        loc = e(str(f.location))
        snippet = f'<div class="fix"><code>{e(f.location.snippet[:160])}</code></div>' if f.location.snippet and f.location.line else ""
        rows += (
            f'<tr data-sev="{f.severity.label}"><td><b class="sev-{f.severity.label}">{f.severity.label.upper()}</b></td>'
            f"<td><b>{e(f.title)}</b><div class=\"fix\">{e(f.message)}</div><details><summary>How to fix</summary>"
            f"<div>{e(f.remediation)}</div></details></td>"
            f"<td><code>{loc}</code>{snippet}</td><td><code>{e(f.rule_id)}</code></td></tr>"
        )
    buttons = '<button data-sev="all" aria-pressed="true">All</button>' + "".join(
        f'<button data-sev="{s.label}" aria-pressed="false">{s.label.capitalize()} ({score.counts[s.label]})</button>'
        for s in sorted(Severity, reverse=True) if score.counts[s.label]
    )
    inv_rows = "".join(f"<tr><td>{e(n)}</td><td>{c}</td><td>{fl}</td></tr>" for n, c, fl in inventory(result.findings))

    # Backslashes are not allowed inside f-string expressions before Python 3.12.
    embedded_score = json.dumps(score.to_dict()).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum Readiness Report</title><style>{_CSS}</style></head>
<body><main>
<header><div><div class="brand">PostShor</div><h1>Quantum Readiness Report</h1></div>
<div class="meta">{e(result.target)}<br>{e(result.finished_at)}<br>{result.files_scanned} files scanned</div></header>

<section class="hero">
<div class="card"><div class="grade g-{score.grade}">{score.grade}</div>
<div class="score">Quantum Readiness Score <b>{score.value}</b>/100<br><span style="font-size:12px">QRS v{score.version}</span></div></div>
<div class="card"><div class="counts">{sev_counts}</div>{callout}</div>
</section>

<h2>Deadlines that apply</h2><div class="timeline">{timeline}</div>

<h2>Migration plan</h2>{phases_html}

<h2>Findings</h2>
<div class="toolbar">{buttons}<input id="q" type="search" placeholder="Filter by file, algorithm, rule…" aria-label="Filter findings"></div>
<div class="table-wrap"><table id="findings"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Rule</th></tr></thead>
<tbody>{rows or '<tr><td colspan="4">No findings.</td></tr>'}</tbody></table></div>

<h2>Cryptographic inventory</h2>
<div class="table-wrap"><table><thead><tr><th>Algorithm</th><th>Occurrences</th><th>Files</th></tr></thead>
<tbody>{inv_rows or '<tr><td colspan="3">No cryptography detected.</td></tr>'}</tbody></table></div>

<footer>Generated by PostShor {__version__}. Scores follow the open Quantum Readiness Score specification (QRS v{score.version}).
Static analysis finds cryptography by pattern and parsing; review findings before acting on them.
<script type="application/json" id="postshor-data">{embedded_score}</script></footer>
</main><script>{_JS}</script></body></html>
"""
