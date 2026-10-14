"""SARIF 2.1.0 output, consumed by GitHub code scanning, Azure DevOps and most IDEs."""

from __future__ import annotations

import json

from postshor import __version__
from postshor.models import ScanResult, Severity
from postshor.score import Score

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
# GitHub maps security-severity: >=9 critical, >=7 high, >=4 medium, else low.
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.1", Severity.HIGH: "7.5", Severity.MEDIUM: "5.0", Severity.LOW: "2.0", Severity.INFO: "0.0"}


def render(result: ScanResult, score: Score) -> str:
    rules: dict[str, dict] = {}
    results = []
    # SARIF is file-oriented; live-endpoint findings live in the JSON, HTML and CBOM reports.
    for f in (f for f in result.findings if not f.location.path.startswith("tls://")):
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": "".join(p.capitalize() for p in f.rule_id.split("-")),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "help": {"text": f.remediation, "markdown": f"**Fix:** {f.remediation}"},
                "properties": {
                    "tags": ["security", "cryptography", "post-quantum", f.category.value],
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "precision": {"high": "high", "medium": "medium", "low": "low"}[f.confidence],
                },
            }
        location: dict = {"artifactLocation": {"uri": f.location.path}}
        if f.location.line:
            location["region"] = {"startLine": f.location.line}
            if f.location.column:
                location["region"]["startColumn"] = f.location.column
        entry = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.message} Fix: {f.remediation}"},
            "partialFingerprints": {"postshor/v1": f.fingerprint},
            "properties": {"algorithm": f.algorithm, "usage": f.usage.value, "severity": f.severity.label},
        }
        entry["locations"] = [{"physicalLocation": location}]
        results.append(entry)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PostShor",
                "version": __version__,
                "informationUri": "https://github.com/postshor/postshor",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"quantumReadinessScore": score.to_dict()},
        }],
    }
    return json.dumps(doc, indent=2)
