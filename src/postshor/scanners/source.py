"""Pattern-rule scanner for source code, configuration and infrastructure-as-code."""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from postshor.models import Category, Finding, Location, Severity, Usage
from postshor.rules import RULES, Rule, explain, remediation, severity_for
from postshor.rules.patterns import algorithm_for_match

SUPPRESS_MARKER = "postshor:ignore"
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", ";", "<!--")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)


class SourceScanner:
    def __init__(self, rules: list[Rule] | None = None, disabled: set[str] | None = None):
        disabled = disabled or set()
        self.rules = [r for r in (rules or RULES) if r.id not in disabled]

    def scan(self, rel_path: str, text: str, kinds: set[str]) -> tuple[list[Finding], int]:
        """Return (findings, suppressed_count) for one file."""
        rules = [r for r in self.rules if kinds.intersection(r.kinds)]
        line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
        lines = text.split("\n")
        language = next((k for k in kinds if k not in ("any", "config", "iac", "ssh-config")), None)

        # Keep the most severe finding per (line, algorithm) so overlapping rules don't double-count.
        best: dict[tuple[int, str], Finding] = {}
        suppressed = 0

        for m in _PRIVATE_KEY.finditer(text):
            lineno = bisect.bisect_right(line_starts, m.start())
            best[(lineno, "secret")] = _private_key_finding(rel_path, lineno, m)

        for rule in rules:
            for m in rule.regex.finditer(text):
                lineno = bisect.bisect_right(line_starts, m.start())
                line = lines[lineno - 1]
                if rule.unless_regex and rule.unless_regex.search(line):
                    continue
                if _is_comment(line):
                    continue
                if _suppressed(lines, lineno):
                    suppressed += 1
                    continue
                algo = algorithm_for_match(rule, m)
                finding = _make_finding(rule, algo, rel_path, lineno, m.start() - line_starts[lineno - 1] + 1, line, language)
                # Configuration checks each report a distinct problem, so they never merge.
                key = (lineno, algo, rule.id if rule.unless or rule.severity else "")
                if key not in best or finding.severity > best[key].severity:
                    best[key] = finding
        findings = _drop_generic_ecc(list(best.values()))
        return sorted(findings, key=lambda f: f.location.line or 0), suppressed


_SPECIFIC_EC = {"ecdsa", "ecdh", "x25519", "eddsa"}


def _drop_generic_ecc(findings: list[Finding]) -> list[Finding]:
    """A generic 'elliptic curve' hit adds nothing when the same line names ECDSA/ECDH."""
    specific_lines = {f.location.line for f in findings if f.algorithm in _SPECIFIC_EC}
    return [f for f in findings if not (f.algorithm == "ecc" and f.location.line in specific_lines)]


def _make_finding(rule: Rule, algo: str, path: str, line: int, col: int, text: str, language: str | None) -> Finding:
    usage = rule.usage
    severity = rule.severity if rule.severity is not None else severity_for(algo, usage)
    if rule.confidence == "low":
        severity = severity.lowered()
    category = Category.CONFIG if set(rule.kinds) <= {"config", "iac", "ssh-config"} else Category.SOURCE
    message = explain(algo, usage)
    if rule.unless:
        message = rule.title + ". " + message
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity,
        category=category,
        algorithm=algo,
        usage=usage,
        location=Location(path, line, col, text.strip()[:200]),
        message=message,
        remediation=remediation(algo, usage, language),
        confidence=rule.confidence,
    )


def _private_key_finding(path: str, line: int, m: re.Match) -> Finding:
    kind = (m.group(1) or "").strip()
    algo = {"RSA": "rsa", "EC": "ecc", "DSA": "dsa"}.get(kind, "rsa")
    return Finding(
        rule_id="GEN-EMBEDDED-PRIVATE-KEY",
        title="Private key embedded in a source/config file",
        severity=Severity.CRITICAL,
        category=Category.SECRET,
        algorithm=algo,
        usage=Usage.KEY_MATERIAL,
        location=Location(path, line, None, m.group(0)),
        message="A PEM private key is committed to the repository. Anyone with read access can impersonate its owner, quantum computer or not.",
        remediation="Remove the key, rotate it (generate a new one, ideally post-quantum or hybrid), purge it from git history and load keys from a secrets manager.",
        confidence="high" if kind else "medium",
    )


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(_COMMENT_PREFIXES)


def _suppressed(lines: list[str], lineno: int) -> bool:
    if SUPPRESS_MARKER in lines[lineno - 1]:
        return True
    return lineno >= 2 and SUPPRESS_MARKER in lines[lineno - 2] and _is_comment(lines[lineno - 2])


def scan_file(scanner: SourceScanner, root: Path, path: Path, text: str, kinds: set[str]):
    rel = path.relative_to(root).as_posix() if path != root else path.name
    return scanner.scan(rel, text, kinds)
