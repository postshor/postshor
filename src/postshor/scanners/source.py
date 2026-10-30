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

        doc_lines = _documentation_lines(text, kinds, line_starts)
        for rule in rules:
            for m in rule.regex.finditer(text):
                lineno = bisect.bisect_right(line_starts, m.start())
                line = lines[lineno - 1]
                if rule.unless_regex and rule.unless_regex.search(m.group(0) if rule.unless_scope == "match" else line):
                    continue
                col = m.start() - line_starts[lineno - 1]
                if _is_comment(line) or lineno in doc_lines or _in_trailing_comment(line, col, kinds):
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
        _mark_hybrid_components(findings, text, line_starts)
        return sorted(findings, key=lambda f: f.location.line or 0), suppressed


_HASH_COMMENT_KINDS = {"python", "ruby", "config", "iac", "ssh-config"}


def _in_trailing_comment(line: str, col: int, kinds: set[str]) -> bool:
    """True if position `col` lies in a comment that starts after code on the same line
    (`code  // note` or `code  # note`). Quotes are tracked so "http://x" is not a comment."""
    markers = []
    if kinds & _C_LIKE:
        markers.append("//")
    if kinds & _HASH_COMMENT_KINDS:
        markers.append("#")
    if not markers:
        return False
    quote = None
    i = 0
    while i < col:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif any(line.startswith(mk, i) for mk in markers):
            return True
        i += 1
    return False


_PY_TRIPLE_QUOTED = re.compile(r'("""|\'\'\')(.*?)\1', re.DOTALL)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LIKE = {"javascript", "jvm", "go", "c", "csharp", "rust", "php", "swift"}


def _documentation_lines(text: str, kinds: set[str], line_starts: list[int]) -> set[int]:
    """Line numbers inside Python triple-quoted strings (docstrings) or C-style block comments.

    Pattern rules skip these lines: algorithm names in documentation ("e.g. 'ES256'") are not
    uses of cryptography. Private-key detection still runs on them.
    """
    spans = []
    if "python" in kinds:
        spans += _python_triple_quoted_spans(text, line_starts)
    if kinds & _C_LIKE:
        spans += [m.span() for m in _BLOCK_COMMENT.finditer(text)]
    lines: set[int] = set()
    for start, end in spans:
        first = bisect.bisect_right(line_starts, start)
        last = bisect.bisect_right(line_starts, max(start, end - 1))
        lines.update(range(first, last + 1))
    return lines


# Explicit hybrid naming only: a bare "ML-KEM" mention elsewhere in a file does not make an
# independent ECDH use safe (that case must stay CRITICAL).
_HYBRID_MARKER = re.compile(
    r"x25519mlkem\d+|secp\d+r1mlkem\d+|mlkem\d+x25519|mlkem\d+nistp\d+|x25519kyber\d+|sntrup761x25519|x-?wing|\bhybrid\b",
    re.IGNORECASE,
)
_HYBRID_WINDOW = 40  # lines
# Configuration checks (rules with an `unless` test or a fixed severity) judge their own match;
# never soften them because of nearby lines.
_PER_LINE_CHECKS = {r.id for r in RULES if r.unless or r.severity is not None}


def _mark_hybrid_components(findings: list[Finding], text: str, line_starts: list[int]) -> None:
    """Classical key exchange near an explicitly named hybrid (X25519MLKEM768, mlkem768x25519-sha256,
    X-Wing, ...) is the classical half of that hybrid, which is quantum-safe as a whole.
    Found on paramiko's kex_mlkem.py during the false-positive review (2026-10-30)."""
    marker_lines = [bisect.bisect_right(line_starts, m.start()) for m in _HYBRID_MARKER.finditer(text)]
    if not marker_lines:
        return
    for f in findings:
        if f.rule_id in _PER_LINE_CHECKS:
            continue
        if f.algorithm in ("x25519", "ecdh", "dh") and f.usage is Usage.KEY_EXCHANGE and f.location.line:
            nearest = min(abs(f.location.line - m) for m in marker_lines)
            if nearest <= _HYBRID_WINDOW:
                f.details["context"] = "hybrid"
                f.details["original_severity"] = f.severity.label
                f.severity = Severity.INFO
                f.confidence = "medium"
                f.message = ("Classical key exchange used next to ML-KEM: likely the classical component of a hybrid "
                             "post-quantum key exchange, which is quantum-safe as a whole. " + f.message)
                f.remediation = "No action if this is part of a hybrid with ML-KEM; verify the classical exchange is not also used on its own."


def _python_triple_quoted_spans(text: str, line_starts: list[int]) -> list[tuple[int, int]]:
    """Character spans of triple-quoted string literals, found with Python's own tokenizer so that
    quote characters inside other strings cannot misalign the pairing. Falls back to a regex for
    files that do not tokenize (syntax errors, other Python versions)."""
    import io
    import tokenize

    spans = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING and tok.string.lstrip("rbuRBUfF").startswith(('"""', "'''")):
                (sl, sc), (el, ec) = tok.start, tok.end
                spans.append((line_starts[sl - 1] + sc, line_starts[el - 1] + ec))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return [m.span() for m in _PY_TRIPLE_QUOTED.finditer(text)]
    return spans


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
