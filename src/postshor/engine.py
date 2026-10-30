"""Orchestrates all scanners over a target and applies config, baseline and filters."""

from __future__ import annotations

import datetime as dt
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from postshor.models import Category, Finding, ScanResult, Severity
from postshor.scanners import certificates, dependencies, files, tls
from postshor.scanners.source import SourceScanner, scan_file

CONFIG_FILE = ".postshor.toml"


@dataclass
class ScanOptions:
    excludes: list[str] = field(default_factory=list)
    include_vendored: bool = False
    disabled_rules: set[str] = field(default_factory=set)
    min_severity: Severity = Severity.INFO
    source: bool = True
    deps: bool = True
    keys: bool = True
    tls_targets: list[str] = field(default_factory=list)
    tls_timeout: float = 5.0
    baseline: set[str] = field(default_factory=set)
    downgrade_tests: bool = True

    @classmethod
    def from_config(cls, root: Path) -> tuple[ScanOptions, dict]:
        """Load .postshor.toml from the scan root (or its parent for a single file)."""
        base = root if root.is_dir() else root.parent
        path = base / CONFIG_FILE
        opts = cls()
        raw: dict = {}
        if path.is_file():
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
            opts.excludes = list(raw.get("exclude", []))
            opts.include_vendored = bool(raw.get("include_vendored", False))
            opts.disabled_rules = set(raw.get("disable_rules", []))
            if "min_severity" in raw:
                opts.min_severity = Severity.parse(raw["min_severity"])
            opts.tls_targets = list(raw.get("tls_targets", []))
            opts.downgrade_tests = bool(raw.get("downgrade_tests", True))
        return opts, raw


def scan(target: str | Path | None, options: ScanOptions | None = None) -> ScanResult:
    """Scan a path (or only TLS targets when target is None)."""
    options = options or ScanOptions()
    root = Path(target).resolve() if target is not None else None
    result = ScanResult(target=str(target or ""), started_at=_now(), test_adjustment=options.downgrade_tests)
    findings: list[Finding] = []

    if root is not None and root.exists():
        src = SourceScanner(disabled=options.disabled_rules)
        for path in files.walk(root, options.excludes, options.include_vendored):
            rel = path.relative_to(root).as_posix() if path != root else path.name
            try:
                if options.keys and files.is_key_file(path):
                    if path.stat().st_size <= files.MAX_FILE_BYTES:
                        findings.extend(certificates.scan_key_file(rel, path.read_bytes()))
                        result.files_scanned += 1
                    continue
                kinds = files.classify(path)
                manifest = options.deps and dependencies.is_manifest(path)
                if not kinds and not manifest:
                    continue
                text = files.read_text(path)
                if text is None:
                    continue
                result.files_scanned += 1
                if manifest:
                    findings.extend(dependencies.scan_manifest(path, rel, text))
                if kinds and options.source:
                    found, suppressed = scan_file(src, root, path, text, kinds)
                    findings.extend(found)
                    result.suppressed += suppressed
            except OSError as exc:
                result.errors.append(f"{rel}: {exc}")
    elif root is not None:
        result.errors.append(f"target not found: {target}")

    if options.tls_targets:
        for report in tls.scan_endpoints(options.tls_targets, options.tls_timeout):
            findings.extend(tls.report_findings(report))

    findings = [f for f in findings if f.rule_id not in options.disabled_rules]
    if options.downgrade_tests:
        _downgrade_test_findings(findings)
    if options.baseline:
        before = len(findings)
        findings = [f for f in findings if f.fingerprint not in options.baseline]
        result.suppressed += before - len(findings)
    findings = [f for f in findings if f.severity >= options.min_severity]
    findings.sort(key=lambda f: (-f.severity, f.location.path, f.location.line or 0))
    result.findings = findings
    result.finished_at = _now()
    return result


# Non-production code: tests, fixtures, examples, samples, demos and documentation.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testdata|test_data|fixtures|src/test"
    r"|examples?|samples?|demos?|docs?)/"
    r"|(^|/)(test_[^/]+\.py|[^/]+_test\.(py|go)|[^/]+\.(test|spec)\.[jt]sx?|[^/]+Tests?\.(java|kt|cs))$"
)


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


def _downgrade_test_findings(findings: list[Finding]) -> None:
    """Non-production code (tests, fixtures, examples, docs) uses throwaway keys and algorithms on
    purpose: keep it in the inventory, cap it at LOW.

    This includes committed private keys. Measured on five widely used cryptography libraries,
    private keys in test paths were intentional public fixtures in every case and made up 40 % of
    all critical/high findings. They stay visible (LOW, marked as presumed fixtures) so a real
    key committed to a test folder is still reported.
    """
    for f in findings:
        if f.severity > Severity.LOW and is_test_path(f.location.path):
            f.details["context"] = "test"
            f.details["original_severity"] = f.severity.label
            if f.category is Category.SECRET:
                f.details["note"] = "Presumed test fixture. If this key is used anywhere outside tests, treat it as compromised."
            f.severity = Severity.LOW


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {f["fingerprint"] for f in data.get("findings", [])} | set(data.get("fingerprints", []))


def _now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
