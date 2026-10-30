"""Command-line interface: `postshor scan`, `postshor tls`, `postshor rules`, `postshor baseline`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from postshor import __version__, engine, score
from postshor.models import Severity
from postshor.reporting import FORMATS, console, format_for_path
from postshor.rules import ALGORITHMS, RULES, load_rule_files
from postshor.rules.testing import check_rule

EXIT_OK, EXIT_POLICY, EXIT_ERROR = 0, 1, 2


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _add_report_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-o", "--output", action="append", default=[], metavar="FILE",
                   help="write a report; format from extension (.html .json .sarif .cdx.json .md). Repeatable.")
    p.add_argument("-f", "--format", choices=["console", *FORMATS], default="console",
                   help="format printed to stdout (default: console)")
    p.add_argument("--fail-on", type=_severity, metavar="SEVERITY",
                   help="exit 1 if any finding is at or above this severity (critical|high|medium|low|info)")
    p.add_argument("--min-severity", type=_severity, metavar="SEVERITY", help="hide findings below this severity")
    p.add_argument("-v", "--verbose", action="store_true", help="show every finding with full explanations")
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing to stdout except errors")
    p.add_argument("--badge", action="store_true", help="print a README badge for the score")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="postshor",
        description="PostShor: find quantum-vulnerable cryptography in code, dependencies, certificates, "
                    "configuration and live servers, and get a migration plan.",
    )
    parser.add_argument("--version", action="version", version=f"postshor {__version__}")
    sub = parser.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a directory or file")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude paths (repeatable)")
    s.add_argument("--include-vendored", action="store_true", help="also scan vendor/, third_party/ and similar")
    s.add_argument("--disable-rule", action="append", default=[], metavar="RULE_ID")
    s.add_argument("--rules", action="append", default=[], type=Path, metavar="FILE",
                   help="add custom rules from a rule file (docs/spec/rule-format-v1.md). Repeatable.")
    s.add_argument("--no-source", action="store_true", help="skip source/config pattern rules")
    s.add_argument("--no-deps", action="store_true", help="skip dependency manifests")
    s.add_argument("--no-keys", action="store_true", help="skip certificate and key files")
    s.add_argument("--tls", action="append", default=[], metavar="HOST[:PORT]", help="also probe a live TLS endpoint (repeatable)")
    s.add_argument("--baseline", type=Path, metavar="FILE", help="hide findings recorded in a baseline file")
    s.add_argument("--tests-as-production", action="store_true",
                   help="do not cap findings in test code at LOW severity")
    _add_report_args(s)

    t = sub.add_parser("tls", help="probe live TLS endpoints for post-quantum key exchange")
    t.add_argument("targets", nargs="*", metavar="HOST[:PORT]")
    t.add_argument("-i", "--input", type=Path, help="file with one HOST[:PORT] per line")
    t.add_argument("--timeout", type=float, default=5.0)
    _add_report_args(t)

    r = sub.add_parser("rules", help="list detection rules, or test them against their examples")
    r.add_argument("action", nargs="?", choices=["list", "test"], default="list",
                   help="list (default) or test: run every rule's match/no_match examples")
    r.add_argument("files", nargs="*", type=Path, metavar="FILE", help="custom rule files (default: built-in rules)")
    r.add_argument("--json", action="store_true")
    r.add_argument("--algorithms", action="store_true", help="list the algorithm IDs rules can report")

    b = sub.add_parser("baseline", help="record current findings so future scans only report new ones")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", type=Path, default=Path(".postshor-baseline.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "tls":
            return _cmd_tls(args)
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "baseline":
            return _cmd_baseline(args)
    except (ValueError, OSError) as exc:
        print(f"postshor: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_OK


def _cmd_scan(args) -> int:
    target = Path(args.path)
    if not target.exists():
        raise ValueError(f"path not found: {args.path}")
    options, config = engine.ScanOptions.from_config(target)
    options.excludes += args.exclude
    options.include_vendored |= args.include_vendored
    options.disabled_rules |= set(args.disable_rule)
    options.rule_files += args.rules
    options.source, options.deps, options.keys = not args.no_source, not args.no_deps, not args.no_keys
    options.tls_targets += args.tls
    if args.tests_as_production:
        options.downgrade_tests = False
    if args.min_severity is not None:
        options.min_severity = args.min_severity
    if args.baseline:
        options.baseline = engine.load_baseline(args.baseline)
    if args.fail_on is None and "fail_on" in config:
        args.fail_on = Severity.parse(config["fail_on"])
    return _finish(engine.scan(args.path, options), args)  # report the target as the user typed it


def _cmd_tls(args) -> int:
    targets = list(args.targets)
    if args.input:
        lines = args.input.read_text(encoding="utf-8").splitlines()
        targets += [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    if not targets:
        raise ValueError("no TLS targets given")
    options = engine.ScanOptions(tls_targets=targets, tls_timeout=args.timeout)
    if args.min_severity is not None:
        options.min_severity = args.min_severity
    result = engine.scan(None, options)
    result.target = ", ".join(targets)
    return _finish(result, args)


def _finish(result, args) -> int:
    s = score.compute(result.findings)
    for out in args.output:
        fmt = format_for_path(out)
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(FORMATS[fmt](result, s), encoding="utf-8")
    if not args.quiet:
        if args.format == "console":
            sys.stdout.write(console.render(result, s, verbose=args.verbose))
            for out in args.output:
                print(f"  report written: {out}")
        else:
            sys.stdout.write(FORMATS[args.format](result, s) + "\n")
        if args.badge:
            print(s.badge_markdown)
    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        if not args.quiet and args.format == "console":
            print(f"  failing: findings at or above '{args.fail_on.label}' (--fail-on)", file=sys.stderr)
        return EXIT_POLICY
    return EXIT_OK


def _cmd_rules(args) -> int:
    if args.algorithms:
        for key, algo in ALGORITHMS.items():
            print(f"{key:<16}  {algo.name}")
        return EXIT_OK
    rules = load_rule_files(args.files, RULES) if args.files else RULES
    if args.action == "test":
        return _test_rules(rules)
    if args.json:
        print(json.dumps([
            {"id": r.id, "kinds": list(r.kinds), "algorithm": r.algorithm, "usage": r.usage.value,
             "title": r.title, "confidence": r.confidence, "pattern": r.pattern, "unless": r.unless,
             "origin": r.origin}
            for r in rules], indent=2))
        return EXIT_OK
    width = max(len(r.id) for r in rules)
    for r in rules:
        print(f"{r.id:<{width}}  {ALGORITHMS[r.algorithm].name:<32}  {r.title}")
    if args.files:
        print(f"\n{len(rules)} custom rules in {len(args.files)} file(s), all valid.")
    else:
        print(f"\n{len(RULES)} pattern rules, plus certificate/key parsing, dependency manifests and live TLS probing.")
    return EXIT_OK


def _test_rules(rules) -> int:
    failures = [msg for r in rules for msg in check_rule(r)]
    examples = sum(len(r.match_examples) + len(r.no_match_examples) for r in rules)
    for msg in failures:
        print(f"FAIL {msg}")
    print(f"{len(rules)} rules, {examples} examples: {len(failures)} failed")
    return EXIT_POLICY if failures else EXIT_OK


def _cmd_baseline(args) -> int:
    target = Path(args.path)
    options, _ = engine.ScanOptions.from_config(target)
    result = engine.scan(target, options)
    data = {
        "tool": "postshor", "version": __version__,
        "note": "Accepted findings. Scans with --baseline hide these and report only new ones.",
        "findings": [{"fingerprint": f.fingerprint, "rule_id": f.rule_id, "location": str(f.location)} for f in result.findings],
    }
    args.output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"baseline with {len(result.findings)} findings written to {args.output}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
