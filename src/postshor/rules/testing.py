"""Run the examples embedded in rule files (`postshor rules test`)."""

from __future__ import annotations

from postshor.rules.rule import Rule


def check_rule(rule: Rule) -> list[str]:
    """Return a description of every example the rule gets wrong (empty when all pass).

    Each example is scanned on its own, as a file of the rule's first target kind, with only this rule
    enabled: the same code path as a real scan, so comment and docstring handling apply too.
    """
    from postshor.scanners.source import SourceScanner

    scanner = SourceScanner(rules=[rule])
    kinds = {rule.kinds[0]}
    failures = []
    for ex in rule.match_examples:
        found = [f for f in scanner.scan("example", ex.text, kinds)[0] if f.rule_id == rule.id]
        if not found:
            failures.append(f"{rule.id}: should match: {ex.text!r}")
        elif ex.algorithm and found[0].algorithm != ex.algorithm:
            failures.append(f"{rule.id}: expected algorithm {ex.algorithm!r}, got {found[0].algorithm!r}: {ex.text!r}")
    for ex in rule.no_match_examples:
        if any(f.rule_id == rule.id for f in scanner.scan("example", ex.text, kinds)[0]):
            failures.append(f"{rule.id}: should not match: {ex.text!r}")
    return failures
