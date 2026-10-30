"""Load and validate PostShor rule files (TOML, format version 1).

The format is specified in docs/spec/rule-format-v1.md. Built-in rules live in
postshor/rules/data/*.toml; users can add their own files with `--rules` or `rules = [...]`
in .postshor.toml. Every problem in a file is reported, not only the first one.
"""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path

from postshor.models import Severity, Usage
from postshor.rules.algorithms import ALGORITHMS
from postshor.rules.rule import TARGETS, Example, Rule

FORMAT_VERSION = 1
BUILTIN_FILES = ("python", "jvm", "go", "javascript", "c", "csharp", "rust", "php", "ruby", "swift",
                 "identifiers", "config", "generic")

_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
_REQUIRED = ("id", "title", "targets", "algorithm", "usage", "pattern", "tests")
_OPTIONAL = ("confidence", "severity", "flags", "unless", "unless_scope", "refine")
_FLAGS = {"ignorecase": re.IGNORECASE}
_CONFIDENCE = ("high", "medium", "low")
_USAGES = {u.value: u for u in Usage}


class RuleFormatError(ValueError):
    """A rule file does not follow the rule format. The message lists every problem found."""


def load_builtin_rules() -> list[Rule]:
    data = resources.files("postshor.rules") / "data"
    rules: list[Rule] = []
    for name in BUILTIN_FILES:
        rules += parse_rules(data.joinpath(f"{name}.toml").read_text(encoding="utf-8"), f"builtin:{name}.toml",
                             taken={r.id for r in rules})
    return rules


def load_rule_files(paths: list[Path], builtin: list[Rule]) -> list[Rule]:
    """Load custom rule files. Their IDs must not collide with built-in rules or with each other."""
    taken = {r.id for r in builtin}
    rules: list[Rule] = []
    for path in paths:
        loaded = parse_rules(Path(path).read_text(encoding="utf-8"), str(path), taken)
        taken |= {r.id for r in loaded}
        rules += loaded
    return rules


def parse_rules(text: str, origin: str, taken: set[str] | None = None) -> list[Rule]:
    taken = set(taken or ())
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleFormatError(f"{origin}: not valid TOML: {exc}") from None
    errors: list[str] = []
    version = doc.get("format", FORMAT_VERSION)
    if version != FORMAT_VERSION:
        errors.append(f"unsupported format {version!r} (this PostShor reads format {FORMAT_VERSION})")
    errors += [f"unknown top-level key {k!r}" for k in doc if k not in ("format", "rule")]
    entries = doc.get("rule", [])
    if not isinstance(entries, list) or not entries:
        errors.append("no [[rule]] entries")
        entries = []

    rules = []
    for i, entry in enumerate(entries, 1):
        label = f"rule {entry.get('id', f'#{i}')}" if isinstance(entry, dict) else f"rule #{i}"
        problems: list[str] = []
        rule = _parse_rule(entry, origin, problems) if isinstance(entry, dict) else None
        if rule is not None and rule.id in taken:
            problems.append(f"duplicate id {rule.id!r}")
        errors += [f"{label}: {p}" for p in problems]
        if rule is not None and not problems:
            taken.add(rule.id)
            rules.append(rule)
    if errors:
        raise RuleFormatError(f"{origin}:\n  " + "\n  ".join(errors))
    return rules


def _parse_rule(entry: dict, origin: str, problems: list[str]) -> Rule | None:
    problems += [f"missing {k!r}" for k in _REQUIRED if k not in entry]
    problems += [f"unknown key {k!r}" for k in entry if k not in _REQUIRED + _OPTIONAL]
    if problems:
        return None

    rule_id = entry["id"]
    if not isinstance(rule_id, str) or not _ID.match(rule_id):
        problems.append(f"id {rule_id!r} must be upper-case words joined by '-' (e.g. ACME-RSA-KEYGEN)")
    for key in ("title", "pattern"):
        if not isinstance(entry[key], str) or not entry[key].strip():
            problems.append(f"{key!r} must be a non-empty string")
    targets = entry["targets"]
    if not isinstance(targets, list) or not targets or any(t not in TARGETS for t in targets):
        problems.append(f"'targets' must be a non-empty list from {', '.join(TARGETS)}")
    _check_algorithm(entry["algorithm"], "algorithm", problems)
    if entry["usage"] not in _USAGES:
        problems.append(f"unknown usage {entry['usage']!r} (one of {', '.join(_USAGES)})")
    if entry.get("confidence", "high") not in _CONFIDENCE:
        problems.append(f"'confidence' must be one of {', '.join(_CONFIDENCE)}")
    severity = None
    if "severity" in entry:
        try:
            severity = Severity.parse(str(entry["severity"]))
        except ValueError:
            problems.append(f"unknown severity {entry['severity']!r}")
    flags = entry.get("flags", [])
    if not isinstance(flags, list) or any(f not in _FLAGS for f in flags):
        problems.append(f"'flags' must be a list from {', '.join(_FLAGS)}")
        flags = []
    if "unless_scope" in entry and ("unless" not in entry or entry["unless_scope"] not in ("line", "match")):
        problems.append("'unless_scope' needs 'unless' and must be 'line' or 'match'")
    for key in ("pattern", "unless"):
        if isinstance(entry.get(key), str):
            _check_regex(entry[key], key, problems)

    refine = []
    for r in entry.get("refine", []):
        if not isinstance(r, dict) or set(r) != {"match", "algorithm"}:
            problems.append("each [[rule.refine]] needs exactly 'match' and 'algorithm'")
            continue
        _check_regex(r["match"], "refine match", problems)
        _check_algorithm(r["algorithm"], "refine algorithm", problems)
        refine.append((r["match"], r["algorithm"]))

    tests = entry["tests"]
    if not isinstance(tests, dict) or set(tests) - {"match", "no_match"}:
        problems.append("'tests' must be a table with 'match' and optional 'no_match'")
        tests = {}
    match = _examples(tests.get("match"), "tests.match", problems)
    no_match = _examples(tests.get("no_match", []), "tests.no_match", problems, allow_empty=True)
    if not match and "match" not in tests:
        problems.append("'tests.match' needs at least one example the rule must find")
    if problems:
        return None
    return Rule(
        id=rule_id, kinds=tuple(targets), pattern=entry["pattern"], algorithm=entry["algorithm"],
        usage=_USAGES[entry["usage"]], title=entry["title"], confidence=entry.get("confidence", "high"),
        unless=entry.get("unless"), severity=severity, unless_scope=entry.get("unless_scope", "line"),
        flags=sum(_FLAGS[f] for f in set(flags)), refine=tuple(refine),
        match_examples=match, no_match_examples=no_match, origin=origin,
    )


def _examples(value, key: str, problems: list[str], allow_empty: bool = False) -> tuple[Example, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or (not value and not allow_empty):
        problems.append(f"{key!r} must be a {'' if allow_empty else 'non-empty '}list")
        return ()
    examples = []
    for item in value:
        if isinstance(item, str):
            examples.append(Example(item))
        elif isinstance(item, dict) and isinstance(item.get("text"), str) and set(item) <= {"text", "algorithm"}:
            if "algorithm" in item:
                _check_algorithm(item["algorithm"], f"{key} algorithm", problems)
            examples.append(Example(item["text"], item.get("algorithm")))
        else:
            problems.append(f"{key!r} entries must be strings or {{ text = ..., algorithm = ... }} tables")
    return tuple(examples)


def _check_algorithm(value, key: str, problems: list[str]) -> None:
    if value not in ALGORITHMS:
        problems.append(f"unknown {key} {value!r} (see `postshor rules --algorithms`)")


def _check_regex(value, key: str, problems: list[str]) -> None:
    if not isinstance(value, str):
        problems.append(f"{key!r} must be a string")
        return
    try:
        re.compile(value)
    except re.error as exc:
        problems.append(f"{key!r} is not a valid regular expression: {exc}")
