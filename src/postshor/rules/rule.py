"""A pattern rule as loaded from a rule file (see docs/spec/rule-format-v1.md)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from postshor.models import Severity, Usage

# File "kinds" a rule can target. See postshor.scanners.files.classify.
CODE = ("python", "javascript", "jvm", "go", "c", "csharp", "rust", "php", "ruby", "swift")
TARGETS = (*CODE, "config", "iac", "ssh-config", "any")


@dataclass(frozen=True)
class Example:
    """A rule test case: `text` must (or must not) produce a finding from the rule."""

    text: str
    algorithm: str | None = None  # expected algorithm after refinement, when the test checks it


@dataclass
class Rule:
    id: str
    kinds: tuple[str, ...]
    pattern: str
    algorithm: str
    usage: Usage
    title: str
    confidence: str = "high"
    unless: str | None = None
    severity: Severity | None = None  # override the derived severity
    unless_scope: str = "line"  # "line": test `unless` on the matched line; "match": on the (multi-line) match
    flags: int = 0
    # (regex, algorithm): the first regex found in the matched text sets the algorithm.
    refine: tuple[tuple[str, str], ...] = ()
    match_examples: tuple[Example, ...] = ()
    no_match_examples: tuple[Example, ...] = ()
    origin: str = ""  # rule file it was loaded from
    regex: re.Pattern = field(init=False, repr=False)
    unless_regex: re.Pattern | None = field(init=False, repr=False)
    refine_regexes: tuple[tuple[re.Pattern, str], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, self.flags | re.MULTILINE)
        self.unless_regex = re.compile(self.unless, re.IGNORECASE) if self.unless else None
        self.refine_regexes = tuple((re.compile(p, re.IGNORECASE), a) for p, a in self.refine)

    @property
    def per_line_check(self) -> bool:
        """Configuration checks (an `unless` test or a fixed severity) judge their own match only."""
        return bool(self.unless) or self.severity is not None


def algorithm_for_match(rule: Rule, match: re.Match) -> str:
    """The algorithm a match reports: the first refinement found in the matched text, else the rule's."""
    text = match.group(0)
    for regex, algorithm in rule.refine_regexes:
        if regex.search(text):
            return algorithm
    return rule.algorithm
