"""Quantum Readiness Score (QRS) v1. The normative definition is docs/spec/qrs-v1.md.

score = max(0, 100 - sum_s W[s] * log2(1 + n_s))

where n_s is the number of distinct findings at severity s. The log keeps one bad pattern
repeated 500 times from scoring worse than ten different problems, while still rewarding
every fix. Grades: A >= 90, B >= 75, C >= 60, D >= 40, else F; any CRITICAL caps the
grade at C and any HIGH caps it at B.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from postshor.models import Finding, Severity

QRS_VERSION = "1.0"
WEIGHTS = {Severity.CRITICAL: 20.0, Severity.HIGH: 8.0, Severity.MEDIUM: 3.0, Severity.LOW: 1.0, Severity.INFO: 0.0}
_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
_COLORS = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}


@dataclass
class Score:
    value: int
    grade: str
    counts: dict[str, int]
    version: str = QRS_VERSION

    @property
    def badge_url(self) -> str:
        return f"https://img.shields.io/badge/quantum--readiness-{self.grade}%20({self.value})-{_COLORS[self.grade]}"

    @property
    def badge_markdown(self) -> str:
        return f"[![Quantum readiness: {self.grade}]({self.badge_url})](https://github.com/postshor/postshor)"

    def to_dict(self) -> dict:
        return {"qrs_version": self.version, "score": self.value, "grade": self.grade, "counts": self.counts, "badge": self.badge_url}


def compute(findings: list[Finding]) -> Score:
    distinct: dict[Severity, set[str]] = {s: set() for s in Severity}
    for f in findings:
        distinct[f.severity].add(f.fingerprint)
    counts = {s: len(v) for s, v in distinct.items()}
    penalty = sum(WEIGHTS[s] * math.log2(1 + n) for s, n in counts.items())
    value = max(0, round(100 - penalty))
    grade = next(g for floor, g in _BANDS if value >= floor)
    if counts[Severity.CRITICAL] and grade in ("A", "B"):
        grade = "C"
    elif counts[Severity.HIGH] and grade == "A":
        grade = "B"
    return Score(value, grade, {s.label: counts[s] for s in sorted(Severity, reverse=True)})
