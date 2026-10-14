"""Core data types shared by scanners and reporters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; expected one of: "
                + ", ".join(s.label for s in cls)
            ) from None

    def lowered(self) -> Severity:
        return Severity(max(0, self - 1))


class QuantumStatus(StrEnum):
    """How an algorithm fares against a cryptographically relevant quantum computer."""

    BROKEN = "quantum-broken"  # Shor's algorithm recovers the private key
    WEAKENED = "quantum-weakened"  # Grover's algorithm halves effective security
    SAFE = "quantum-safe"  # standardized post-quantum or adequately sized symmetric
    PRE_STANDARD = "pre-standard-pqc"  # PQC from before FIPS 203/204/205, not interoperable
    CLASSICALLY_BROKEN = "classically-broken"  # already insecure without a quantum computer


class Usage(StrEnum):
    KEY_EXCHANGE = "key-exchange"
    ENCRYPTION = "encryption"
    SIGNATURE = "signature"
    KEY_GENERATION = "key-generation"
    HASH = "hash"
    SYMMETRIC = "symmetric"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    KEY_MATERIAL = "key-material"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class Category(StrEnum):
    SOURCE = "source"
    DEPENDENCY = "dependency"
    CERTIFICATE = "certificate"
    KEY = "key"
    CONFIG = "config"
    NETWORK = "network"
    SECRET = "secret"  # noqa: S105 - a finding category, not a password


@dataclass
class Location:
    path: str
    line: int | None = None
    column: int | None = None
    snippet: str | None = None

    def __str__(self) -> str:
        if self.line is None:
            return self.path
        return f"{self.path}:{self.line}"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    algorithm: str  # key into postshor.rules.algorithms.ALGORITHMS
    usage: Usage
    location: Location
    message: str
    remediation: str
    confidence: str = "high"  # high | medium | low
    details: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives line-number shifts, used for baselines and SARIF."""
        snippet = " ".join((self.location.snippet or "").split())
        raw = f"{self.rule_id}|{self.location.path}|{snippet}|{self.details.get('subject', '')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category.value,
            "algorithm": self.algorithm,
            "usage": self.usage.value,
            "location": {
                "path": self.location.path,
                "line": self.location.line,
                "column": self.location.column,
                "snippet": self.location.snippet,
            },
            "message": self.message,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "details": self.details,
        }


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    suppressed: int = 0
    test_adjustment: bool = True  # QRS section 3: findings in test code capped at LOW
    started_at: str = ""
    finished_at: str = ""

    def by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity].append(f)
        return out
