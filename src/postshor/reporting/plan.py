"""Turns findings into a phased migration plan, shared by the HTML and Markdown reports."""

from __future__ import annotations

from dataclasses import dataclass, field

from postshor.models import Category, Finding, QuantumStatus, Severity, Usage
from postshor.rules import ALGORITHMS


@dataclass
class Phase:
    key: str
    title: str
    deadline: str
    why: str
    actions: list[str]
    findings: list[Finding] = field(default_factory=list)


def build_plan(findings: list[Finding]) -> list[Phase]:
    phases = [
        Phase("now", "Phase 1: Stop the harvest", "Now (0–12 months)",
              "Key exchange and encryption recorded today can be decrypted later. This exposure is already happening.",
              ["Remove committed private keys and rotate them.",
               "Enable hybrid X25519MLKEM768 on every TLS endpoint and mlkem768x25519-sha256 for SSH.",
               "Replace RSA-OAEP / ECDH / DH key wrapping of long-lived data with ML-KEM (hybrid during transition).",
               "Upgrade TLS stacks: OpenSSL 3.5+, Go 1.24+, Java 24+, .NET 10, rustls with aws-lc-rs."]),
        Phase("2030", "Phase 2: Replace signatures and identities", "Before 2030 (NIST deprecation)",
              "Signatures can only be forged after Q-day, but roots, firmware keys and PKI take years to rotate.",
              ["Inventory CAs and long-lived certificates; plan ML-DSA (or composite) hierarchies.",
               "Move firmware and code signing to ML-DSA, SLH-DSA or LMS/XMSS.",
               "Replace RSA/ECDSA JWT and API signatures with ML-DSA once your libraries support it.",
               "Automate certificate rotation so the switch is a configuration change."]),
        Phase("hygiene", "Phase 3: Clean up and build agility", "Ongoing",
              "Algorithms that are already broken, plus everything that makes the next migration cheaper.",
              ["Remove MD5, SHA-1, DES/3DES, RC4 and legacy TLS versions.",
               "Move to AES-256 where CNSA 2.0 applies.",
               "Upgrade pre-standard Kyber/Dilithium to ML-KEM/ML-DSA.",
               "Route cryptography through a central, configurable layer (crypto-agility)."]),
    ]
    by_key = {p.key: p for p in phases}
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        status = ALGORITHMS[f.algorithm].status if f.algorithm in ALGORITHMS else None
        if f.category is Category.SECRET or (
            status is QuantumStatus.BROKEN and f.usage in (Usage.KEY_EXCHANGE, Usage.ENCRYPTION)
        ) or f.rule_id in ("TLS-NO-TLS13", "CFG-TLS-NO13", "DEP-GO-TOOLCHAIN-PRE-PQ"):
            by_key["now"].findings.append(f)
        elif status is QuantumStatus.BROKEN:
            by_key["2030"].findings.append(f)
        else:
            by_key["hygiene"].findings.append(f)
    return phases


def inventory(findings: list[Finding]) -> list[tuple[str, int, int]]:
    """(algorithm name, occurrences, distinct files) sorted by occurrences."""
    counts: dict[str, tuple[int, set[str]]] = {}
    for f in findings:
        name = ALGORITHMS[f.algorithm].name if f.algorithm in ALGORITHMS else f.algorithm
        n, paths = counts.get(name, (0, set()))
        paths.add(f.location.path)
        counts[name] = (n + 1, paths)
    return sorted(((k, n, len(p)) for k, (n, p) in counts.items()), key=lambda r: -r[1])
