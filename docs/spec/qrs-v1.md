# Quantum Readiness Score (QRS) — Specification v1.0

**Status:** Draft for public comment
**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Anyone may implement, adapt and redistribute this specification with attribution.
**Reference implementation:** [PostShor](https://github.com/postshor/postshor) (`src/postshor/score.py`, `src/postshor/rules/algorithms.py`)

## 1. Purpose

Organisations must move from RSA and elliptic-curve cryptography to post-quantum algorithms (FIPS 203/204/205) before a cryptographically relevant quantum computer (CRQC) exists. Today, nobody can say *how ready* a codebase, product or organisation is in a way that is comparable between tools and over time.

QRS defines:

1. a **severity classification** for cryptographic findings that accounts for *when* the quantum risk materialises, and
2. a **score (0–100) and grade (A–F)** computed from those findings.

QRS does not specify how findings are discovered. Any scanner, manual audit or CBOM can produce QRS-conformant results.

## 2. Terms

| Term | Meaning |
|---|---|
| Finding | One occurrence of a cryptographic algorithm, key, certificate, protocol setting or library at a location. |
| Quantum-broken | Broken by Shor's algorithm on a CRQC: RSA, DSA, finite-field DH, ECDSA, ECDH, EdDSA, X25519/X448, other discrete-log and factoring schemes. |
| Quantum-weakened | Security margin reduced by Grover's algorithm but not broken, e.g. AES-128. |
| Classically broken | Insecure without a quantum computer: MD5, SHA-1 (for signatures/integrity), DES, 3DES, RC4, SSL 3.0, TLS 1.0/1.1. |
| Pre-standard PQC | Post-quantum schemes from before the final FIPS: Kyber round 3, Dilithium round 3, SPHINCS+, original Falcon, X25519Kyber768Draft00. |
| Quantum-safe | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, LMS/XMSS, hybrid groups containing ML-KEM, and adequately sized symmetric primitives. |
| HNDL | Harvest-now-decrypt-later: recording encrypted data today to decrypt after a CRQC exists. |

## 3. Severity classification

A finding receives exactly one severity. Implementations MUST apply the first matching row.

| # | Condition | Severity | Rationale |
|---|---|---|---|
| 1 | Private key material stored in source, configuration or an artifact repository | CRITICAL | Compromised today regardless of quantum computing. |
| 2 | Quantum-broken algorithm used for **key exchange or encryption** (including TLS/SSH configurations that offer no hybrid PQ group, and TLS endpoints without TLS 1.3) | CRITICAL | HNDL: the exposure starts the moment traffic is recorded. |
| 3 | Classically weak key size (RSA/DSA/DH < 2048 bits, EC < 224 bits) | CRITICAL | Breakable without a quantum computer. |
| 4 | Quantum-broken algorithm used for **signatures, authentication, certificates or key generation of unknown purpose** | HIGH | Forgery requires a CRQC, but long-lived keys and PKI take years to replace. |
| 5 | Classically broken cipher or protocol version | HIGH | |
| 6 | Classically broken hash (MD5, SHA-1) | MEDIUM | Frequently used for non-security checksums; requires review. |
| 7 | Quantum-broken certificate observed on a live public endpoint | MEDIUM | Public CAs do not yet issue PQ certificates; this is a planning item, not an actionable defect. |
| 8 | Public key (not certificate) of a quantum-broken algorithm | MEDIUM | |
| 9 | Library that provides quantum-broken primitives (inventory only) | LOW | Usage is assessed by rows 1–8. |
| 10 | Quantum-weakened or pre-standard PQC | LOW | |
| 11 | Trust store / CA bundle containing quantum-broken roots | LOW | Requires updatability, not action. |
| 12 | Quantum-safe usage | INFO | Positive evidence; does not affect the score. |

**Context adjustment.** Findings located in test code (test directories and test-file naming conventions of the language) SHOULD be capped at LOW, except row 1. Implementations MUST disclose whether this adjustment was applied.

## 4. Score

Let *n*<sub>s</sub> be the number of **distinct** findings at severity *s* (findings are distinct when they differ in rule, location path, or matched content; line numbers alone do not distinguish findings).

```
penalty = 20·log2(1 + n_critical) + 8·log2(1 + n_high) + 3·log2(1 + n_medium) + 1·log2(1 + n_low)
score   = max(0, round(100 − penalty))
```

Rationale for the logarithm: one pattern repeated 500 times should not outweigh ten different problems, yet every remediated finding must still raise the score (the function is strictly monotonic).

Reference values:

| Findings | Score |
|---|---|
| none | 100 |
| 1 high | 92 |
| 1 critical | 80 |
| 3 critical, 7 high | 36 |
| 15 critical, 19 high, 5 medium, 1 low | 0 |

## 5. Grade

| Score | Grade |
|---|---|
| ≥ 90 | A |
| ≥ 75 | B |
| ≥ 60 | C |
| ≥ 40 | D |
| < 40 | F |

**Caps:** any CRITICAL finding caps the grade at **C**; any HIGH finding caps it at **B**. An organisation with live HNDL exposure cannot present itself as "B" or better.

## 6. Reporting requirements

A QRS result MUST state: the QRS version, the score, the grade, the per-severity counts, the scope (what was scanned), and whether the test-code adjustment was applied. Example (JSON):

```json
{ "qrs_version": "1.0", "score": 72, "grade": "C",
  "counts": { "critical": 1, "high": 0, "medium": 4, "low": 2, "info": 7 },
  "scope": "repository github.com/acme/payments@3f2c1e", "test_adjustment": true }
```

Badges SHOULD use the form `quantum-readiness: <grade> (<score>)`.

## 7. Versioning

Changes to weights, caps or classification rows produce a new minor (compatible intent) or major (incompatible) version. Scores from different major versions MUST NOT be compared.

## 8. Known limitations (v1)

- The score measures the *presence* of risky cryptography, not the value of the data it protects. Organisations should weight results by data lifetime (Mosca's inequality: if data shelf-life + migration time > time to CRQC, act now).
- Static discovery has false negatives (dynamic algorithm selection, binaries, hardware). A high score means "no known problems found", not "quantum-safe".
- Hybrid deployments are treated as quantum-safe.

## 9. Feedback

Open an issue labelled `spec:qrs` in the PostShor repository. Proposed changes are discussed publicly before a version is published.
