<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/postshor/.github/main/brand/logo/postshor-lockup-on-dark.png">
    <img src="https://raw.githubusercontent.com/postshor/.github/main/brand/logo/postshor-lockup-on-light.png" alt="PostShor" width="320">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/postshor/postshor/actions/workflows/ci.yml"><img src="https://github.com/postshor/postshor/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/postshor/postshor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-0B0E14" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-0B0E14" alt="Python 3.11 | 3.12 | 3.13">
  <a href="https://github.com/postshor/postshor/blob/main/docs/spec/qrs-v1.md"><img src="https://img.shields.io/badge/QRS-v1%20draft-FFA630" alt="Quantum Readiness Score v1 draft"></a>
  <a href="https://github.com/marketplace/actions/postshor"><img src="https://img.shields.io/badge/GitHub%20Marketplace-PostShor-0B0E14?logo=github" alt="GitHub Marketplace"></a>
</p>

# PostShor

**Find every piece of quantum-vulnerable cryptography in your software, and get the plan to fix it.**

PostShor scans source code, dependencies, certificates, keys, server configuration, infrastructure-as-code and live TLS endpoints for cryptography that a quantum computer will break. It produces a prioritised migration plan, a standard CycloneDX cryptography bill of materials (CBOM), and an open, comparable [Quantum Readiness Score](https://github.com/postshor/postshor/blob/main/docs/spec/qrs-v1.md).

```
pip install postshor
postshor scan .
```

```
 CRITICAL  RSA-OAEP encryption  PY-RSA-OAEP
           app/crypto.py:14  return public_key.encrypt(data, padding.OAEP(...))
           fix: Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. ...

 CRITICAL  nginx ssl_ecdh_curve excludes post-quantum hybrid groups  CFG-NGINX-CURVES
           deploy/nginx.conf:4  ssl_ecdh_curve X25519:prime256v1;

Summary
  Files scanned:  1,284
  Findings:        3 critical   11 high   4 medium   9 low   6 info
  Quantum Readiness Score (QRS v1.0): D (44/100)
  Harvest-now-decrypt-later exposure detected: fix CRITICAL findings first.
```

## Why now

- **The replacements are standardized.** NIST published ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) in August 2024.
- **The deadlines are set.** NIST plans to deprecate RSA and elliptic-curve cryptography after 2030 and disallow them after 2035. The EU roadmap requires high-risk systems to migrate by 2030, and NSA's CNSA 2.0 has similar dates.
- **The attack has already started.** Data encrypted with RSA or ECDH today can be recorded and decrypted once a quantum computer exists (*harvest now, decrypt later*). You cannot migrate what you cannot find.

## What it finds

| Surface | How | Examples |
|---|---|---|
| Source code | 170 rules for Python, JavaScript/TypeScript, Java/Kotlin, Go, C/C++, C#, Rust, PHP, Ruby, Swift | `rsa.generate_private_key`, `KeyAgreement.getInstance("ECDH")`, `crypto.createECDH`, OpenSSL/mbedTLS/wolfSSL calls |
| Dependencies | 57 known crypto libraries across PyPI, npm, Go, Cargo, Maven/Gradle, NuGet, Composer, RubyGems | `pycrypto`, `node-forge`, `elliptic`, Go toolchains older than 1.24 |
| Certificates & keys | Parses PEM/DER/PKCS#12/OpenSSH | RSA-1024 certs, CA certs valid past 2035, private keys committed to the repo |
| Server configuration | nginx, Apache, HAProxy, OpenSSL, OpenSSH | TLS groups without `X25519MLKEM768`, SSH without `mlkem768x25519-sha256`, no TLS 1.3 |
| Infrastructure-as-code | Terraform, cloud KMS, cert-manager | `tls_private_key` RSA, `ECC_NIST_P256` KMS keys |
| Live endpoints | Active TLS 1.3 probe | Does the server actually negotiate hybrid post-quantum key exchange? |

It also reports what you have **already done right**: ML-KEM, ML-DSA, hybrid groups and post-quantum libraries are recorded as positive evidence.

### Probing live servers

```
postshor tls example.com api.example.com:8443
postshor tls -i hosts.txt -o tls-report.html
```

The probe sends a TLS 1.3 ClientHello that offers a single key-exchange group and no key share. A server that supports the group must answer with a HelloRetryRequest naming it. That proves hybrid ML-KEM support without generating any key material, and it works with any server.

## Reports

Write as many as you need in one run; the format comes from the file extension:

```
postshor scan . -o report.html -o cbom.cdx.json -o results.sarif -o summary.md -o results.json
```

| File | Format | For |
|---|---|---|
| `.html` | Self-contained executive report: grade, deadlines, three-phase migration plan, filterable findings | Leadership, auditors |
| `.cdx.json` | CycloneDX 1.6 CBOM (validated against the official schema) | Compliance, asset inventory, CERT-In / regulator requests |
| `.sarif` | SARIF 2.1.0 | GitHub code scanning, IDEs, Azure DevOps |
| `.md` | Markdown summary with badge | Pull-request comments, CI job summaries |
| `.json` | Complete native output | Automation |

See [docs/examples](https://github.com/postshor/postshor/tree/main/docs/examples) for sample output.

## In CI

**GitHub Actions:**

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: postshor/postshor-action@v1
    with:
      fail-on: critical      # block new harvest-now-decrypt-later exposure
```

Findings appear in GitHub code scanning; the job summary shows the score and migration plan. See [postshor/postshor-action](https://github.com/postshor/postshor-action) for all inputs; it is also listed on the GitHub Marketplace.

**pre-commit:**

```yaml
- repo: https://github.com/postshor/postshor
  rev: v0.1.0
  hooks: [{ id: postshor }]
```

**Docker:** `docker build -t postshor https://github.com/postshor/postshor.git && docker run --rm -v "$PWD:/src" postshor scan .`

### Adopting on an existing codebase

```
postshor baseline .                       # record today's findings
postshor scan . --baseline .postshor-baseline.json --fail-on high
```

New problems fail the build while the backlog is migrated at your own pace.

## Configuration

`.postshor.toml` in the scanned directory:

```toml
exclude = ["third_party/**", "docs"]
disable_rules = ["JOSE-RSA-SIG"]
fail_on = "critical"
min_severity = "low"
tls_targets = ["api.example.com"]
downgrade_tests = true          # cap findings in test code at LOW (default)
```

Suppress a single line with a `postshor:ignore` comment on it or on the line above.

## Quantum Readiness Score

Every scan produces a score from 0 to 100 and a grade from A to F, following the open [QRS v1 specification](https://github.com/postshor/postshor/blob/main/docs/spec/qrs-v1.md). Severity reflects *when* the risk becomes real: key exchange and encryption are CRITICAL because they can be harvested today; signatures are HIGH because forgery needs a working quantum computer. Any critical finding caps the grade at C.

Show it in your README with `postshor scan . --badge`:

![quantum readiness](https://img.shields.io/badge/quantum--readiness-A%20(98)-brightgreen)

## How to read the results

PostShor uses pattern matching and real parsing (certificates, keys, manifests, TLS handshakes). It is a discovery and prioritisation tool:

- A finding means "a quantum-vulnerable primitive is used here". It does not mean the code is exploitable today.
- A clean scan means no known patterns were found, not that the system is quantum-safe. Dynamically chosen algorithms, compiled binaries and hardware modules need additional review.
- Run `postshor rules` to see every rule.

## Project

- [Roadmap](https://github.com/postshor/postshor/blob/main/ROADMAP.md)
- [Architecture](https://github.com/postshor/postshor/blob/main/docs/architecture.md)
- [Contributing](https://github.com/postshor/postshor/blob/main/CONTRIBUTING.md): new rules with tests are the most valuable contribution
- [Security policy](https://github.com/postshor/postshor/blob/main/SECURITY.md)
- [QRS specification](https://github.com/postshor/postshor/blob/main/docs/spec/qrs-v1.md) (CC BY 4.0)

Licensed under the [Apache License 2.0](https://github.com/postshor/postshor/blob/main/LICENSE).
