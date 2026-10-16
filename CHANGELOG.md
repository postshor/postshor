# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). Rule IDs are part of the public interface: removing or renaming one is a breaking change.

## [Unreleased]

## [0.1.0] - 2026-10-17

### Added

- `postshor scan`: detection of quantum-vulnerable cryptography in source code (170 rules across Python, JavaScript/TypeScript, Java/Kotlin/Scala, Go, C/C++, C#, Rust, PHP, Ruby, Swift), server configuration (OpenSSH, nginx, Apache, HAProxy, OpenSSL) and infrastructure-as-code (Terraform, cloud KMS, cert-manager).
- Certificate and key analysis for PEM, DER, PKCS#12 and OpenSSH formats, including key sizes, validity beyond NIST's 2030/2035 dates, CA detection and trust-store collapsing.
- Dependency analysis for PyPI, npm, Go, Cargo, Maven/Gradle, NuGet, Composer and RubyGems manifests (57 known cryptographic libraries).
- `postshor tls`: live TLS 1.3 probe for hybrid post-quantum key exchange (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) using HelloRetryRequest.
- Reports: console, JSON, SARIF 2.1.0, CycloneDX 1.6 CBOM, Markdown and self-contained HTML with a three-phase migration plan.
- Quantum Readiness Score (QRS) v1 and its specification (`docs/spec/qrs-v1.md`, draft for comment).
- Baselines, inline `postshor:ignore` suppression, `.postshor.toml` configuration, test-code severity cap.
- GitHub Action, pre-commit hook and Dockerfile.
- SARIF output contains only problems; quantum-safe (INFO) findings stay in the JSON, HTML and CBOM reports.

[Unreleased]: https://github.com/postshor/postshor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/postshor/postshor/releases/tag/v0.1.0
