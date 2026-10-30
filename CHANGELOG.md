# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). Rule IDs are part of the public interface: removing or renaming one is a breaking change.

## [Unreleased]

### Added

- Rules found by the round-2 recall check (`docs/precision.md`): Rust `openssl` crate (`RS-OPENSSL-*`); JWT/COSE algorithm identifiers (`JWT-ALG-*`); OpenPGP key generation (`PGP-KEYGEN-*`); HTTP message signatures (`HTTPSIG-ALG`); HPKE with classical KEMs, e.g. Encrypted Client Hello (`HPKE-DHKEM`); `GO-TLS-CURVES-DYNAMIC`, `C-TLS-GROUPS-DYNAMIC`, `GO-ECDH-KEY`, `GO-ECDH-EXCHANGE`, `GO-X25519-KEY`.

### Changed

- `GO-TLS-CURVES` and `C-TLS-GROUPS` judge the whole literal list (CRITICAL only when it is classical); lists set from a variable are reported as LOW for review.
- `GO-ECDH` and `GO-X25519` report key exchange only for key generation and the exchange itself; parsing keys is reported as an elliptic-curve key.
- Directories ending in `test`/`tests` (e.g. `caddytest/`) count as test code, except ordinary words such as `latest` or `attest`.

### Fixed

- Matches inside trailing `//` and `#` comments are no longer reported.
- SSH ECDSA host keys are labelled ECDSA instead of RSA.

## [0.1.1] - 2026-10-30

### Fixed

- Remediation advice for Java no longer says JDK 24 provides post-quantum TLS: JDK 24 adds the ML-KEM/ML-DSA APIs, while hybrid TLS (X25519MLKEM768) arrives in JDK 27 (JEP 527). Same correction in the migration plan and TLS endpoint advice.
- More precise ecosystem guidance: pyca/cryptography 47+ (only with AWS-LC/BoringSSL builds), Node.js 24.7+, .NET 10 caveats (MLDsa/SlhDsa experimental, no macOS), rustls `prefer-post-quantum`, Go 1.26 defaults.
- PyCrypto notice now states what is verifiable: no release since 2.6.1, CVE-2013-7459.
- Rule `SW-PQC` matches the CryptoKit ML-KEM/ML-DSA type family instead of unconfirmed symbol names.
- Precision: serious findings that were not real uses dropped from 47% to 0% on a five-library sample (see `docs/precision.md`):
  - private keys in test, fixture, example and documentation paths are capped at LOW and marked as presumed fixtures (still listed);
  - `examples/`, `samples/`, `demos/` and `docs/` count as non-production paths;
  - pattern rules skip Python docstrings and C-style block comments;
  - classical key exchange next to an explicitly named hybrid (X25519MLKEM768, mlkem768x25519, X-Wing) is reported as INFO, not CRITICAL.

### Added

- `docs/sources.md`: a source for every factual claim PostShor makes, with verification dates.
- `docs/precision.md`: measured precision of CRITICAL/HIGH findings, with method and limitations.
- GitHub Marketplace action in its own repository: [postshor/postshor-action](https://github.com/postshor/postshor-action) (`uses: postshor/postshor-action@v1`).

### Security

- The in-repo action no longer interpolates the `fail-on` input directly into a shell command (script-injection hardening).

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

[Unreleased]: https://github.com/postshor/postshor/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/postshor/postshor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/postshor/postshor/releases/tag/v0.1.0
