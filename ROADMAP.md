# Roadmap

PostShor aims to be the open baseline the industry uses to find, measure and track quantum-vulnerable cryptography. Dates are targets, not promises.

## v0.1 — Foundation (released)

- [x] 170 pattern rules across 10 languages plus server configuration and IaC
- [x] Certificate, key, PKCS#12 and OpenSSH parsing with NIST-date awareness
- [x] Dependency manifests for 10 ecosystems
- [x] Live TLS 1.3 post-quantum key-exchange probe
- [x] Reports: console, JSON, SARIF 2.1.0, CycloneDX 1.6 CBOM, Markdown, HTML
- [x] Quantum Readiness Score specification v1 (draft for comment)
- [x] GitHub Action, pre-commit hook, Docker image, baselines, inline suppression

## v0.2 — Measured precision (released)

- [x] Precision and recall measured on nine open-source projects and published (`docs/precision.md`)
- [x] 188 rules, including JWT/COSE identifiers, OpenPGP, HTTP message signatures and HPKE

## v0.3 — Open rules (current)

- [x] Data-driven rule format with its own published spec ([Rule Format v1](docs/spec/rule-format-v1.md), TOML), so other tools and teams can share rules
- [x] Rule test harness: every rule carries its own positive and negative examples (`postshor rules test`)
- [x] Custom rule files (`--rules`, `rules = [...]` in `.postshor.toml`)
- SSH endpoint probe (`postshor ssh host`) for `mlkem768x25519-sha256`
- More ecosystems: Kotlin Multiplatform, Dart/Flutter, Elixir, Erlang, Scala libraries; Kubernetes TLS secrets; Helm charts
- Java keystores (JKS/PKCS#12 with password prompts)

## v0.4 — Semantic analysis

- Tree-sitter based rules that follow simple data flow (algorithm names held in variables or config)
- Call-graph context: is this crypto reachable from a network handler?
- Lower false-positive rate, measured on a public benchmark corpus

## v0.5 — Beyond source code

- Container images and binaries: linked OpenSSL/BoringSSL/Go versions, embedded certificates, crypto constants
- Cloud account inventory (AWS KMS / ACM, Azure Key Vault, GCP KMS) through read-only APIs
- Network capture analysis (pcap) for observed key exchanges

## v0.6 — Assisted migration

- `postshor fix`: AI-assisted remediation that proposes reviewed patches (hybrid TLS settings, library upgrades, ML-KEM/ML-DSA API changes), always as a reviewable diff and never applied silently
- Migration playbooks per stack

## Standards work (ongoing)

- QRS v1.0 final after public comment
- Contribute CBOM improvements upstream to CycloneDX
- Engage with the Post-Quantum Cryptography Alliance (Linux Foundation), OpenSSF and national agencies on shared inventory formats
