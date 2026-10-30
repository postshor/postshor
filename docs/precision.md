# Precision of PostShor's findings

How often is a CRITICAL or HIGH finding a real use of quantum-vulnerable cryptography? This page records each measurement, its method and its limits. A tool that cries wolf gets ignored, so we measure instead of assuming.

## Round 1 · 2026-10-30 · five cryptography libraries

**Corpus** (default branch, shallow clone):

| Repository | Commit | Language |
|---|---|---|
| [paramiko/paramiko](https://github.com/paramiko/paramiko) | `0e9ccb9` | Python |
| [jpadilla/pyjwt](https://github.com/jpadilla/pyjwt) | `16231ab` | Python |
| [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) | `b924272` | JavaScript |
| [digitalbazaar/forge](https://github.com/digitalbazaar/forge) | `29e670a` | JavaScript |
| [golang-jwt/jwt](https://github.com/golang-jwt/jwt) | `9a618ef` | Go |

**Labelling.** Every CRITICAL and HIGH finding was reviewed by hand against its source line. A finding counts as **correct** if it identifies a real use, implementation or configuration of a quantum-vulnerable algorithm at that location with a defensible severity. It counts as **incorrect** if the match is not a use (documentation text, comments), if the location is intentional non-production material reported as production (test fixture keys, example scripts), or if the severity contradicts the context (the classical half of a hybrid post-quantum key exchange reported as CRITICAL).

**Results.**

| | Serious findings | Correct | Precision |
|---|---|---|---|
| PostShor 0.1.0 | 154 | 81 | **52.6%** |
| After fixes (0.1.1) | 81 | 81 | **100%** |

**Causes of incorrect findings in 0.1.0 and the fixes:**

| Cause | Findings | Fix |
|---|---|---|
| Intentional test fixture private keys reported as CRITICAL | 62 | Private keys in test, fixture, example and documentation paths are capped at LOW and marked as presumed fixtures (still listed) |
| Example scripts (`examples/`) treated as production code | 5 | `examples/`, `samples/`, `demos/`, `docs/` added to non-production paths |
| Algorithm names inside Python docstrings | 4 | Pattern rules skip Python triple-quoted blocks and C-style `/* */` block comments (private-key detection still runs there) |
| X25519 in paramiko's ML-KEM hybrid key exchange reported as CRITICAL | 2 | Classical key exchange within 40 lines of an explicitly named hybrid (X25519MLKEM768, mlkem768x25519, X-Wing, "hybrid") is reported as INFO; per-line configuration checks are never softened |

A regression test guards against the opposite error: independent ECDH next to an unrelated ML-KEM mention stays CRITICAL.

**Limitations.** This round measures *precision* only, not recall (findings PostShor misses). The corpus is five cryptography libraries, where nearly every match is real; ordinary applications may show different error patterns. Labelling was done by the PostShor maintainers, not an independent reviewer. Round 2 will add application code and an independent labeller.

## Round 2 · 2026-10-30 · four applications, precision and recall

**Corpus** (default branch, shallow clone):

| Repository | Commit | Language | What it is |
|---|---|---|---|
| [netbox-community/netbox](https://github.com/netbox-community/netbox) | `7a68044` | Python | Network source of truth (Django) |
| [go-gitea/gitea](https://github.com/go-gitea/gitea) | `2660b4d` | Go | Git hosting (SSH, OAuth/OIDC, package registries) |
| [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden) | `e056359` | Rust | Password-manager server |
| [caddyserver/caddy](https://github.com/caddyserver/caddy) | `eb04ed5` | Go | Web server with automatic TLS |

**Precision** was labelled as in round 1. **Recall** was estimated by searching every production code file (tests excluded) for asymmetric-crypto keywords (`rsa`, `ecdsa`, `ed25519`, `x25519`, `ecdh`, `elliptic`, curve names, JWT algorithm names, key-generation calls, …) and reviewing each line PostShor did not report: is it a real use of quantum-vulnerable cryptography?

**Results.**

| | Serious findings | Correct | Precision | Real uses found / known | Recall |
|---|---|---|---|---|---|
| PostShor 0.1.1 | 54 | 42 | **77.8%** | 43 / 63 | **68%** |
| After round-2 fixes | 63 | 63 | **100%** | 63 / 63 | **100%** of known uses |

**Incorrect findings in 0.1.1 and the fixes:**

| Cause | Findings | Fix |
|---|---|---|
| Caddy's TLS curve list, set from configuration and including X25519MLKEM768 by default, reported as "classical only" CRITICAL | 3 (+1 in gitea) | Literal curve/group lists are judged across the whole list (CRITICAL if classical only); lists set from a variable become LOW "verify it includes X25519MLKEM768" (Go and OpenSSL rules) |
| Test certificates and keys in `caddytest/` | 6 | Directories ending in `test`/`tests` count as test code, with an exception list (`latest`, `attest`, `contest`, …) |
| `ecdh.P256().NewPublicKey(...)` used to convert WebAuthn signature keys reported as key exchange | 1 | crypto/ecdh key generation and `.ECDH()` count as key exchange; parsing keys counts as a (HIGH) elliptic-curve key |
| Example SSH key in a trailing `// format: ssh-rsa AAAA…` comment | 1 | Matches inside trailing `//` and `#` comments are skipped (quote-aware) |

**Missed uses in 0.1.1 and the new rules:**

| Missed | Where | New rule |
|---|---|---|
| Rust `openssl` crate RSA (`Rsa::generate`, `Rsa::private_key_from_pem`) | vaultwarden | `RS-OPENSSL-*` |
| JWT/COSE algorithms as identifiers (`jwt.SigningMethodRS256`, `Algorithm::RS256`, `COSEAlgorithm::ES256`) | gitea, vaultwarden | `JWT-ALG-RSA/ECDSA/EDDSA` (the Go form requires a package qualifier to avoid flagging the JWT library's own declarations) |
| OpenPGP package-repository signing keys (`openpgp.NewEntity`, RSA by default, long-lived) | gitea | `PGP-KEYGEN-GO/PY/JS` |
| HTTP message signatures (`httpsig.RSA_SHA256`, `httpsig.ED25519`, `"rsa-sha256"`) | gitea | `HTTPSIG-ALG` |
| HPKE with a classical KEM for Encrypted Client Hello (`hpke.KEM_X25519_HKDF_SHA256`) | caddy | `HPKE-DHKEM` (CRITICAL: harvest-now-decrypt-later) |

Round 1's libraries were re-scanned after every change: no regressions (81 serious findings, all correct).

**Limitations.** Recall is measured against the uses a keyword review could find; uses invisible to keyword search (algorithm chosen entirely by configuration at runtime, uses inside compiled dependencies) are outside this estimate. Labelling was still done by the PostShor maintainers. An independent labeller and a larger, randomly sampled corpus are the next step.
