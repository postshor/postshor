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
