## PostShor: quantum-readiness report

[![Quantum readiness: F](https://img.shields.io/badge/quantum--readiness-F%20(0)-red)](https://github.com/postshor/postshor)

**Quantum Readiness Score (QRS v1.0): F (0/100)** · 13 files scanned

| Severity | Count |
|---|---|
| 🔴 critical | 15 |
| 🟠 high | 18 |
| 🟡 medium | 5 |
| 🔵 low | 1 |
| ⚪ info | 10 |

### Migration plan

- **Phase 1: Stop the harvest** (Now (0–12 months)): 16 findings. Key exchange and encryption recorded today can be decrypted later. This exposure is already happening.
- **Phase 2: Replace signatures and identities** (Before 2030 (NIST deprecation)): 16 findings. Signatures can only be forged after Q-day, but roots, firmware keys and PKI take years to rotate.
- **Phase 3: Clean up and build agility** (Ongoing): 7 findings. Algorithms that are already broken, plus everything that makes the next migration cheaper.

### Top findings

| | Finding | Location | Fix |
|---|---|---|---|
| 🔴 | TLS group list set without a post-quantum hybrid group | `c/tls.c:5` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. OpenSSL 3.5+ supports ML-KEM, ML-DSA and SLH-DSA and offers X25519MLKEM768 in TLS by default; liboqs for other algorithms. |
| 🔴 | TLS 1.3 not enabled (post-quantum key exchange requires TLS 1.3) | `config/nginx.conf:3` | Replace with TLS 1.3 (required for hybrid post-quantum key exchange). |
| 🔴 | nginx ssl_ecdh_curve excludes post-quantum hybrid groups | `config/nginx.conf:4` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. |
| 🔴 | SSH KexAlgorithms set without a post-quantum hybrid | `config/sshd_config:4` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. |
| 🔴 | RSA encryption (.NET) | `cs/Keys.cs:6` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Prioritise this: the exposure starts the day data is recorded. .NET 10 adds MLKem, MLDsa and SlhDsa; Bouncy Castle .NET for earlier runtimes. |
| 🔴 | ECDH (.NET) | `cs/Keys.cs:7` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. .NET 10 adds MLKem, MLDsa and SlhDsa; Bouncy Castle .NET for earlier runtimes. |
| 🔴 | RSA encryption | `go/server.go:13` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Prioritise this: the exposure starts the day data is recorded. Go 1.24+ ships crypto/mlkem and enables X25519MLKEM768 in crypto/tls by default. |
| 🔴 | TLS CurvePreferences pins classical groups only, disabling Go's default hybrid PQ key exchange | `go/server.go:15` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. Go 1.24+ ships crypto/mlkem and enables X25519MLKEM768 in crypto/tls by default. |
| 🔴 | RSA encryption (JCA Cipher) | `java/Crypto.java:7` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Prioritise this: the exposure starts the day data is recorded. Java 24+ provides ML-KEM (JEP 496) and ML-DSA (JEP 497); Bouncy Castle supports them on older JDKs. |
| 🔴 | ECDH key agreement (JCA) | `java/Crypto.java:9` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. Java 24+ provides ML-KEM (JEP 496) and ML-DSA (JEP 497); Bouncy Castle supports them on older JDKs. |
| 🔴 | ECDH (node:crypto) | `js/auth.ts:4` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. JS options: @noble/post-quantum, or Node.js builds linked against OpenSSL 3.5+. |
| 🔴 | RSA encryption (node:crypto) | `js/auth.ts:5` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Prioritise this: the exposure starts the day data is recorded. JS options: @noble/post-quantum, or Node.js builds linked against OpenSSL 3.5+. |
| 🔴 | ECDH key agreement | `py/crypto_utils.py:9` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition. Prioritise this: the exposure starts the day data is recorded. Python options: liboqs-python (Open Quantum Safe, good for prototyping) or newer pyca/cryptography releases (check release notes for ML-KEM/ML-DSA). |
| 🔴 | RSA-OAEP encryption | `py/crypto_utils.py:14` | Migrate to ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Prioritise this: the exposure starts the day data is recorded. Python options: liboqs-python (Open Quantum Safe, good for prototyping) or newer pyca/cryptography releases (check release notes for ML-KEM/ML-DSA). |
| 🔴 | X25519 key agreement | `rust/main.rs:2` | Migrate to Hybrid X25519MLKEM768 (keeps X25519, adds ML-KEM-768). Prioritise this: the exposure starts the day data is recorded. Rust options: RustCrypto ml-kem / ml-dsa crates; rustls with aws-lc-rs supports X25519MLKEM768. |
| 🟠 | RSA key | `c/tls.c:7` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. OpenSSL 3.5+ supports ML-KEM, ML-DSA and SLH-DSA and offers X25519MLKEM768 in TLS by default; liboqs for other algorithms. |
| 🟠 | EC key (OpenSSL 3 by-name API) | `c/tls.c:8` | Replace with Hybrid X25519MLKEM768 (keeps X25519, adds ML-KEM-768). OpenSSL 3.5+ supports ML-KEM, ML-DSA and SLH-DSA and offers X25519MLKEM768 in TLS by default; liboqs for other algorithms. |
| 🟠 | Legacy SSL/TLS protocol version enabled | `config/nginx.conf:3` | Replace with TLS 1.3 (required for hybrid post-quantum key exchange). |
| 🟠 | SSH host key uses RSA/ECDSA | `config/sshd_config:2` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. |
| 🟠 | RSA (.NET) | `cs/Keys.cs:5` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. .NET 10 adds MLKem, MLDsa and SlhDsa; Bouncy Castle .NET for earlier runtimes. |
| 🟠 | RSA key generation | `go/server.go:12` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Go 1.24+ ships crypto/mlkem and enables X25519MLKEM768 in crypto/tls by default. |
| 🟠 | ECDSA | `go/server.go:14` | Replace with ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys. Go 1.24+ ships crypto/mlkem and enables X25519MLKEM768 in crypto/tls by default. |
| 🟠 | Terraform tls_private_key with classical algorithm | `infra/main.tf:2` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. |
| 🟠 | Cloud KMS / ACM elliptic-curve key | `infra/main.tf:7` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for key agreement; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. |
| 🟠 | RSA key pair generation (JCA) | `java/Crypto.java:6` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Java 24+ provides ML-KEM (JEP 496) and ML-DSA (JEP 497); Bouncy Castle supports them on older JDKs. |
| 🟠 | ECDSA signature (JCA) | `java/Crypto.java:8` | Replace with ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys. Java 24+ provides ML-KEM (JEP 496) and ML-DSA (JEP 497); Bouncy Castle supports them on older JDKs. |
| 🟠 | RSA key generation (node:crypto) | `js/auth.ts:3` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. JS options: @noble/post-quantum, or Node.js builds linked against OpenSSL 3.5+. |
| 🟠 | ECDSA (WebCrypto) | `js/auth.ts:9` | Replace with ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys. JS options: @noble/post-quantum, or Node.js builds linked against OpenSSL 3.5+. |
| 🟠 | RSA key generation (pyca/cryptography) | `py/crypto_utils.py:8` | Replace with ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition for encryption/key transport; ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys for signatures. Python options: liboqs-python (Open Quantum Safe, good for prototyping) or newer pyca/cryptography releases (check release notes for ML-KEM/ML-DSA). |
| 🟠 | DES / 3DES cipher | `py/crypto_utils.py:19` | Replace with AES-256-GCM. |

_9 more findings in the full report._

<details><summary>Cryptographic inventory</summary>

| Algorithm | Occurrences | Files |
|---|---|---|
| RSA | 17 | 11 |
| ECDH | 9 | 9 |
| ECDSA | 3 | 3 |
| MD5 | 3 | 3 |
| Post-quantum algorithm (unspecified) | 3 | 3 |
| ML-KEM (FIPS 203) | 3 | 3 |
| SSL 3.0 / TLS 1.0 / TLS 1.1 | 2 | 1 |
| X25519/X448 key agreement | 2 | 2 |
| Elliptic-curve cryptography | 2 | 2 |
| Hybrid PQ key exchange (X25519MLKEM768 etc.) | 2 | 2 |
| DES / 3DES | 1 | 1 |
| PyCrypto (unmaintained library) | 1 | 1 |
| SHA-1 | 1 | 1 |

</details>
