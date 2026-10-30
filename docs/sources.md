# Sources for PostShor's claims

PostShor tells users which algorithms are at risk, by when, and what to use instead. Every factual claim it makes in rules, remediation text and documentation must be traceable to a source listed here. When a claim changes, update the code and this file in the same pull request.

**Status:** ✅ verified · ⚠️ verified with caveats noted · ⏳ pending a primary source. *Verified* is the date the source was last checked.

## Standards and deadlines

| Claim | Source | Status | Verified |
|---|---|---|---|
| ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are final NIST standards (August 2024) | [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | ✅ | 2026-10-15 |
| NIST plans to deprecate RSA, ECDSA, ECDH and finite-field DH after 2030 and disallow them after 2035 | [NIST IR 8547 (initial public draft, Nov 2024)](https://csrc.nist.gov/pubs/ir/8547/ipd) | ⚠️ Still a draft; wording says "planned" | 2026-10-15 |
| DSA is no longer approved for signature generation; only verification of existing signatures (FIPS 186-5, Feb 2023) | [Federal Register, 3 Feb 2023](https://www.govinfo.gov/content/pkg/FR-2023-02-03/html/2023-02273.htm) | ✅ | 2026-10-30 |
| CNSA 2.0 specifies ML-KEM-1024, ML-DSA-87, LMS/XMSS for software and firmware signing, AES-256 and SHA-384/SHA-512 | [PostQuantum.com CNSA 2.0 guide](https://postquantum.com/cnsa-2-0/complete-guide/), [Encryption Consulting](https://www.encryptionconsulting.com/education-center/what-is-cnsa-2-0/) | ⚠️ Secondary sources; check NSA's CNSA 2.0 FAQ for authoritative wording | 2026-10-30 |
| EU coordinated roadmap: national plans by end 2026, high-risk systems by end 2030, all by end 2035 | [PQShield summary of the EU roadmap](https://pqshield.com/eu-pqc-workstream-publishes-a-coordinated-implementation-roadmap-for-the-transition-to-post-quantum-cryptography/) | ⚠️ Secondary source | 2026-10-15 |
| TLS 1.3 servers that support a client's offered group but received no key share must answer with a HelloRetryRequest (basis of `postshor tls`) | [RFC 8446 §4.1.4](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4) | ✅ | 2026-10-15 |

## Library and platform support (remediation hints)

| Claim | Source | Status | Verified |
|---|---|---|---|
| OpenSSL 3.5 adds ML-KEM, ML-DSA, SLH-DSA; default keyshares X25519MLKEM768 and X25519 | [OpenSSL 3.5 beta announcement](https://openssl-library.org/post/2025-03-25-openssl-3.5-beta/), [Help Net Security](https://www.helpnetsecurity.com/2025/04/09/openssl-3-5-0-released/) | ✅ | 2026-10-30 |
| Go 1.24 adds `crypto/mlkem` and enables X25519MLKEM768 in `crypto/tls` by default when `CurvePreferences` is nil; `GODEBUG=tlsmlkem=0` reverts | [golang/go#69985](https://github.com/golang/go/issues/69985) quoting the release notes | ✅ | 2026-10-30 |
| Go 1.26 also enables SecP256r1MLKEM768 and SecP384r1MLKEM1024 by default (`tlssecpmlkem=0` reverts only those) | [crypto/tls defaults.go](https://go.googlesource.com/go/+/69f60cd49a18bbb2cef2674fac4fc12de419a7ae/src/crypto/tls/defaults.go) | ✅ | 2026-10-30 |
| JDK 24 provides ML-KEM (JEP 496) and ML-DSA (JEP 497) APIs | [JEP 527 text referencing JEP 496 in Java 24](https://openjdk.org/jeps/527), [Oracle JDK 24 significant changes](https://docs.oracle.com/en/java/javase/24/migrate/significant-changes-jdk-24.html) | ⚠️ JEP 496's own page not readable by our tooling; open it to confirm final status | 2026-10-30 |
| Hybrid post-quantum TLS (X25519MLKEM768, preferred by default) arrives in JDK 27 via JEP 527 | [JEP 527](https://openjdk.org/jeps/527): "Status: Closed / Delivered", "Release: 27" | ✅ **Corrected** (previously "Java 24+") | 2026-10-30 |
| Bouncy Castle Java 1.79 (Oct 2024) adds ML-KEM, ML-DSA and SLH-DSA | [Bouncy Castle 1.79 announcement](https://www.bouncycastle.org/resources/latest-nist-pqc-standards-and-more-bouncy-castle-java-1-79/), [Keyfactor](https://keyfactor.com/blog/bouncy-castle-java-1-79-introduces-support-for-nist-pqc-standards) | ✅ | 2026-10-30 |
| .NET 10 adds `MLKem`, `MLDsa`, `SlhDsa`; `MLDsa`/`SlhDsa` are experimental (SYSLIB5006); not on macOS; Linux needs OpenSSL 3.5+ | [Microsoft: What's new in .NET 10 libraries](https://learn.microsoft.com/dotnet/core/whats-new/dotnet-10/libraries), [Duende guide](https://duendesoftware.com/blog/20260514-post-quantum-cryptography-in-dotnet-10) | ✅ **Refined** (caveats added) | 2026-10-30 |
| pyca/cryptography 47+ has ML-KEM/ML-DSA APIs, only with AWS-LC or BoringSSL backends | [cryptography changelog](https://cryptography.io/changelog.html), [Trail of Bits](https://blog.trailofbits.com/2026/06/30/shipping-post-quantum-cryptography-to-python/) | ✅ **Refined** (was "newer releases") | 2026-10-30 |
| Node.js 24.7+ supports ML-KEM and ML-DSA (node:crypto and WebCrypto) | [Node.js Web Crypto API docs](https://nodejs.org/api/webcrypto.md) | ✅ **Refined** (was "builds linked against OpenSSL 3.5+") | 2026-10-30 |
| rustls with the aws-lc-rs provider supports X25519MLKEM768; `prefer-post-quantum` makes it preferred (0.23.22+) | [rustls defaults](https://docs.rs/crate/rustls/latest/source/src/manual/defaults.rs), [rustls-post-quantum](https://docs.rs/rustls-post-quantum/latest/rustls_post_quantum/) | ✅ | 2026-10-30 |
| Apple CryptoKit (iOS/macOS 26) adds ML-KEM and ML-DSA types (`MLKEM768`, `MLDSA65` confirmed) and post-quantum HPKE (X-Wing) | [Apple: MLKEM768](https://developer.apple.com/documentation/cryptokit/mlkem768), [Apple: MLDSA65](https://developer.apple.com/documentation/cryptokit/mldsa65), [Encryption Consulting](https://www.encryptionconsulting.com/microsoft-and-apple-advance-post-quantum-cryptography-support-in-upcoming-os-releases/) | ⚠️ Other parameter-set and X-Wing symbol names unconfirmed; rule `SW-PQC` matches the `MLKEM`/`MLDSA` family generically | 2026-10-30 |
| OpenSSH 9.0 made sntrup761x25519-sha512 the default; 9.9 added mlkem768x25519-sha256; 10.0 made it the default | OpenSSH release notes [9.0](https://www.openssh.com/txt/release-9.0), [9.9](https://www.openssh.com/txt/release-9.9), [10.0](https://www.openssh.com/txt/release-10.0) | ✅ Primary source | 2026-10-30 |

## Library advisories

| Claim | Source | Status | Verified |
|---|---|---|---|
| Rust `rsa` crate: RUSTSEC-2023-0071 (Marvin timing side channel) | [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071) | ✅ | 2026-10-30 |
| PyCrypto has had no release since 2.6.1 and is affected by CVE-2013-7459 (critical heap overflow) | [PyPI pycrypto](https://pypi.org/project/pycrypto/), [CVE-2013-7459](https://cve.circl.lu/cve/CVE-2013-7459) | ✅ **Corrected** (was "unmaintained since 2013"; PyPI files date from 2014) | 2026-10-30 |

## Pending

| Claim | What is needed |
|---|---|
| Algorithm OIDs in `rules/algorithms.py` (used in CBOM output) | Check each against the IANA/NIST OID registries |
| AES-128 security under Grover ("~64-bit") and CNSA 2.0 requiring AES-256 | Cite NIST and CNSA 2.0 primary text |
