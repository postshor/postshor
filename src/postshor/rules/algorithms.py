"""Knowledge base: every algorithm PostShor reports on, its quantum status and its replacement.

Severity is derived from (status, usage) by ``severity_for``. The reasoning:

* Quantum-broken key exchange / encryption is CRITICAL because of "harvest now, decrypt
  later": traffic recorded today can be decrypted once a quantum computer exists, so the
  exposure has already started.
* Quantum-broken signatures are HIGH: forgery only becomes possible after Q-day, but
  long-lived keys (roots, firmware signing) take years to rotate.
* Classically broken primitives are flagged because a migration is the time to fix them.
"""

from __future__ import annotations

from dataclasses import dataclass

from postshor.models import QuantumStatus, Severity, Usage


@dataclass(frozen=True)
class Algorithm:
    id: str
    name: str
    status: QuantumStatus
    primitive: str  # CycloneDX 1.6 cryptoProperties.algorithmProperties.primitive
    replacement: str
    nist_quantum_level: int  # 0 = no quantum security
    oid: str | None = None
    note: str = ""


_B, _W, _S, _P, _C = (
    QuantumStatus.BROKEN,
    QuantumStatus.WEAKENED,
    QuantumStatus.SAFE,
    QuantumStatus.PRE_STANDARD,
    QuantumStatus.CLASSICALLY_BROKEN,
)

_KEM = "ML-KEM-768 (FIPS 203), deployed as the hybrid X25519MLKEM768 during the transition"
_SIG = "ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) or LMS/XMSS for long-lived firmware/root keys"

ALGORITHMS: dict[str, Algorithm] = {
    a.id: a
    for a in [
        # --- Quantum-broken public-key cryptography (Shor) ---
        Algorithm("rsa", "RSA", _B, "pke", f"{_KEM} for encryption/key transport; {_SIG} for signatures", 0, "1.2.840.113549.1.1.1"),
        Algorithm("ecdsa", "ECDSA", _B, "signature", _SIG, 0, "1.2.840.10045.2.1"),
        Algorithm("ecdh", "ECDH", _B, "key-agree", _KEM, 0, "1.3.132.1.12"),
        Algorithm("ecc", "Elliptic-curve cryptography", _B, "other", f"{_KEM} for key agreement; {_SIG} for signatures", 0, "1.2.840.10045.2.1"),
        Algorithm("eddsa", "EdDSA (Ed25519/Ed448)", _B, "signature", _SIG, 0, "1.3.101.112"),
        Algorithm("x25519", "X25519/X448 key agreement", _B, "key-agree", "Hybrid X25519MLKEM768 (keeps X25519, adds ML-KEM-768)", 0, "1.3.101.110"),
        Algorithm("dh", "Finite-field Diffie-Hellman", _B, "key-agree", _KEM, 0, "1.2.840.113549.1.3.1"),
        Algorithm("dsa", "DSA", _B, "signature", _SIG, 0, "1.2.840.10040.4.1", "DSA is also withdrawn by FIPS 186-5."),
        # --- Classically broken / deprecated ---
        Algorithm("md5", "MD5", _C, "hash", "SHA-256 or SHA-3 (SHA-384+ for CNSA 2.0)", 0, "1.2.840.113549.2.5"),
        Algorithm("sha1", "SHA-1", _C, "hash", "SHA-256 or SHA-3 (SHA-384+ for CNSA 2.0)", 0, "1.3.14.3.2.26"),
        Algorithm("des", "DES / 3DES", _C, "block-cipher", "AES-256-GCM", 0, "1.2.840.113549.3.7"),
        Algorithm("rc4", "RC4", _C, "stream-cipher", "AES-256-GCM or ChaCha20-Poly1305", 0, "1.2.840.113549.3.4"),
        Algorithm("blowfish", "Blowfish / RC2", _C, "block-cipher", "AES-256-GCM", 0),
        Algorithm("tls-legacy", "SSL 3.0 / TLS 1.0 / TLS 1.1", _C, "other", "TLS 1.3 (required for hybrid post-quantum key exchange)", 0),
        Algorithm("pycrypto", "PyCrypto (unmaintained library)", _C, "other", "pycryptodome or pyca/cryptography", 0, note="PyCrypto has had no release since 2.6.1 and is affected by CVE-2013-7459 (critical heap buffer overflow)."),
        # --- Grover-weakened symmetric ---
        Algorithm("aes-128", "AES-128", _W, "block-cipher", "AES-256 (required by CNSA 2.0)", 1, "2.16.840.1.101.3.4.1.2", "AES-128 keeps ~64-bit security against Grover; NIST still rates it adequate, CNSA 2.0 does not."),
        # --- Standardized post-quantum (good) ---
        Algorithm("ml-kem", "ML-KEM (FIPS 203)", _S, "kem", "Already quantum-safe", 3, "2.16.840.1.101.3.4.4.2"),
        Algorithm("ml-dsa", "ML-DSA (FIPS 204)", _S, "signature", "Already quantum-safe", 3, "2.16.840.1.101.3.4.3.18"),
        Algorithm("slh-dsa", "SLH-DSA (FIPS 205)", _S, "signature", "Already quantum-safe", 1),
        Algorithm("fn-dsa", "FN-DSA / Falcon (FIPS 206)", _S, "signature", "Already quantum-safe (confirm the final FIPS 206 parameters)", 1),
        Algorithm("hybrid-kem", "Hybrid PQ key exchange (X25519MLKEM768 etc.)", _S, "kem", "Already quantum-safe", 3),
        Algorithm("stateful-hbs", "LMS / XMSS hash-based signatures", _S, "signature", "Already quantum-safe (protect signing state carefully)", 1),
        Algorithm("pqc", "Post-quantum algorithm (unspecified)", _S, "other", "Verify it is a FIPS 203/204/205 algorithm", 1),
        # --- Pre-standard PQC (good intent, needs upgrade) ---
        Algorithm("kyber", "CRYSTALS-Kyber (pre-standard)", _P, "kem", "ML-KEM (FIPS 203); Kyber round-3 is not interoperable with ML-KEM", 3),
        Algorithm("dilithium", "CRYSTALS-Dilithium (pre-standard)", _P, "signature", "ML-DSA (FIPS 204)", 3),
        Algorithm("sphincs", "SPHINCS+ (pre-standard)", _P, "signature", "SLH-DSA (FIPS 205)", 1),
        Algorithm("falcon", "Falcon (pre-standard)", _P, "signature", "FN-DSA (FIPS 206); original Falcon is not compatible with FN-DSA", 1),
    ]
}


def severity_for(algorithm_id: str, usage: Usage) -> Severity:
    algo = ALGORITHMS[algorithm_id]
    if algo.status is QuantumStatus.BROKEN:
        if usage in (Usage.KEY_EXCHANGE, Usage.ENCRYPTION):
            return Severity.CRITICAL
        if usage is Usage.LIBRARY:
            return Severity.LOW
        return Severity.HIGH
    if algo.status is QuantumStatus.CLASSICALLY_BROKEN:
        # Hashes are often used for non-security checksums; ciphers almost never are.
        if usage is Usage.LIBRARY:
            return Severity.MEDIUM
        return Severity.MEDIUM if algo.primitive == "hash" else Severity.HIGH
    if algo.status in (QuantumStatus.WEAKENED, QuantumStatus.PRE_STANDARD):
        return Severity.LOW
    return Severity.INFO


_WHY = {
    QuantumStatus.BROKEN: "{name} is broken by Shor's algorithm on a cryptographically relevant quantum computer.",
    QuantumStatus.CLASSICALLY_BROKEN: "{name} is already insecure today, independent of quantum computing.",
    QuantumStatus.WEAKENED: "{name} has reduced security margin against Grover's algorithm.",
    QuantumStatus.PRE_STANDARD: "{name} predates the final NIST standards and will not interoperate with them.",
    QuantumStatus.SAFE: "{name} is a post-quantum-safe choice.",
}

_USAGE_IMPACT = {
    Usage.KEY_EXCHANGE: " Data protected by this key exchange can be recorded now and decrypted later (harvest-now-decrypt-later).",
    Usage.ENCRYPTION: " Anything encrypted this way can be recorded now and decrypted later (harvest-now-decrypt-later).",
    Usage.SIGNATURE: " Signatures could be forged after Q-day; long-lived signing keys need to rotate well before then.",
}


def explain(algorithm_id: str, usage: Usage) -> str:
    algo = ALGORITHMS[algorithm_id]
    text = _WHY[algo.status].format(name=algo.name)
    if algo.status is QuantumStatus.BROKEN:
        text += _USAGE_IMPACT.get(usage, "")
        text += " NIST IR 8547 (draft) deprecates it after 2030 and disallows it after 2035."
    if algo.note:
        text += " " + algo.note
    return text


def remediation(algorithm_id: str, usage: Usage, language: str | None = None) -> str:
    algo = ALGORITHMS[algorithm_id]
    if algo.status is QuantumStatus.SAFE:
        return "No action needed. Keep the implementation up to date and FIPS-validated where required."
    text = f"Replace with {algo.replacement}."
    if algo.status is QuantumStatus.BROKEN and usage in (Usage.KEY_EXCHANGE, Usage.ENCRYPTION):
        text = f"Migrate to {algo.replacement}. Prioritise this: the exposure starts the day data is recorded."
    hint = LANGUAGE_HINTS.get(language or "")
    if hint and algo.status in (QuantumStatus.BROKEN, QuantumStatus.PRE_STANDARD):
        text += " " + hint
    return text


# Where post-quantum support lives in each ecosystem. Every statement here is sourced in
# docs/sources.md; update both together. Phrased conservatively: users should check versions.
LANGUAGE_HINTS = {
    "python": "Python: pyca/cryptography 47+ has ML-KEM and ML-DSA APIs, but only when built against AWS-LC or BoringSSL (the standard wheels use OpenSSL); liboqs-python (Open Quantum Safe) is suitable for prototyping.",
    "go": "Go 1.24+ ships crypto/mlkem and enables X25519MLKEM768 in crypto/tls by default (Go 1.26 also enables SecP256r1MLKEM768 and SecP384r1MLKEM1024); leave Config.CurvePreferences unset to keep the defaults.",
    "jvm": "Java: JDK 24+ provides ML-KEM (JEP 496) and ML-DSA (JEP 497) APIs; hybrid post-quantum TLS (X25519MLKEM768) arrives in JDK 27 (JEP 527). Bouncy Castle 1.79+ provides ML-KEM, ML-DSA and SLH-DSA on older JDKs.",
    "javascript": "JavaScript: Node.js 24.7+ supports ML-KEM and ML-DSA in node:crypto and WebCrypto; @noble/post-quantum is a pure-JS option.",
    "c": "OpenSSL 3.5+ supports ML-KEM, ML-DSA and SLH-DSA and offers X25519MLKEM768 in TLS by default; liboqs for other algorithms.",
    "csharp": ".NET 10 adds MLKem (stable) plus MLDsa and SlhDsa (experimental, SYSLIB5006); not supported on macOS, and Linux needs OpenSSL 3.5+. Bouncy Castle .NET for earlier runtimes.",
    "rust": "Rust: RustCrypto ml-kem / ml-dsa crates; rustls with the aws-lc-rs provider supports X25519MLKEM768 (make it preferred with the prefer-post-quantum feature, rustls 0.23.22+).",
    "swift": "Apple CryptoKit (iOS/macOS 26+) adds ML-KEM and ML-DSA types (for example MLKEM768, MLDSA65) and post-quantum HPKE (X-Wing).",
    "php": "PHP: no mainstream native ML-KEM/ML-DSA API is established yet; route post-quantum operations through a service or library that supports them.",
    "ruby": "Ruby: post-quantum support depends on the openssl gem and the linked OpenSSL (3.5+ implements ML-KEM/ML-DSA); check that your gem version exposes them.",
}
