"""Pattern rules for source code, configuration and infrastructure-as-code.

Each rule is a regex applied to the whole file; matches are reported with their line.
``unless`` is checked against the matched line and suppresses the match when it hits — it is
how "this directive is set but does not include a post-quantum option" is expressed.

Rule IDs are stable public identifiers (they appear in SARIF and baselines): never reuse one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from postshor.models import Severity, Usage

K, E, S, G, H, Y, P, M, U = (
    Usage.KEY_EXCHANGE,
    Usage.ENCRYPTION,
    Usage.SIGNATURE,
    Usage.KEY_GENERATION,
    Usage.HASH,
    Usage.SYMMETRIC,
    Usage.PROTOCOL,
    Usage.KEY_MATERIAL,
    Usage.UNKNOWN,
)

# File "kinds" a rule can target. See postshor.scanners.files.classify.
CODE = ("python", "javascript", "jvm", "go", "c", "csharp", "rust", "php", "ruby", "swift")
CONFIG = ("config", "iac")
ANY = ("any",)


@dataclass
class Rule:
    id: str
    kinds: tuple[str, ...]
    pattern: str
    algorithm: str
    usage: Usage
    title: str
    confidence: str = "high"
    unless: str | None = None
    severity: Severity | None = None  # override the derived severity
    flags: int = 0
    regex: re.Pattern = field(init=False, repr=False)
    unless_regex: re.Pattern | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, self.flags | re.MULTILINE)
        self.unless_regex = re.compile(self.unless, re.IGNORECASE) if self.unless else None


_PQ_GROUP = r"mlkem|ml-kem|kyber|sntrup|x25519mlkem|secp256r1mlkem|secp384r1mlkem"

RULES: list[Rule] = [
    # ------------------------------------------------------------------ Python
    Rule("PY-RSA-KEYGEN", ("python",), r"\brsa\.generate_private_key\s*\(", "rsa", G, "RSA key generation (pyca/cryptography)"),
    Rule("PY-RSA-PYCRYPTODOME", ("python",), r"\bRSA\.(?:generate|import_key|importKey|construct)\s*\(", "rsa", G, "RSA key (PyCryptodome)"),
    Rule("PY-RSA-OAEP", ("python",), r"\bPKCS1_OAEP\.new\s*\(|\bpadding\.OAEP\s*\(", "rsa", E, "RSA-OAEP encryption"),
    Rule("PY-RSA-PKCS1V15", ("python",), r"\bPKCS1_v1_5\.new\s*\(", "rsa", U, "RSA PKCS#1 v1.5 (PyCryptodome)"),
    Rule("PY-RSA-PYRSA", ("python",), r"\brsa\.newkeys\s*\(", "rsa", G, "RSA key generation (python-rsa)"),
    Rule("PY-RSA-PYRSA-ENC", ("python",), r"\brsa\.encrypt\s*\(", "rsa", E, "RSA encryption (python-rsa)", "medium"),
    Rule("PY-EC-KEYGEN", ("python",), r"\bec\.generate_private_key\s*\(|\bECC\.(?:generate|import_key|construct)\s*\(", "ecc", G, "Elliptic-curve key generation"),
    Rule("PY-ECDH", ("python",), r"\bec\.ECDH\s*\(", "ecdh", K, "ECDH key agreement"),
    Rule("PY-ECDSA", ("python",), r"\bec\.ECDSA\s*\(|\bDSS\.new\s*\(", "ecdsa", S, "ECDSA signature"),
    Rule("PY-ECDSA-LIB", ("python",), r"\bSigningKey\.generate\s*\(\s*curve\s*=", "ecdsa", S, "ECDSA key (python-ecdsa)"),
    # Match key creation/loading, not type references such as isinstance(k, Ed25519PrivateKey).
    Rule("PY-EDDSA", ("python",), r"\b(?:Ed25519|Ed448)PrivateKey\.(?:generate|from_private_bytes)\s*\(|\bnacl\.signing\.SigningKey\b", "eddsa", S, "EdDSA signature key"),
    Rule("PY-X25519", ("python",), r"\b(?:X25519|X448)PrivateKey\.(?:generate|from_private_bytes)\s*\(|\bnacl\.public\.(?:PrivateKey|Box|SealedBox)\b", "x25519", K, "X25519/X448 key agreement"),
    Rule("PY-DH", ("python",), r"\bdh\.generate_parameters\s*\(|\bDHParameterNumbers\b", "dh", K, "Diffie-Hellman key agreement"),
    Rule("PY-DSA", ("python",), r"\bdsa\.generate_private_key\s*\(|\bDSA\.generate\s*\(", "dsa", S, "DSA signature key"),
    Rule("PY-PARAMIKO", ("python",), r"\b(RSAKey|ECDSAKey|DSSKey)\.(?:generate|from_private_key(?:_file)?)\s*\(", "rsa", S, "SSH key via Paramiko"),
    Rule("PY-MD5", ("python",), r"\bhashlib\.md5\s*\(|\bhashlib\.new\s*\(\s*['\"]md5|\bMD5\.new\s*\(", "md5", H, "MD5 hash"),
    Rule("PY-SHA1", ("python",), r"\bhashlib\.sha1\s*\(|\bhashlib\.new\s*\(\s*['\"]sha1|\bSHA1?\.new\s*\(", "sha1", H, "SHA-1 hash"),
    Rule("PY-DES", ("python",), r"\b(?:DES|DES3)\.new\s*\(|\balgorithms\.TripleDES\s*\(", "des", Y, "DES / 3DES cipher"),
    Rule("PY-RC4", ("python",), r"\bARC4\.new\s*\(|\balgorithms\.ARC4\s*\(", "rc4", Y, "RC4 cipher"),
    Rule("PY-PYCRYPTO-IMPORT", ("python",), r"^\s*from\s+Crypto\.PublicKey\s+import\s+.*\bRSA\b", "rsa", U, "RSA imported from PyCrypto/PyCryptodome", "medium"),
    Rule("PY-OQS", ("python",), r"\boqs\.(?:KeyEncapsulation|Signature)\s*\(", "pqc", U, "Open Quantum Safe (liboqs) usage"),
    # ------------------------------------------------------------------ Java / Kotlin / Scala
    Rule("JVM-RSA-KEYGEN", ("jvm",), r"KeyPairGenerator\.getInstance\(\s*\"RSA", "rsa", G, "RSA key pair generation (JCA)"),
    Rule("JVM-EC-KEYGEN", ("jvm",), r"KeyPairGenerator\.getInstance\(\s*\"(?:EC|ECDSA)\"", "ecc", G, "EC key pair generation (JCA)"),
    Rule("JVM-DSA-KEYGEN", ("jvm",), r"KeyPairGenerator\.getInstance\(\s*\"DSA\"", "dsa", S, "DSA key pair generation (JCA)"),
    Rule("JVM-DH-KEYGEN", ("jvm",), r"(?:KeyPairGenerator|KeyAgreement)\.getInstance\(\s*\"(?:DH|DiffieHellman)\"", "dh", K, "Diffie-Hellman (JCA)"),
    Rule("JVM-EDDSA", ("jvm",), r"(?:KeyPairGenerator|Signature)\.getInstance\(\s*\"(?:Ed25519|Ed448|EdDSA)\"", "eddsa", S, "EdDSA (JCA)"),
    Rule("JVM-XDH", ("jvm",), r"(?:KeyPairGenerator|KeyAgreement)\.getInstance\(\s*\"(?:X25519|X448|XDH)\"", "x25519", K, "X25519/X448 key agreement (JCA)"),
    Rule("JVM-ECDH", ("jvm",), r"KeyAgreement\.getInstance\(\s*\"(?:ECDH|ECDHC|ECMQV)\"", "ecdh", K, "ECDH key agreement (JCA)"),
    Rule("JVM-RSA-CIPHER", ("jvm",), r"Cipher\.getInstance\(\s*\"RSA", "rsa", E, "RSA encryption (JCA Cipher)"),
    Rule("JVM-RSA-SIG", ("jvm",), r"Signature\.getInstance\(\s*\"(?:\w*with(?:RSA|RSA/PSS|RSAandMGF1)|RSASSA-PSS)\"", "rsa", S, "RSA signature (JCA)"),
    Rule("JVM-ECDSA-SIG", ("jvm",), r"Signature\.getInstance\(\s*\"\w*withECDSA\"", "ecdsa", S, "ECDSA signature (JCA)"),
    Rule("JVM-DSA-SIG", ("jvm",), r"Signature\.getInstance\(\s*\"\w*withDSA\"", "dsa", S, "DSA signature (JCA)"),
    Rule("JVM-RSA-KEYFACTORY", ("jvm",), r"KeyFactory\.getInstance\(\s*\"RSA\"", "rsa", U, "RSA key loading (JCA)"),
    Rule("JVM-EC-KEYFACTORY", ("jvm",), r"KeyFactory\.getInstance\(\s*\"EC\"", "ecc", U, "EC key loading (JCA)"),
    Rule("JVM-DES", ("jvm",), r"Cipher\.getInstance\(\s*\"(?:DES|DESede|TripleDES)", "des", Y, "DES / 3DES cipher (JCA)"),
    Rule("JVM-RC4", ("jvm",), r"Cipher\.getInstance\(\s*\"(?:RC4|ARCFOUR)", "rc4", Y, "RC4 cipher (JCA)"),
    Rule("JVM-MD5", ("jvm",), r"MessageDigest\.getInstance\(\s*\"MD5\"", "md5", H, "MD5 hash (JCA)"),
    Rule("JVM-SHA1", ("jvm",), r"MessageDigest\.getInstance\(\s*\"SHA-?1\"", "sha1", H, "SHA-1 hash (JCA)"),
    Rule("JVM-BC-PQC", ("jvm",), r"\b(?:MLKEM|MLDSA|SLHDSA)(?:ParameterSpec|Parameters|KeyGenerationParameters)\b", "pqc", U, "Bouncy Castle post-quantum API"),
    Rule("JVM-BC-PRESTANDARD", ("jvm",), r"\b(?:Kyber|Dilithium|SPHINCSPlus|Falcon)(?:ParameterSpec|Parameters)\b", "kyber", U, "Bouncy Castle pre-standard PQC API"),
    # ------------------------------------------------------------------ Go
    Rule("GO-RSA-KEYGEN", ("go",), r"\brsa\.GenerateKey\(", "rsa", G, "RSA key generation"),
    Rule("GO-RSA-ENC", ("go",), r"\brsa\.(?:EncryptOAEP|EncryptPKCS1v15|DecryptOAEP|DecryptPKCS1v15)\(", "rsa", E, "RSA encryption"),
    Rule("GO-RSA-SIG", ("go",), r"\brsa\.(?:SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS)\(", "rsa", S, "RSA signature"),
    Rule("GO-ECDSA", ("go",), r"\becdsa\.(?:GenerateKey|Sign|SignASN1|Verify|VerifyASN1)\(", "ecdsa", S, "ECDSA"),
    Rule("GO-ECDH", ("go",), r"\becdh\.(?:P256|P384|P521)\(\)", "ecdh", K, "ECDH key agreement"),
    Rule("GO-X25519", ("go",), r"\becdh\.X25519\(\)|\bcurve25519\.(?:X25519|ScalarMult)\(", "x25519", K, "X25519 key agreement"),
    Rule("GO-ELLIPTIC", ("go",), r"\belliptic\.(?:P224|P256|P384|P521)\(\)", "ecc", U, "Elliptic curve (crypto/elliptic)"),
    Rule("GO-ED25519", ("go",), r"\bed25519\.(?:GenerateKey|Sign|NewKeyFromSeed)\(", "eddsa", S, "Ed25519 signature"),
    Rule("GO-DSA", ("go",), r"\bdsa\.GenerateKey\(", "dsa", S, "DSA key generation"),
    Rule("GO-TLS-CURVES", ("go",), r"\bCurvePreferences\s*[:=]", "ecdh", K,
         "TLS CurvePreferences pins classical groups only, disabling Go's default hybrid PQ key exchange", "medium", unless=_PQ_GROUP),
    Rule("GO-GODEBUG-NOPQ", ("go", "config", "iac", "any"), r"\btls(?:mlkem|kyber)=0\b", "ecdh", K, "GODEBUG disables post-quantum TLS key exchange"),
    Rule("GO-MD5", ("go",), r"\"crypto/md5\"", "md5", H, "MD5 hash (crypto/md5)"),
    Rule("GO-SHA1", ("go",), r"\"crypto/sha1\"", "sha1", H, "SHA-1 hash (crypto/sha1)"),
    Rule("GO-DES", ("go",), r"\"crypto/des\"", "des", Y, "DES / 3DES (crypto/des)"),
    Rule("GO-RC4", ("go",), r"\"crypto/rc4\"", "rc4", Y, "RC4 (crypto/rc4)"),
    Rule("GO-MLKEM", ("go",), r"\"crypto/mlkem\"|\btls\.(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024)\b", "ml-kem", K, "ML-KEM / hybrid PQ key exchange"),
    # ------------------------------------------------------------------ JavaScript / TypeScript
    Rule("JS-RSA-KEYGEN", ("javascript",), r"generateKeyPair(?:Sync)?\(\s*['\"](?:rsa|rsa-pss)['\"]", "rsa", G, "RSA key generation (node:crypto)"),
    Rule("JS-EC-KEYGEN", ("javascript",), r"generateKeyPair(?:Sync)?\(\s*['\"]ec['\"]", "ecc", G, "EC key generation (node:crypto)"),
    Rule("JS-EDDSA-KEYGEN", ("javascript",), r"generateKeyPair(?:Sync)?\(\s*['\"](?:ed25519|ed448)['\"]", "eddsa", S, "EdDSA key generation (node:crypto)"),
    Rule("JS-X25519-KEYGEN", ("javascript",), r"generateKeyPair(?:Sync)?\(\s*['\"](?:x25519|x448)['\"]", "x25519", K, "X25519 key generation (node:crypto)"),
    Rule("JS-DSA-KEYGEN", ("javascript",), r"generateKeyPair(?:Sync)?\(\s*['\"]dsa['\"]", "dsa", S, "DSA key generation (node:crypto)"),
    Rule("JS-DH", ("javascript",), r"\b(?:createDiffieHellman(?:Group)?|getDiffieHellman)\(|generateKeyPair(?:Sync)?\(\s*['\"]dh['\"]", "dh", K, "Diffie-Hellman (node:crypto)"),
    Rule("JS-ECDH", ("javascript",), r"\bcreateECDH\(", "ecdh", K, "ECDH (node:crypto)"),
    Rule("JS-RSA-ENC", ("javascript",), r"\b(?:publicEncrypt|privateDecrypt)\(", "rsa", E, "RSA encryption (node:crypto)"),
    Rule("JS-WEBCRYPTO-RSA-SIG", ("javascript",), r"['\"](?:RSASSA-PKCS1-v1_5|RSA-PSS)['\"]", "rsa", S, "RSA signature (WebCrypto)"),
    Rule("JS-WEBCRYPTO-ECDSA", ("javascript",), r"name\s*:\s*['\"]ECDSA['\"]", "ecdsa", S, "ECDSA (WebCrypto)"),
    Rule("JS-WEBCRYPTO-ECDH", ("javascript",), r"name\s*:\s*['\"]ECDH['\"]", "ecdh", K, "ECDH (WebCrypto)"),
    Rule("JS-WEBCRYPTO-X25519", ("javascript",), r"name\s*:\s*['\"]X25519['\"]", "x25519", K, "X25519 (WebCrypto)"),
    Rule("JS-WEBCRYPTO-ED25519", ("javascript",), r"name\s*:\s*['\"]Ed25519['\"]", "eddsa", S, "Ed25519 (WebCrypto)"),
    Rule("JS-FORGE-RSA", ("javascript",), r"\bpki\.rsa\.generateKeyPair\(|\bpki\.(?:publicKeyFromPem|privateKeyFromPem)\(", "rsa", G, "RSA via node-forge"),
    Rule("JS-NODERSA", ("javascript",), r"\bnew\s+NodeRSA\(", "rsa", G, "RSA via node-rsa"),
    Rule("JS-ELLIPTIC", ("javascript",), r"\bnew\s+(?:EC|ec|EdDSA)\(\s*['\"](?:secp256k1|p256|p384|p521|curve25519|ed25519)['\"]", "ecc", U, "Elliptic curve via elliptic"),
    Rule("JS-NACL-BOX", ("javascript",), r"\bnacl\.box\b", "x25519", K, "X25519 box (tweetnacl)"),
    Rule("JS-NACL-SIGN", ("javascript",), r"\bnacl\.sign\b", "eddsa", S, "Ed25519 signature (tweetnacl)"),
    Rule("JS-NOBLE-CURVES", ("javascript",), r"@noble/curves/(?:secp256k1|p256|p384|p521|nist|ed25519|ed448)", "ecc", U, "Elliptic curve via @noble/curves"),
    Rule("JS-NOBLE-PQ", ("javascript",), r"@noble/post-quantum", "pqc", U, "@noble/post-quantum usage"),
    Rule("JS-MD5", ("javascript",), r"createHash\(\s*['\"]md5['\"]|\bCryptoJS\.MD5\b", "md5", H, "MD5 hash"),
    Rule("JS-SHA1", ("javascript",), r"createHash\(\s*['\"]sha1['\"]|\bCryptoJS\.SHA1\b", "sha1", H, "SHA-1 hash"),
    Rule("JS-DES", ("javascript",), r"createCipheriv\(\s*['\"](?:des|des-ede3|des3|des-ede)[\w-]*['\"]|\bCryptoJS\.(?:DES|TripleDES)\b", "des", Y, "DES / 3DES cipher"),
    Rule("JS-RC4", ("javascript",), r"createCipheriv\(\s*['\"]rc4[\w-]*['\"]|\bCryptoJS\.RC4\b", "rc4", Y, "RC4 cipher"),
    # ------------------------------------------------------------------ C / C++ (OpenSSL, mbedTLS, wolfSSL, liboqs)
    Rule("C-RSA-KEYGEN", ("c",), r"\bRSA_generate_key(?:_ex)?\b|\bEVP_PKEY_RSA(?:_PSS)?\b|\bmbedtls_rsa_gen_key\b|\bwc_MakeRsaKey\b", "rsa", G, "RSA key"),
    Rule("C-RSA-ENC", ("c",), r"\bRSA_(?:public_encrypt|private_decrypt)\b|\bmbedtls_rsa_(?:pkcs1_encrypt|rsaes_oaep_encrypt)\b|\bwc_RsaPublicEncrypt\b", "rsa", E, "RSA encryption"),
    Rule("C-RSA-SIG", ("c",), r"\bRSA_(?:sign|verify)\b|\bmbedtls_rsa_pkcs1_sign\b|\bwc_RsaSSL_Sign\b", "rsa", S, "RSA signature"),
    Rule("C-EC", ("c",), r"\bEVP_PKEY_EC\b|\bEC_KEY_(?:new_by_curve_name|generate_key)\b|\bwc_ecc_make_key\b", "ecc", G, "Elliptic-curve key"),
    Rule("C-ECDSA", ("c",), r"\bECDSA_(?:sign|do_sign|verify|do_verify)\b|\bmbedtls_ecdsa_\w+\b|\bwc_ecc_sign_hash\b", "ecdsa", S, "ECDSA signature"),
    Rule("C-ECDH", ("c",), r"\bECDH_compute_key\b|\bmbedtls_ecdh_\w+\b|\bwc_ecc_shared_secret\b", "ecdh", K, "ECDH key agreement"),
    Rule("C-DH", ("c",), r"\bDH_(?:generate_key|compute_key|new)\b|\bEVP_PKEY_DH\b|\bmbedtls_dhm_\w+\b", "dh", K, "Diffie-Hellman"),
    Rule("C-DSA", ("c",), r"\bDSA_(?:generate_parameters(?:_ex)?|generate_key|sign)\b|\bEVP_PKEY_DSA\b", "dsa", S, "DSA"),
    Rule("C-EDDSA", ("c",), r"\bEVP_PKEY_(?:ED25519|ED448)\b|\bcrypto_sign_(?:keypair|detached)\b", "eddsa", S, "EdDSA"),
    Rule("C-X25519", ("c",), r"\bEVP_PKEY_(?:X25519|X448)\b|\bcrypto_(?:box|kx|scalarmult)_\w+\b", "x25519", K, "X25519/X448 key agreement"),
    Rule("C-OSSL3-NAMED", ("c",), r"\bEVP_PKEY_(?:CTX_new_from_name|Q_keygen)\s*\([^;]*?\"(?:RSA|RSA-PSS)\"", "rsa", G, "RSA key (OpenSSL 3 by-name API)"),
    Rule("C-OSSL3-NAMED-EC", ("c",), r"\bEVP_PKEY_(?:CTX_new_from_name|Q_keygen)\s*\([^;]*?\"(?:EC|X25519|ED25519)\"", "ecc", G, "EC key (OpenSSL 3 by-name API)"),
    Rule("C-TLS-GROUPS", ("c",), r"\bSSL_(?:CTX_)?set1_(?:groups|curves)_list\s*\(", "ecdh", K,
         "TLS group list set without a post-quantum hybrid group", "medium", unless=_PQ_GROUP),
    Rule("C-MD5", ("c",), r"\bMD5(?:_Init)?\s*\(|\bEVP_md5\s*\(", "md5", H, "MD5 hash"),
    Rule("C-SHA1", ("c",), r"\bSHA1(?:_Init)?\s*\(|\bEVP_sha1\s*\(", "sha1", H, "SHA-1 hash"),
    Rule("C-DES", ("c",), r"\bEVP_des_\w+\s*\(|\bDES_\w+crypt\b", "des", Y, "DES / 3DES cipher"),
    Rule("C-RC4", ("c",), r"\bEVP_rc4\w*\s*\(|\bRC4_set_key\b", "rc4", Y, "RC4 cipher"),
    Rule("C-LIBOQS", ("c",), r"\bOQS_(?:KEM|SIG)_new\s*\(", "pqc", U, "liboqs post-quantum usage"),
    # ------------------------------------------------------------------ C# / .NET
    Rule("CS-RSA", ("csharp",), r"\bRSA\.Create\(|\bnew\s+RSA(?:CryptoServiceProvider|Cng|OpenSsl)\(", "rsa", G, "RSA (.NET)"),
    Rule("CS-RSA-ENC", ("csharp",), r"\bRSAEncryptionPadding\.", "rsa", E, "RSA encryption (.NET)"),
    Rule("CS-RSA-SIG", ("csharp",), r"\bRSASignaturePadding\.", "rsa", S, "RSA signature (.NET)"),
    Rule("CS-ECDSA", ("csharp",), r"\bECDsa\.Create\(|\bnew\s+ECDsa(?:Cng|OpenSsl)\(", "ecdsa", S, "ECDSA (.NET)"),
    Rule("CS-ECDH", ("csharp",), r"\bECDiffieHellman\.Create\(|\bnew\s+ECDiffieHellman(?:Cng|OpenSsl)\(", "ecdh", K, "ECDH (.NET)"),
    Rule("CS-DSA", ("csharp",), r"\bDSA\.Create\(|\bDSACryptoServiceProvider\b", "dsa", S, "DSA (.NET)"),
    Rule("CS-MD5", ("csharp",), r"\bMD5\.(?:Create|HashData)\(|\bMD5CryptoServiceProvider\b", "md5", H, "MD5 (.NET)"),
    Rule("CS-SHA1", ("csharp",), r"\bSHA1\.(?:Create|HashData)\(|\bSHA1(?:Managed|CryptoServiceProvider)\b", "sha1", H, "SHA-1 (.NET)"),
    Rule("CS-DES", ("csharp",), r"\b(?:DES|TripleDES|RC2)\.Create\(|\b(?:DES|TripleDES|RC2)CryptoServiceProvider\b", "des", Y, "DES / 3DES / RC2 (.NET)"),
    Rule("CS-PQC", ("csharp",), r"\b(?:MLKem|MLDsa|SlhDsa)\.(?:GenerateKey|Import\w*)\(", "pqc", U, ".NET post-quantum API"),
    # ------------------------------------------------------------------ Rust
    Rule("RS-RSA", ("rust",), r"\bRsaPrivateKey::new\(|\brsa::(?:Pkcs1v15Encrypt|Oaep)\b", "rsa", G, "RSA (RustCrypto rsa)"),
    Rule("RS-ECC", ("rust",), r"\buse\s+(?:p256|p384|p521|k256)::", "ecc", U, "Elliptic curve (RustCrypto)"),
    Rule("RS-ED25519", ("rust",), r"\bed25519_dalek::|\bring::signature::ED25519\b", "eddsa", S, "Ed25519 signature"),
    Rule("RS-X25519", ("rust",), r"\bx25519_dalek::|\bring::agreement::X25519\b", "x25519", K, "X25519 key agreement"),
    Rule("RS-RING-RSA", ("rust",), r"\bring::signature::RSA_\w+", "rsa", S, "RSA signature (ring)"),
    Rule("RS-RING-ECDSA", ("rust",), r"\bring::signature::ECDSA_\w+", "ecdsa", S, "ECDSA signature (ring)"),
    Rule("RS-RING-ECDH", ("rust",), r"\bring::agreement::ECDH_P(?:256|384)\b", "ecdh", K, "ECDH key agreement (ring)"),
    Rule("RS-MD5-SHA1", ("rust",), r"\buse\s+md5::|\bMd5::new\(", "md5", H, "MD5 hash"),
    Rule("RS-SHA1", ("rust",), r"\buse\s+sha1::|\bSha1::new\(", "sha1", H, "SHA-1 hash"),
    Rule("RS-PQC", ("rust",), r"\buse\s+(?:ml_kem|ml_dsa|slh_dsa|pqcrypto\w*|oqs)::", "pqc", U, "Rust post-quantum crate"),
    # ------------------------------------------------------------------ PHP
    Rule("PHP-PKEY-NEW", ("php",), r"\bopenssl_pkey_new\s*\(", "rsa", G, "OpenSSL key generation (defaults to RSA)", "medium"),
    Rule("PHP-KEYTYPE-RSA", ("php",), r"\bOPENSSL_KEYTYPE_RSA\b", "rsa", G, "RSA key type"),
    Rule("PHP-KEYTYPE-EC", ("php",), r"\bOPENSSL_KEYTYPE_EC\b", "ecc", G, "EC key type"),
    Rule("PHP-RSA-ENC", ("php",), r"\bopenssl_(?:public_encrypt|private_decrypt|seal|open)\s*\(", "rsa", E, "RSA encryption (openssl_*)"),
    Rule("PHP-SIGN", ("php",), r"\bopenssl_(?:sign|verify)\s*\(", "rsa", S, "Public-key signature (openssl_sign)", "medium"),
    Rule("PHP-SODIUM-BOX", ("php",), r"\bsodium_crypto_(?:box|kx)\w*\s*\(", "x25519", K, "X25519 (libsodium)"),
    Rule("PHP-SODIUM-SIGN", ("php",), r"\bsodium_crypto_sign\w*\s*\(", "eddsa", S, "Ed25519 (libsodium)"),
    Rule("PHP-PHPSECLIB", ("php",), r"\b(?:RSA|EC)::createKey\s*\(", "rsa", G, "Key generation (phpseclib)"),
    Rule("PHP-MD5", ("php",), r"(?<![\w>$:])md5\s*\(", "md5", H, "MD5 hash", "medium"),
    Rule("PHP-SHA1", ("php",), r"(?<![\w>$:])sha1\s*\(", "sha1", H, "SHA-1 hash", "medium"),
    # ------------------------------------------------------------------ Ruby
    Rule("RB-RSA", ("ruby",), r"OpenSSL::PKey::RSA\.(?:new|generate)", "rsa", G, "RSA (Ruby OpenSSL)"),
    Rule("RB-EC", ("ruby",), r"OpenSSL::PKey::EC\.(?:new|generate)", "ecc", G, "EC (Ruby OpenSSL)"),
    Rule("RB-DH", ("ruby",), r"OpenSSL::PKey::DH\b", "dh", K, "Diffie-Hellman (Ruby OpenSSL)"),
    Rule("RB-DSA", ("ruby",), r"OpenSSL::PKey::DSA\b", "dsa", S, "DSA (Ruby OpenSSL)"),
    Rule("RB-MD5", ("ruby",), r"\b(?:OpenSSL::)?Digest::MD5\b", "md5", H, "MD5 hash"),
    Rule("RB-SHA1", ("ruby",), r"\b(?:OpenSSL::)?Digest::SHA1\b", "sha1", H, "SHA-1 hash"),
    # ------------------------------------------------------------------ Swift (CryptoKit / Security)
    Rule("SW-P-SIGN", ("swift",), r"\bP(?:256|384|521)\.Signing\b", "ecdsa", S, "ECDSA (CryptoKit)"),
    Rule("SW-P-KA", ("swift",), r"\bP(?:256|384|521)\.KeyAgreement\b", "ecdh", K, "ECDH (CryptoKit)"),
    Rule("SW-25519-SIGN", ("swift",), r"\bCurve25519\.Signing\b", "eddsa", S, "Ed25519 (CryptoKit)"),
    Rule("SW-25519-KA", ("swift",), r"\bCurve25519\.KeyAgreement\b", "x25519", K, "X25519 (CryptoKit)"),
    Rule("SW-SECKEY-RSA", ("swift",), r"\bkSecAttrKeyTypeRSA\b", "rsa", G, "RSA (Security framework)"),
    Rule("SW-SECKEY-EC", ("swift",), r"\bkSecAttrKeyTypeEC(?:SECPrimeRandom)?\b", "ecc", G, "EC (Security framework)"),
    Rule("SW-INSECURE", ("swift",), r"\bInsecure\.MD5\b", "md5", H, "MD5 (CryptoKit Insecure)"),
    Rule("SW-INSECURE-SHA1", ("swift",), r"\bInsecure\.SHA1\b", "sha1", H, "SHA-1 (CryptoKit Insecure)"),
    Rule("SW-PQC", ("swift",), r"\b(?:MLKEM768|MLKEM1024|MLDSA65|MLDSA87|XWingMLKEM768X25519)\b", "pqc", U, "CryptoKit post-quantum API"),
    # ------------------------------------------------------------------ JOSE / JWT (code and config)
    Rule("JOSE-RSA-SIG", CODE + CONFIG, r"['\"](?:RS|PS)(?:256|384|512)['\"]", "rsa", S, "JWT/JOSE RSA signature algorithm", "medium"),
    Rule("JOSE-ECDSA-SIG", CODE + CONFIG, r"['\"]ES(?:256K?|384|512)['\"]", "ecdsa", S, "JWT/JOSE ECDSA signature algorithm", "medium"),
    Rule("JOSE-EDDSA", CODE + CONFIG, r"['\"]EdDSA['\"]", "eddsa", S, "JWT/JOSE EdDSA signature algorithm", "medium"),
    Rule("JOSE-RSA-ENC", CODE + CONFIG, r"['\"](?:RSA-OAEP(?:-256|-384|-512)?|RSA1_5)['\"]", "rsa", E, "RSA key encryption (JOSE / WebCrypto)"),
    Rule("JOSE-ECDH-ES", CODE + CONFIG, r"['\"]ECDH-ES(?:\+A\d+KW)?['\"]", "ecdh", K, "JWE ECDH-ES key agreement"),
    # ------------------------------------------------------------------ Server / protocol configuration
    Rule("CFG-SSH-KEX", ("ssh-config",), r"^\s*KexAlgorithms\s+\S", "ecdh", K,
         "SSH KexAlgorithms set without a post-quantum hybrid", unless=r"mlkem768x25519|sntrup761x25519", flags=re.IGNORECASE),
    Rule("CFG-SSH-RSA-HOSTKEY", ("ssh-config",), r"^\s*HostKey\s+\S*(?:rsa|ecdsa)\S*", "rsa", S, "SSH host key uses RSA/ECDSA", flags=re.IGNORECASE),
    Rule("CFG-SSH-DSS", ("ssh-config",), r"\bssh-dss\b", "dsa", S, "SSH DSA (ssh-dss) enabled"),
    Rule("CFG-NGINX-CURVES", ("config",), r"^\s*ssl_ecdh_curve\s+\S", "ecdh", K,
         "nginx ssl_ecdh_curve excludes post-quantum hybrid groups", unless=_PQ_GROUP),
    Rule("CFG-APACHE-CURVES", ("config",), r"^\s*SSLOpenSSLConfCmd\s+(?:Curves|Groups)\s", "ecdh", K,
         "Apache TLS groups exclude post-quantum hybrid groups", unless=_PQ_GROUP),
    Rule("CFG-HAPROXY-CURVES", ("config",), r"^\s*(?:ssl-default-bind-curves|ssl-default-server-curves)\s|\bcurves\s+\S+", "ecdh", K,
         "HAProxy TLS curves exclude post-quantum hybrid groups", "medium", unless=_PQ_GROUP),
    Rule("CFG-OPENSSL-GROUPS", ("config",), r"^\s*Groups\s*=", "ecdh", K, "OpenSSL Groups setting excludes post-quantum hybrid groups", unless=_PQ_GROUP),
    Rule("CFG-TLS-NO13", ("config",), r"^\s*(?:ssl_protocols|SSLProtocol)\s+[^#\n]*", "tls-legacy", P,
         "TLS 1.3 not enabled (post-quantum key exchange requires TLS 1.3)", unless=r"TLSv1\.3|\ball\b", severity=Severity.CRITICAL),
    Rule("CFG-TLS-LEGACY", ("config",), r"^\s*(?:ssl_protocols|SSLProtocol|ssl-min-ver)\b[^#\n]*\b(?:SSLv3|TLSv1(?!\.)|TLSv1\.1)\b", "tls-legacy", P,
         "Legacy SSL/TLS protocol version enabled", unless=r"-TLSv1\b|-TLSv1\.1"),
    # ------------------------------------------------------------------ Infrastructure as code / cloud KMS
    Rule("IAC-TLS-PRIVATE-KEY", ("iac",), r"\balgorithm\s*=\s*\"(?:RSA|ECDSA|ED25519)\"", "rsa", G, "Terraform tls_private_key with classical algorithm"),
    Rule("IAC-KMS-RSA", ("iac", "config"), r"(?:key_spec|customer_master_key_spec|KeySpec|key_algorithm)\W{1,6}(?:RSA_\d+)", "rsa", G, "Cloud KMS / ACM RSA key"),
    Rule("IAC-KMS-ECC", ("iac", "config"), r"(?:key_spec|customer_master_key_spec|KeySpec|key_algorithm)\W{1,6}(?:ECC_\w+|EC_\w+)", "ecc", G, "Cloud KMS / ACM elliptic-curve key"),
    Rule("IAC-GCP-KMS", ("iac", "config"), r"\b(?:RSA_(?:SIGN|DECRYPT)_\w+|EC_SIGN_\w+)\b", "rsa", U, "Google Cloud KMS classical key algorithm"),
    Rule("IAC-AZURE-KEY", ("iac",), r"\bkey_type\s*=\s*\"(?:RSA|RSA-HSM|EC|EC-HSM)\"", "rsa", G, "Azure Key Vault classical key"),
    Rule("IAC-CERTMANAGER", ("iac", "config"), r"^\s*algorithm\s*:\s*(?:RSA|ECDSA|Ed25519)\s*$", "rsa", G, "Certificate private key algorithm (cert-manager style)", "medium"),
    # ------------------------------------------------------------------ Any text file
    Rule("GEN-SSH-PUBKEY", ANY, r"\b(?:ssh-rsa|ecdsa-sha2-nistp\d+|ssh-ed25519|ssh-dss)\s+AAAA[0-9A-Za-z+/]{20,}", "rsa", S, "SSH public key (classical algorithm)"),
    Rule("GEN-ML-KEM", ANY, r"\b(?:ML[-_]?KEM[-_]?(?:512|768|1024)|MLKEM(?:512|768|1024))\b", "ml-kem", K, "ML-KEM reference", flags=re.IGNORECASE),
    Rule("GEN-HYBRID-KEM", ANY, r"\b(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|mlkem768x25519-sha256|sntrup761x25519-sha512|X-?Wing)\b", "hybrid-kem", K, "Hybrid post-quantum key exchange", flags=re.IGNORECASE),
    Rule("GEN-ML-DSA", ANY, r"\bML[-_]?DSA[-_]?(?:44|65|87)\b", "ml-dsa", S, "ML-DSA reference", flags=re.IGNORECASE),
    Rule("GEN-SLH-DSA", ANY, r"\bSLH[-_]?DSA\b", "slh-dsa", S, "SLH-DSA reference", flags=re.IGNORECASE),
    Rule("GEN-KYBER", ANY, r"\b(?:Kyber(?:512|768|1024)|X25519Kyber768(?:Draft00)?)\b", "kyber", K, "Pre-standard Kyber reference", flags=re.IGNORECASE),
    Rule("GEN-DILITHIUM", ANY, r"\bDilithium[2-5]\b", "dilithium", S, "Pre-standard Dilithium reference", flags=re.IGNORECASE),
]

# Fixed up after construction: rules whose algorithm depends on the matched text.
_GROUP_ALGORITHMS = {
    "PY-PARAMIKO": {"RSAKey": "rsa", "ECDSAKey": "ecdsa", "DSSKey": "dsa"},
}


def algorithm_for_match(rule: Rule, match: re.Match) -> str:
    """Refine the algorithm for rules that cover several algorithms with one pattern."""
    text = match.group(0)
    if rule.id in _GROUP_ALGORITHMS and match.groups():
        return _GROUP_ALGORITHMS[rule.id].get(match.group(1), rule.algorithm)
    if rule.id == "GEN-SSH-PUBKEY":
        if text.startswith("ecdsa"):
            return "ecdsa"
        if text.startswith("ssh-ed25519"):
            return "eddsa"
        if text.startswith("ssh-dss"):
            return "dsa"
    if rule.id in ("IAC-TLS-PRIVATE-KEY", "IAC-CERTMANAGER"):
        upper = text.upper()
        if "ECDSA" in upper:
            return "ecdsa"
        if "ED25519" in upper:
            return "eddsa"
    if rule.id == "IAC-GCP-KMS" and text.startswith("EC_"):
        return "ecdsa"
    if rule.id == "IAC-AZURE-KEY" and "\"EC" in text:
        return "ecc"
    if rule.id == "C-OSSL3-NAMED-EC":
        if "X25519" in text:
            return "x25519"
        if "ED25519" in text:
            return "eddsa"
    return rule.algorithm


def rules_by_id() -> dict[str, Rule]:
    return {r.id: r for r in RULES}
