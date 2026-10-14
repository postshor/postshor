"""Parse certificates and key files and report their algorithms, sizes and lifetimes."""

from __future__ import annotations

import datetime as dt
import re
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import pkcs12

from postshor.models import Category, Finding, Location, Severity, Usage
from postshor.rules import explain, remediation

# NIST IR 8547 (draft): quantum-vulnerable algorithms deprecated after 2030, disallowed after 2035.
DEPRECATION_DATE = dt.datetime(2031, 1, 1, tzinfo=dt.UTC)
DISALLOWED_DATE = dt.datetime(2036, 1, 1, tzinfo=dt.UTC)

_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.+?-----END \1-----", re.DOTALL)
_SSH_PUB = re.compile(rb"^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp\d+|sk-\S+)\s+AAAA\S+", re.MULTILINE)


def describe_key(key) -> tuple[str, str, int | None]:
    """Return (algorithm id, human name, key size in bits) for any public or private key."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "rsa", f"RSA-{key.key_size}", key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ecc", f"EC {key.curve.name}", key.curve.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "eddsa", "Ed25519", 256
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "eddsa", "Ed448", 456
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "x25519", "X25519", 256
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "x25519", "X448", 448
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "dsa", f"DSA-{key.key_size}", key.key_size
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return "dh", f"DH-{key.key_size}", key.key_size
    return "pqc", type(key).__name__, None


def _size_severity(algo: str, bits: int | None, base: Severity) -> Severity:
    """Keys that are too small are broken classically, which outranks the quantum concern."""
    if bits is None:
        return base
    if algo in ("rsa", "dsa", "dh") and bits < 2048:
        return Severity.CRITICAL
    if algo == "ecc" and bits < 224:
        return Severity.CRITICAL
    return base


def certificate_finding(cert: x509.Certificate, path: str, line: int | None = None, live: bool = False) -> Finding:
    pub = cert.public_key()
    algo, name, bits = describe_key(pub)
    not_after = cert.not_valid_after_utc
    subject = cert.subject.rfc4514_string() or "(empty subject)"
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    is_ca = _is_ca(cert)

    notes: list[str] = []
    severity = Severity.INFO if algo == "pqc" else Severity.HIGH
    if live and severity == Severity.HIGH:
        # Post-quantum certificates are not yet issued by public CAs; this is a planning item.
        severity = Severity.MEDIUM
        notes.append("Public CAs do not issue post-quantum certificates yet; make sure certificate rotation is automated so you can switch quickly.")
    if not_after > DISALLOWED_DATE and algo != "pqc":
        notes.append(f"Valid until {not_after.date()}, beyond the 2035 point where NIST plans to disallow {name.split('-')[0]}.")
        severity = max(severity, Severity.HIGH)
    elif not_after > DEPRECATION_DATE and algo != "pqc":
        notes.append(f"Valid until {not_after.date()}, beyond NIST's planned 2030 deprecation of quantum-vulnerable algorithms.")
    if not_after < dt.datetime.now(dt.UTC):
        notes.append(f"Already expired on {not_after.date()}.")
    if sig_hash in ("md5", "sha1"):
        notes.append(f"Signed with {sig_hash.upper()}, which is already broken.")
        severity = max(severity, Severity.HIGH)
    if is_ca:
        notes.append("This is a CA certificate: everything it signs inherits its quantum exposure, so plan its replacement first.")
    severity = _size_severity(algo, bits, severity)

    return Finding(
        rule_id="CERT-QUANTUM-VULNERABLE" if algo != "pqc" else "CERT-PQC",
        title=f"{'CA certificate' if is_ca else 'Certificate'} with {name} key",
        severity=severity,
        category=Category.NETWORK if live else Category.CERTIFICATE,
        algorithm=algo,
        usage=Usage.CERTIFICATE,
        location=Location(path, line, None, subject),
        message=(explain(algo, Usage.SIGNATURE) + " " + " ".join(notes)).strip(),
        remediation=remediation(algo, Usage.SIGNATURE),
        details={
            "subject": subject,
            "issuer": cert.issuer.rfc4514_string(),
            "serial": format(cert.serial_number, "x"),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": not_after.isoformat(),
            "key": name,
            "key_bits": bits,
            "signature_algorithm": getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string,
            "signature_hash": sig_hash,
            "is_ca": is_ca,
            "oid": cert.signature_algorithm_oid.dotted_string,
        },
    )


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _key_finding(key, path: str, private: bool, line: int | None = None, encrypted: bool = False) -> Finding:
    algo, name, bits = describe_key(key) if key is not None else ("rsa", "unknown (encrypted)", None)
    if private:
        severity = Severity.HIGH if encrypted else Severity.CRITICAL
        title = f"{'Encrypted p' if encrypted else 'P'}rivate key ({name}) stored in repository"
        message = (
            "A private key is committed to the repository. "
            + ("It is password-protected, but the password may be weak or shared. " if encrypted else "Anyone with read access can use it. ")
            + explain(algo, Usage.SIGNATURE)
        )
        fix = "Remove it, rotate the key, purge it from git history and load keys from a secrets manager or HSM. " + remediation(algo, Usage.SIGNATURE)
        category, rule_id = Category.SECRET, "KEY-PRIVATE-IN-REPO"
    else:
        severity = _size_severity(algo, bits, Severity.MEDIUM if algo != "pqc" else Severity.INFO)
        title = f"Public key ({name})"
        message = explain(algo, Usage.SIGNATURE) + " Whoever holds the matching private key is exposed once a quantum computer can derive it from this public key."
        fix = remediation(algo, Usage.SIGNATURE)
        category, rule_id = Category.KEY, "KEY-PUBLIC-QUANTUM-VULNERABLE"
    return Finding(
        rule_id=rule_id, title=title, severity=severity, category=category, algorithm=algo,
        usage=Usage.KEY_MATERIAL, location=Location(path, line, None, name), message=message,
        remediation=fix, details={"key": name, "key_bits": bits, "subject": name},
    )


def scan_key_file(rel_path: str, data: bytes) -> list[Finding]:
    """Inspect one certificate/key file. Never raises on malformed input."""
    with warnings.catch_warnings():
        # Real-world CA bundles contain certs that trip pyca deprecation warnings (e.g. negative serials).
        warnings.simplefilter("ignore")
        return _scan_key_file(rel_path, data)


def _scan_key_file(rel_path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    blocks = list(_PEM_BLOCK.finditer(data))
    certs = [m for m in blocks if m.group(1) == b"CERTIFICATE"]
    if len(certs) >= 5 and len(certs) == len(blocks):
        trust_store = _trust_store_finding(rel_path, certs)
        if trust_store:
            return [trust_store]
    if blocks:
        for m in blocks:
            line = data.count(b"\n", 0, m.start()) + 1
            findings.extend(_scan_pem_block(m.group(1).decode(), m.group(0), rel_path, line))
    else:
        for m in _SSH_PUB.finditer(data):
            line = data.count(b"\n", 0, m.start()) + 1
            try:
                key = serialization.load_ssh_public_key(m.group(0))
                findings.append(_key_finding(key, rel_path, private=False, line=line))
            except Exception:
                continue
        if not findings:
            findings.extend(_scan_der(data, rel_path))
    return findings


def _trust_store_finding(path: str, blocks: list[re.Match]) -> Finding | None:
    """A bundle of mostly CA certificates is a trust store (e.g. certifi), not your own PKI."""
    parsed = []
    for m in blocks:
        try:
            parsed.append(x509.load_pem_x509_certificate(m.group(0)))
        except Exception:
            continue
    if not parsed or sum(_is_ca(c) for c in parsed) < 0.8 * len(parsed):
        return None
    classical = [c for c in parsed if describe_key(c.public_key())[0] != "pqc"]
    pq = len(parsed) - len(classical)
    return Finding(
        rule_id="CERT-TRUST-STORE",
        title=f"Trust store with {len(classical)} classical root certificates",
        severity=Severity.LOW if classical else Severity.INFO,
        category=Category.CERTIFICATE,
        algorithm="rsa" if classical else "pqc",
        usage=Usage.CERTIFICATE,
        location=Location(path, None, None, f"{len(parsed)} CA certificates"),
        message=(f"This file is a CA bundle ({len(parsed)} certificates, {pq} post-quantum). Every root uses RSA or ECC today, "
                 "as does the whole public PKI. You do not fix this yourself; you need the bundle to stay updatable so "
                 "post-quantum roots can be added when CAs issue them."),
        remediation="Load the trust store from the OS or a maintained package (certifi, ca-certificates) rather than a pinned copy, and keep it updated.",
        details={"subject": path, "certificates": len(parsed), "post_quantum": pq},
    )


def _scan_pem_block(label: str, block: bytes, path: str, line: int) -> list[Finding]:
    try:
        if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
            return [certificate_finding(x509.load_pem_x509_certificate(block), path, line)]
        if label == "CERTIFICATE REQUEST":
            csr = x509.load_pem_x509_csr(block)
            f = _key_finding(csr.public_key(), path, private=False, line=line)
            f.title = "Certificate signing request " + f.title[len("Public key "):]
            f.rule_id = "CSR-QUANTUM-VULNERABLE" if f.algorithm != "pqc" else "CSR-PQC"
            return [f]
        if label == "OPENSSH PRIVATE KEY":
            try:
                return [_key_finding(serialization.load_ssh_private_key(block, None), path, True, line)]
            except (TypeError, ValueError):
                return [_key_finding(None, path, True, line, encrypted=True)]
        if label == "ENCRYPTED PRIVATE KEY" or (label.endswith("PRIVATE KEY") and b"ENCRYPTED" in block[:200]):
            return [_key_finding(None, path, True, line, encrypted=True)]
        if label.endswith("PRIVATE KEY"):
            return [_key_finding(serialization.load_pem_private_key(block, None), path, True, line)]
        if label.endswith("PUBLIC KEY"):
            return [_key_finding(serialization.load_pem_public_key(block), path, False, line)]
    except Exception as exc:  # unsupported algorithm or malformed block
        return [_unparsed(path, line, label, exc)]
    return []


def _scan_der(data: bytes, path: str) -> list[Finding]:
    loaders = (
        lambda d: [certificate_finding(x509.load_der_x509_certificate(d), path)],
        lambda d: [_key_finding(serialization.load_der_private_key(d, None), path, True)],
        lambda d: [_key_finding(serialization.load_der_public_key(d), path, False)],
        lambda d: _scan_pkcs12(d, path),
    )
    for load in loaders:
        try:
            return load(data)
        except Exception:
            continue
    return []


def _scan_pkcs12(data: bytes, path: str) -> list[Finding]:
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, None)
    except ValueError as exc:
        if "password" in str(exc).lower() or "mac" in str(exc).lower():
            return [_key_finding(None, path, True, encrypted=True)]
        raise
    out = []
    if key is not None:
        out.append(_key_finding(key, path, True))
    for c in [cert, *extra]:
        if c is not None:
            out.append(certificate_finding(c, path))
    return out


def _unparsed(path: str, line: int, label: str, exc: Exception) -> Finding:
    return Finding(
        rule_id="KEY-UNPARSED",
        title=f"Could not parse {label.lower()} block",
        severity=Severity.INFO,
        category=Category.KEY,
        algorithm="pqc",
        usage=Usage.KEY_MATERIAL,
        location=Location(path, line, None, label),
        message=f"PostShor found a {label} block but could not parse it ({type(exc).__name__}). It may use an algorithm this build does not know, which can include post-quantum keys.",
        remediation="Inspect manually, e.g. `openssl x509 -text -noout -in FILE`.",
        confidence="low",
        details={"subject": label},
    )
