from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from conftest import make_cert, pem
from postshor.models import Category, Severity
from postshor.scanners.certificates import scan_key_file


def test_ec_certificate_is_high():
    cert, _ = make_cert()
    [f] = scan_key_file("server.crt", pem(cert))
    assert f.rule_id == "CERT-QUANTUM-VULNERABLE"
    assert f.algorithm == "ecc"
    assert f.severity == Severity.HIGH
    assert f.details["key"] == "EC secp256r1"


def test_small_rsa_key_is_critical():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert, _ = make_cert(key)
    [f] = scan_key_file("legacy.pem", pem(cert))
    assert f.severity == Severity.CRITICAL
    assert f.details["key_bits"] == 1024


def test_certificate_past_2035_is_called_out(rsa_key):
    cert, _ = make_cert(rsa_key, days=365 * 15, ca=True)
    [f] = scan_key_file("root-ca.pem", pem(cert))
    assert "2035" in f.message
    assert "CA certificate" in f.title


def test_private_key_in_repo_is_critical_secret(rsa_key):
    data = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    [f] = scan_key_file("deploy.key", data)
    assert f.category is Category.SECRET
    assert f.severity == Severity.CRITICAL
    assert f.details["key"] == "RSA-2048"


def test_encrypted_private_key(rsa_key):
    data = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.BestAvailableEncryption(b"pw"))
    [f] = scan_key_file("deploy.key", data)
    assert f.severity == Severity.HIGH
    assert "Encrypted" in f.title


def test_ssh_public_key():
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    data = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH) + b" dev@laptop\n"
    [f] = scan_key_file("id_ed25519.pub", data)
    assert f.algorithm == "eddsa"
    assert f.rule_id == "KEY-PUBLIC-QUANTUM-VULNERABLE"


def test_der_certificate(rsa_key):
    cert, _ = make_cert(rsa_key)
    [f] = scan_key_file("server.der", cert.public_bytes(serialization.Encoding.DER))
    assert f.algorithm == "rsa"


def test_trust_store_collapses_to_one_finding(rsa_key):
    bundle = b"".join(pem(make_cert(rsa_key, ca=True, cn=f"Root {i}")[0]) for i in range(6))
    [f] = scan_key_file("cacert.pem", bundle)
    assert f.rule_id == "CERT-TRUST-STORE"
    assert f.severity == Severity.LOW
    assert f.details["certificates"] == 6


def test_garbage_does_not_raise():
    assert scan_key_file("junk.pem", b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")[0].rule_id == "KEY-UNPARSED"
    assert scan_key_file("empty.key", b"") == []
