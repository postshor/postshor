import re

import pytest

from postshor import engine
from postshor.models import Severity
from postshor.rules import ALGORITHMS, RULES
from postshor.scanners.source import SourceScanner


@pytest.fixture(scope="module")
def result():
    from conftest import FIXTURES
    return engine.scan(FIXTURES / "vulnerable_app")


def hits(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_rule_ids_unique_and_algorithms_known():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert r.algorithm in ALGORITHMS, r.id
        assert re.fullmatch(r"[A-Z]+(-[A-Z0-9]+)+", r.id), r.id


@pytest.mark.parametrize("rule_id,path_fragment", [
    ("PY-RSA-KEYGEN", "py/"), ("PY-RSA-OAEP", "py/"), ("PY-ECDH", "py/"), ("PY-DES", "py/"), ("PY-MD5", "py/"),
    ("JS-RSA-KEYGEN", "js/"), ("JS-ECDH", "js/"), ("JS-RSA-ENC", "js/"), ("JS-SHA1", "js/"), ("JS-WEBCRYPTO-ECDSA", "js/"),
    ("JVM-RSA-KEYGEN", "java/"), ("JVM-RSA-CIPHER", "java/"), ("JVM-ECDSA-SIG", "java/"), ("JVM-ECDH", "java/"), ("JVM-MD5", "java/"),
    ("GO-RSA-KEYGEN", "go/"), ("GO-RSA-ENC", "go/"), ("GO-ECDSA", "go/"), ("GO-TLS-CURVES", "go/"),
    ("C-RSA-KEYGEN", "c/"), ("C-TLS-GROUPS", "c/"),
    ("CS-RSA", "cs/"), ("CS-RSA-ENC", "cs/"), ("CS-ECDH", "cs/"), ("CS-MD5", "cs/"),
    ("RS-RSA", "rust/"), ("RS-X25519", "rust/"), ("RS-PQC", "rust/"),
    ("CFG-SSH-KEX", "sshd_config"), ("CFG-SSH-RSA-HOSTKEY", "sshd_config"),
    ("CFG-NGINX-CURVES", "nginx.conf"), ("CFG-TLS-NO13", "nginx.conf"), ("CFG-TLS-LEGACY", "nginx.conf"),
    ("IAC-TLS-PRIVATE-KEY", "main.tf"), ("IAC-KMS-ECC", "main.tf"),
    ("JOSE-RSA-SIG", "py/"), ("GEN-ML-KEM", "java/"), ("GEN-HYBRID-KEM", "c/"),
    ("DEP-PYPI-PYCRYPTO", "requirements.txt"), ("DEP-NPM-NODE-FORGE", "package.json"),
    ("DEP-GO-TOOLCHAIN-PRE-PQ", "go.mod"),
])
def test_detects(result, rule_id, path_fragment):
    found = hits(result, rule_id)
    assert found, f"{rule_id} not reported"
    assert any(path_fragment in f.location.path for f in found)


def test_harvest_now_decrypt_later_is_critical(result):
    for rule_id in ("PY-RSA-OAEP", "JVM-ECDH", "GO-RSA-ENC", "CFG-SSH-KEX"):
        assert all(f.severity == Severity.CRITICAL for f in hits(result, rule_id)), rule_id


def test_signatures_are_high(result):
    assert all(f.severity == Severity.HIGH for f in hits(result, "JVM-ECDSA-SIG"))


def test_pq_configuration_is_not_flagged(result):
    # go/server.go:16 and c/tls.c:12 configure X25519MLKEM768 and must not be reported as classical-only.
    assert [f.location.line for f in hits(result, "GO-TLS-CURVES")] == [15]
    assert [f.location.line for f in hits(result, "C-TLS-GROUPS")] == [5]


def test_comments_are_ignored(result):
    lines = [f.location.line for f in hits(result, "PY-MD5")]
    assert lines == [20]  # line 18 mentions hashlib.md5 inside a comment
    assert not [f for f in hits(result, "CFG-SSH-KEX") if f.location.line == 3]


def test_inline_suppression(result):
    assert not hits(result, "PY-SHA1")
    assert result.suppressed >= 1


def test_generic_ecc_dropped_when_specific_on_same_line(result):
    lines_go = {f.location.line for f in result.findings if f.location.path.endswith("server.go") and f.algorithm == "ecc"}
    assert 14 not in lines_go


def test_embedded_private_key_detected():
    scanner = SourceScanner()
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"  # split so this test file is not itself flagged
    text = f'KEY = """{header}\nMIIB...\n"""\n'
    found, _ = scanner.scan("settings.py", text, {"python", "any"})
    assert found[0].rule_id == "GEN-EMBEDDED-PRIVATE-KEY"
    assert found[0].severity == Severity.CRITICAL


def test_clean_app_has_no_findings(fixtures):
    result = engine.scan(fixtures / "clean_app")
    assert result.findings == []


def test_exclude_glob(fixtures):
    result = engine.scan(fixtures / "vulnerable_app", engine.ScanOptions(excludes=["java/*", "go"]))
    assert not [f for f in result.findings if f.location.path.startswith(("java/", "go/"))]
