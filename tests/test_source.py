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


def test_swift_pqc_rule_matches_cryptokit_type_family():
    scanner = SourceScanner()
    text = "let kem = try MLKEM768.PrivateKey()\nlet sig = try MLDSA65.PrivateKey()\nlet name = \"MLKEMish\"\n"
    found, _ = scanner.scan("Crypto.swift", text, {"swift", "any"})
    assert {f.location.line for f in found if f.rule_id == "SW-PQC"} == {1, 2}


def test_remediation_hints_reflect_verified_facts():
    # Regression guard for fact-check corrections (sources in docs/sources.md).
    from postshor.rules.algorithms import LANGUAGE_HINTS

    assert "JDK 27" in LANGUAGE_HINTS["jvm"] and "JEP 527" in LANGUAGE_HINTS["jvm"]
    assert "Java 24+ provides" not in LANGUAGE_HINTS["jvm"]
    assert "AWS-LC or BoringSSL" in LANGUAGE_HINTS["python"]
    assert "24.7" in LANGUAGE_HINTS["javascript"]


def test_python_docstrings_are_not_findings():
    scanner = SourceScanner()
    text = 'def sign(alg):\n    """Sign a token.\n\n    :param alg: e.g. "ES256"\n    >>> rsa.generate_private_key(65537, 2048)\n    """\n    return "RS256"\n'
    found, _ = scanner.scan("api.py", text, {"python", "any"})
    assert [(f.rule_id, f.location.line) for f in found] == [("JOSE-RSA-SIG", 7)]


def test_block_comments_are_not_findings():
    scanner = SourceScanner()
    text = '/*\n  Example: generateKeyPairSync("rsa", {...})\n*/\nconst k = generateKeyPairSync("ec", {});\n'
    found, _ = scanner.scan("keys.js", text, {"javascript", "any"})
    assert [f.location.line for f in found] == [4]


def test_private_key_in_docstring_is_still_reported():
    scanner = SourceScanner()
    header = "-----BEGIN " + "PRIVATE KEY-----"
    found, _ = scanner.scan("settings.py", f'"""\n{header}\nMIIB\n"""\n', {"python", "any"})
    assert [f.rule_id for f in found] == ["GEN-EMBEDDED-PRIVATE-KEY"]


def test_classical_half_of_hybrid_is_not_critical():
    scanner = SourceScanner()
    text = ("from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\n"
            "class KexMLKEM768X25519:\n"
            "    name = 'mlkem768x25519-sha256'\n"
            "    def start(self):\n"
            "        self.key = X25519PrivateKey.generate()\n")
    found, _ = scanner.scan("kex_mlkem.py", text, {"python", "any"})
    x = next(f for f in found if f.rule_id == "PY-X25519")
    assert x.severity == Severity.INFO and x.details["context"] == "hybrid"


def test_classical_key_exchange_far_from_mlkem_stays_critical():
    scanner = SourceScanner()
    text = "# ML-KEM support planned\n" + "\n" * 60 + "key = X25519PrivateKey.generate()\n"
    found, _ = scanner.scan("kex.py", text, {"python", "any"})
    assert next(f for f in found if f.rule_id == "PY-X25519").severity == Severity.CRITICAL


def test_plain_mlkem_mention_does_not_soften_independent_ecdh(result):
    # Fixture Crypto.java uses ECDH (line 9) and, separately, ML-KEM (line 11): ECDH stays critical.
    assert all(f.severity == Severity.CRITICAL for f in hits(result, "JVM-ECDH"))


def test_docstring_detection_survives_quotes_inside_other_strings():
    # A regex for triple quotes appears before the docstring; naive pairing would misalign.
    scanner = SourceScanner()
    text = ("PATTERN = r'(\"\"\"|\'\'\')'\n"
            "def f():\n"
            "    \"\"\"Docs mention 'ES256' as an example.\"\"\"\n"
            "    return 1\n")
    found, _ = scanner.scan("mod.py", text, {"python", "any"})
    assert not [f for f in found if f.rule_id.startswith("JOSE")]


def test_go_curve_preferences_literal_vs_dynamic():
    scanner = SourceScanner()
    text = ("a := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}\n"
            "b := &tls.Config{CurvePreferences: []tls.CurveID{\n\ttls.X25519MLKEM768,\n\ttls.X25519,\n}}\n"
            "cfg.CurvePreferences = defaultCurves\n")
    found, _ = scanner.scan("tls.go", text, {"go", "any"})
    by_rule = {(f.rule_id, f.location.line): f.severity for f in found}
    assert by_rule[("GO-TLS-CURVES", 1)] == Severity.CRITICAL          # literal, classical only
    assert ("GO-TLS-CURVES", 2) not in by_rule                          # multi-line literal containing ML-KEM
    assert by_rule[("GO-TLS-CURVES-DYNAMIC", 6)] == Severity.LOW        # from a variable: review, not critical


def test_openssl_group_list_literal_vs_dynamic():
    scanner = SourceScanner()
    text = 'SSL_CTX_set1_groups_list(ctx, "X25519:P-256");\nSSL_CTX_set1_groups_list(ctx, groups);\n'
    found, _ = scanner.scan("tls.c", text, {"c", "any"})
    assert {(f.rule_id, f.severity) for f in found} == {("C-TLS-GROUPS", Severity.CRITICAL), ("C-TLS-GROUPS-DYNAMIC", Severity.LOW)}


def test_curve_preferences_comparison_is_not_a_finding():
    scanner = SourceScanner()
    found, _ = scanner.scan("tls.go", "if cfg.CurvePreferences == nil {\n", {"go", "any"})
    assert not found


def test_trailing_comment_is_not_a_finding_but_strings_with_slashes_are_code():
    scanner = SourceScanner()
    text = ('fields := strings.Split(key, " ") // format: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC\n'
            'u := "https://x.example/" ; k, _ := rsa.GenerateKey(rand.Reader, 2048)\n')
    found, _ = scanner.scan("ssh_key.go", text, {"go", "any"})
    assert [(f.rule_id, f.location.line) for f in found] == [("GO-RSA-KEYGEN", 2)]


def test_go_ecdh_parsing_is_not_key_exchange():
    scanner = SourceScanner()
    text = ("pub, _ := ecdh.P256().NewPublicKey(raw)\n"
            "priv, _ := ecdh.P256().GenerateKey(rand.Reader)\n"
            "secret, _ := priv.ECDH(peer)\n")
    found, _ = scanner.scan("kex.go", text, {"go", "any"})
    got = {f.location.line: (f.rule_id, f.severity) for f in found}
    assert got[1] == ("GO-ECDH-KEY", Severity.HIGH)
    assert got[2] == ("GO-ECDH", Severity.CRITICAL)
    assert got[3][1] == Severity.CRITICAL


def test_ssh_ecdsa_host_key_is_labelled_ecdsa():
    scanner = SourceScanner()
    found, _ = scanner.scan("sshd_config", "HostKey /etc/ssh/ssh_host_ecdsa_key\n", {"ssh-config", "any"})
    assert found[0].algorithm == "ecdsa"


@pytest.mark.parametrize("path,kinds,line,rule,algo", [
    ("auth.rs", {"rust"}, "let rsa_key = Rsa::generate(2048)?;", "RS-OPENSSL-RSA", "rsa"),
    ("auth.rs", {"rust"}, "const JWT_ALGORITHM: Algorithm = Algorithm::RS256;", "JWT-ALG-RSA", "rsa"),
    ("two_factor.rs", {"rust"}, "type_: COSEAlgorithm::ES256,", "JWT-ALG-ECDSA", "ecdsa"),
    ("auth.go", {"go"}, "token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)", "JWT-ALG-RSA", "rsa"),
    ("Jwt.java", {"jvm"}, "Jwts.builder().signWith(key, SignatureAlgorithm.ES384)", "JWT-ALG-ECDSA", "ecdsa"),
    ("Tokens.cs", {"csharp"}, "new SigningCredentials(key, SecurityAlgorithms.RsaSha256)", "JWT-ALG-RSA", "rsa"),
    ("ech.go", {"go"}, "const kemChoice = hpke.KEM_X25519_HKDF_SHA256", "HPKE-DHKEM", "x25519"),
    ("ohttp.go", {"go"}, "suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, kdf, aead)", "HPKE-DHKEM", "ecdh"),
])
def test_recall_round_2_rules(path, kinds, line, rule, algo):
    found, _ = SourceScanner().scan(path, line + "\n", kinds | {"any"})
    assert any(f.rule_id == rule and f.algorithm == algo for f in found), [(f.rule_id, f.algorithm) for f in found]


def test_hpke_x25519_is_critical():
    found, _ = SourceScanner().scan("ech.go", "const k = hpke.KEM_X25519_HKDF_SHA256\n", {"go", "any"})
    assert found[0].severity == Severity.CRITICAL


@pytest.mark.parametrize("path,kinds,line,rule,algo", [
    ("repo.go", {"go"}, 'e, err := openpgp.NewEntity("", "RPM Registry", "", nil)', "PGP-KEYGEN-GO", "rsa"),
    ("keys.py", {"python"}, "params = gpg.gen_key_input(name_email='ci@example.com')", "PGP-KEYGEN-PY", "rsa"),
    ("keys.js", {"javascript"}, "const k = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519' })", "PGP-KEYGEN-JS", "ecc"),
    ("httpsign.go", {"go"}, "algos = []httpsig.Algorithm{httpsig.ED25519}", "HTTPSIG-ALG", "eddsa"),
    ("httpsign.go", {"go"}, "algos = []httpsig.Algorithm{httpsig.RSA_SHA256, httpsig.RSA_SHA512}", "HTTPSIG-ALG", "rsa"),
])
def test_recall_signing_keys(path, kinds, line, rule, algo):
    found, _ = SourceScanner().scan(path, line + "\n", kinds | {"any"})
    assert any(f.rule_id == rule and f.algorithm == algo for f in found), [(f.rule_id, f.algorithm) for f in found]
