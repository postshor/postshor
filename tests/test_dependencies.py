from pathlib import Path

from postshor.models import Severity
from postshor.scanners.dependencies import scan_manifest


def ids(findings):
    return {f.rule_id for f in findings}


def test_pyproject_and_poetry():
    text = '[project]\ndependencies = ["rsa>=4", "liboqs-python"]\n[tool.poetry.dependencies]\npython = "^3.11"\necdsa = "*"\n'
    found = scan_manifest(Path("pyproject.toml"), "pyproject.toml", text)
    assert ids(found) == {"DEP-PYPI-RSA", "DEP-PYPI-LIBOQS-PYTHON", "DEP-PYPI-ECDSA"}


def test_cargo_and_go_prefix_match():
    cargo = scan_manifest(Path("Cargo.toml"), "Cargo.toml", '[dependencies]\nrsa = "0.9"\nml-kem = "0.2"\n')
    assert ids(cargo) == {"DEP-CARGO-RSA", "DEP-CARGO-ML-KEM"}
    gomod = "module x\n\ngo 1.24\n\nrequire github.com/btcsuite/btcd/btcec/v2 v2.3.2\n"
    found = scan_manifest(Path("go.mod"), "go.mod", gomod)
    assert ids(found) == {"DEP-GO-GITHUB-COM-BTCSUITE-BTCD-BTCEC"}


def test_maven_and_nuget():
    pom = "<dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId></dependency>"
    assert ids(scan_manifest(Path("pom.xml"), "pom.xml", pom)) == {"DEP-MAVEN-BCPROV"}
    csproj = '<PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />'
    assert ids(scan_manifest(Path("app.csproj"), "app.csproj", csproj)) == {"DEP-NUGET-BOUNCYCASTLE-CRYPTOGRAPHY"}


def test_pycrypto_is_high_and_malformed_is_ignored():
    [f] = scan_manifest(Path("requirements.txt"), "requirements.txt", "pycrypto==2.6.1\n")
    assert f.severity == Severity.HIGH
    assert scan_manifest(Path("package.json"), "package.json", "{not json") == []
