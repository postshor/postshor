"""Find cryptographic libraries declared in dependency manifests.

Dependency findings are inventory: they say a library that *can* do quantum-vulnerable
crypto is present. The source scanner reports how it is actually used, so most of these
are LOW/INFO and do not dominate the readiness score.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from postshor.models import Category, Finding, Location, Severity, Usage


@dataclass(frozen=True)
class KnownLib:
    algorithm: str
    severity: Severity
    note: str


_CLASSICAL = "Provides classical public-key crypto (RSA/ECC). Review how it is used and plan the post-quantum path."
_PQ = "Provides post-quantum algorithms."

LIBRARIES: dict[str, dict[str, KnownLib]] = {
    "pypi": {
        "pycrypto": KnownLib("pycrypto", Severity.HIGH, "PyCrypto has been unmaintained since 2013 and has known CVEs. Replace it with pycryptodome or pyca/cryptography."),
        "cryptography": KnownLib("rsa", Severity.INFO, _CLASSICAL),
        "pycryptodome": KnownLib("rsa", Severity.LOW, _CLASSICAL),
        "pycryptodomex": KnownLib("rsa", Severity.LOW, _CLASSICAL),
        "rsa": KnownLib("rsa", Severity.LOW, "Pure-Python RSA library. RSA is quantum-broken."),
        "ecdsa": KnownLib("ecdsa", Severity.LOW, "Pure-Python ECDSA library. ECDSA is quantum-broken."),
        "pynacl": KnownLib("x25519", Severity.LOW, "libsodium bindings (X25519/Ed25519), both quantum-broken."),
        "paramiko": KnownLib("rsa", Severity.LOW, "SSH library; check which key exchange and host key algorithms are negotiated."),
        "pyjwt": KnownLib("rsa", Severity.INFO, "JWT library; RS*/ES*/EdDSA algorithms are quantum-broken."),
        "python-jose": KnownLib("rsa", Severity.INFO, "JOSE library; RS*/ES*/EdDSA algorithms are quantum-broken."),
        "liboqs-python": KnownLib("pqc", Severity.INFO, _PQ),
        "oqs": KnownLib("pqc", Severity.INFO, _PQ),
        "pqcrypto": KnownLib("pqc", Severity.INFO, _PQ),
    },
    "npm": {
        "node-rsa": KnownLib("rsa", Severity.LOW, "RSA library. RSA is quantum-broken."),
        "node-forge": KnownLib("rsa", Severity.LOW, _CLASSICAL),
        "jsrsasign": KnownLib("rsa", Severity.LOW, _CLASSICAL),
        "elliptic": KnownLib("ecc", Severity.LOW, "Elliptic-curve library. ECC is quantum-broken."),
        "secp256k1": KnownLib("ecdsa", Severity.LOW, "secp256k1 ECDSA, quantum-broken."),
        "tweetnacl": KnownLib("x25519", Severity.LOW, "X25519/Ed25519, both quantum-broken."),
        "libsodium-wrappers": KnownLib("x25519", Severity.LOW, "X25519/Ed25519, both quantum-broken."),
        "@noble/curves": KnownLib("ecc", Severity.LOW, "Elliptic-curve library. ECC is quantum-broken."),
        "@noble/secp256k1": KnownLib("ecdsa", Severity.LOW, "secp256k1 ECDSA, quantum-broken."),
        "@noble/ed25519": KnownLib("eddsa", Severity.LOW, "Ed25519, quantum-broken."),
        "crypto-js": KnownLib("md5", Severity.LOW, "Includes MD5, SHA-1, DES and RC4; check none are used."),
        "jsonwebtoken": KnownLib("rsa", Severity.INFO, "JWT library; RS*/ES* algorithms are quantum-broken."),
        "jose": KnownLib("rsa", Severity.INFO, "JOSE library; RS*/ES*/EdDSA algorithms are quantum-broken."),
        "@noble/post-quantum": KnownLib("pqc", Severity.INFO, _PQ),
        "liboqs-node": KnownLib("pqc", Severity.INFO, _PQ),
    },
    "go": {
        "golang.org/x/crypto": KnownLib("ecc", Severity.INFO, _CLASSICAL),
        "github.com/cloudflare/circl": KnownLib("pqc", Severity.INFO, "Cloudflare CIRCL: includes ML-KEM, ML-DSA and hybrids alongside classical algorithms."),
        "github.com/open-quantum-safe/liboqs-go": KnownLib("pqc", Severity.INFO, _PQ),
        "github.com/btcsuite/btcd/btcec": KnownLib("ecdsa", Severity.LOW, "secp256k1 ECDSA, quantum-broken."),
        "github.com/ethereum/go-ethereum": KnownLib("ecdsa", Severity.LOW, "secp256k1 ECDSA, quantum-broken."),
    },
    "cargo": {
        "rsa": KnownLib("rsa", Severity.LOW, "RustCrypto RSA. RSA is quantum-broken (and this crate has had the Marvin timing advisory RUSTSEC-2023-0071)."),
        "p256": KnownLib("ecc", Severity.LOW, "NIST P-256. Quantum-broken."),
        "p384": KnownLib("ecc", Severity.LOW, "NIST P-384. Quantum-broken."),
        "k256": KnownLib("ecdsa", Severity.LOW, "secp256k1. Quantum-broken."),
        "ed25519-dalek": KnownLib("eddsa", Severity.LOW, "Ed25519. Quantum-broken."),
        "x25519-dalek": KnownLib("x25519", Severity.LOW, "X25519. Quantum-broken."),
        "ring": KnownLib("ecc", Severity.INFO, _CLASSICAL),
        "ml-kem": KnownLib("ml-kem", Severity.INFO, _PQ),
        "ml-dsa": KnownLib("ml-dsa", Severity.INFO, _PQ),
        "slh-dsa": KnownLib("slh-dsa", Severity.INFO, _PQ),
        "oqs": KnownLib("pqc", Severity.INFO, _PQ),
        "pqcrypto": KnownLib("pqc", Severity.INFO, _PQ),
    },
    "maven": {
        "bcprov": KnownLib("rsa", Severity.INFO, "Bouncy Castle: classical and (in recent versions) post-quantum algorithms."),
        "bcpkix": KnownLib("rsa", Severity.INFO, "Bouncy Castle PKIX: certificate handling."),
        "jjwt": KnownLib("rsa", Severity.INFO, "JWT library; RS*/ES* algorithms are quantum-broken."),
        "nimbus-jose-jwt": KnownLib("rsa", Severity.INFO, "JOSE library; RS*/ES*/EdDSA algorithms are quantum-broken."),
        "web3j": KnownLib("ecdsa", Severity.LOW, "secp256k1 ECDSA, quantum-broken."),
    },
    "nuget": {
        "bouncycastle.cryptography": KnownLib("rsa", Severity.INFO, "Bouncy Castle .NET: classical and post-quantum algorithms."),
        "portable.bouncycastle": KnownLib("rsa", Severity.INFO, "Old Bouncy Castle port; switch to BouncyCastle.Cryptography."),
        "system.identitymodel.tokens.jwt": KnownLib("rsa", Severity.INFO, "JWT library; RS*/ES* algorithms are quantum-broken."),
    },
    "composer": {
        "phpseclib/phpseclib": KnownLib("rsa", Severity.LOW, _CLASSICAL),
        "firebase/php-jwt": KnownLib("rsa", Severity.INFO, "JWT library; RS*/ES* algorithms are quantum-broken."),
    },
    "gem": {
        "rbnacl": KnownLib("x25519", Severity.LOW, "X25519/Ed25519, both quantum-broken."),
        "jwt": KnownLib("rsa", Severity.INFO, "JWT library; RS*/ES* algorithms are quantum-broken."),
    },
}

_GO_PQ_DEFAULT = (1, 24)


def scan_manifest(path: Path, rel: str, text: str) -> list[Finding]:
    name = path.name.lower()
    try:
        if name.startswith("requirements") and name.endswith(".txt"):
            deps = _requirements(text)
            eco = "pypi"
        elif name == "pyproject.toml":
            deps, eco = _pyproject(text), "pypi"
        elif name == "pipfile":
            deps, eco = _toml_tables(text, ("packages", "dev-packages")), "pypi"
        elif name == "package.json":
            deps, eco = _package_json(text), "npm"
        elif name == "go.mod":
            return _go_mod(text, rel)
        elif name == "cargo.toml":
            deps, eco = _toml_tables(text, ("dependencies", "dev-dependencies")), "cargo"
        elif name == "pom.xml" or name.startswith("build.gradle"):
            deps, eco = _jvm(text), "maven"
        elif name.endswith(".csproj") or name == "packages.config":
            deps, eco = _nuget(text), "nuget"
        elif name == "composer.json":
            deps, eco = _composer(text), "composer"
        elif name == "gemfile":
            deps, eco = _gemfile(text), "gem"
        else:
            return []
    except (ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError):
        return []
    return _match(deps, eco, rel, text)


def is_manifest(path: Path) -> bool:
    n = path.name.lower()
    return (
        (n.startswith("requirements") and n.endswith(".txt"))
        or n in ("pyproject.toml", "pipfile", "package.json", "go.mod", "cargo.toml", "pom.xml",
                 "composer.json", "gemfile", "packages.config")
        or n.startswith("build.gradle")
        or n.endswith(".csproj")
    )


def _match(deps: list[str], eco: str, rel: str, text: str) -> list[Finding]:
    known = LIBRARIES[eco]
    out = []
    for dep in dict.fromkeys(deps):
        key = dep.lower()
        lib = known.get(key)
        if lib is None and eco in ("maven", "go"):  # versioned module paths / artifact suffixes
            key = next((k for k in known if key.startswith(k)), key)
            lib = known.get(key)
        if lib is None:
            continue
        line = _line_of(text, dep)
        out.append(Finding(
            rule_id=f"DEP-{eco.upper()}-{re.sub(r'[^A-Za-z0-9]+', '-', key).strip('-').upper()}",
            title=f"Cryptographic dependency: {dep}",
            severity=lib.severity,
            category=Category.DEPENDENCY,
            algorithm=lib.algorithm,
            usage=Usage.LIBRARY,
            location=Location(rel, line, None, dep),
            message=lib.note,
            remediation="Track this library's post-quantum roadmap; the source findings show where it is called." if lib.algorithm != "pycrypto" else lib.note,
            confidence="high",
            details={"ecosystem": eco, "package": dep, "subject": dep},
        ))
    return out


def _line_of(text: str, needle: str) -> int | None:
    idx = text.lower().find(needle.lower())
    return None if idx < 0 else text.count("\n", 0, idx) + 1


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _requirements(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_NAME.match(line)
        if m:
            out.append(m.group(1))
    return out


def _pyproject(text: str) -> list[str]:
    data = tomllib.loads(text)
    reqs = list(data.get("project", {}).get("dependencies", []))
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        reqs.extend(group)
    names = [m.group(1) for r in reqs if (m := _REQ_NAME.match(r))]
    poetry = data.get("tool", {}).get("poetry", {})
    names.extend(k for k in poetry.get("dependencies", {}) if k != "python")
    return names


def _toml_tables(text: str, tables: tuple[str, ...]) -> list[str]:
    data = tomllib.loads(text)
    return [k for t in tables for k in data.get(t, {})]


def _package_json(text: str) -> list[str]:
    data = json.loads(text)
    return [k for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
            for k in data.get(section, {}) or {}]


def _composer(text: str) -> list[str]:
    data = json.loads(text)
    return [k for section in ("require", "require-dev") for k in data.get(section, {}) or {}]


def _jvm(text: str) -> list[str]:
    names = re.findall(r"<artifactId>\s*([\w.\-]+)\s*</artifactId>", text)
    names += re.findall(r"['\"][\w.\-]+:([\w.\-]+)(?::[^'\"]*)?['\"]", text)
    return names


def _nuget(text: str) -> list[str]:
    return re.findall(r"(?:PackageReference\s+Include|package\s+id)\s*=\s*\"([^\"]+)\"", text, re.IGNORECASE)


def _gemfile(text: str) -> list[str]:
    return re.findall(r"^\s*gem\s+['\"]([^'\"]+)['\"]", text, re.MULTILINE)


def _go_mod(text: str, rel: str) -> list[Finding]:
    deps = re.findall(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[\w./\-]+)\s+v", text, re.MULTILINE)
    findings = _match(deps, "go", rel, text)
    m = re.search(r"^go\s+(\d+)\.(\d+)", text, re.MULTILINE)
    if m and (int(m.group(1)), int(m.group(2))) < _GO_PQ_DEFAULT:
        findings.append(Finding(
            rule_id="DEP-GO-TOOLCHAIN-PRE-PQ",
            title=f"Go {m.group(1)}.{m.group(2)} predates default post-quantum TLS",
            severity=Severity.MEDIUM,
            category=Category.DEPENDENCY,
            algorithm="ecdh",
            usage=Usage.PROTOCOL,
            location=Location(rel, text.count("\n", 0, m.start()) + 1, None, m.group(0)),
            message="Go 1.24 added crypto/mlkem and turned on hybrid X25519MLKEM768 key exchange in crypto/tls by default. Builds targeting older Go versions negotiate classical key exchange only.",
            remediation="Raise the go directive to 1.24 or later and build with a current toolchain.",
            details={"subject": m.group(0)},
        ))
    return findings
