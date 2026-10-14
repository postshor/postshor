"""CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

Findings are folded into assets: one component per algorithm (with every occurrence as
evidence), one per certificate, one per key, one per TLS endpoint and one per crypto library.
"""

from __future__ import annotations

import json
import re
import uuid

from postshor import __version__
from postshor.models import Category, Finding, ScanResult, Usage
from postshor.rules import ALGORITHMS
from postshor.score import Score

_FUNCTIONS = {
    Usage.KEY_EXCHANGE: ["keyderive"],
    Usage.ENCRYPTION: ["encrypt", "decrypt"],
    Usage.SIGNATURE: ["sign", "verify"],
    Usage.KEY_GENERATION: ["keygen"],
    Usage.HASH: ["digest"],
    Usage.SYMMETRIC: ["encrypt", "decrypt"],
}
_PURL = {"pypi": "pypi", "npm": "npm", "go": "golang", "cargo": "cargo", "nuget": "nuget", "composer": "composer", "gem": "gem"}


def _ref(*parts: str) -> str:
    return "crypto/" + "/".join(re.sub(r"[^A-Za-z0-9._-]+", "-", p).strip("-").lower() for p in parts)


def _occurrence(f: Finding) -> dict:
    occ: dict = {"location": f.location.path}
    if f.location.line:
        occ["line"] = f.location.line
    if f.location.snippet:
        occ["additionalContext"] = f"{f.rule_id}: {f.location.snippet[:180]}"
    return occ


def _algorithm_component(algo_id: str, items: list[Finding]) -> dict:
    algo = ALGORITHMS[algo_id]
    functions = sorted({fn for f in items for fn in _FUNCTIONS.get(f.usage, ["unknown"])})
    props: dict = {
        "primitive": algo.primitive,
        "executionEnvironment": "software-plain-ram",
        "implementationPlatform": "generic",
        "cryptoFunctions": functions,
        "nistQuantumSecurityLevel": algo.nist_quantum_level,
    }
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": _ref("algorithm", algo_id),
        "name": algo.name,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
        "evidence": {"occurrences": [_occurrence(f) for f in items]},
        "properties": [
            {"name": "postshor:quantumStatus", "value": algo.status.value},
            {"name": "postshor:maxSeverity", "value": max(f.severity for f in items).label},
            {"name": "postshor:replacement", "value": algo.replacement},
        ],
    }
    if algo.oid:
        comp["cryptoProperties"]["oid"] = algo.oid
    return comp


def _certificate_component(f: Finding, key_ref: str) -> dict:
    d = f.details
    return {
        "type": "cryptographic-asset",
        "bom-ref": _ref("certificate", f.location.path, d.get("serial", "")),
        "name": d.get("subject", "certificate"),
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": d.get("subject", ""),
                "issuerName": d.get("issuer", ""),
                "notValidBefore": d.get("not_before"),
                "notValidAfter": d.get("not_after"),
                "subjectPublicKeyRef": key_ref,
                "certificateFormat": "X.509",
            },
        },
        "evidence": {"occurrences": [_occurrence(f)]},
        "properties": [
            {"name": "postshor:severity", "value": f.severity.label},
            {"name": "postshor:signatureAlgorithm", "value": str(d.get("signature_algorithm"))},
            {"name": "postshor:isCA", "value": str(d.get("is_ca", False)).lower()},
        ],
    }


def _key_component(f: Finding, private: bool, algo_ref: str) -> dict:
    props: dict = {"type": "private-key" if private else "public-key", "algorithmRef": algo_ref}
    if f.details.get("key_bits"):
        props["size"] = f.details["key_bits"]
    return {
        "type": "cryptographic-asset",
        "bom-ref": _ref("key", f.location.path, str(f.location.line or 0), f.details.get("key", "")),
        "name": f.details.get("key", "key"),
        "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": props},
        "evidence": {"occurrences": [_occurrence(f)]},
        "properties": [{"name": "postshor:severity", "value": f.severity.label}],
    }


def _protocol_component(endpoint: str, items: list[Finding]) -> dict:
    d = next((f.details for f in items if "supported_groups" in f.details), {})
    version = (d.get("protocol") or "").replace("TLSv", "") or None
    props: dict = {"type": "tls"}
    if version:
        props["version"] = version
    if d.get("cipher"):
        props["cipherSuites"] = [{"name": d["cipher"]}]
    return {
        "type": "cryptographic-asset",
        "bom-ref": _ref("protocol", endpoint),
        "name": f"TLS {endpoint}",
        "cryptoProperties": {"assetType": "protocol", "protocolProperties": props},
        "evidence": {"occurrences": [{"location": endpoint}]},
        "properties": [
            {"name": "postshor:supportedGroups", "value": ",".join(d.get("supported_groups", []))},
            {"name": "postshor:maxSeverity", "value": max(f.severity for f in items).label},
        ],
    }


def _library_component(f: Finding) -> dict:
    eco, pkg = f.details.get("ecosystem", ""), f.details.get("package", f.title)
    comp = {
        "type": "library",
        "bom-ref": _ref("library", eco, pkg),
        "name": pkg,
        "evidence": {"occurrences": [_occurrence(f)]},
        "properties": [
            {"name": "postshor:severity", "value": f.severity.label},
            {"name": "postshor:note", "value": f.message},
        ],
    }
    if eco in _PURL:
        comp["purl"] = f"pkg:{_PURL[eco]}/{pkg}"
    return comp


def build(result: ScanResult, score: Score) -> dict:
    components: dict[str, dict] = {}
    by_algo: dict[str, list[Finding]] = {}
    endpoints: dict[str, list[Finding]] = {}

    for f in result.findings:
        if f.location.path.startswith("tls://") and f.category is Category.NETWORK and f.usage is not Usage.CERTIFICATE:
            endpoints.setdefault(f.location.path, []).append(f)
            continue
        if f.category is Category.DEPENDENCY and f.usage is Usage.LIBRARY:
            comp = _library_component(f)
            components.setdefault(comp["bom-ref"], comp)
            continue
        if f.algorithm in ALGORITHMS and f.algorithm not in ("tls-legacy", "pycrypto"):
            by_algo.setdefault(f.algorithm, []).append(f)

    for algo_id, items in by_algo.items():
        comp = _algorithm_component(algo_id, items)
        components[comp["bom-ref"]] = comp

    for f in result.findings:
        algo_ref = _ref("algorithm", f.algorithm)
        if f.usage is Usage.CERTIFICATE:
            key = _key_component(f, False, algo_ref)
            cert = _certificate_component(f, key["bom-ref"])
            components.setdefault(key["bom-ref"], key)
            components.setdefault(cert["bom-ref"], cert)
        elif f.usage is Usage.KEY_MATERIAL and f.rule_id.startswith(("KEY-", "CSR-")) and f.rule_id != "KEY-UNPARSED":
            key = _key_component(f, f.category is Category.SECRET, algo_ref)
            components.setdefault(key["bom-ref"], key)

    for endpoint, items in endpoints.items():
        comp = _protocol_component(endpoint, items)
        components[comp["bom-ref"]] = comp

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": result.finished_at or result.started_at,
            "tools": {"components": [{"type": "application", "name": "postshor", "version": __version__}]},
            "component": {"type": "application", "bom-ref": "target", "name": result.target},
            "properties": [
                {"name": "postshor:qrsVersion", "value": score.version},
                {"name": "postshor:quantumReadinessScore", "value": str(score.value)},
                {"name": "postshor:grade", "value": score.grade},
            ],
        },
        "components": list(components.values()),
    }


def render(result: ScanResult, score: Score) -> str:
    return json.dumps(build(result, score), indent=2)
