import json

import pytest

from conftest import make_cert, pem
from postshor import engine, score
from postshor.models import Category, Finding, Location, Severity, Usage
from postshor.reporting import cbom, format_for_path, html_report, markdown, sarif
from postshor.scanners import tls


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    import shutil

    from conftest import FIXTURES
    root = tmp_path_factory.mktemp("app")
    shutil.copytree(FIXTURES / "vulnerable_app", root, dirs_exist_ok=True)
    (root / "server.crt").write_bytes(pem(make_cert()[0]))
    result = engine.scan(root)
    # Add a live-endpoint result without touching the network.
    result.findings += tls.report_findings(tls.TlsReport("svc.example", 443, supported_groups=["x25519"], tls13=True,
                                                         certificate=make_cert()[0], protocol="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256"))
    return result, score.compute(result.findings)


def test_cbom_validates_against_cyclonedx_1_6(scanned):
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    doc = cbom.render(*scanned)
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(doc)
    assert error is None, error
    data = json.loads(doc)
    types = {c.get("cryptoProperties", {}).get("assetType") for c in data["components"]}
    assert {"algorithm", "certificate", "related-crypto-material", "protocol"} <= types
    rsa = next(c for c in data["components"] if c["bom-ref"] == "crypto/algorithm/rsa")
    assert rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert len(rsa["evidence"]["occurrences"]) > 3


def test_sarif_structure(scanned):
    data = json.loads(sarif.render(*scanned))
    run = data["runs"][0]
    assert data["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"])
    assert not any(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("tls://") for r in run["results"])
    assert all(float(r["properties"]["security-severity"]) >= 0 for r in run["tool"]["driver"]["rules"])


def test_html_report_is_self_contained(scanned):
    html = html_report.render(*scanned)
    assert html.startswith("<!doctype html>")
    assert "Quantum Readiness Report" in html and "Migration plan" in html
    assert "http://" not in html.replace("http://cyclonedx", "") and "<link" not in html


def test_html_escapes_untrusted_snippets():
    f = Finding("X", "<script>alert(1)</script>", Severity.HIGH, Category.SOURCE, "rsa", Usage.UNKNOWN,
                Location("a.py", 1, 1, "<img src=x onerror=alert(1)>"), "m", "r")
    from postshor.models import ScanResult
    html = html_report.render(ScanResult("t", [f]), score.compute([f]))
    assert "<script>alert(1)" not in html and "<img src=x" not in html


def test_markdown_report(scanned):
    md = markdown.render(*scanned)
    assert md.startswith("## PostShor")
    assert "img.shields.io" in md


@pytest.mark.parametrize("path,fmt", [("r.html", "html"), ("r.json", "json"), ("r.sarif", "sarif"),
                                      ("r.cdx.json", "cbom"), ("r.md", "markdown")])
def test_format_inference(path, fmt):
    assert format_for_path(path) == fmt
