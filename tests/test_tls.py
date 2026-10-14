import struct

import pytest

from postshor.models import Severity
from postshor.scanners import tls


def _server_hello(random: bytes, extensions: bytes) -> bytes:
    body = b"\x03\x03" + random + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack("!H", len(extensions)) + extensions
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def test_client_hello_offers_single_group_without_key_share():
    hello = tls.build_client_hello("example.com", 0x11EC)
    assert hello[0] == 0x16 and hello[5] == 0x01
    assert struct.pack("!HHHH", 0x000A, 4, 2, 0x11EC) in hello  # supported_groups = [X25519MLKEM768]
    assert struct.pack("!HHH", 0x0033, 2, 0) in hello  # key_share with no entries
    assert b"example.com" in hello
    assert len(hello) - 5 == struct.unpack("!H", hello[3:5])[0]


def test_parse_hello_retry_request_selects_group():
    exts = struct.pack("!HH", 0x002B, 2) + b"\x03\x04" + struct.pack("!HHH", 0x0033, 2, 0x11EC)
    assert tls.parse_server_response(_server_hello(tls.HRR_RANDOM, exts)) == ("hrr", 0x11EC)


def test_parse_alert_and_tls12():
    assert tls.parse_server_response(b"\x15\x03\x03\x00\x02\x02\x28") == ("alert", None)
    assert tls.parse_server_response(_server_hello(b"\x11" * 32, b"")) == ("tls12", None)
    assert tls.parse_server_response(b"") == ("unknown", None)


@pytest.mark.parametrize("target,expected", [
    ("example.com", ("example.com", 443)),
    ("example.com:8443", ("example.com", 8443)),
    ("https://example.com/path", ("example.com", 443)),
    ("[::1]:4433", ("::1", 4433)),
])
def test_parse_target(target, expected):
    assert tls.parse_target(target) == expected


def test_findings_for_classical_only_server():
    report = tls.TlsReport("legacy.example", 443, supported_groups=["x25519", "secp256r1"], tls13=True)
    [f] = tls.report_findings(report)
    assert f.rule_id == "TLS-NO-PQ-KEX" and f.severity == Severity.CRITICAL


def test_findings_for_pq_server():
    report = tls.TlsReport("modern.example", 443, supported_groups=["X25519MLKEM768", "x25519"], tls13=True)
    [f] = tls.report_findings(report)
    assert f.rule_id == "TLS-PQ-KEX-SUPPORTED" and f.severity == Severity.INFO


def test_findings_for_tls12_only_server():
    [f] = tls.report_findings(tls.TlsReport("old.example", 443, tls13=False))
    assert f.rule_id == "TLS-NO-TLS13"


@pytest.mark.network
def test_live_cloudflare_supports_hybrid():
    report = tls.scan_endpoint("cloudflare.com")
    assert "X25519MLKEM768" in report.supported_groups
