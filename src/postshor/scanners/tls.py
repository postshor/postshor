"""Live TLS endpoint probe: does a server support hybrid post-quantum key exchange?

Python's ssl module cannot report the negotiated key-exchange group, so PostShor sends its
own minimal TLS 1.3 ClientHello that offers exactly one group and *no* key share. A server
that supports the group must answer with a HelloRetryRequest naming it; one that does not
answers with a handshake_failure alert. No key material is ever generated, so the probe
needs no post-quantum library and works for any group codepoint.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from cryptography import x509

from postshor.models import Category, Finding, Location, Severity, Usage
from postshor.scanners.certificates import certificate_finding

# IANA TLS Supported Groups registry.
GROUPS = {
    0x11EC: ("X25519MLKEM768", "hybrid-kem"),
    0x11EB: ("SecP256r1MLKEM768", "hybrid-kem"),
    0x11ED: ("SecP384r1MLKEM1024", "hybrid-kem"),
    0x6399: ("X25519Kyber768Draft00", "kyber"),  # postshor:ignore (detected, not used)
    0x001D: ("x25519", "x25519"),
    0x0017: ("secp256r1", "ecdh"),
    0x0018: ("secp384r1", "ecdh"),
}
PQ_GROUPS = (0x11EC, 0x11EB, 0x11ED)

# SHA-256("HelloRetryRequest"), RFC 8446 section 4.1.3
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

_SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807, 0x0808, 0x0904, 0x0905, 0x0906]


@dataclass
class TlsReport:
    host: str
    port: int
    supported_groups: list[str] = field(default_factory=list)
    tls13: bool | None = None
    protocol: str | None = None
    cipher: str | None = None
    certificate: x509.Certificate | None = None
    error: str | None = None


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def build_client_hello(host: str, group: int) -> bytes:
    """A TLS 1.3 ClientHello offering one group with an empty key_share list."""
    exts = b""
    if host and not _is_ip(host):
        name = host.encode("idna")
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += _ext(0x0000, struct.pack("!H", len(entry)) + entry)
    exts += _ext(0x000A, struct.pack("!HH", 2, group))  # supported_groups
    exts += _ext(0x000D, struct.pack("!H", 2 * len(_SIG_ALGS)) + b"".join(struct.pack("!H", s) for s in _SIG_ALGS))
    exts += _ext(0x002B, b"\x02\x03\x04")  # supported_versions: TLS 1.3
    exts += _ext(0x002D, b"\x01\x01")  # psk_key_exchange_modes: psk_dhe_ke
    exts += _ext(0x0033, b"\x00\x00")  # key_share: no shares -> forces HelloRetryRequest

    suites = struct.pack("!HHHH", 6, 0x1301, 0x1302, 0x1303)
    body = (
        b"\x03\x03" + os.urandom(32)
        + b"\x20" + os.urandom(32)  # legacy session id (middlebox compatibility)
        + suites
        + b"\x01\x00"
        + struct.pack("!H", len(exts)) + exts
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def parse_server_response(data: bytes) -> tuple[str, int | None]:
    """Classify the first server flight.

    Returns ("hrr", group) when the server accepted the group, ("alert", None) when it
    refused, ("tls12", None) when it fell back to TLS 1.2, or ("unknown", None).
    """
    if len(data) < 5:
        return "unknown", None
    rtype = data[0]
    if rtype == 21:
        return "alert", None
    if rtype != 22 or len(data) < 9 or data[5] != 2:
        return "unknown", None
    body = data[9:]
    if len(body) < 35:
        return "unknown", None
    random = body[2:34]
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len + 2 + 1  # session id, cipher suite, compression
    if pos + 2 > len(body):
        return ("hrr", None) if random == HRR_RANDOM else ("tls12", None)
    ext_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    end = min(len(body), pos + ext_len)
    selected_group = None
    is_tls13 = False
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", body[pos:pos + 4])
        edata = body[pos + 4:pos + 4 + elen]
        if etype == 0x002B and edata == b"\x03\x04":
            is_tls13 = True
        if etype == 0x0033 and len(edata) >= 2:
            selected_group = struct.unpack("!H", edata[:2])[0]
        pos += 4 + elen
    if random == HRR_RANDOM:
        return "hrr", selected_group
    if not is_tls13:
        return "tls12", None
    return "unknown", selected_group


def _recv_first_flight(sock: socket.socket) -> bytes:
    data = b""
    while len(data) < 5 or len(data) < 5 + struct.unpack("!H", data[3:5])[0]:
        chunk = sock.recv(16384)
        if not chunk:
            break
        data += chunk
    return data


def probe_group(host: str, port: int, group: int, timeout: float = 5.0) -> tuple[str, int | None]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(build_client_hello(host, group))
        return parse_server_response(_recv_first_flight(sock))


def _fetch_certificate(host: str, port: int, timeout: float) -> tuple[x509.Certificate | None, str | None, str | None]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inventory, not validation: self-signed certs still count
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
        cipher = tls.cipher()
        return (x509.load_der_x509_certificate(der) if der else None, tls.version(), cipher[0] if cipher else None)


def scan_endpoint(target: str, timeout: float = 5.0) -> TlsReport:
    host, port = parse_target(target)
    report = TlsReport(host, port)
    failures, saw_tls12, last_error = 0, False, None
    for group in GROUPS:
        try:
            outcome, selected = probe_group(host, port, group, timeout)
        except OSError as exc:  # some servers reset instead of sending an alert
            failures, last_error = failures + 1, exc
            continue
        if outcome == "hrr" and selected == group:
            report.supported_groups.append(GROUPS[group][0])
        elif outcome == "tls12":
            saw_tls12 = True
    if failures == len(GROUPS):
        report.error = f"{type(last_error).__name__}: {last_error}"
        return report
    try:
        report.certificate, report.protocol, report.cipher = _fetch_certificate(host, port, timeout)
    except (OSError, ssl.SSLError, ValueError) as exc:
        report.error = f"certificate fetch failed: {exc}"
    if report.supported_groups or report.protocol == "TLSv1.3":
        report.tls13 = True
    elif saw_tls12 or report.protocol in ("TLSv1.2", "TLSv1.1", "TLSv1"):
        report.tls13 = False
    return report


def scan_endpoints(targets: list[str], timeout: float = 5.0, workers: int = 8) -> list[TlsReport]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda t: scan_endpoint(t, timeout), targets))


def report_findings(report: TlsReport) -> list[Finding]:
    where = f"tls://{report.host}:{report.port}"
    details = {"subject": where, "supported_groups": report.supported_groups, "protocol": report.protocol, "cipher": report.cipher}
    if report.error and not report.supported_groups and report.certificate is None:
        return [Finding("TLS-UNREACHABLE", "Endpoint could not be probed", Severity.INFO, Category.NETWORK, "pqc",
                        Usage.PROTOCOL, Location(where), report.error, "Check the host, port and firewall rules.",
                        "low", details)]
    findings: list[Finding] = []
    pq = [g for g in report.supported_groups if g in {GROUPS[c][0] for c in PQ_GROUPS}]
    if pq:
        findings.append(Finding(
            "TLS-PQ-KEX-SUPPORTED", f"Hybrid post-quantum key exchange supported ({', '.join(pq)})", Severity.INFO,
            Category.NETWORK, "hybrid-kem", Usage.KEY_EXCHANGE, Location(where),
            "The server negotiates hybrid ML-KEM key exchange with clients that offer it, protecting recorded traffic against future quantum decryption.",
            "No action needed. Keep the TLS library current.", "high", details))
    elif report.tls13 is False:
        findings.append(Finding(
            "TLS-NO-TLS13", "TLS 1.3 not supported", Severity.CRITICAL, Category.NETWORK, "tls-legacy", Usage.PROTOCOL,
            Location(where), "The server does not support TLS 1.3, which is required for hybrid post-quantum key exchange. All traffic is exposed to harvest-now-decrypt-later.",
            "Enable TLS 1.3, then enable X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+, rustls, recent Java/.NET).", "high", details))
    else:
        legacy = "X25519Kyber768Draft00" in report.supported_groups  # postshor:ignore
        findings.append(Finding(
            "TLS-NO-PQ-KEX", "No hybrid post-quantum key exchange" + (" (only obsolete Kyber draft)" if legacy else ""),
            Severity.CRITICAL, Category.NETWORK, "kyber" if legacy else "ecdh", Usage.KEY_EXCHANGE, Location(where),
            "The server only negotiates classical key exchange"
            + (f" ({', '.join(report.supported_groups)})" if report.supported_groups else "")
            + ". Traffic recorded today can be decrypted once a quantum computer exists (harvest-now-decrypt-later).",
            "Enable the X25519MLKEM768 group: OpenSSL 3.5+ (default), nginx `ssl_ecdh_curve X25519MLKEM768:X25519`, Go 1.24+ (default), "
            "rustls with aws-lc-rs, or terminate TLS at a CDN/load balancer that supports it.", "high", details))
    if report.certificate is not None:
        findings.append(certificate_finding(report.certificate, where, live=True))
    return findings


def parse_target(target: str) -> tuple[str, int]:
    t = target.strip()
    for prefix in ("https://", "tls://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    t = t.split("/", 1)[0]
    if t.startswith("["):  # [IPv6]:port
        host, _, rest = t[1:].partition("]")
        return host, int(rest.lstrip(":") or 443)
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, 443


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False
