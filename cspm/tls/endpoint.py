"""TLS endpoint checker: protocol versions, weak ciphers, chain and certificate checks.

Loopback only unless the caller passes `allow_remote=True`, since we do not scan hosts we do not own.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cspm.contracts.rule import Violation
from cspm.tls.certs import check_certificate, load_certificate

PROTOCOLS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)
LEGACY = frozenset({"TLSv1", "TLSv1.1"})
WEAK_CIPHER_PROBES: tuple[tuple[str, str], ...] = (
    ("RC4", "RC4"),
    ("3DES", "3DES"),
    ("NULL", "eNULL"),
    ("EXPORT", "EXPORT"),
    ("ANON", "aNULL"),
)
# OpenSSL reasons that mean our own client could not offer the probe, not that the server said no.
_CLIENT_SIDE = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH", "UNSUPPORTED_PROTOCOL")


class RemoteHostRefused(PermissionError):
    """Raised for a non-loopback target when remote scanning was not allowed."""


@dataclass(slots=True)
class EndpointReport:
    host: str
    port: int
    protocols: dict[str, str] = field(default_factory=dict)
    weak_ciphers: dict[str, str] = field(default_factory=dict)
    untestable: list[str] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocols": dict(self.protocols),
            "weak_ciphers": dict(self.weak_ciphers),
            "untestable": list(self.untestable),
            "violations": [dict(v.evidence) for v in self.violations],
        }


def _exposure(host: str, port: int, allow_remote: bool) -> str:
    addrs = {str(info[4][0]).split("%")[0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    ips = [ipaddress.ip_address(a) for a in addrs]
    if all(ip.is_loopback for ip in ips):
        return "internal"
    if not allow_remote:
        raise RemoteHostRefused(f"{host} is not a loopback address; pass allow_remote only for hosts you own")
    return "internet" if any(ip.is_global for ip in ips) else "internal"


def _probe_context(low: ssl.TLSVersion, high: ssl.TLSVersion, ciphers: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Probing old versions is the point here, so their deprecation warnings are noise.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = low
        ctx.maximum_version = high
    # Security level 0 lets the probe offer legacy suites so we can see whether the server takes them.
    ctx.set_ciphers(f"{ciphers}:@SECLEVEL=0")
    return ctx


def _handshake(
    host: str, port: int, ctx: ssl.SSLContext, server_hostname: str | None, timeout: float
) -> tuple[str | None, str | None, bytes | None]:
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(
        raw, server_hostname=server_hostname
    ) as tls:
        cipher = tls.cipher()
        return tls.version(), cipher[0] if cipher else None, tls.getpeercert(binary_form=True)


def _client_side(exc: ssl.SSLError) -> bool:
    text = f"{getattr(exc, 'reason', '')} {exc}".upper()
    return any(code in text for code in _CLIENT_SIDE)


def _is_cbc(cipher: str) -> bool:
    name = cipher.upper()
    return not any(tag in name for tag in ("GCM", "CHACHA", "CCM", "RC4", "NULL"))


def _v(report: EndpointReport, check: str, severity: str, exposure: str, **extra: Any) -> None:
    evidence = {"check": check, "severity": severity, "host": report.host, "port": report.port, **extra}
    report.violations.append(Violation(evidence=evidence, exposure=exposure))


def _probe_protocols(report: EndpointReport, timeout: float) -> tuple[bytes | None, dict[str, str]]:
    leaf: bytes | None = None
    ciphers: dict[str, str] = {}
    for label, version in PROTOCOLS:
        try:
            ctx = _probe_context(version, version, "ALL:COMPLEMENTOFDEFAULT")
            got, cipher, der = _handshake(report.host, report.port, ctx, None, timeout)
        except ValueError:
            report.protocols[label] = "untestable"
            report.untestable.append(f"{label}: local OpenSSL cannot offer it")
            continue
        except ssl.SSLError as exc:
            if _client_side(exc):
                report.protocols[label] = "untestable"
                report.untestable.append(f"{label}: local OpenSSL cannot offer it ({exc})")
            else:
                report.protocols[label] = "rejected"
            continue
        except OSError:
            report.protocols[label] = "rejected"
            continue
        report.protocols[label] = "accepted" if got == label else f"negotiated {got}"
        if cipher:
            ciphers[label] = cipher
        leaf = leaf or der
    return leaf, ciphers


def _weak_context(spec: str) -> ssl.SSLContext:
    try:
        return _probe_context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2, spec)
    except ValueError:
        # Builds without TLS 1.0 can still offer most weak suites over TLS 1.2.
        return _probe_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, spec)


def _probe_weak_ciphers(report: EndpointReport, timeout: float) -> None:
    for label, spec in WEAK_CIPHER_PROBES:
        try:
            ctx = _weak_context(spec)
        except (ValueError, ssl.SSLError):
            report.weak_ciphers[label] = "untestable"
            report.untestable.append(f"{label} ciphers: not built into local OpenSSL")
            continue
        try:
            _, cipher, _ = _handshake(report.host, report.port, ctx, None, timeout)
        except ssl.SSLError as exc:
            report.weak_ciphers[label] = "untestable" if _client_side(exc) else "rejected"
            continue
        except OSError:
            report.weak_ciphers[label] = "rejected"
            continue
        report.weak_ciphers[label] = f"accepted {cipher}"


def _check_chain(
    report: EndpointReport, ca_bundle: Path | None, server_hostname: str, timeout: float, exposure: str
) -> None:
    ctx = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
    try:
        _handshake(report.host, report.port, ctx, server_hostname, timeout)
    except ssl.SSLCertVerificationError as exc:
        _v(report, "chain_invalid", "high", exposure, reason=exc.verify_message or str(exc),
           ca_bundle=ca_bundle.name if ca_bundle else "system")
    except (ssl.SSLError, OSError) as exc:
        _v(report, "modern_handshake_failed", "high", exposure, reason=str(exc))


def scan_endpoint(
    host: str,
    port: int,
    *,
    ca_bundle: Path | None = None,
    server_hostname: str | None = None,
    allow_remote: bool = False,
    now: datetime | None = None,
    timeout: float = 5.0,
) -> EndpointReport:
    """Probe one endpoint and return the full report, including probes our OpenSSL could not run."""
    exposure = _exposure(host, port, allow_remote)
    report = EndpointReport(host=host, port=port)
    leaf, ciphers = _probe_protocols(report, timeout)
    for label in sorted(LEGACY):
        if report.protocols.get(label) == "accepted":
            _v(report, "legacy_protocol", "high", exposure, protocol=label)
    if not any(report.protocols.get(p) == "accepted" for p in ("TLSv1.2", "TLSv1.3")):
        _v(report, "no_modern_protocol", "high", exposure)
    tls10_cipher = ciphers.get("TLSv1")
    if tls10_cipher and _is_cbc(tls10_cipher):
        _v(report, "tls10_cbc", "medium", exposure, cipher=tls10_cipher)
    _probe_weak_ciphers(report, timeout)
    for label, state in report.weak_ciphers.items():
        if state.startswith("accepted"):
            _v(report, "weak_cipher", "high", exposure, family=label, cipher=state.split(" ", 1)[1])
    _check_chain(report, ca_bundle, server_hostname or host, timeout, exposure)
    if leaf:
        cert = load_certificate(leaf)
        for found in check_certificate(cert, now or datetime.now(UTC), exposure=exposure):
            evidence = {**found.evidence, "host": host, "port": port}
            report.violations.append(Violation(evidence=evidence, exposure=exposure))
    return report


def check_endpoint(
    host: str,
    port: int,
    *,
    ca_bundle: Path | None = None,
    server_hostname: str | None = None,
    allow_remote: bool = False,
    now: datetime | None = None,
    timeout: float = 5.0,
) -> list[Violation]:
    """Return TLS violations for one endpoint. Refuses non-loopback hosts unless `allow_remote` is set."""
    return scan_endpoint(
        host, port, ca_bundle=ca_bundle, server_hostname=server_hostname, allow_remote=allow_remote,
        now=now, timeout=timeout,
    ).violations
