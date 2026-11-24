from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any

import pytest

from cspm.tls import RemoteHostRefused, check_endpoint, main_tls_check
from cspm.tls import endpoint as ep


def test_remote_host_is_refused_by_default() -> None:
    with pytest.raises(RemoteHostRefused):
        check_endpoint("203.0.113.10", 443)


def test_allow_remote_classifies_exposure() -> None:
    assert ep._exposure("127.0.0.1", 443, False) == "internal"
    assert ep._exposure("10.0.0.5", 443, True) == "internal"
    assert ep._exposure("203.0.113.10", 443, True) == "internal"
    # A numeric address resolves without any lookup, so nothing is contacted here.
    assert ep._exposure("8.8.8.8", 443, True) == "internet"


def test_closed_port_reports_no_modern_protocol() -> None:
    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    report = ep.scan_endpoint("127.0.0.1", port, timeout=1)
    checks = {v.evidence["check"] for v in report.violations}
    assert {"no_modern_protocol", "modern_handshake_failed"} <= checks
    assert set(report.protocols.values()) <= {"rejected", "untestable"}


def test_is_cbc() -> None:
    assert ep._is_cbc("ECDHE-RSA-AES256-SHA")
    assert not ep._is_cbc("ECDHE-RSA-AES128-GCM-SHA256")
    assert not ep._is_cbc("ECDHE-RSA-CHACHA20-POLY1305")


def test_client_side_error_detection() -> None:
    err = ssl.SSLError(1, "[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available")
    assert ep._client_side(err)
    assert not ep._client_side(ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] alert"))


def test_untestable_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate a client OpenSSL without legacy protocols or weak suites."""

    def fake_context(low: ssl.TLSVersion, high: ssl.TLSVersion, ciphers: str) -> ssl.SSLContext:
        if low < ssl.TLSVersion.TLSv1_2:
            raise ValueError("unsupported protocol")
        if ciphers != "ALL:COMPLEMENTOFDEFAULT":
            raise ssl.SSLError(1, "No cipher can be selected")
        raise ssl.SSLError(1, "[SSL: NO_PROTOCOLS_AVAILABLE] no protocols available")

    monkeypatch.setattr(ep, "_probe_context", fake_context)
    monkeypatch.setattr(ep, "_check_chain", lambda *a, **k: None)
    report = ep.scan_endpoint("127.0.0.1", 1)
    assert set(report.protocols.values()) == {"untestable"}
    assert set(report.weak_ciphers.values()) == {"untestable"}
    assert any("TLSv1:" in u for u in report.untestable)


def test_weak_probe_handshake_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_handshake(*args: Any) -> Any:
        calls.append("x")
        if len(calls) % 2:
            raise ConnectionResetError
        raise ssl.SSLError(1, "[SSL: NO_CIPHERS_AVAILABLE] none")

    monkeypatch.setattr(ep, "_weak_context", lambda spec: None)
    monkeypatch.setattr(ep, "_handshake", fake_handshake)
    report = ep.EndpointReport("127.0.0.1", 1)
    ep._probe_weak_ciphers(report, 1)
    assert list(report.weak_ciphers.values()) == ["rejected", "untestable", "rejected", "untestable", "rejected"]


def test_cli_input_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main_tls_check([]) == 2
    assert main_tls_check(["no-port"]) == 2
    assert main_tls_check(["203.0.113.10:443"]) == 2
    assert main_tls_check(["--cert", str(tmp_path / "missing.pem")]) == 2
    assert "tls-check:" in capsys.readouterr().err
