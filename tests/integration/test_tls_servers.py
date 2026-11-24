"""Endpoint checker against strong and weak TLS servers started on 127.0.0.1."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from cspm.tls import EndpointReport, check_endpoint, main_tls_check, scan_endpoint
from tests.tls_servers.certs import strong_chain, weak_self_signed
from tests.tls_servers.server import LocalTLSServer, strong_context, weak_context

HOST = "127.0.0.1"


@dataclass
class Servers:
    ca: Path
    strong: int
    weak: int
    weak_cert: Path


@pytest.fixture(scope="module")
def servers(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Servers]:
    folder = tmp_path_factory.mktemp("tls")
    ca, leaf = strong_chain()
    ca_pem, _ = ca.write(folder, "ca")
    cert, key = leaf.write(folder, "leaf")
    weak_cert, weak_key = weak_self_signed(days=5).write(folder, "weak")
    with LocalTLSServer(strong_context(cert, key)) as strong, LocalTLSServer(weak_context(weak_cert, weak_key)) as weak:
        yield Servers(ca_pem, strong.port, weak.port, weak_cert)


def test_strong_server_is_clean(servers: Servers) -> None:
    report = scan_endpoint(HOST, servers.strong, ca_bundle=servers.ca)
    assert report.violations == []
    assert report.protocols["TLSv1.3"] == "accepted"
    assert report.protocols["TLSv1.2"] == "accepted"
    assert report.protocols["TLSv1"] in ("rejected", "untestable")
    assert not any(s.startswith("accepted") for s in report.weak_ciphers.values())


def test_strong_server_with_wrong_ca_bundle(servers: Servers) -> None:
    found = check_endpoint(HOST, servers.strong, ca_bundle=servers.weak_cert)
    assert [v.evidence["check"] for v in found] == ["chain_invalid"]


def test_strong_server_with_wrong_name(servers: Servers) -> None:
    found = check_endpoint(HOST, servers.strong, ca_bundle=servers.ca, server_hostname="example.test")
    assert [v.evidence["check"] for v in found] == ["chain_invalid"]
    assert "mismatch" in found[0].evidence["reason"].lower()


@pytest.fixture(scope="module")
def weak_report(servers: Servers) -> EndpointReport:
    return scan_endpoint(HOST, servers.weak, ca_bundle=servers.ca)


def _checks(report: EndpointReport) -> list[str]:
    return [v.evidence["check"] for v in report.violations]


def test_weak_server_cert_and_chain(weak_report: EndpointReport) -> None:
    for expected in ("chain_invalid", "expiring", "weak_key", "weak_signature", "self_signed"):
        assert expected in _checks(weak_report)
    assert all(v.exposure == "internal" for v in weak_report.violations)


@pytest.mark.parametrize("proto", ["TLSv1", "TLSv1.1"])
def test_weak_server_legacy_protocols(weak_report: EndpointReport, proto: str) -> None:
    # Legacy protocols depend on the local OpenSSL build; record a skip rather than pretend.
    if weak_report.protocols[proto] == "untestable":
        pytest.skip(f"{proto} not available in local OpenSSL")
    assert weak_report.protocols[proto] == "accepted"
    assert any(v.evidence.get("protocol") == proto for v in weak_report.violations
               if v.evidence["check"] == "legacy_protocol")


def test_weak_server_tls10_cbc(weak_report: EndpointReport) -> None:
    if weak_report.protocols["TLSv1"] == "untestable":
        pytest.skip("TLSv1 not available in local OpenSSL")
    assert "tls10_cbc" in _checks(weak_report)


def test_weak_server_weak_ciphers(weak_report: EndpointReport) -> None:
    states = weak_report.weak_ciphers
    if all(s == "untestable" for s in states.values()):
        pytest.skip("local OpenSSL has none of the weak cipher families")
    accepted = {k for k, s in states.items() if s.startswith("accepted")}
    assert {"NULL", "ANON"} <= accepted
    flagged = {v.evidence["family"] for v in weak_report.violations if v.evidence["check"] == "weak_cipher"}
    assert flagged == accepted


def test_cli_against_servers(servers: Servers, capsys: pytest.CaptureFixture[str]) -> None:
    assert main_tls_check([f"{HOST}:{servers.strong}", "--ca-bundle", str(servers.ca)]) == 0
    assert "0 issue(s)" in capsys.readouterr().out
    assert main_tls_check([f"{HOST}:{servers.weak}", "--ca-bundle", str(servers.ca)]) == 1
    text = capsys.readouterr().out
    assert "[high] weak_signature" in text
    assert main_tls_check(["--cert", str(servers.weak_cert), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert {e["check"] for e in data["certificates"][str(servers.weak_cert)]} >= {"weak_key", "self_signed"}
