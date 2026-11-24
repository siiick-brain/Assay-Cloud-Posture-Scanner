from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cspm.tls import check_certificate, check_certificate_file, is_self_signed, load_certificate
from tests.tls_servers.certs import Issued, build, resign_legacy, strong_chain, weak_self_signed

NOW = datetime.now(UTC)


def _checks(cert: x509.Certificate, now: datetime = NOW) -> set[str]:
    return {v.evidence["check"] for v in check_certificate(cert, now)}


def test_strong_leaf_is_clean() -> None:
    _, leaf = strong_chain()
    assert check_certificate(leaf.cert, NOW) == []
    assert not is_self_signed(leaf.cert)


def test_weak_cert_flags_every_problem() -> None:
    weak = weak_self_signed(days=5)
    found = {v.evidence["check"]: v.evidence for v in check_certificate(weak.cert, NOW, exposure="internal")}
    assert set(found) == {"expiring", "weak_key", "weak_signature", "self_signed"}
    assert found["weak_key"]["key_bits"] == 1024
    assert found["weak_signature"]["hash"] == "sha1"
    assert found["expiring"]["days_left"] < 30


def test_md5_signature() -> None:
    weak = weak_self_signed(days=400, hash_name="md5", bits=2048)
    assert _checks(weak.cert) == {"weak_signature", "self_signed"}


def test_expired_and_not_yet_valid() -> None:
    cert = build("old", days=10).cert
    assert "expired" in _checks(cert, NOW + timedelta(days=11))
    future = build("future", start_offset_days=3, days=200).cert
    assert "not_yet_valid" in _checks(future)


def test_warn_window_is_configurable() -> None:
    cert = build("soon", days=45).cert
    assert "expiring" not in _checks(cert)
    assert any(v.evidence["check"] == "expiring" for v in check_certificate(cert, NOW, warn_days=60))


def test_small_ec_key() -> None:
    try:
        key = ec.generate_private_key(ec.SECP192R1())
    except Exception:
        pytest.skip("local OpenSSL has no P-192")
    found = [v.evidence for v in check_certificate(build("ec", key=key).cert, NOW)]
    assert {"check": "weak_key", "key_type": "EC", "key_bits": 192}.items() <= found[0].items()


def test_rsa_2048_sha256_is_fine() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, leaf = strong_chain()
    assert _checks(build("rsa", key=key, issuer=leaf).cert) == set()


def test_self_signed_needs_a_matching_signature() -> None:
    assert is_self_signed(build("same").cert)
    # Issuer name equals subject name but another key signed it.
    fake = build("same", issuer=build("same", ca=True))
    assert fake.cert.issuer == fake.cert.subject
    assert not is_self_signed(fake.cert)


def test_legacy_self_signed_with_wrong_key() -> None:
    weak = weak_self_signed()
    assert is_self_signed(weak.cert)
    base = build("localhost", key=rsa.generate_private_key(public_exponent=65537, key_size=1024))  # noqa: S505
    imposter = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    forged = resign_legacy(Issued(base.cert, imposter), "sha1")
    assert not is_self_signed(forged.cert)


def test_load_pem_and_der(tmp_path: Path) -> None:
    _, leaf = strong_chain()
    der = tmp_path / "leaf.der"
    der.write_bytes(leaf.cert.public_bytes(serialization.Encoding.DER))
    pem_path, _ = leaf.write(tmp_path, "leaf")
    assert load_certificate(der.read_bytes()) == load_certificate(pem_path.read_bytes())
    assert check_certificate_file(der, NOW) == []
    weak_pem, _ = weak_self_signed().write(tmp_path, "weak")
    assert check_certificate_file(weak_pem, NOW)
