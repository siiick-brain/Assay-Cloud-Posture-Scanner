"""Certificate checks on PEM or DER data: expiry, key size, signature hash and self-signed."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

from cspm.contracts.rule import Violation

EXPIRY_WARN_DAYS = 30
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256
WEAK_HASHES = frozenset({"md5", "sha1"})


def load_certificate(data: bytes) -> x509.Certificate:
    """Parse one certificate from PEM or DER bytes."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _subject(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


def _violation(check: str, severity: str, cert: x509.Certificate, exposure: str, **extra: Any) -> Violation:
    evidence = {"check": check, "severity": severity, "subject": _subject(cert),
                "serial": format(cert.serial_number, "x"), **extra}
    return Violation(evidence=evidence, exposure=exposure)


def is_self_signed(cert: x509.Certificate) -> bool:
    """True when the issuer equals the subject and the cert verifies with its own key."""
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, UnsupportedAlgorithm):
        return _verify_legacy_rsa(cert)
    except (TypeError, InvalidSignature):
        return False
    return True


def _verify_legacy_rsa(cert: x509.Certificate) -> bool:
    # cryptography refuses SHA-1 and MD5 in verify_directly_issued_by but raw RSA verify still works.
    key = cert.public_key()
    try:
        algo = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return False
    if not isinstance(key, rsa.RSAPublicKey) or algo is None:
        return False
    try:
        key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), algo)
    except InvalidSignature:
        return False
    return True


def _key_violation(cert: x509.Certificate, exposure: str) -> Violation | None:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey | dsa.DSAPublicKey) and key.key_size < MIN_RSA_BITS:
        kind = "RSA" if isinstance(key, rsa.RSAPublicKey) else "DSA"
        return _violation("weak_key", "high", cert, exposure, key_type=kind, key_bits=key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.key_size < MIN_EC_BITS:
        return _violation("weak_key", "high", cert, exposure, key_type="EC", key_bits=key.curve.key_size)
    return None


def _hash_name(cert: x509.Certificate) -> str | None:
    try:
        algo = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        # Unknown OIDs here are usually legacy hashes like MD2 that cryptography refuses.
        return "unsupported"
    return algo.name.lower() if algo else None


def check_certificate(
    cert: x509.Certificate,
    now: datetime,
    *,
    warn_days: int = EXPIRY_WARN_DAYS,
    exposure: str = "none",
) -> list[Violation]:
    """Return one Violation per failed check. `now` must be timezone aware."""
    out: list[Violation] = []
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days
    if now > not_after:
        out.append(_violation("expired", "high", cert, exposure, not_after=not_after.isoformat(),
                              days_left=days_left))
    elif days_left < warn_days:
        out.append(_violation("expiring", "medium", cert, exposure, not_after=not_after.isoformat(),
                              days_left=days_left, warn_days=warn_days))
    if now < cert.not_valid_before_utc:
        out.append(_violation("not_yet_valid", "medium", cert, exposure,
                              not_before=cert.not_valid_before_utc.isoformat()))
    weak_key = _key_violation(cert, exposure)
    if weak_key:
        out.append(weak_key)
    hash_name = _hash_name(cert)
    if hash_name in WEAK_HASHES or hash_name == "unsupported":
        out.append(_violation("weak_signature", "high", cert, exposure, hash=hash_name))
    if is_self_signed(cert):
        out.append(_violation("self_signed", "low", cert, exposure))
    return out


def check_certificate_file(path: Path, now: datetime, *, warn_days: int = EXPIRY_WARN_DAYS) -> list[Violation]:
    """Load a PEM or DER file and run `check_certificate` on it."""
    return check_certificate(load_certificate(path.read_bytes()), now, warn_days=warn_days)
