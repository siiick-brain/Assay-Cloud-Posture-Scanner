"""Certificates generated at test time. Nothing here is written to the repo."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


@dataclass(frozen=True)
class Issued:
    cert: x509.Certificate
    key: PrivateKey

    def write(self, folder: Path, stem: str) -> tuple[Path, Path]:
        cert_path = folder / f"{stem}.pem"
        key_path = folder / f"{stem}.key"
        cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert_path, key_path


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def build(
    cn: str,
    *,
    key: PrivateKey | None = None,
    issuer: Issued | None = None,
    hash_algo: hashes.HashAlgorithm | None = None,
    days: int = 365,
    start_offset_days: int = -1,
    ca: bool = False,
    now: datetime | None = None,
) -> Issued:
    """Build one certificate. Without `issuer` it is self-signed."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = now or datetime.now(UTC)
    signer_key = issuer.key if issuer else key
    issuer_name = issuer.cert.subject if issuer else _name(cn)
    start = now + timedelta(days=start_offset_days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]),
            critical=False,
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = builder.sign(signer_key, hash_algo or hashes.SHA256())
    return Issued(cert, key)


def strong_chain() -> tuple[Issued, Issued]:
    """A test CA and a leaf for localhost signed by it, P-256 and SHA-256."""
    ca = build("Assay Test CA", ca=True, days=365)
    leaf = build("localhost", issuer=ca, days=200)
    return ca, leaf


_SHA256_RSA = bytes.fromhex("06092a864886f70d01010b")
_LEGACY_OID = {"sha1": bytes.fromhex("06092a864886f70d010105"), "md5": bytes.fromhex("06092a864886f70d010104")}


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def resign_legacy(issued: Issued, hash_name: str) -> Issued:
    """Re-sign an RSA SHA-256 cert with SHA-1 or MD5.

    cryptography no longer signs certificates with those hashes, so we swap the
    equal-length algorithm OID in the TBS bytes and sign them with the raw RSA key.
    """
    assert isinstance(issued.key, rsa.RSAPrivateKey)
    tbs = issued.cert.tbs_certificate_bytes
    assert tbs.count(_SHA256_RSA) == 1
    oid = _LEGACY_OID[hash_name]
    tbs = tbs.replace(_SHA256_RSA, oid)
    algo: hashes.HashAlgorithm = hashes.SHA1() if hash_name == "sha1" else hashes.MD5()  # noqa: S303
    sig = issued.key.sign(tbs, padding.PKCS1v15(), algo)
    alg_id = _der(0x30, oid + b"\x05\x00")
    der = _der(0x30, tbs + alg_id + _der(0x03, b"\x00" + sig))
    return Issued(x509.load_der_x509_certificate(der), issued.key)


def weak_self_signed(days: int = 5, hash_name: str = "sha1", bits: int = 1024) -> Issued:
    """RSA 1024, SHA-1, self-signed and close to expiry."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return resign_legacy(build("localhost", key=key, days=days), hash_name)
