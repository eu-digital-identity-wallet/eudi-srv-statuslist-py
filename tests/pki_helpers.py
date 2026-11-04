"""Throw-away signing keys and certificates for the tests."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class Signer(NamedTuple):
    """Files and objects of a generated signer."""

    key_path: Path
    cert_path: Path
    private_key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate


def make_signer(
    directory: Path,
    name: str,
    *,
    country: str = "LU",
    password: str | None = None,
    pem_certificate: bool = False,
    expired: bool = False,
) -> Signer:
    """Writes a self-signed EC P-256 key and certificate to ``directory``.

    Args:
        directory: Target directory.
        name: File name stem.
        country: Certificate subject country.
        password: Encrypts the PEM key when given.
        pem_certificate: Writes the certificate as PEM instead of DER.
        expired: The certificate expired yesterday.

    Returns:
        The written files and the key / certificate objects.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.COMMON_NAME, f"Test status list signer {name}"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        now -= datetime.timedelta(days=31)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    key_path = directory / f"{name}.pem"
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    )
    cert_path = directory / (f"{name}_cert.pem" if pem_certificate else f"{name}_cert.der")
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM if pem_certificate else serialization.Encoding.DER)
    )
    return Signer(key_path, cert_path, key, cert)
