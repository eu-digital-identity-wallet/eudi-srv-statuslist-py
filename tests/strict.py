"""Strict checks of published lists: what a strict verifier accepts (issue #191)."""

from __future__ import annotations

import base64
import io
import json
import zlib
from pathlib import Path

import cbor2
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app.storage import FULL_LIST


def strict_cbor(data: bytes):
    """Decodes exactly one CBOR item; trailing bytes are an error."""
    fp = io.BytesIO(data)
    item = cbor2.CBORDecoder(fp).decode()
    assert fp.tell() == len(data), f"{len(data) - fp.tell()} trailing byte(s) after the CBOR item"
    return item


def verify_cwt(data: bytes) -> tuple[dict, dict]:
    """Strictly decodes a tagged COSE_Sign1 and checks its ES256 signature (x5chain key)."""
    tagged = strict_cbor(data)
    assert tagged.tag == 18
    protected_bytes, _, payload, signature = tagged.value
    protected = strict_cbor(protected_bytes)
    cert = x509.load_der_x509_certificate(protected[33])
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    cert.public_key().verify(der, cbor2.dumps(["Signature1", protected_bytes, b"", payload]), ec.ECDSA(hashes.SHA256()))
    return protected, strict_cbor(payload)


def verify_jwt(token: str) -> dict:
    """Verifies a status list JWT with the key of its x5c."""
    header = jwt.get_unverified_header(token)
    cert = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    return jwt.decode(token, cert.public_key(), algorithms=["ES256"])


def status_bit(compressed: bytes, idx: int) -> int:
    lst = zlib.decompress(compressed)
    return (lst[idx // 8] >> (idx % 8)) & 1


def check_list_files(token_dir: Path, identifier_dir: Path) -> dict:
    """Every file of one list is complete and valid; returns the JWT claims."""
    json.loads((token_dir / FULL_LIST).read_text())
    json.loads((identifier_dir / FULL_LIST).read_text())
    claims = verify_jwt((token_dir / "token_status_list.jwt").read_text())
    _, cwt_claims = verify_cwt((token_dir / "token_status_list.cwt").read_bytes())
    assert cwt_claims[65533]["lst"] == base64.urlsafe_b64decode(claims["status_list"]["lst"] + "==")
    verify_cwt((identifier_dir / "identifier_list.cwt").read_bytes())
    return claims


def jwt_status(token_dir: Path, idx: int) -> int:
    claims = verify_jwt((token_dir / "token_status_list.jwt").read_text())
    return status_bit(base64.urlsafe_b64decode(claims["status_list"]["lst"] + "=="), idx)
