"""Signed list formats: status list JWT / CWT and identifier list JWT / CWT."""

from __future__ import annotations

import base64
import time
import zlib

import cbor2
import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app.identifier_list_format import identifier_list_cwt_format, identifier_list_jwt_format
from app.status_list import IssuerStatusList
from app.status_list_format import cwt_format, jwt_format
from tests.strict import strict_cbor

URL = "https://statuslist.test/token_status_list/FC/doc/id"


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_cose_sign1(encoded: bytes, public_key) -> tuple[dict, dict]:
    """Checks a tagged COSE_Sign1 ES256 signature; returns (protected, claims).

    Decoded strictly: trailing bytes fail (issue #191).
    """
    tagged = strict_cbor(encoded)
    assert tagged.tag == 18
    protected, unprotected, payload, signature = tagged.value
    assert unprotected == {}  # x5chain identifies the key, no kid
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    public_key.verify(der, sig_structure, ec.ECDSA(hashes.SHA256()))
    return cbor2.loads(protected), cbor2.loads(payload)


@pytest.fixture
def status_list():
    lst = IssuerStatusList.new(1, 16)
    lst.status_list.set(3, 1)
    return lst


def test_signer_returns_the_loaded_material(signer):
    from app.status_list_format import signer as loaded_signer

    key, cert = loaded_signer("FC")
    assert cert == signer.certificate.public_bytes(serialization.Encoding.DER)
    assert key.public_key().public_numbers() == signer.private_key.public_key().public_numbers()


def test_status_list_jwt(signer, configuration, status_list):
    configuration.update(status_list_ttl=600, status_list_validity=90000)
    token = jwt_format(status_list, "FC", URL)
    header = jwt.get_unverified_header(token)
    assert header["typ"] == "statuslist+jwt"
    assert header["alg"] == "ES256"
    assert base64.b64decode(header["x5c"][0]) == signer.certificate.public_bytes(serialization.Encoding.DER)

    claims = jwt.decode(token, signer.private_key.public_key(), algorithms=["ES256"])
    assert claims["sub"] == URL
    assert claims["exp"] == claims["iat"] + 90000
    assert claims["ttl"] == 600
    assert abs(claims["iat"] - time.time()) < 60
    assert claims["status_list"]["bits"] == 1
    bits = zlib.decompress(b64url_decode(claims["status_list"]["lst"]))
    assert bits[0] == 0b00001000


def test_status_list_cwt(signer, configuration, status_list):
    configuration.update(status_list_ttl=600, status_list_validity=90000)
    protected, claims = verify_cose_sign1(cwt_format(status_list, "FC", URL), signer.private_key.public_key())
    assert protected[1] == -7
    assert protected[16] == "application/statuslist+cwt"
    assert protected[33] == signer.certificate.public_bytes(serialization.Encoding.DER)
    assert claims[2] == URL
    assert claims[4] == claims[6] + 90000
    assert claims[65534] == 600
    assert claims[65533]["bits"] == 1
    assert zlib.decompress(claims[65533]["lst"])[0] == 0b00001000


def test_identifier_list_jwt(signer):
    token = identifier_list_jwt_format({"identifiers": {"5": {}}}, "FC", URL)
    assert jwt.get_unverified_header(token)["typ"] == "application/identifierlist+jwt"
    claims = jwt.decode(token, signer.private_key.public_key(), algorithms=["ES256"])
    assert claims["iss"] == "https://statuslist.test"
    assert claims["exp"] == claims["iat"] + 86400
    assert claims["identifier_list"] == {"identifiers": {"5": {}}}


def test_identifier_list_cwt(signer):
    identifier_list = {"identifiers": {"5": {}}}
    protected, claims = verify_cose_sign1(
        identifier_list_cwt_format(identifier_list, "FC", URL), signer.private_key.public_key()
    )
    assert protected[16] == "application/identifierlist+cwt"
    assert claims[1] == "https://statuslist.test"
    assert claims[2] == URL
    assert claims[4] == claims[6] + 86400
    assert claims[65534] == 3600
    assert claims[65530] == {"identifiers": {b"5": {}}}


def test_identifier_list_cwt_leaves_its_input_alone():
    identifier_list = {"identifiers": {"5": {}}}
    identifier_list_cwt_format(identifier_list, "FC", URL)
    identifier_list_cwt_format(identifier_list, "FC", URL)  # twice: was AttributeError on bytes keys
    assert identifier_list == {"identifiers": {"5": {}}}


def test_strict_decoding_rejects_trailing_bytes(signer, status_list):
    """The issue #191 file: a valid COSE_Sign1 followed by stray bytes."""
    encoded = cwt_format(status_list, "FC", URL)
    verify_cose_sign1(encoded, signer.private_key.public_key())
    with pytest.raises(AssertionError, match="2 trailing byte"):
        strict_cbor(encoded + b"wt")
