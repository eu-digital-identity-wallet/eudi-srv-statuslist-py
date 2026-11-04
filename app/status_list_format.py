# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import base64
import time

import cbor2
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.config import CONFIGURATION
from app.status_list import IssuerStatusList


def signer(country: str):
    """Returns the signing key and DER certificate of a country.

    Both are loaded once at start-up (``countries`` in the configuration).

    Args:
        country: Country code.

    Returns:
        ``(private_key, certificate_der)``.
    """
    entry = CONFIGURATION["countries"][country]
    return entry["private_key"], entry["certificate"]


def validity(issued_at: int) -> dict[str, int]:
    """``exp`` and ``ttl`` of a list signed at ``issued_at`` (draft-12 section 13.7).

    ``exp`` is ``status_list_validity`` after signing: the renewals re-sign
    every list well before (see ``check_settings``). ``ttl`` is how long a
    relying party may cache the list.
    """
    return {"exp": issued_at + CONFIGURATION["status_list_validity"], "ttl": CONFIGURATION["status_list_ttl"]}


def cose_es256_sign(private_key, cbor_header: bytes, cbor_claims: bytes) -> bytes:
    """
    Signs a COSE_Sign1 Sig_structure with ES256 and returns raw r||s (64 bytes)
    """
    sig_structure = cbor2.dumps(["Signature1", cbor_header, b"", cbor_claims])
    der_signature = private_key.sign(sig_structure, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")

def jwt_format(token_status_list: IssuerStatusList, country: str, list_url: str) -> str:
    """
    Issues a token status list in JWT format

    Args:
        token_status_list (IssuerStatusList): an instance of the IssuerStatusList class containing the token status information

    Returns:
        str: The encoded JWT
    """

    private_key, _cert = signer(country)

    _cert_b64 = base64.b64encode(_cert).decode()

    issued_at = int(time.time())
    payload = {
        "sub": list_url,
        "iat": issued_at,
        **validity(issued_at),
        "status_list": {
            "bits": token_status_list.status_list.bits,
            "lst": base64.urlsafe_b64encode(token_status_list.status_list.compressed())
            .decode("utf-8")
            .rstrip("="),
        },
    }

    headers = {"typ": "statuslist+jwt", "x5c": [_cert_b64]}

    signed_jwt = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)

    return signed_jwt


def cwt_format(
    token_status_list: IssuerStatusList, country: str, list_url: str
) -> bytes:
    """
    Issues a token status list in CWT format

    Args:
        token_status_list (IssuerStatusList): an instance of the IssuerStatusList class containing the token status information

    Returns:
        str: The encoded CWT
    """
    private_key, _cert = signer(country)

    # x5chain (33) identifies the key; no kid (draft-12 section 11.3).
    unprotected = {}
    protected = {1: -7, 16: "application/statuslist+cwt", 33: _cert}

    issued_at = int(time.time())
    times = validity(issued_at)
    claims = {
        2: list_url,
        4: times["exp"],
        6: issued_at,
        65534: times["ttl"],
        65533: {"bits": token_status_list.status_list.bits, "lst": token_status_list.status_list.compressed()},
    }

    cbor_header = cbor2.dumps(protected)
    cbor_claims = cbor2.dumps(claims)

    signature = cose_es256_sign(private_key, cbor_header, cbor_claims)

    cose_sign1 = [cbor_header, unprotected, cbor_claims, signature]
    tagged = cbor2.CBORTag(18, cose_sign1)

    return cbor2.dumps(tagged)
