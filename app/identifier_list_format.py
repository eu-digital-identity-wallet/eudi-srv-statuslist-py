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

from app.config import CONFIGURATION
from app.status_list_format import cose_es256_sign, signer, validity


def identifier_list_jwt_format(
    identifier_list: dict, country: str, list_url: str
) -> str:
    """
    Issues an identifier list in jwt format

    Args:
        identifier_list (dict): The identifier list.

    Returns:
        str: The encoded JWT
    """

    private_key, _cert = signer(country)

    _cert_b64 = base64.b64encode(_cert).decode()

    issued_at = int(time.time())
    payload = {
        "iss": CONFIGURATION["service_url"].rstrip("/"),
        "sub": list_url,
        "iat": issued_at,
        **validity(issued_at),
        "identifier_list": identifier_list,
    }

    headers = {"typ": "application/identifierlist+jwt", "x5c": [_cert_b64]}

    signed_jwt = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)

    return signed_jwt


def identifier_list_cwt_format(
    identifier_list: dict, country: str, list_url: str
) -> bytes:
    """
    Issues an identifier list in cwt format

    Args:
        identifier_list (dict): The identifier list.

    Returns:
        str: The encoded CWT
    """

    private_key, _cert = signer(country)

    # x5chain (33) identifies the key; no kid.
    unprotected = {}
    protected = {1: -7, 16: "application/identifierlist+cwt", 33: _cert}

    # Identifiers are byte strings in the CWT; the caller's dict is left as is.
    encoded = {
        **identifier_list,
        "identifiers": {
            key if isinstance(key, bytes) else str(key).encode("utf-8"): value
            for key, value in identifier_list["identifiers"].items()
        },
    }

    issued_at = int(time.time())
    times = validity(issued_at)
    claims = {
        1: CONFIGURATION["service_url"].rstrip("/"),
        2: list_url,
        4: times["exp"],
        6: issued_at,
        65534: times["ttl"],
        65530: encoded,
    }

    cbor_header = cbor2.dumps(protected)
    cbor_claims = cbor2.dumps(claims)

    signature = cose_es256_sign(private_key, cbor_header, cbor_claims)

    cose_sign1 = [cbor_header, unprotected, cbor_claims, signature]
    tagged = cbor2.CBORTag(18, cose_sign1)

    """ try:
        private_key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("CWT signature is valid.")
    except: """

    return cbor2.dumps(tagged)
