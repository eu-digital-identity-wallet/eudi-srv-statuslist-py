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
import cbor2, jwt
from datetime import datetime, timedelta
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from app.config_service import ConfService as cfgservice


def identifier_list_jwt_format(identifier_list: dict, country: str, list_url: str) -> str:
    """
    Issues an identifier list in jwt format

    Args:
        identifier_list (dict): The identifier list.

    Returns:
        str: The encoded JWT
    """

    #private_key = ec.generate_private_key(ec.SECP256R1())

    with open(cfgservice.countries[country]["privKey"], "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password= cfgservice.countries[country]["privkey_passwd"] if cfgservice.countries[country]["privkey_passwd"] is not None else None,
            backend=default_backend()
        )

    with open(cfgservice.countries[country]["cert"], "rb") as file:
        certificate = file.read()

    cert = x509.load_der_x509_certificate(certificate)

    _cert = cert.public_bytes(getattr(serialization.Encoding, "DER"))

    _cert_b64 = base64.b64encode(_cert).decode()

    print("\ncert_b64", _cert_b64, flush=True)

    payload = {
        "iss": cfgservice.service_url[:-1],
        "sub": list_url,
        "iat": int(time.time()),
        #"exp": datetime.now() + timedelta(days=1),
        "identifier_list": identifier_list,
    }

    headers = {"typ": "identifierlist+jwt", "x5c": [_cert_b64]}

    signed_jwt = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)

    return signed_jwt


def identifier_list_cwt_format(identifier_list: dict, country: str, list_url: str) -> str:
    """
    Issues an identifier list in cwt format

    Args:
        identifier_list (dict): The identifier list.

    Returns:
        str: The encoded CWT
    """

    #private_key = ec.generate_private_key(ec.SECP256R1())

    with open(cfgservice.countries[country]["privKey"], "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password= cfgservice.countries[country]["privkey_passwd"] if cfgservice.countries[country]["privkey_passwd"] is not None else None,
            backend=default_backend()
        )

    with open(cfgservice.countries[country]["cert"], "rb") as file:
        certificate = file.read()

    cert = x509.load_der_x509_certificate(certificate)

    _cert = cert.public_bytes(getattr(serialization.Encoding, "DER"))

    unprotected = {4: b"1"}
    protected = {1: -7, 16: "identifierlist+cwt", 33: _cert}

    claims = {
        1: cfgservice.service_url[:-1],
        2: list_url,
        6: int(time.time()),
        #4: int((datetime.now() + timedelta(days=1)).timestamp()),
        65535: cbor2.dumps(identifier_list),
    }

    cbor_header = cbor2.dumps(protected)
    cbor_claims = cbor2.dumps(claims)

    message = cbor_header + cbor_claims

    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    cose_sign1 = [cbor_header, unprotected, cbor_claims, signature]
    tagged = cbor2.CBORTag(18, cose_sign1)

    """ try:
        private_key.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("CWT signature is valid.")
    except:
        print("CWT signature is invalid.") """

    return cbor2.dumps(tagged).hex()
