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
"""Runtime configuration loading for the Status List service.

The service is configured through a YAML file whose location is given by the
``STATUS_LIST_CONFIG_PATH`` environment variable (see
``app/config_statuslist_example.yaml``). Every country's signing key and
certificate are read and parsed at start-up, so the rest of the code base
never touches the filesystem for key material.

When ``MOCK_CONFIGURATION`` is set (test / CI runs) a minimal in-memory
configuration is used instead.

Attributes:
    CONFIGURATION: The process-wide configuration dictionary.
    IS_TEST_ENV: ``True`` only when ``EUDIW_TEST_ENV=true`` is set.
"""

from __future__ import annotations

import copy
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/statuslist_config/config_statuslist.yaml"

#: Values used for the keys the configuration file leaves out.
DEFAULTS: dict[str, Any] = {
    "service_url": "https://issuer.eudiw.dev/",
    "debug": False,
    "token_status_list_size": 10000,
    "batch_max_size": 1000,
    "status_list_ttl": 3600,
    "status_list_validity": 86400,
    "max_expiry_days": 3650,
    "status_list_dir": "/var/opt/status_lists",
    "backup_dir": "/var/opt/status_list_backup",
    "renewal": {"hours": [0, 12]},
    "logging": {
        "path": "/var/log/status_lists/status_lists.log",
        "log_level": "INFO",
        "backup_count": 7,
    },
    "allowed_doctypes": [
        "eu.europa.ec.eudi.cor.1",
        "eu.europa.ec.eudi.ehic.1",
        "eu.europa.ec.eudi.hiid.1",
        "eu.europa.ec.eudi.iban.1",
        "eu.europa.ec.eudi.loyalty.1",
        "eu.europa.ec.eudi.msisdn.1",
        "eu.europa.ec.eudi.pda1.1",
        "eu.europa.ec.eudi.pid.1",
        "eu.europa.ec.eudi.por.1",
        "eu.europa.ec.eudi.pseudonym.age_over_18.1",
        "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint",
        "eu.europa.ec.eudi.tax.1",
        "org.iso.18013.5.1.mDL",
        "org.iso.18013.5.1.reservation",
        "org.iso.23220.2.photoid.1",
        "org.iso.23220.photoID.1",
        "urn:eudi:pid:1",
        "urn:eu.europa.ec.eudi:pid:1",
        "eu.europa.ec.av.1",
        "urn:eu.europa.ec.eudi:diploma:1:1",
        "urn:eudi:ehic:1",
        "eu.europa.ec.eudi.employee.1",
        "urn:eu.europa.ec.eudi:hiid:1",
        "urn:eu.europa.ec.eudi:iban:1",
        "urn:eu.europa.ec.eudi:msisdn:1",
        "urn:eu.europa.ec.eudi:pda1:1",
        "urn:eu.europa.ec.eudi:por:1",
        "eu.europa.ec.eudi.seafarer.1",
        "urn:eu.europa.ec.eudi:tax:1",
        "urn:eu.europa.ec.eudi:tax:1:1",
        "urn:eu.europa.ec.eudi:learning:credential:1",
        "org.iso.7367.2.1.mVC",
        "key-attestation+jwt",
        "wrprc",
        "oauth-client-attestation+jwt",
    ],
}

#: ``${name}`` placeholder of a value defined in the ``variables`` section.
_PLACEHOLDER = re.compile(r"\$\{(\w+)\}", re.ASCII)


def _substitute(text: str, variables: dict[str, str]) -> str:
    """Replaces the ``${name}`` placeholders of ``text``.

    Args:
        text: String value of the configuration.
        variables: Resolved variables.

    Returns:
        ``text`` with every placeholder replaced by its variable.

    Raises:
        RuntimeError: If a placeholder names an undefined variable.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise RuntimeError(f"Undefined config variable: ${{{name}}}")
        return variables[name]

    return _PLACEHOLDER.sub(replace, text)


def _interpolate(value: Any, variables: dict[str, str]) -> Any:
    """Substitutes the variables in every string of ``value``, recursively.

    Dictionaries and lists are rebuilt, so values shared through YAML aliases
    become independent copies.

    Args:
        value: Configuration value.
        variables: Resolved variables.

    Returns:
        The value with its placeholders replaced.
    """
    if isinstance(value, dict):
        return {key: _interpolate(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, variables) for item in value]
    if isinstance(value, str):
        return _substitute(value, variables)
    return value


def resolve_variables(config: dict[str, Any]) -> dict[str, Any]:
    """Applies the top-level ``variables`` section to the configuration.

    ``variables`` maps names to strings; any string value of the
    configuration may then use ``${name}``, e.g.
    ``"${keys_dir}/PID-DS-0001_LU.pem"``. A variable may use the variables
    defined before it. The section is removed from the result.

    Args:
        config: Parsed YAML configuration.

    Returns:
        A new configuration with the placeholders replaced.

    Raises:
        RuntimeError: If ``variables`` is not a mapping of strings, or a
            placeholder names an undefined variable.
    """
    config = dict(config)
    raw = config.pop("variables", None) or {}
    if not isinstance(raw, dict):
        raise RuntimeError("Config section 'variables' must be a mapping")

    variables: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(value, str):
            raise RuntimeError(f"Config variable '{name}' must be a string")
        variables[name] = _substitute(value, variables)

    return _interpolate(config, variables)


def apply_defaults(config: dict[str, Any]) -> dict[str, Any]:
    """Fills in the keys the configuration leaves out from :data:`DEFAULTS`.

    ``logging`` and ``renewal`` are merged key by key; ``service_url`` always
    ends with ``/`` (list URIs are appended to it).

    Args:
        config: Configuration after variable substitution.

    Returns:
        A new configuration with every default key present.
    """
    merged = copy.deepcopy(DEFAULTS)
    for key, value in config.items():
        if key in ("logging", "renewal") and isinstance(value, dict):
            merged[key].update(value)
        else:
            merged[key] = value
    if not merged["service_url"].endswith("/"):
        merged["service_url"] += "/"
    return merged


def _load_file(path: str) -> bytes:
    """Reads a file as raw bytes.

    Args:
        path: Filesystem path to read.

    Returns:
        The file contents.

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as f:
        return f.read()


def load_signer(country: str, entry: dict[str, Any]) -> None:
    """Reads and parses the signing key and certificate of one country.

    Stores the private key object under ``private_key`` and the DER
    certificate under ``certificate`` (a PEM file is accepted too).

    Args:
        country: Country code (for errors).
        entry: The country's configuration entry. Mutated in place.

    Raises:
        RuntimeError: If an entry is incomplete or a file cannot be read or
            parsed (wrong password, not a key / certificate).
    """
    try:
        key_path = entry["private_key_path"]
        cert_path = entry["certificate_path"]
    except (KeyError, TypeError) as e:
        raise RuntimeError(
            f"Country {country} needs private_key_path and certificate_path"
        ) from e

    password = entry.get("private_key_password")
    try:
        entry["private_key"] = serialization.load_pem_private_key(
            _load_file(key_path), password=password.encode() if password else None
        )
    except (OSError, ValueError, TypeError) as e:
        raise RuntimeError(f"Cannot load the private key of country {country}: {key_path}: {e}") from e

    try:
        raw = _load_file(cert_path)
        cert = (
            x509.load_pem_x509_certificate(raw)
            if raw.lstrip().startswith(b"-----BEGIN")
            else x509.load_der_x509_certificate(raw)
        )
    except (OSError, ValueError) as e:
        raise RuntimeError(f"Cannot load the certificate of country {country}: {cert_path}: {e}") from e
    _check_signer(country, entry["private_key"], cert)
    entry["certificate"] = cert.public_bytes(serialization.Encoding.DER)


def _check_signer(country: str, private_key: Any, cert: x509.Certificate) -> None:
    """Makes sure the lists of ``country`` can be signed (ES256) and verified.

    No extended key usage is required: the ``id-kp-oauthStatusSigning`` OID
    of draft-ietf-oauth-status-list-12 section 10 is not assigned yet.

    Raises:
        RuntimeError: The key is not EC P-256, or the certificate is not the
            key's (verifiers would reject every list).
    """
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise RuntimeError(f"The private key of country {country} must be an EC P-256 key (ES256)")
    public = serialization.PublicFormat.SubjectPublicKeyInfo
    if private_key.public_key().public_bytes(serialization.Encoding.DER, public) != cert.public_key().public_bytes(
        serialization.Encoding.DER, public
    ):
        raise RuntimeError(f"The certificate of country {country} does not match its private key")
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        logger.warning(
            "The certificate of country %s is not valid now (%s to %s)",
            country, cert.not_valid_before_utc, cert.not_valid_after_utc,
        )


def _positive_int(config: dict[str, Any], name: str) -> int:
    value = config.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuntimeError(f"Config '{name}' must be a positive integer")
    return value


def longest_renewal_gap(hours: list[int]) -> int:
    """Longest time between two renewals, in hours (across midnight too)."""
    hours = sorted(hours)
    return max(b - a for a, b in zip(hours, hours[1:] + [hours[0] + 24]))


def check_settings(config: dict[str, Any]) -> None:
    """Checks the numeric settings, so that a bad value stops the service at start-up.

    Raises:
        RuntimeError: A setting out of range, named in the message.
    """
    for name in ("token_status_list_size", "status_list_ttl", "batch_max_size", "max_expiry_days"):
        _positive_int(config, name)
    hours = config["renewal"].get("hours") if isinstance(config["renewal"], dict) else None
    if (
        not isinstance(hours, list)
        or not hours
        or len(set(hours)) != len(hours)
        or not all(isinstance(h, int) and not isinstance(h, bool) and 0 <= h <= 23 for h in hours)
    ):
        raise RuntimeError("Config 'renewal.hours' must list distinct hours from 0 to 23")
    # The published lists must outlive a missed renewal.
    minimum = (longest_renewal_gap(hours) + 1) * 3600
    if _positive_int(config, "status_list_validity") <= minimum:
        raise RuntimeError(
            f"Config 'status_list_validity' must be more than {minimum} seconds "
            "(the longest time between renewals plus one hour)"
        )


def process_config(config: dict[str, Any]) -> dict[str, Any]:
    """Checks the configuration and loads every country's key material.

    Args:
        config: Configuration with defaults applied. Mutated in place.

    Returns:
        The same ``config`` object, for convenience.

    Raises:
        RuntimeError: If ``countries`` is missing or empty, a country's
            key material cannot be loaded, or a numeric setting is invalid.
    """
    check_settings(config)
    countries = config.get("countries")
    if not isinstance(countries, dict) or not countries:
        raise RuntimeError("Config section 'countries' must map at least one country to its signer")
    for country, entry in countries.items():
        load_signer(country, entry)
    return config


def load_config(path: str | None = None) -> dict[str, Any]:
    """Reads and processes the status list YAML configuration.

    Args:
        path: Explicit configuration path. Defaults to
            ``STATUS_LIST_CONFIG_PATH`` or :data:`DEFAULT_CONFIG_PATH`.

    Returns:
        The processed configuration dictionary.

    Raises:
        RuntimeError: If the file is missing, empty or not valid YAML, uses
            an undefined variable, or its key material cannot be loaded.
    """
    config_path = path or os.environ.get("STATUS_LIST_CONFIG_PATH", DEFAULT_CONFIG_PATH)
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Config file not found: {config_path}") from e
    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML in config: {e}") from e

    if not config:
        raise RuntimeError(f"Config file is empty: {config_path}")
    if not isinstance(config, dict):
        raise RuntimeError(f"Config file must hold a mapping: {config_path}")

    return process_config(apply_defaults(resolve_variables(config)))


def mock_config() -> dict[str, Any]:
    """Returns the minimal configuration used when ``MOCK_CONFIGURATION`` is set.

    Returns:
        The defaults with a test service URL, a test API key and no
        countries (tests add the signers they need).
    """
    config = apply_defaults({"service_url": "https://statuslist.test/", "api_key": "test-api-key"})
    config["countries"] = {}
    return config


#: Environment variable that switches the test-environment defaults on.
TEST_ENV_VARIABLE = "EUDIW_TEST_ENV"


def _detect_test_env() -> bool:
    """Tells whether the process runs as a test environment.

    The test environment relaxes start-up checks (weak API key allowed, no
    renewal thread), so it needs an explicit opt-in: generic variables such
    as ``CI`` do not enable it.

    Returns:
        ``True`` only for ``EUDIW_TEST_ENV=true``.
    """
    return os.getenv(TEST_ENV_VARIABLE) == "true"


CONFIGURATION: dict[str, Any] = mock_config() if os.getenv("MOCK_CONFIGURATION") else load_config()

IS_TEST_ENV: bool = _detect_test_env()
