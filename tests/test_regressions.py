"""Regression tests of the bugs found by the 0.1.0 bug hunt, one test each.

A new bug may land here first as ``@bug(...)`` (a strict ``xfail``): its fix
then makes the test pass, ``strict`` turns that into a failure, and the
marker is removed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import wrappers

from app import config as app_config
from app import lists_renewal, storage
from app.storage import TOKEN_LIST
from tests.conftest import PID
from tests.pki_helpers import make_signer


def bug(reason: str):
    return pytest.mark.xfail(strict=True, reason=reason)


def take(client, headers, expiry_date="2099-01-01"):
    r = client.post(
        "/token_status_list/take", data={"doctype": PID, "country": "FC", "expiry_date": expiry_date}, headers=headers
    )
    assert r.status_code == 200
    return r.get_json()


# ------------------------------------------------------------ requests ----


@pytest.mark.parametrize("path", ["/token_status_list/take/batch", "/token_status_list/set/batch"])
def test_deeply_nested_json_is_a_bad_request(client, headers, path):
    body = '{"refs": ' + "[" * 100_000 + "]" * 100_000 + "}"
    r = client.post(path, data=body, content_type="application/json", headers=headers)
    assert r.status_code == 400


def test_take_checks_the_api_key_before_reading_the_body(client, monkeypatch):
    def refuse(self):
        raise AssertionError("form parsed before the API key check")

    monkeypatch.setattr(wrappers.Request, "_load_form_data", refuse)
    r = client.post("/token_status_list/take", data={"doctype": PID}, headers={"X-Api-Key": "wrong"})
    assert r.status_code == 401


def test_form_bodies_are_bounded(client, headers):
    r = client.post("/token_status_list/set", data={"uri": "x" * (2 * 1024 * 1024)}, headers=headers)
    assert r.status_code == 413


def test_list_id_with_a_trailing_newline_is_rejected(client, headers):
    t = take(client, headers)
    r = client.get("/token_status_list/get", query_string={"uri": t["status_list"]["uri"] + "\n", "idx": 0})
    assert r.status_code == 400


@pytest.mark.parametrize("value", [" {i}", "+{i}", "0{i}", "{i}\n", "٣", "1_0"])
def test_index_must_be_canonical_decimal(client, headers, value):
    t = take(client, headers)
    idx = t["status_list"]["idx"]
    r = client.get("/token_status_list/get", query_string={"uri": t["status_list"]["uri"], "idx": value.format(i=idx)})
    assert r.status_code == 400


@pytest.mark.parametrize("status", [" 1", "+1", "01", "١"])
def test_status_must_be_exactly_1(client, headers, status):
    t = take(client, headers)
    data = {"uri": t["status_list"]["uri"], "idx": t["status_list"]["idx"], "status": status}
    assert client.post("/token_status_list/set", data=data, headers=headers).status_code == 400


# ------------------------------------------------------------- renewal ----


def test_list_survives_renewal_on_its_expiry_date(client, headers):
    t = take(client, headers, expiry_date=datetime.now(timezone.utc).date().isoformat())
    lists_renewal.renew_lists()
    r = client.get("/token_status_list/get", query_string=t["status_list"])
    assert r.status_code == 200


def test_deeply_nested_full_list_is_reported_as_corrupt(client, headers):
    t = take(client, headers)
    _, country, doctype, list_id = t["status_list"]["uri"].rsplit("/", 3)
    path = storage.list_dir(TOKEN_LIST, country, doctype, list_id) / storage.FULL_LIST
    path.write_text("[" * 100_000 + "]" * 100_000)
    r = client.get("/token_status_list/get", query_string=t["status_list"])
    assert r.get_json() == {"error": "List unavailable"}
    assert lists_renewal.renew_lists()["corrupt"]


# ------------------------------------------------------- configuration ----


def test_certificate_must_match_the_key(tmp_path):
    a, b = make_signer(tmp_path, "a"), make_signer(tmp_path, "b")
    with pytest.raises(RuntimeError):
        app_config.load_signer("XX", {"private_key_path": str(a.key_path), "certificate_path": str(b.cert_path)})


def test_signing_key_must_be_p256(tmp_path):
    key = ec.generate_private_key(ec.SECP384R1())
    key_path = tmp_path / "p384.pem"
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    cert = make_signer(tmp_path, "c")
    with pytest.raises(RuntimeError):
        app_config.load_signer("XX", {"private_key_path": str(key_path), "certificate_path": str(cert.cert_path)})


@pytest.mark.parametrize(
    "setting",
    [
        {"status_list_ttl": 0},  # draft-12 5.2: ttl MUST be positive
        {"status_list_ttl": "1h"},
        {"token_status_list_size": 0},
        {"batch_max_size": 0},
        {"renewal": {"hours": []}},
        {"renewal": {"hours": [25]}},
    ],
)
def test_numeric_settings_are_validated(configuration, setting):
    config = app_config.apply_defaults({**{k: v for k, v in configuration.items() if k != "countries"}, **setting})
    config["countries"] = {}
    config["countries"]["FC"] = {
        "private_key_path": configuration["countries"]["FC"]["private_key_path"],
        "certificate_path": configuration["countries"]["FC"]["certificate_path"],
    }
    with pytest.raises(RuntimeError):
        app_config.process_config(config)


def test_method_not_allowed_lists_the_allowed_methods(client, headers):
    r = client.open("/token_status_list/take", method="TRACE", headers=headers)
    assert r.status_code == 405
    assert r.headers.get("Allow")
