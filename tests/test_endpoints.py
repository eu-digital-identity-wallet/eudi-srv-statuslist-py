"""HTTP endpoints: /take, /get and /set."""

from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse

import jwt
import pytest
from flask import wrappers

from app.storage import FULL_LIST
from tests.conftest import MDL, PID

FUTURE = (date.today() + timedelta(days=365)).isoformat()
UNKNOWN_ID = "00000000-0000-0000-0000-000000000000"


def take(client, headers, doctype=PID, country="FC", expiry_date=FUTURE):
    return client.post(
        "/token_status_list/take",
        headers=headers,
        data={"doctype": doctype, "country": country, "expiry_date": expiry_date},
    )


def get(client, uri, idx=None, id=None):
    query = {"uri": uri, **({} if idx is None else {"idx": idx}), **({} if id is None else {"id": id})}
    return client.get("/token_status_list/get", query_string=query)


def is_random_id(value):
    return isinstance(value, str) and len(value) == 32 and int(value, 16) >= 0 and not value.isdigit()


def revoke(client, headers, uri, idx, status=1):
    return client.post("/token_status_list/set", headers=headers, data={"uri": uri, "idx": idx, "status": status})


class TestTake:
    def test_returns_both_list_pointers(self, client, headers):
        response = take(client, headers)
        assert response.status_code == 200
        body = response.json
        status, identifier = body["status_list"], body["identifier_list"]
        assert status["uri"].startswith(f"https://statuslist.test/token_status_list/FC/{PID}/")
        assert identifier["uri"].startswith(f"https://statuslist.test/identifier_list/FC/{PID}/")
        assert is_random_id(identifier["id"])
        assert 0 <= status["idx"] < 10000

    def test_writes_signed_lists(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        directory = configuration["status_list_dir"] + urlparse(uri).path
        assert sorted(os.listdir(directory)) == [FULL_LIST, "token_status_list.cwt", "token_status_list.jwt"]

    def test_same_list_for_same_country_and_doctype(self, client, headers):
        first = take(client, headers).json["status_list"]
        second = take(client, headers).json["status_list"]
        assert first["uri"] == second["uri"]
        assert first["idx"] != second["idx"]

    def test_other_doctype_gets_another_list(self, client, headers):
        assert take(client, headers).json["status_list"]["uri"] != take(client, headers, MDL).json["status_list"]["uri"]

    def test_list_expiry_follows_the_latest_credential(self, client, headers, configuration):
        later = (date.today() + timedelta(days=700)).isoformat()
        uri = take(client, headers).json["status_list"]["uri"]
        take(client, headers, expiry_date=later)
        take(client, headers)
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json") as f:
            assert json.load(f)["expires"] == later

    @pytest.mark.parametrize("key", [None, "wrong"])
    def test_api_key_required(self, client, key):
        response = take(client, {"X-Api-Key": key} if key else {})
        assert response.status_code == 401
        assert response.json == {"message": "Unauthorized access"}

    @pytest.mark.parametrize(
        "field,value,error",
        [
            ("doctype", "unknown.doctype", "Invalid document type"),
            ("country", "XX", "Invalid country"),
            ("expiry_date", "01-01-2030", "Invalid expiry date format. Use YYYY-MM-DD."),
            ("expiry_date", "2000-01-01", "Expiry date must be in the future."),
        ],
    )
    def test_invalid_input(self, client, headers, field, value, error):
        response = take(client, headers, **{field: value})
        assert response.status_code == 400
        assert response.json == {"error": error}

    @pytest.mark.parametrize("field", ["doctype", "country", "expiry_date"])
    def test_missing_field(self, client, headers, field):
        data = {"doctype": PID, "country": "FC", "expiry_date": FUTURE}
        del data[field]
        assert client.post("/token_status_list/take", headers=headers, data=data).status_code == 400


class TestGet:
    def test_status_and_identifier_lists(self, client, headers):
        body = take(client, headers).json
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"0"
        assert get(client, body["identifier_list"]["uri"], id=body["identifier_list"]["id"]).data == b"0"
        assert get(client, body["identifier_list"]["uri"], body["status_list"]["idx"]).data == b"0"

    @pytest.mark.parametrize("query", [{}, {"uri": "x"}, {"idx": "1"}])
    def test_missing_parameters(self, client, query):
        response = client.get("/token_status_list/get", query_string=query)
        assert response.status_code == 400
        assert response.json == {"error": "Missing URI or idx/id"}

    def test_index_not_a_number(self, client):
        assert get(client, "https://statuslist.test/token_status_list/FC/x/y", "a").status_code == 400

    def test_uri_of_another_kind(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        other = uri.replace("/token_status_list/", "/other_list/")
        directory = configuration["status_list_dir"] + urlparse(other).path
        os.makedirs(directory)
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json") as src:
            open(directory + "/full_list.json", "w").write(src.read())
        response = get(client, other, 1)
        assert response.status_code == 400
        assert response.json == {"error": "uri is not a list of this service"}

    def test_id_is_not_the_index(self, client, headers):
        body = take(client, headers).json
        assert get(client, body["status_list"]["uri"], id=body["identifier_list"]["id"]).data == b"0"
        response = get(client, body["status_list"]["uri"], id=str(body["status_list"]["idx"]))
        assert response.status_code == 404
        assert response.json == {"error": "Unknown identifier"}

    @pytest.mark.parametrize("id", ["x" * 65])
    def test_id_too_long(self, client, headers, id):
        uri = take(client, headers).json["status_list"]["uri"]
        assert get(client, uri, id=id).status_code == 400

    def test_id_and_idx_must_agree(self, client, headers):
        first, second = take(client, headers).json, take(client, headers).json
        uri, idx = first["status_list"]["uri"], first["status_list"]["idx"]
        assert get(client, uri, idx, id=first["identifier_list"]["id"]).data == b"0"
        response = get(client, uri, idx, id=second["identifier_list"]["id"])
        assert response.status_code == 400
        assert response.json == {"error": "id and idx name different entries"}

    def test_unknown_list(self, client):
        response = get(client, f"https://statuslist.test/token_status_list/FC/{PID}/{UNKNOWN_ID}", 1)
        assert response.status_code == 404
        assert response.json == {"error": "Unknown list"}

    def test_identifier_list_shows_revocations(self, client, headers):
        """Before, /get on the identifier list always answered 0."""
        body = take(client, headers).json
        revoke(client, headers, body["status_list"]["uri"], body["status_list"]["idx"])
        assert get(client, body["identifier_list"]["uri"], id=body["identifier_list"]["id"]).data == b"1"

    @pytest.mark.parametrize("idx", ["-1", "10000", str(10**12)])
    def test_index_out_of_range(self, client, headers, idx):
        uri = take(client, headers).json["status_list"]["uri"]
        response = get(client, uri, idx)
        assert response.status_code == 400
        assert response.is_json

    def test_corrupt_list(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json", "w").write("{")
        response = get(client, uri, 1)
        assert response.status_code == 500
        assert response.json == {"error": "List unavailable"}

    def test_uri_cannot_leave_status_list_dir(self, client, configuration, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / FULL_LIST).write_text(json.dumps({"token_status_list": None, "identifier_list": {"1": 1}}))
        response = get(client, "https://statuslist.test/identifier_list/../../outside", 1)
        assert response.status_code in (400, 404)


class TestPublishedLists:
    """GET <service_url>token_status_list/... and identifier_list/...: the signed lists."""

    def published(self, configuration, uri, name):
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/" + name, "rb") as f:
            return f.read()

    def test_status_list_jwt_by_default(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        response = client.get(urlparse(uri).path)
        assert response.status_code == 200
        assert response.mimetype == "application/statuslist+jwt"
        assert response.data == self.published(configuration, uri, "token_status_list.jwt")
        assert jwt.decode(response.data, options={"verify_signature": False})["sub"] == uri
        assert "Accept" in response.vary
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert response.cache_control.no_cache

    @pytest.mark.parametrize("accept", ["application/statuslist+cwt", "application/json, application/statuslist+cwt;q=0.9"])
    def test_status_list_cwt_when_accepted(self, client, headers, configuration, accept):
        uri = take(client, headers).json["status_list"]["uri"]
        response = client.get(urlparse(uri).path, headers={"Accept": accept})
        assert response.status_code == 200
        assert response.mimetype == "application/statuslist+cwt"
        assert response.data == self.published(configuration, uri, "token_status_list.cwt")
        assert "Accept" in response.vary

    def test_identifier_list_cwt(self, client, headers, configuration):
        uri = take(client, headers).json["identifier_list"]["uri"]
        response = client.get(urlparse(uri).path)
        assert response.status_code == 200
        assert response.mimetype == "application/identifierlist+cwt"
        assert response.data == self.published(configuration, uri, "identifier_list.cwt")
        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_not_modified_until_revoked(self, client, headers):
        body = take(client, headers).json["status_list"]
        path = urlparse(body["uri"]).path
        etag = client.get(path).headers["ETag"]
        assert client.get(path, headers={"If-None-Match": etag}).status_code == 304
        revoke(client, headers, body["uri"], body["idx"])
        response = client.get(path, headers={"If-None-Match": etag})
        assert response.status_code == 200
        assert response.headers["ETag"] != etag

    @pytest.mark.parametrize(
        "path",
        [
            f"/token_status_list/XX/{PID}/{UNKNOWN_ID}",
            f"/token_status_list/FC/unknown.doctype/{UNKNOWN_ID}",
            f"/token_status_list/FC/{PID}/not-a-list-id",
            f"/token_status_list/FC/{PID}/{UNKNOWN_ID}",
            f"/identifier_list/FC/{PID}/{UNKNOWN_ID}",
            f"/token_status_list/FC/{PID}/..",
            f"/token_status_list/FC/{PID}/%2E%2E",
        ],
    )
    def test_unknown_list(self, client, path):
        response = client.get(path)
        assert response.status_code == 404
        assert response.is_json

    @pytest.mark.parametrize("suffix", ["/full_list.json", "/token_status_list.jwt", "/%2Ffull_list.json"])
    def test_only_the_signed_list_is_served(self, client, headers, suffix):
        path = urlparse(take(client, headers).json["status_list"]["uri"]).path
        assert client.get(path + suffix).status_code == 404

    def test_state_is_not_served(self, client, headers):
        take(client, headers)
        assert client.get(f"/token_status_list/state/FC/{PID}").status_code == 404
        assert client.get(f"/token_status_list/../state/FC/{PID}/current.json").status_code == 404


class TestSet:
    def test_revokes(self, client, headers, configuration):
        body = take(client, headers).json
        uri, idx = body["status_list"]["uri"], body["status_list"]["idx"]
        response = revoke(client, headers, uri, idx)
        assert response.status_code == 200
        assert response.data == b"Status Changed\n"
        assert get(client, uri, idx).data == b"1"
        assert get(client, body["identifier_list"]["uri"], idx).data == b"1"

    def test_revocation_survives_the_next_take(self, client, headers):
        body = take(client, headers).json
        uri, idx = body["status_list"]["uri"], body["status_list"]["idx"]
        revoke(client, headers, uri, idx)
        take(client, headers)
        assert get(client, uri, idx).data == b"1"

    def test_api_key_required(self, client):
        response = revoke(client, {"X-Api-Key": "wrong"}, "u", 1)
        assert response.status_code == 401
        assert response.json == {"message": "Unauthorized access"}

    @pytest.mark.parametrize(
        "idx,status,error",
        [
            ("a", 1, "'idx' must be a non-negative integer"),
            (1, "x", "Wrong Status Change"),
            (1, 0, "Wrong Status Change"),
            (1, 2, "Wrong Status Change"),
        ],
    )
    def test_invalid_input(self, client, headers, idx, status, error):
        response = revoke(client, headers, "https://statuslist.test/token_status_list/FC/x/y", idx, status)
        assert response.status_code == 400
        assert response.json == {"error": error}

    @pytest.mark.parametrize("field", ["uri", "status"])
    def test_missing_field(self, client, headers, field):
        data = {"uri": "u", "idx": 1, "status": 1}
        del data[field]
        assert client.post("/token_status_list/set", headers=headers, data=data).status_code == 400

    def test_missing_index(self, client, headers):
        response = client.post("/token_status_list/set", headers=headers, data={"uri": "u", "status": 1})
        assert response.status_code == 400
        assert response.json == {"error": "Missing URI/index/status"}

    @pytest.mark.parametrize("part,error", [(2, "Invalid country"), (3, "Invalid document type")])
    def test_uri_with_unknown_country_or_doctype(self, client, headers, configuration, part, error):
        uri = take(client, headers).json["status_list"]["uri"]
        path = urlparse(uri).path.split("/")
        path[part] = "XX"
        bad = "https://statuslist.test" + "/".join(path)
        os.makedirs(configuration["status_list_dir"] + "/".join(path))
        with open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json") as src:
            open(configuration["status_list_dir"] + "/".join(path) + "/full_list.json", "w").write(src.read())
        response = revoke(client, headers, bad, 1)
        assert response.status_code == 400
        assert response.json == {"error": error}

    def test_takes_after_a_revocation(self, client, headers):
        """issue 1: the second take after a revocation failed with a 500."""
        body = take(client, headers).json
        revoke(client, headers, body["status_list"]["uri"], body["status_list"]["idx"])
        assert take(client, headers).status_code == 200
        assert take(client, headers).status_code == 200


class TestSetValidation:
    """issues 6, 12 and 13."""

    @pytest.mark.parametrize("idx", ["-1", "10000", str(10**12)])
    def test_index_out_of_range(self, client, headers, idx):
        body = take(client, headers).json
        uri = body["status_list"]["uri"]
        response = revoke(client, headers, uri, idx)
        assert response.status_code == 400
        assert response.is_json
        assert get(client, uri, 9999).data == b"0"  # -1 used to revoke the last entry

    @pytest.mark.parametrize(
        "make_uri",
        [
            lambda uri: uri.replace("https://statuslist.test", "https://other.host"),
            lambda uri: urlparse(uri).path,
            lambda uri: uri + "/",
            lambda uri: uri + "?x=1",
            lambda uri: uri.rsplit("/", 1)[0] + "/../../../../x",
            lambda uri: uri.rsplit("/", 1)[0] + "/not-a-list-id",
            lambda uri: uri.replace("/token_status_list/", "/token_status_list/FC/"),
        ],
    )
    def test_uri_must_be_a_list_of_this_service(self, client, headers, make_uri):
        body = take(client, headers).json
        bad = make_uri(body["status_list"]["uri"])
        response = revoke(client, headers, bad, body["status_list"]["idx"])
        assert response.status_code == 400
        assert response.json == {"error": "uri is not a list of this service"}
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"0"

    def test_unknown_list(self, client, headers):
        response = revoke(client, headers, f"https://statuslist.test/token_status_list/FC/{PID}/{UNKNOWN_ID}", 1)
        assert response.status_code == 404

    def test_corrupt_list(self, client, headers, configuration):
        uri = take(client, headers).json["status_list"]["uri"]
        open(configuration["status_list_dir"] + urlparse(uri).path + "/full_list.json", "w").write("{")
        assert revoke(client, headers, uri, 1).status_code == 500

    def test_identifier_list_uri_revokes_the_same_entry(self, client, headers):
        body = take(client, headers).json
        response = client.post(
            "/token_status_list/set",
            headers=headers,
            data={"uri": body["identifier_list"]["uri"], "id": body["identifier_list"]["id"], "status": 1},
        )
        assert response.status_code == 200
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"1"

    def test_by_identifier(self, client, headers):
        body = take(client, headers).json
        data = {"uri": body["identifier_list"]["uri"], "id": body["identifier_list"]["id"], "status": 1}
        assert client.post("/token_status_list/set", headers=headers, data=data).status_code == 200
        assert get(client, body["status_list"]["uri"], body["status_list"]["idx"]).data == b"1"

    def test_index_with_the_identifier_list_uri(self, client, headers):
        body = take(client, headers).json
        assert revoke(client, headers, body["identifier_list"]["uri"], body["status_list"]["idx"]).status_code == 200
        assert get(client, body["identifier_list"]["uri"], id=body["identifier_list"]["id"]).data == b"1"

    def test_id_and_idx_must_agree(self, client, headers):
        first, second = take(client, headers).json, take(client, headers).json
        data = {"uri": first["status_list"]["uri"], "idx": first["status_list"]["idx"],
                "id": second["identifier_list"]["id"], "status": 1}
        response = client.post("/token_status_list/set", headers=headers, data=data)
        assert response.status_code == 400
        assert response.json == {"error": "id and idx name different entries"}
        data["id"] = first["identifier_list"]["id"]
        assert client.post("/token_status_list/set", headers=headers, data=data).status_code == 200
        assert get(client, second["status_list"]["uri"], second["status_list"]["idx"]).data == b"0"

    def test_unknown_identifier(self, client, headers):
        body = take(client, headers).json
        data = {"uri": body["identifier_list"]["uri"], "id": str(body["status_list"]["idx"]), "status": 1}
        response = client.post("/token_status_list/set", headers=headers, data=data)
        assert response.status_code == 404
        assert response.json == {"error": "Unknown identifier"}

    def test_untaken_entry(self, client, headers, configuration):
        configuration["token_status_list_size"] = 8
        body = take(client, headers).json["status_list"]
        free = next(i for i in range(8) if i != body["idx"])
        response = revoke(client, headers, body["uri"], free)
        assert response.status_code == 404
        assert response.json == {"error": "Unknown entry"}

    def test_revoking_twice(self, client, headers):
        body = take(client, headers).json
        uri, idx = body["status_list"]["uri"], body["status_list"]["idx"]
        assert revoke(client, headers, uri, idx).status_code == 200
        assert revoke(client, headers, uri, idx).status_code == 200


def take_batch(client, headers, count=3, **fields):
    body = {"doctype": PID, "country": "FC", "expiry_date": FUTURE, "count": count, **fields}
    return client.post("/token_status_list/take/batch", headers=headers, json=body)


def revoke_batch(client, headers, refs):
    return client.post("/token_status_list/set/batch", headers=headers, json={"refs": refs})


class TestTakeBatch:
    def test_returns_take_items(self, client, headers):
        response = take_batch(client, headers, 3)
        assert response.status_code == 200
        items = response.json["items"]
        assert len(items) == 3
        assert len({item["status_list"]["idx"] for item in items}) == 3
        single = take(client, headers).json
        for item in items:
            assert item.keys() == single.keys()
            assert item["status_list"]["uri"] == single["status_list"]["uri"]
            assert is_random_id(item["identifier_list"]["id"])

    def test_spans_a_rollover_and_publishes_the_new_list(self, client, headers, configuration):
        configuration["token_status_list_size"] = 8
        items = take_batch(client, headers, 12).json["items"]
        uris = list(dict.fromkeys(item["status_list"]["uri"] for item in items))
        assert len(uris) == 2
        assert len({(item["status_list"]["uri"], item["status_list"]["idx"]) for item in items}) == 12
        for uri in uris:
            assert "token_status_list.jwt" in os.listdir(configuration["status_list_dir"] + urlparse(uri).path)

    @pytest.mark.parametrize("key", [None, "wrong"])
    def test_api_key_required(self, client, key):
        response = take_batch(client, {"X-Api-Key": key} if key else {})
        assert response.status_code == 401
        assert response.json == {"message": "Unauthorized access"}

    @pytest.mark.parametrize(
        "fields,error",
        [
            ({"doctype": "unknown.doctype"}, "Invalid document type"),
            ({"country": ["FC"]}, "Missing country"),
            ({"expiry_date": "2000-01-01"}, "Expiry date must be in the future."),
            ({"count": 0}, "count must be at least 1"),
            ({"count": "3"}, "count must be an integer"),
            ({"count": True}, "count must be an integer"),
        ],
    )
    def test_invalid_input(self, client, headers, configuration, fields, error):
        response = take_batch(client, headers, **fields)
        assert response.status_code == 400
        assert response.json == {"error": error}
        assert not os.path.exists(configuration["status_list_dir"])

    def test_over_the_cap(self, client, headers, configuration):
        configuration["batch_max_size"] = 5
        assert take_batch(client, headers, 5).status_code == 200
        response = take_batch(client, headers, 6)
        assert response.status_code == 413
        assert response.json == {"error": "count must be at most 5"}

    def test_json_required(self, client, headers):
        response = client.post(
            "/token_status_list/take/batch",
            headers=headers,
            data={"doctype": PID, "country": "FC", "expiry_date": FUTURE, "count": 1},
        )
        assert response.status_code == 400
        assert response.json == {"error": "Content-Type must be application/json"}

    @pytest.mark.parametrize("body", ["[1]", "{", "null"])
    def test_body_must_be_an_object(self, client, headers, body):
        response = client.post(
            "/token_status_list/take/batch", headers=headers, data=body, content_type="application/json"
        )
        assert response.status_code == 400
        assert response.json == {"error": "body must be a JSON object"}


class TestSetBatch:
    def test_revokes_every_ref(self, client, headers):
        items = take_batch(client, headers, 3).json["items"] + take_batch(client, headers, 1, doctype=MDL).json["items"]
        refs = [{"uri": item["status_list"]["uri"], "idx": item["status_list"]["idx"]} for item in items]
        response = revoke_batch(client, headers, refs)
        assert response.status_code == 200
        assert response.json == {"revoked": 4}
        for item in items:
            assert get(client, item["status_list"]["uri"], item["status_list"]["idx"]).data == b"1"
            assert get(client, item["identifier_list"]["uri"], id=item["identifier_list"]["id"]).data == b"1"

    def test_same_entry_through_both_uris_counts_once(self, client, headers):
        item = take(client, headers).json
        refs = [
            {"uri": item["status_list"]["uri"], "idx": item["status_list"]["idx"]},
            {"uri": item["identifier_list"]["uri"], "id": item["identifier_list"]["id"]},
            {"uri": item["status_list"]["uri"], "idx": str(item["status_list"]["idx"])},
        ]
        assert revoke_batch(client, headers, refs).json == {"revoked": 1}

    def test_idx_zero(self, client, headers, configuration):
        configuration["token_status_list_size"] = 8
        uri = take_batch(client, headers, 8).json["items"][0]["status_list"]["uri"]
        assert revoke_batch(client, headers, [{"uri": uri, "idx": 0}]).status_code == 200
        assert get(client, uri, 0).data == b"1"
        assert get(client, uri, 5).data == b"0"

    def test_by_id_and_by_both(self, client, headers):
        first, second = take_batch(client, headers, 2).json["items"]
        refs = [
            {"uri": first["identifier_list"]["uri"], "id": first["identifier_list"]["id"]},
            {"uri": second["status_list"]["uri"], "idx": second["status_list"]["idx"], "id": second["identifier_list"]["id"]},
        ]
        assert revoke_batch(client, headers, refs).json == {"revoked": 2}
        for item in (first, second):
            assert get(client, item["status_list"]["uri"], item["status_list"]["idx"]).data == b"1"

    def test_already_revoked(self, client, headers):
        item = take(client, headers).json["status_list"]
        revoke(client, headers, item["uri"], item["idx"])
        assert revoke_batch(client, headers, [item]).json == {"revoked": 1}

    @pytest.mark.parametrize("key", [None, "wrong"])
    def test_api_key_required(self, client, key):
        response = revoke_batch(client, {"X-Api-Key": key} if key else {}, [])
        assert response.status_code == 401
        assert response.json == {"message": "Unauthorized access"}

    @pytest.mark.parametrize(
        "bad,status,error",
        [
            ({"uri": None, "idx": 1}, 400, "refs[1]: Missing URI or idx/id"),
            ("x", 400, "refs[1]: must be an object with 'uri' and 'idx' or 'id'"),
            ({"uri": "https://other.host/x", "idx": 1}, 400, "refs[1]: uri is not a list of this service"),
            ({"idx": 1.5}, 400, "refs[1]: 'idx' must be a non-negative integer"),
            ({"idx": -1}, 400, "refs[1]: 'idx' must be a non-negative integer"),
            ({"idx": 10000}, 400, "refs[1]: index must be between 0 and 9999"),
            ({"uri": f"https://statuslist.test/token_status_list/FC/{PID}/{UNKNOWN_ID}", "idx": 1}, 404, "refs[1]: Unknown list"),
            ({"id": "f" * 32}, 404, "refs[1]: Unknown identifier"),
            ({"id": 5}, 400, "refs[1]: 'id' must be a string of 1 to 64 characters"),
            ({"id": ""}, 400, "refs[1]: 'id' must be a string of 1 to 64 characters"),
        ],
    )
    def test_one_bad_ref_revokes_nothing(self, client, headers, bad, status, error):
        item = take(client, headers).json["status_list"]
        if isinstance(bad, dict):
            bad = {"uri": item["uri"], **bad}
        response = revoke_batch(client, headers, [item, bad])
        assert response.status_code == status
        assert response.json == {"error": error}
        assert get(client, item["uri"], item["idx"]).data == b"0"

    def test_conflicting_and_untaken_refs(self, client, headers, configuration):
        configuration["token_status_list_size"] = 8
        first, second = take_batch(client, headers, 2).json["items"]
        uri = first["status_list"]["uri"]
        conflict = {"uri": uri, "idx": first["status_list"]["idx"], "id": second["identifier_list"]["id"]}
        response = revoke_batch(client, headers, [first["status_list"], conflict])
        assert response.status_code == 400
        assert response.json == {"error": "refs[1]: id and idx name different entries"}
        taken = {first["status_list"]["idx"], second["status_list"]["idx"]}
        free = next(i for i in range(8) if i not in taken)
        response = revoke_batch(client, headers, [first["status_list"], {"uri": uri, "idx": free}])
        assert response.status_code == 404
        assert response.json == {"error": "refs[1]: Unknown entry"}
        assert get(client, uri, first["status_list"]["idx"]).data == b"0"

    def test_corrupt_list(self, client, headers, configuration):
        good = take(client, headers).json["status_list"]
        bad = take(client, headers, MDL).json["status_list"]
        open(configuration["status_list_dir"] + urlparse(bad["uri"]).path + "/full_list.json", "w").write("{")
        response = revoke_batch(client, headers, [good, bad])
        assert response.status_code == 500
        assert response.json == {"error": "refs[1]: List unavailable"}
        assert get(client, good["uri"], good["idx"]).data == b"0"

    @pytest.mark.parametrize("refs,error", [([], "refs must be at least 1"), ({}, "refs must be a list")])
    def test_refs_must_be_a_non_empty_list(self, client, headers, refs, error):
        response = revoke_batch(client, headers, refs)
        assert response.status_code == 400
        assert response.json == {"error": error}

    def test_over_the_cap(self, client, headers, configuration):
        configuration["batch_max_size"] = 2
        item = take(client, headers).json["status_list"]
        assert revoke_batch(client, headers, [item] * 2).status_code == 200
        response = revoke_batch(client, headers, [item] * 3)
        assert response.status_code == 413
        assert response.json == {"error": "refs must be at most 2"}

    def test_body_over_one_mebibyte(self, client, headers):
        response = revoke_batch(client, headers, ["x" * 1024 * 1024])
        assert response.status_code == 413
        assert response.is_json

    def test_json_required(self, client, headers):
        response = client.post("/token_status_list/set/batch", headers=headers, data={"refs": "x"})
        assert response.status_code == 400
        assert response.json == {"error": "Content-Type must be application/json"}


class TestErrors:
    def test_unknown_route_is_json(self, client):
        response = client.get("/token_status_list/nothing")
        assert response.status_code == 404
        assert response.is_json

    def test_unhandled_error_is_json(self, client, headers, monkeypatch):
        from app import list_management

        def boom(*_):
            raise RuntimeError("boom")

        monkeypatch.setattr(list_management, "take", boom)
        response = take(client, headers)
        assert response.status_code == 500
        assert response.json == {"error": "Internal server error"}


class TestRequests:
    @pytest.mark.parametrize("path", ["/token_status_list/take", "/token_status_list/take/batch", "/token_status_list/set", "/token_status_list/set/batch"])
    def test_failed_api_key_is_logged(self, client, path, caplog):
        response = client.post(path, headers={"X-Api-Key": "wrong"})
        assert response.status_code == 401
        assert response.json == {"message": "Unauthorized access"}
        assert f"Unauthorized access: POST {path}" in caplog.text

    def test_plain_text_bodies(self, client, headers):
        body = take(client, headers).json["status_list"]
        response = get(client, body["uri"], body["idx"])
        assert (response.mimetype, response.data) == ("text/plain", b"0")
        response = revoke(client, headers, body["uri"], body["idx"])
        assert (response.mimetype, response.data) == ("text/plain", b"Status Changed\n")

    def test_every_body_is_bounded(self, client, headers):
        data = {"doctype": PID, "country": "FC", "expiry_date": FUTURE, "x": "x" * (1024 * 1024)}
        assert client.post("/token_status_list/take", headers=headers, data=data).status_code == 413

    def test_percent_encoded_uri_is_rejected(self, client, headers):
        body = take(client, headers).json["status_list"]
        encoded = body["uri"].replace("/FC/", "/F%43/")
        response = get(client, encoded, body["idx"])
        assert response.status_code == 400
        assert get(client, body["uri"], body["idx"]).status_code == 200

    def test_expiry_date_up_to_max_expiry_days(self, client, headers, configuration):
        configuration["max_expiry_days"] = 30
        today = datetime.now(timezone.utc).date()
        assert take(client, headers, expiry_date=today.isoformat()).status_code == 200
        assert take(client, headers, expiry_date=(today + timedelta(days=30)).isoformat()).status_code == 200
        response = take(client, headers, expiry_date=(today + timedelta(days=31)).isoformat())
        assert response.status_code == 400
        assert response.json == {"error": "Expiry date must be at most 30 days from today."}
        assert take(client, headers, expiry_date=(today - timedelta(days=1)).isoformat()).status_code == 400

    @pytest.mark.parametrize("path", ["/token_status_list/take", "/token_status_list/set"])
    def test_malformed_form_body_is_a_bad_request(self, client, headers, monkeypatch, path):
        def broken(self):
            raise OSError("Invalid chunk header")

        monkeypatch.setattr(wrappers.Request, "_load_form_data", broken)
        response = client.post(path, headers=headers, data={"uri": "u"})
        assert response.status_code == 400
        assert response.json == {"error": "Malformed request body"}

    @pytest.mark.parametrize("path", ["/token_status_list/take/batch", "/token_status_list/set/batch"])
    def test_malformed_json_body_is_a_bad_request(self, client, headers, monkeypatch, path):
        def broken(self, *args, **kwargs):
            raise OSError("Invalid chunk header")

        monkeypatch.setattr(wrappers.Request, "get_data", broken)
        response = client.post(path, headers=headers, json={"refs": []})
        assert response.status_code == 400
        assert response.json == {"error": "Malformed request body"}
