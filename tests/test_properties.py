"""Property-based tests (Hypothesis): parsers, encodings and the API as a whole.

The stateful test drives ``/take``, ``/take/batch``, ``/set``, ``/set/batch``,
``/get`` and renewals in random order against an in-memory model, with
16-entry lists so that rollovers happen, and checks the signed files after
every step.
"""

from __future__ import annotations

import base64
import os
import tempfile
import zlib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, invariant, multiple, rule

from app import config as app_config
from app import lists_renewal, storage
from app.config import _substitute, resolve_variables
from app.status_list import BitArray, IssuerStatusList, NoMoreIndices
from app.status_list_endpoints import BadRequest, parse_index, parse_list_uri
from app.storage import IDENTIFIER_LIST, LIST_KINDS, TOKEN_LIST
from tests import strict
from tests.conftest import MDL, PID
from tests.config_helpers import set_configuration
from tests.pki_helpers import make_signer

# HYPOTHESIS_PROFILE=hunt runs ten times more examples (a long bug hunt, not CI).
settings.register_profile("hunt", max_examples=1000)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
HUNT = os.environ.get("HYPOTHESIS_PROFILE") == "hunt"

FIXTURE_OK = settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)

list_ids = st.uuids().map(str)


def countries(config):
    return st.sampled_from(sorted(config["countries"]))


def doctypes(config):
    return st.sampled_from(config["allowed_doctypes"])


# ------------------------------------------------------------- parsers ----


@FIXTURE_OK
@given(text=st.text())
def test_parse_index_accepts_only_non_negative_integers(text):
    try:
        index = parse_index(text)
    except BadRequest:
        return
    assert index >= 0


@FIXTURE_OK
@given(data=st.data(), kind=st.sampled_from(LIST_KINDS), list_id=list_ids)
def test_list_uris_round_trip(configuration, data, kind, list_id):
    country, doctype = data.draw(countries(configuration)), data.draw(doctypes(configuration))
    assert parse_list_uri(storage.list_uri(kind, country, doctype, list_id)) == (kind, country, doctype, list_id)


uri_noise = st.text(st.sampled_from("/.%2e2f5cAa0-:+?#\\\x00\n "), max_size=12)


@FIXTURE_OK
@given(data=st.data(), kind=st.sampled_from(LIST_KINDS), list_id=list_ids, noise=uri_noise, where=st.integers(0, 4))
def test_mangled_uris_never_leave_status_list_dir(configuration, data, kind, list_id, noise, where):
    country, doctype = data.draw(countries(configuration)), data.draw(doctypes(configuration))
    parts = [kind, country, doctype, list_id]
    parts.insert(where, noise)
    uri = configuration["service_url"] + "/".join(parts)
    try:
        kind2, country2, doctype2, list_id2 = parse_list_uri(uri)
    except BadRequest:
        return
    assert kind2 in LIST_KINDS
    assert country2 in configuration["countries"]
    assert doctype2 in configuration["allowed_doctypes"]
    base = storage.base_dir().resolve()
    assert base in storage.list_dir(kind2, country2, doctype2, list_id2).resolve().parents


@FIXTURE_OK
@given(text=st.text())
def test_any_text_is_rejected_or_names_a_list(configuration, text):
    try:
        kind, country, doctype, _ = parse_list_uri(configuration["service_url"] + text)
    except BadRequest:
        return
    assert kind in LIST_KINDS and country in configuration["countries"] and doctype in configuration["allowed_doctypes"]


# ------------------------------------------------------- configuration ----

names = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,8}", fullmatch=True)
plain = st.text(alphabet=st.characters(blacklist_characters="$"), max_size=20)


@given(text=plain)
def test_text_without_placeholders_is_unchanged(text):
    assert _substitute(text, {}) == text


@given(variables=st.dictionaries(names, plain, min_size=1, max_size=5), data=st.data())
def test_placeholders_are_replaced_by_their_variables(variables, data):
    name = data.draw(st.sampled_from(sorted(variables)))
    prefix, suffix = data.draw(plain), data.draw(plain)
    config = {"variables": variables, "value": f"{prefix}${{{name}}}{suffix}"}
    assert resolve_variables(config) == {"value": prefix + variables[name] + suffix}


@given(name=names, text=plain)
def test_undefined_placeholder_is_an_error(name, text):
    with pytest.raises(RuntimeError, match="Undefined config variable"):
        _substitute(f"{text}${{{name}}}", {})


# ----------------------------------------------------------- encodings ----


@given(
    bits=st.sampled_from([1, 2, 4, 8]),
    size=st.integers(1, 300),
    ops=st.lists(st.tuples(st.integers(0, 10**6), st.integers(0, 255)), max_size=50),
)
def test_bit_array_matches_a_model_and_survives_a_dump(bits, size, ops):
    array = BitArray.with_at_least(bits, size)
    model = [0] * array.size
    for index, status in ops:
        index %= array.size
        status &= (1 << bits) - 1
        array.set(index, status)
        model[index] = status
    loaded = BitArray.load(array.dump())
    assert [loaded.get(i) for i in range(array.size)] == model
    # Every entry is in its draft position (section 4: least significant bits first).
    raw = zlib.decompress(base64.urlsafe_b64decode(array.dump()["lst"] + "=="))
    assert [(raw[i * bits // 8] >> (i * bits % 8)) & ((1 << bits) - 1) for i in range(array.size)] == model


@given(size=st.integers(1, 100), takes=st.integers(0, 100))
def test_allocator_never_repeats_or_leaves_the_list(size, takes):
    status_list = IssuerStatusList.new(1, size)
    taken = []
    for _ in range(takes):
        try:
            taken.append(status_list.allocator.take())
        except NoMoreIndices:
            break
        status_list = IssuerStatusList.load(status_list.dump())
    assert len(set(taken)) == len(taken)
    assert all(0 <= index < status_list.status_list.size for index in taken)
    assert len(taken) == min(takes, status_list.status_list.size)


# ------------------------------------------------------------ the API ----

_SIGNER_DIR = Path(tempfile.mkdtemp(prefix="statuslist-properties-"))
_SIGNER = make_signer(_SIGNER_DIR, "machine")
API_KEY = "m" * 40
H = {"X-Api-Key": API_KEY}
EXPIRY = "2099-01-01"


class ApiMachine(RuleBasedStateMachine):
    """The whole API against a model: which entries are taken and which are revoked."""

    taken = Bundle("taken")

    def __init__(self):
        super().__init__()
        self.dir = Path(tempfile.mkdtemp(prefix="statuslist-machine-"))
        config = app_config.apply_defaults(
            {
                "service_url": "https://statuslist.test",
                "api_key": API_KEY,
                "token_status_list_size": 16,
                "batch_max_size": 40,
                "max_expiry_days": 36500,
                "status_list_dir": str(self.dir / "lists"),
                "backup_dir": str(self.dir / "backup"),
                "logging": {"path": str(self.dir / "log" / "sl.log"), "log_level": "ERROR"},
                "countries": {
                    cc: {"private_key_path": str(_SIGNER.key_path), "certificate_path": str(_SIGNER.cert_path)}
                    for cc in ("FC", "LU")
                },
            }
        )
        app_config.process_config(config)
        self.monkeypatch = pytest.MonkeyPatch()
        set_configuration(self.monkeypatch, config)
        self.monkeypatch.setattr(app_config, "IS_TEST_ENV", True)
        from app import create_app

        self.client = create_app().test_client()
        # (token uri, idx) -> {"id", "identifier_uri", "revoked"}
        self.model: dict[tuple[str, int], dict] = {}

    def teardown(self):
        self.monkeypatch.undo()

    def _record(self, item):
        key = (item["status_list"]["uri"], item["status_list"]["idx"])
        assert key not in self.model, f"index handed out twice: {key}"
        assert item["status_list"]["uri"].rsplit("/", 1)[1] == item["identifier_list"]["uri"].rsplit("/", 1)[1]
        self.model[key] = {"id": item["identifier_list"]["id"], "identifier_uri": item["identifier_list"]["uri"], "revoked": False}
        return key

    @rule(target=taken, country=st.sampled_from(["FC", "LU"]), doctype=st.sampled_from([PID, MDL]))
    def take(self, country, doctype):
        r = self.client.post(
            "/token_status_list/take", data={"doctype": doctype, "country": country, "expiry_date": EXPIRY}, headers=H
        )
        assert r.status_code == 200, r.get_data(as_text=True)
        return self._record(r.get_json())

    @rule(target=taken, country=st.sampled_from(["FC", "LU"]), doctype=st.sampled_from([PID, MDL]), count=st.integers(1, 40))
    def take_batch(self, country, doctype, count):
        body = {"doctype": doctype, "country": country, "expiry_date": EXPIRY, "count": count}
        r = self.client.post("/token_status_list/take/batch", json=body, headers=H)
        assert r.status_code == 200, r.get_data(as_text=True)
        items = r.get_json()["items"]
        assert len(items) == count
        return multiple(*(self._record(item) for item in items))

    def _ref(self, key, how, via_identifier):
        uri, idx = key
        entry = self.model[key]
        ref = {"uri": entry["identifier_uri"] if via_identifier else uri}
        if how in ("idx", "both"):
            ref["idx"] = idx
        if how in ("id", "both"):
            ref["id"] = entry["id"]
        return ref

    @rule(key=taken, how=st.sampled_from(["idx", "id", "both"]), via_identifier=st.booleans())
    def revoke(self, key, how, via_identifier):
        ref = self._ref(key, how, via_identifier)
        r = self.client.post("/token_status_list/set", data={**ref, "status": "1"}, headers=H)
        assert r.status_code == 200, r.get_data(as_text=True)
        self.model[key]["revoked"] = True

    @rule(keys=st.lists(taken, min_size=1, max_size=10), how=st.sampled_from(["idx", "id", "both"]), via_identifier=st.booleans())
    def revoke_batch(self, keys, how, via_identifier):
        r = self.client.post(
            "/token_status_list/set/batch", json={"refs": [self._ref(k, how, via_identifier) for k in keys]}, headers=H
        )
        assert r.status_code == 200, r.get_data(as_text=True)
        assert r.get_json()["revoked"] == len(set(keys))
        for k in keys:
            self.model[k]["revoked"] = True

    @rule(keys=st.lists(taken, min_size=1, max_size=5), bad=st.sampled_from(["unknown_id", "unknown_list", "conflict"]))
    def revoke_batch_with_a_bad_ref(self, keys, bad):
        refs = [self._ref(k, "idx", False) for k in keys]
        uri, idx = keys[0]
        if bad == "unknown_id":
            refs.append({"uri": uri, "id": "f" * 32})
        elif bad == "unknown_list":
            refs.append({"uri": uri.rsplit("/", 1)[0] + "/00000000-0000-4000-8000-000000000000", "idx": 0})
        else:
            other = next((k for k in self.model if k[0] == uri and k[1] != idx), None)
            assume(other is not None)
            refs.append({"uri": uri, "idx": idx, "id": self.model[other]["id"]})
        r = self.client.post("/token_status_list/set/batch", json={"refs": refs}, headers=H)
        assert r.status_code in (400, 404), r.get_data(as_text=True)
        assert r.get_json()["error"].startswith(f"refs[{len(refs) - 1}]")

    @rule(key=taken, how=st.sampled_from(["idx", "id", "both"]), via_identifier=st.booleans())
    def get(self, key, how, via_identifier):
        ref = self._ref(key, how, via_identifier)
        r = self.client.get("/token_status_list/get", query_string=ref)
        assert r.status_code == 200, r.get_data(as_text=True)
        assert r.get_data(as_text=True) == ("1" if self.model[key]["revoked"] else "0")

    @rule()
    def renew(self):
        report = lists_renewal.renew_lists()
        assert not report["corrupt"] and not report["failed"] and not report["removed"]

    @invariant()
    def published_lists_match_the_model(self):
        by_list: dict[str, list] = {}
        for (uri, idx), entry in self.model.items():
            by_list.setdefault(uri, []).append((idx, entry))
        for uri, entries in by_list.items():
            _, country, doctype, list_id = parse_list_uri(uri)
            token_dir = storage.list_dir(TOKEN_LIST, country, doctype, list_id)
            identifier_dir = storage.list_dir(IDENTIFIER_LIST, country, doctype, list_id)
            claims = strict.check_list_files(token_dir, identifier_dir)
            assert claims["sub"] == uri
            lst = base64.urlsafe_b64decode(claims["status_list"]["lst"] + "==")
            for idx, entry in entries:
                assert strict.status_bit(lst, idx) == int(entry["revoked"]), (uri, idx)
            _, identifier_claims = strict.verify_cwt((identifier_dir / "identifier_list.cwt").read_bytes())
            listed = {key.decode() for key in identifier_claims[65530]["identifiers"]}
            assert listed == {entry["id"] for _, entry in entries if entry["revoked"]}


ApiMachine.TestCase.settings = settings(
    max_examples=600 if HUNT else 60, stateful_step_count=25, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
TestApi = ApiMachine.TestCase
