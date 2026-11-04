"""List renewal (app/lists_renewal.py) and the renew-lists command."""

from __future__ import annotations

import json
import os
from datetime import datetime

import pytest

from app import list_management as lm
from app import lists_renewal, storage
from app.storage import FULL_LIST, IDENTIFIER_LIST, TOKEN_LIST
from tests.conftest import MDL, PID
from tests.strict import check_list_files, jwt_status


def make_list(expires="2099-01-01", doctype=PID):
    info = lm.take("FC", doctype, expires)
    list_id = info["status_list"]["uri"].rsplit("/", 1)[1]
    return list_id, info["status_list"]["idx"]


def dirs(list_id, doctype=PID):
    return storage.list_dir(TOKEN_LIST, "FC", doctype, list_id), storage.list_dir(IDENTIFIER_LIST, "FC", doctype, list_id)


def expire(list_id):
    for d in dirs(list_id):
        path = d / FULL_LIST
        data = json.loads(path.read_text())
        data["expires"] = "2000-01-01"
        path.write_text(json.dumps(data))


class TestNextRenewal:
    @pytest.mark.parametrize(
        "now,expected",
        [
            (datetime(2026, 1, 1, 8, 30), datetime(2026, 1, 1, 12, 0)),
            (datetime(2026, 1, 1, 12, 0), datetime(2026, 1, 2, 0, 0)),
            (datetime(2026, 1, 1, 23, 59), datetime(2026, 1, 2, 0, 0)),
            (datetime(2026, 12, 31, 13, 0), datetime(2027, 1, 1, 0, 0)),
        ],
    )
    def test_default_hours(self, now, expected):
        assert lists_renewal.next_renewal(now) == expected

    def test_configured_hours(self, configuration):
        configuration["renewal"]["hours"] = [18, 6, 6]
        assert lists_renewal.next_renewal(datetime(2026, 1, 1, 7)) == datetime(2026, 1, 1, 18)
        assert lists_renewal.next_renewal(datetime(2026, 1, 1, 19)) == datetime(2026, 1, 2, 6)

    def test_errors_do_not_stop_the_renewal_thread(self, monkeypatch, caplog):
        class Stop(BaseException):
            pass

        def broken(now):
            raise RuntimeError("boom")

        def sleep(seconds):
            assert seconds == 60
            raise Stop

        monkeypatch.setattr(lists_renewal, "next_renewal", broken)
        monkeypatch.setattr(lists_renewal.time, "sleep", sleep)
        with pytest.raises(Stop):
            lists_renewal.daily_renewal()
        assert "List renewal failed" in caplog.text

    def test_no_hours(self, configuration):
        configuration["renewal"]["hours"] = []
        with pytest.raises(RuntimeError, match="renewal.hours"):
            lists_renewal.next_renewal(datetime(2026, 1, 1))


class TestRenewLists:
    def test_resigns_and_backs_up_both_lists(self, configuration):
        list_id, idx = make_list()
        lm.revoke("FC", PID, list_id, idx)
        token_dir, identifier_dir = dirs(list_id)
        old_jwt = (token_dir / "token_status_list.jwt").read_text()

        report = lists_renewal.renew_lists()

        assert report == {"renewed": [f"FC/{PID}/{list_id}"], "removed": [], "corrupt": [], "failed": []}
        assert (token_dir / "token_status_list.jwt").read_text() != old_jwt  # new ECDSA signature
        check_list_files(token_dir, identifier_dir)
        assert jwt_status(token_dir, idx) == 1
        (stamp,) = os.listdir(configuration["backup_dir"])
        backup = os.path.join(configuration["backup_dir"], stamp)
        assert sorted(os.listdir(os.path.join(backup, TOKEN_LIST, "FC", PID, list_id))) == [
            FULL_LIST, "token_status_list.cwt", "token_status_list.jwt"]
        assert sorted(os.listdir(os.path.join(backup, IDENTIFIER_LIST, "FC", PID, list_id))) == [
            FULL_LIST, "identifier_list.cwt"]
        assert open(os.path.join(backup, TOKEN_LIST, "FC", PID, list_id, "token_status_list.jwt")).read() == old_jwt

    def test_list_with_one_index_is_renewed(self):
        """issue 4: such lists were skipped ("Uris don't exist")."""
        list_id, _ = make_list()
        assert lists_renewal.renew_lists()["renewed"] == [f"FC/{PID}/{list_id}"]

    def test_renews_identifier_lists_without_a_jwt(self):
        """issue 5: renewal stopped on the never-written identifier_list.jwt."""
        first, _ = make_list()
        second, _ = make_list(doctype=MDL)
        report = lists_renewal.renew_lists()
        assert sorted(report["renewed"]) == sorted([f"FC/{PID}/{first}", f"FC/{MDL}/{second}"])
        assert not (dirs(first)[1] / "identifier_list.jwt").exists()

    def test_repairs_damaged_files(self):
        """The issue #191 file: stray bytes after the CWT and the JWT signature."""
        list_id, idx = make_list()
        token_dir, identifier_dir = dirs(list_id)
        for name in ("token_status_list.cwt", "token_status_list.jwt"):
            with open(token_dir / name, "ab") as f:
                f.write(b"wt")
        with pytest.raises(Exception):  # trailing CWT bytes / invalid JWT signature
            check_list_files(token_dir, identifier_dir)
        lists_renewal.renew_lists()
        check_list_files(token_dir, identifier_dir)

    def test_removes_expired_lists_and_their_pointer(self):
        list_id, _ = make_list()
        expire(list_id)
        assert lists_renewal.renew_lists()["removed"] == [f"FC/{PID}/{list_id}"]
        assert not any(d.exists() for d in dirs(list_id))
        assert storage.current_list_id("FC", PID) is None

    def test_removing_an_old_list_keeps_the_pointer(self):
        old, _ = make_list()
        storage.set_current_list_id("FC", PID, None)
        new, _ = make_list()
        expire(old)
        lists_renewal.renew_lists()
        assert storage.current_list_id("FC", PID) == new

    def test_corrupt_and_failing_lists_do_not_stop_the_others(self, configuration):
        bad, _ = make_list()
        storage.set_current_list_id("FC", PID, None)
        good, _ = make_list()
        (dirs(bad)[0] / FULL_LIST).write_text("{not json")
        unknown = storage.list_dir(TOKEN_LIST, "XX", PID, "11111111-1111-1111-1111-111111111111")
        unknown.mkdir(parents=True)
        (unknown / FULL_LIST).write_text((dirs(good)[0] / FULL_LIST).read_text())

        report = lists_renewal.renew_lists()

        assert report["corrupt"] == [f"FC/{PID}/{bad}"]
        assert report["failed"] == [f"XX/{PID}/11111111-1111-1111-1111-111111111111"]  # no signer for XX
        assert report["renewed"] == [f"FC/{PID}/{good}"]

    def test_list_removed_while_renewing(self, monkeypatch):
        list_id, _ = make_list()
        real = storage.load_entry

        def vanished(*args):
            raise storage.ListNotFound("gone")

        monkeypatch.setattr(storage, "load_entry", vanished)
        assert lists_renewal.renew_lists()["renewed"] == []
        monkeypatch.setattr(storage, "load_entry", real)


class TestRenewalPass:
    def test_runs_when_free(self):
        make_list()
        assert len(lists_renewal.renewal_pass()["renewed"]) == 1

    def test_skips_when_another_process_renews(self):
        with storage.file_lock(storage.base_dir() / "state" / "renewal.lock"):
            assert lists_renewal.renewal_pass() is None


class TestCommand:
    def test_renew_lists_command(self, client):
        make_list()
        result = client.application.test_cli_runner().invoke(args=["renew-lists"])
        assert result.exit_code == 0
        assert "renewed: 1" in result.output

    def test_renew_lists_command_reports_corrupt_lists(self, client):
        list_id, _ = make_list()
        (dirs(list_id)[0] / FULL_LIST).write_text("{")
        result = client.application.test_cli_runner().invoke(args=["renew-lists"])
        assert result.exit_code == 1
        assert f"FC/{PID}/{list_id}" in result.output


class TestRenewalLoop:
    def test_daily_renewal_sleeps_until_next_and_logs_failures(self, monkeypatch, caplog):
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) > 1:
                raise SystemExit

        def failing_pass():
            raise ValueError("boom")

        monkeypatch.setattr(lists_renewal.time, "sleep", fake_sleep)
        monkeypatch.setattr(lists_renewal, "renewal_pass", failing_pass)
        with caplog.at_level("INFO"), pytest.raises(SystemExit):
            lists_renewal.daily_renewal()
        assert 0 < sleeps[0] <= 12 * 3600
        assert "List renewal failed" in caplog.text

    def test_start_renewal_thread(self, monkeypatch):
        started = {}

        class FakeThread:
            def __init__(self, target, daemon):
                started.update(target=target, daemon=daemon)

            def start(self):
                started["started"] = True

        monkeypatch.setattr(lists_renewal.threading, "Thread", FakeThread)
        lists_renewal.start_renewal_thread()
        assert started == {"target": lists_renewal.daily_renewal, "daemon": True, "started": True}
