"""Concurrent requests and several processes on the same lists (issues 7, 8, 10, 11)."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

from app import list_management as lm
from app import lists_renewal, storage
from app.storage import IDENTIFIER_LIST, TOKEN_LIST
from tests.conftest import API_KEY, MDL, PID
from tests.strict import check_list_files, jwt_status

REPO = Path(__file__).resolve().parent.parent


def ref(info):
    return info["status_list"]["uri"].rsplit("/", 1)[1], info["status_list"]["idx"]


def dirs(country, doctype, list_id):
    return storage.list_dir(TOKEN_LIST, country, doctype, list_id), storage.list_dir(IDENTIFIER_LIST, country, doctype, list_id)


def check_all_files(configuration):
    """Every list on disk is complete and valid."""
    for path in Path(configuration["status_list_dir"], TOKEN_LIST).glob("*/*/*/full_list.json"):
        country, doctype, list_id = path.parts[-4:-1]
        check_list_files(*dirs(country, doctype, list_id))


def test_concurrent_takes_hand_out_unique_indices(configuration):
    with ThreadPoolExecutor(16) as pool:
        taken = list(pool.map(lambda _: ref(lm.take("FC", PID, "2099-01-01")), range(200)))
    assert len(set(taken)) == 200
    assert len({list_id for list_id, _ in taken}) == 1
    check_all_files(configuration)


def test_concurrent_revocations_are_all_kept(configuration):
    taken = [ref(lm.take("FC", PID, "2099-01-01")) for _ in range(100)]
    with ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda r: lm.revoke("FC", PID, *r), taken))
    list_id = taken[0][0]
    token_dir, identifier_dir = dirs("FC", PID, list_id)
    check_list_files(token_dir, identifier_dir)
    assert all(jwt_status(token_dir, idx) == 1 for _, idx in taken)
    assert len(storage.load_entry("FC", PID, list_id)["identifier_list"]["identifiers"]) == 100


def test_revocations_while_taking(configuration):
    taken = [ref(lm.take("FC", PID, "2099-01-01")) for _ in range(50)]
    stop = threading.Event()
    errors = []

    def taker():
        while not stop.is_set():
            try:
                lm.take("FC", PID, "2099-01-01")
            except Exception as e:  # noqa: BLE001
                errors.append(e)

    threads = [threading.Thread(target=taker) for _ in range(4)]
    for t in threads:
        t.start()
    try:
        for r in taken:
            lm.revoke("FC", PID, *r)
            # Readers never see a partial file (issue 8).
            assert lm.read_status(TOKEN_LIST, "FC", PID, *r) == 1
    finally:
        stop.set()
        for t in threads:
            t.join()
    assert errors == []
    token_dir, _ = dirs("FC", PID, taken[0][0])
    assert all(jwt_status(token_dir, idx) == 1 for _, idx in taken)
    check_all_files(configuration)


def test_concurrent_revocations_by_identifier(configuration):
    taken = lm.take_many("FC", PID, "2099-01-01", 60)
    list_id = ref(taken[0])[0]
    with ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda info: lm.revoke("FC", PID, list_id, identifier=info["identifier_list"]["id"]), taken))
    token_dir, identifier_dir = dirs("FC", PID, list_id)
    check_list_files(token_dir, identifier_dir)
    assert all(jwt_status(token_dir, ref(info)[1]) == 1 for info in taken)
    identifiers = storage.load_entry("FC", PID, list_id)["identifier_list"]["identifiers"]
    assert set(identifiers) == {info["identifier_list"]["id"] for info in taken}


def test_revocations_during_renewal(configuration):
    taken = [ref(lm.take("FC", PID, "2099-01-01")) for _ in range(40)]
    done = threading.Event()

    def renew():
        while not done.is_set():
            lists_renewal.renew_lists()

    renewer = threading.Thread(target=renew)
    renewer.start()
    try:
        for r in taken:
            lm.revoke("FC", PID, *r)
    finally:
        done.set()
        renewer.join()
    token_dir, _ = dirs("FC", PID, taken[0][0])
    assert all(jwt_status(token_dir, idx) == 1 for _, idx in taken)
    check_all_files(configuration)


def test_rollover_under_load(configuration):
    """issue 11: no duplicates, no errors, other lists kept."""
    configuration["token_status_list_size"] = 8
    other = ref(lm.take("LU", MDL, "2099-01-01"))[0]
    with ThreadPoolExecutor(16) as pool:
        taken = list(pool.map(lambda _: ref(lm.take("FC", PID, "2099-01-01")), range(80)))
    assert len(set(taken)) == 80
    assert len({list_id for list_id, _ in taken}) == 10
    assert all(0 <= idx < 8 for _, idx in taken)
    assert storage.current_list_id("LU", MDL) == other
    check_all_files(configuration)


def test_batch_takes_with_single_takes_across_rollovers(configuration):
    configuration["token_status_list_size"] = 8

    def work(n):
        if n % 2:
            return [ref(info) for info in lm.take_many("FC", PID, "2099-01-01", 5)]
        return [ref(lm.take("FC", PID, "2099-01-01"))]

    with ThreadPoolExecutor(16) as pool:
        taken = [r for batch in pool.map(work, range(40)) for r in batch]
    assert len(taken) == 120
    assert len(set(taken)) == 120
    check_all_files(configuration)


def test_overlapping_revoke_batches_do_not_deadlock(configuration):
    """Batches naming the same doctypes in opposite orders."""
    pid = [lm.Ref("FC", PID, *ref(info)) for info in lm.take_many("FC", PID, "2099-01-01", 40)]
    mdl = [lm.Ref("FC", MDL, *ref(info)) for info in lm.take_many("FC", MDL, "2099-01-01", 40)]
    batches = [pid[i:i + 4] + mdl[i:i + 4] if i % 8 else mdl[i:i + 4] + pid[i:i + 4] for i in range(0, 40, 4)]
    with ThreadPoolExecutor(10) as pool:
        futures = [pool.submit(lm.revoke_many, batch) for batch in batches * 3]
        assert [f.result(timeout=30) for f in futures] == [8] * 30
    for r in pid + mdl:
        assert jwt_status(dirs(r.country, r.doctype, r.list_id)[0], r.index) == 1
    check_all_files(configuration)


# ---------------------------------------------------------- two processes ----


def http(method: str, url: str, data: dict | None = None, headers: dict | None = None) -> tuple[int, str]:
    """Minimal HTTP client (urllib): returns (status, body)."""
    body = urllib.parse.urlencode(data).encode() if data and method == "POST" else None
    if data and method == "GET":
        url = f"{url}?{urllib.parse.urlencode(data)}"
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def two_processes(tmp_path, signer):
    """Two ``flask run`` processes of the service on the same directories."""
    config = tmp_path / "config.yaml"
    config.write_text(
        f"service_url: http://lists.test/\napi_key: {API_KEY}\n"
        f"status_list_dir: {tmp_path}/shared/lists\nbackup_dir: {tmp_path}/shared/backup\n"
        f"logging:\n  path: {tmp_path}/log/sl.log\nmax_expiry_days: 36500\n"
        f"countries:\n  FC:\n    private_key_path: {signer.key_path}\n    certificate_path: {signer.cert_path}\n"
    )
    env = {k: v for k, v in os.environ.items() if k not in ("MOCK_CONFIGURATION", "EUDIW_TEST_ENV")}
    env["STATUS_LIST_CONFIG_PATH"] = str(config)
    processes, urls = [], []
    for _ in range(2):
        port = free_port()
        processes.append(
            subprocess.Popen(
                [sys.executable, "-m", "flask", "--app", "app:create_app", "run", "--host", "127.0.0.1", "--port", str(port)],
                cwd=REPO, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        )
        urls.append(f"http://127.0.0.1:{port}/token_status_list")
    try:
        for url in urls:
            for _ in range(100):
                try:
                    http("GET", f"{url}/static/swagger.json")
                    break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                pytest.fail(f"{url} did not start")
        yield urls, tmp_path / "shared" / "lists"
    finally:
        for p in processes:
            p.terminate()
            p.wait(10)


def test_two_processes_share_lists_and_revocations(two_processes):
    """issue 10: a take on one process no longer undoes revocations made through the other."""
    (a, b), lists = two_processes
    headers = {"X-Api-Key": API_KEY}
    data = {"doctype": PID, "country": "FC", "expiry_date": "2099-01-01"}

    def take(url):
        status, body = http("POST", f"{url}/take", data, headers)
        assert status == 200, body
        return json.loads(body)["status_list"]

    refs = [take(a) for _ in range(5)]
    for r in refs[:3]:
        assert http("POST", f"{b}/set", {**r, "status": 1}, headers)[0] == 200
    from_b = take(b)
    take(a)
    assert from_b["uri"] == refs[0]["uri"]  # one current list for both processes

    with ThreadPoolExecutor(8) as pool:
        more = list(pool.map(lambda i: take(a if i % 2 else b), range(40)))
    pairs = [(r["uri"], r["idx"]) for r in refs + [from_b] + more]
    assert len(set(pairs)) == len(pairs)

    for r in refs[:3]:
        assert http("GET", f"{a}/get", r) == (200, "1")
    list_id = refs[0]["uri"].rsplit("/", 1)[1]
    token_dir = lists / TOKEN_LIST / "FC" / PID / list_id
    check_list_files(token_dir, lists / IDENTIFIER_LIST / "FC" / PID / list_id)
    assert [jwt_status(token_dir, r["idx"]) for r in refs] == [1, 1, 1, 0, 0]
