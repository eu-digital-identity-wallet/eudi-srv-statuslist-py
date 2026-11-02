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
"""On-disk state of the lists: the single source of truth.

Every list lives in two directories under ``status_list_dir``::

    token_status_list/<CC>/<doctype>/<id>/full_list.json, token_status_list.jwt, token_status_list.cwt
    identifier_list/<CC>/<doctype>/<id>/full_list.json, identifier_list.cwt

``state/<CC>/<doctype>/current.json`` names the list new indices are taken
from, and ``state/<CC>/<doctype>/.lock`` serializes every change to the lists
of that country and doctype, across threads and processes. Files are
replaced atomically, so readers (the list routes, a web server) never see a
partly written file.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from app.config import CONFIGURATION
from app.identifier_list_format import identifier_list_cwt_format
from app.status_list import IssuerStatusList
from app.status_list_format import cwt_format, jwt_format

TOKEN_LIST = "token_status_list"
IDENTIFIER_LIST = "identifier_list"
LIST_KINDS = (TOKEN_LIST, IDENTIFIER_LIST)

#: Name of the file holding a list's state (never served).
FULL_LIST = "full_list.json"
#: Names of the published (signed) lists.
STATUS_JWT = "token_status_list.jwt"
STATUS_CWT = "token_status_list.cwt"
IDENTIFIER_CWT = "identifier_list.cwt"

#: Mode of the published JWT / CWT files (a web server may read them as another user).
PUBLISHED_MODE = 0o644
#: Mode of every other file: the list state, ``state/`` and the backups.
PRIVATE_MODE = 0o600


class ListNotFound(LookupError):
    """No list with that country, doctype and id."""


class CorruptList(ValueError):
    """A ``full_list.json`` that cannot be parsed."""


_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


def base_dir() -> Path:
    """Returns ``status_list_dir``."""
    return Path(CONFIGURATION["status_list_dir"])


def state_dir(country: str, doctype: str) -> Path:
    """Returns the state directory of a country and doctype."""
    return base_dir() / "state" / country / doctype


def list_dir(kind: str, country: str, doctype: str, list_id: str) -> Path:
    """Returns the directory of one list (``kind`` is token or identifier list)."""
    return base_dir() / kind / country / doctype / list_id


def list_uri(kind: str, country: str, doctype: str, list_id: str) -> str:
    """Returns the public URI of one list."""
    return f"{CONFIGURATION['service_url']}{kind}/{country}/{doctype}/{list_id}"


@contextlib.contextmanager
def file_lock(path: Path, *, blocking: bool = True) -> Iterator[bool]:
    """Holds an exclusive ``flock`` on ``path`` (created when missing).

    Args:
        path: Lock file.
        blocking: Wait for the lock; otherwise yield ``False`` when it is held
            elsewhere.

    Yields:
        ``True`` when the lock is held.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@contextlib.contextmanager
def country_doctype_lock(country: str, doctype: str) -> Iterator[None]:
    """Serializes the changes to the lists of one country and doctype.

    A thread lock orders the threads of this process (``flock`` is held per
    open file, so threads would not exclude each other reliably); the file
    lock orders the processes.
    """
    key = f"{country}/{doctype}"
    with _thread_locks_guard:
        thread_lock = _thread_locks.setdefault(key, threading.Lock())
    with thread_lock, file_lock(state_dir(country, doctype) / ".lock"):
        yield


def atomic_write(path: Path, data: bytes | str, mode: int = PRIVATE_MODE) -> None:
    """Replaces ``path`` with ``data`` in one step.

    The data goes to a temporary file in the same directory, which is then
    renamed over ``path``: readers see the old or the new file, never a
    partial one, and a failure leaves the old file in place. There is no
    ``fsync`` (it made ``/take`` 60 times slower): after a power cut the
    latest write may be lost, never half written.

    Args:
        path: File to replace.
        data: New content.
        mode: Permissions of the new file; :data:`PUBLISHED_MODE` only for
            the files served at the list URIs.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode() if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        # Other users may read only the published lists (PUBLISHED_MODE).
        os.chmod(tmp, mode)  # NOSONAR
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def new_entry(country: str, doctype: str) -> dict[str, Any]:
    """Returns a new, empty list (not yet saved)."""
    list_id = str(uuid4())
    return {
        "token_status_list": IssuerStatusList.new(1, CONFIGURATION["token_status_list_size"]),
        "identifier_list": {"identifiers": {}},
        "ids": {},
        "expires": None,
        "rand": list_id,
        "country": country,
        "doctype": doctype,
        "status_list_uri": list_uri(TOKEN_LIST, country, doctype, list_id),
        "identifier_list_uri": list_uri(IDENTIFIER_LIST, country, doctype, list_id),
    }


def _stringify_keys(d: dict) -> dict:
    return {(k.decode() if isinstance(k, bytes) else str(k)): v for k, v in d.items()}


def load_entry(country: str, doctype: str, list_id: str) -> dict[str, Any]:
    """Reads one list from its ``full_list.json``.

    Lists written before the URIs were stored get them back, and lists from
    before the random identifier list ids an empty ``ids``.

    Raises:
        ListNotFound: No such list.
        CorruptList: The file cannot be parsed.
    """
    path = list_dir(TOKEN_LIST, country, doctype, list_id) / FULL_LIST
    try:
        data = json.loads(path.read_text())
        data["token_status_list"] = IssuerStatusList.load(data["token_status_list"])
    except FileNotFoundError as e:
        raise ListNotFound(f"{country}/{doctype}/{list_id}") from e
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
        raise CorruptList(f"{path}: {e!r}") from e
    try:
        identifiers = data.setdefault("identifier_list", {}).get("identifiers") or {}
        data["identifier_list"]["identifiers"] = _stringify_keys(identifiers)
    except AttributeError as e:
        raise CorruptList(f"{path}: {e}") from e
    # Identifier list id of each index; lists from before the random ids have none.
    ids = data.setdefault("ids", {})
    if not isinstance(ids, dict) or not all(
        isinstance(index, str) and index.isdigit() and isinstance(identifier, str) for index, identifier in ids.items()
    ):
        raise CorruptList(f"{path}: 'ids' must map indices to identifiers")
    data.update(
        country=country,
        doctype=doctype,
        rand=list_id,
        status_list_uri=list_uri(TOKEN_LIST, country, doctype, list_id),
        identifier_list_uri=list_uri(IDENTIFIER_LIST, country, doctype, list_id),
    )
    return data


def save_entry(entry: dict[str, Any], *, publish: bool = True) -> None:
    """Writes one list; with ``publish``, also signs and writes its public files.

    All documents are built first, so a signing error leaves the published
    files untouched; each file is then replaced atomically.

    Args:
        entry: The list.
        publish: Re-sign the JWT / CWT files. Taking an index only changes
            the allocator state in ``full_list.json``, not the published
            statuses, so it skips this.
    """
    country, doctype, list_id = entry["country"], entry["doctype"], entry["rand"]
    stored = {key: value for key, value in entry.items() if key != "token_status_list"}
    stored = copy.deepcopy(stored)
    stored["token_status_list"] = entry["token_status_list"].dump()
    full_list = json.dumps(stored)
    token_dir = list_dir(TOKEN_LIST, country, doctype, list_id)
    identifier_dir = list_dir(IDENTIFIER_LIST, country, doctype, list_id)
    if not publish:
        atomic_write(token_dir / FULL_LIST, full_list)
        atomic_write(identifier_dir / FULL_LIST, full_list)
        return
    status_jwt = jwt_format(entry["token_status_list"], country, entry["status_list_uri"])
    status_cwt = cwt_format(entry["token_status_list"], country, entry["status_list_uri"])
    identifier_cwt = identifier_list_cwt_format(entry["identifier_list"], country, entry["identifier_list_uri"])

    atomic_write(token_dir / FULL_LIST, full_list)
    atomic_write(token_dir / STATUS_JWT, status_jwt, PUBLISHED_MODE)
    atomic_write(token_dir / STATUS_CWT, status_cwt, PUBLISHED_MODE)
    atomic_write(identifier_dir / FULL_LIST, full_list)
    atomic_write(identifier_dir / IDENTIFIER_CWT, identifier_cwt, PUBLISHED_MODE)


def current_list_id(country: str, doctype: str) -> str | None:
    """Returns the id of the list new indices come from, if any."""
    try:
        return json.loads((state_dir(country, doctype) / "current.json").read_text())["id"]
    except (FileNotFoundError, ValueError, KeyError, TypeError):
        return None


def set_current_list_id(country: str, doctype: str, list_id: str | None) -> None:
    """Points ``current.json`` at a list (``None`` removes the pointer)."""
    path = state_dir(country, doctype) / "current.json"
    if list_id is None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        return
    atomic_write(path, json.dumps({"id": list_id}))
