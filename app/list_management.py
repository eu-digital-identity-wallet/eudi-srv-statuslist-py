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
"""Taking, revoking and reading list entries.

Every operation works on the files of :mod:`app.storage`, under the lock of
the list's country and doctype, so concurrent requests, several service
processes and restarts all see the same lists.
"""

from __future__ import annotations

import contextlib
import logging
import secrets
from collections.abc import Sequence
from datetime import datetime
from typing import Any, NamedTuple

from app import storage
from app.config import CONFIGURATION
from app.status_list import NoMoreIndices
from app.storage import IDENTIFIER_LIST, TOKEN_LIST, CorruptList, ListNotFound

logger = logging.getLogger(__name__)


class IndexOutOfRange(ValueError):
    """An index outside the list."""


class UnknownIdentifier(LookupError):
    """An identifier no entry of the list has."""


class UnknownEntry(LookupError):
    """An index that was never taken."""


class ConflictingRef(ValueError):
    """An index and an identifier naming different entries."""


class Ref(NamedTuple):
    """One entry of a list, by index, by identifier or by both."""

    country: str
    doctype: str
    list_id: str
    index: int | None = None
    identifier: str | None = None


#: Errors of one ref of :func:`revoke_many` (they carry its ``position``).
REF_ERRORS = (ListNotFound, CorruptList, IndexOutOfRange, UnknownIdentifier, UnknownEntry, ConflictingRef)


def _later(a: str | None, b: str) -> str:
    """The later of two ``YYYY-MM-DD`` dates (``a`` may be unset)."""
    if a is None:
        return b
    return b if datetime.strptime(b, "%Y-%m-%d") > datetime.strptime(a, "%Y-%m-%d") else a


def _current_entry(country: str, doctype: str) -> dict[str, Any]:
    """The list new indices come from; a new one when there is none (call under the lock)."""
    list_id = storage.current_list_id(country, doctype)
    if list_id:
        try:
            return storage.load_entry(country, doctype, list_id)
        except (ListNotFound, CorruptList):
            logger.warning("Current list %s/%s/%s unusable, starting a new one", country, doctype, list_id, exc_info=True)
    return storage.new_entry(country, doctype)


def take(country: str, doctype: str, expiry_date: str) -> dict[str, Any]:
    """Takes a free index for a credential about to be issued.

    When the current list is full a new one is started; the index and the
    URIs returned always belong to the same list.

    Args:
        country: Country code.
        doctype: Doctype (or vct) of the credential.
        expiry_date: Expiry of the credential, ``YYYY-MM-DD``; the list is
            kept at least until then.

    Returns:
        The ``status_list`` and ``identifier_list`` pointers for the issuer.
    """
    return take_many(country, doctype, expiry_date, 1)[0]


def take_many(country: str, doctype: str, expiry_date: str, count: int) -> list[dict[str, Any]]:
    """Takes ``count`` free indices for credentials about to be issued.

    As :func:`take`, under one lock: new lists are started as the current
    ones fill up, so the indices may belong to several lists. Each list is
    written once.

    Returns:
        The pointers of every index, in the order they were taken.

    Raises:
        ValueError: ``count`` is not between 1 and ``batch_max_size``.
    """
    max_count = CONFIGURATION["batch_max_size"]
    if not 1 <= count <= max_count:
        raise ValueError(f"count must be between 1 and {max_count}")
    with storage.country_doctype_lock(country, doctype):
        entry = _current_entry(country, doctype)
        touched: dict[str, dict[str, Any]] = {}
        taken = []
        for _ in range(count):
            try:
                index = entry["token_status_list"].allocator.take()
            except NoMoreIndices:
                logger.info("List %s/%s/%s is full, starting a new one", country, doctype, entry["rand"])
                entry = storage.new_entry(country, doctype)
                index = entry["token_status_list"].allocator.take()
            identifier = _new_identifier()
            entry["ids"][str(index)] = identifier
            touched[entry["rand"]] = entry
            taken.append(
                {
                    "status_list": {"uri": entry["status_list_uri"], "idx": index},
                    "identifier_list": {"uri": entry["identifier_list_uri"], "id": identifier},
                }
            )
        for touched_entry in touched.values():
            touched_entry["expires"] = _later(touched_entry["expires"], expiry_date)
            # The statuses are unchanged: a new list is published, an existing one only stored.
            storage.save_entry(touched_entry, publish=_is_new(touched_entry))
        if storage.current_list_id(country, doctype) != entry["rand"]:
            storage.set_current_list_id(country, doctype, entry["rand"])
    return taken


def _is_new(entry: dict[str, Any]) -> bool:
    """Whether the list has no published files yet."""
    token_dir = storage.list_dir(TOKEN_LIST, entry["country"], entry["doctype"], entry["rand"])
    return not (token_dir / storage.STATUS_JWT).exists()


def _new_identifier() -> str:
    """A random identifier list id: 32 hex characters, never all digits.

    Entries taken before the ids were random have ``str(index)`` as id, so a
    new id must never look like one.
    """
    while True:
        identifier = secrets.token_hex(16)
        if not identifier.isdigit():
            return identifier


def _identifier_of(entry: dict[str, Any], index: int) -> str:
    """The identifier list id of an entry (``str(index)`` for the entries taken before random ids)."""
    return entry["ids"].get(str(index), str(index))


def _indices_by_identifier(entry: dict[str, Any]) -> dict[str, int]:
    return {identifier: int(index) for index, identifier in entry["ids"].items()}


def _check_index(entry: dict[str, Any], index: int) -> None:
    size = entry["token_status_list"].status_list.size
    if not 0 <= index < size:
        raise IndexOutOfRange(f"index must be between 0 and {size - 1}")


def _resolve(entry: dict[str, Any], by_identifier: dict[str, int], index: int | None, identifier: str | None) -> int:
    """The index of the entry a ref names.

    An identifier is a stored random id, or ``str(index)`` of an entry that
    has none (taken before the ids were random).

    Raises:
        IndexOutOfRange: ``index`` is outside the list.
        UnknownIdentifier: No entry has ``identifier``.
        ConflictingRef: ``index`` and ``identifier`` name different entries.
    """
    if index is not None:
        _check_index(entry, index)
    if identifier is None:
        return index
    found = by_identifier.get(identifier)
    if found is None and identifier.isdigit() and identifier == str(int(identifier)):
        legacy = int(identifier)
        size = entry["token_status_list"].status_list.size
        if legacy < size and str(legacy) not in entry["ids"]:
            found = legacy
    if found is None:
        raise UnknownIdentifier("Unknown identifier")
    if index is not None and index != found:
        raise ConflictingRef("id and idx name different entries")
    return found


def revoke(
    country: str, doctype: str, list_id: str, index: int | None = None, identifier: str | None = None
) -> None:
    """Revokes one entry: sets its status to 1 and adds its id to the identifier list.

    Raises:
        ListNotFound: No such list.
        CorruptList: The list cannot be read.
        IndexOutOfRange: ``index`` is outside the list.
        UnknownIdentifier, ConflictingRef: As for :func:`_resolve`.
        UnknownEntry: The entry was never taken.
    """
    revoke_many([Ref(country, doctype, list_id, index, identifier)])


def revoke_many(refs: Sequence[Ref]) -> int:
    """Revokes several entries, all or none.

    The locks of every country and doctype involved are taken in sorted
    order (so two batches cannot deadlock), every entry is checked, and only
    then are they revoked; each list is signed once.

    Args:
        refs: The entries; repeated entries (by index, by identifier or
            both) are revoked once, revoked ones stay revoked.

    Returns:
        The number of distinct entries.

    Raises:
        REF_ERRORS: As for :func:`revoke`, with ``position`` set to the
            first ref that failed. Nothing is revoked.
    """
    by_list: dict[tuple[str, str, str], list[tuple[int, Ref]]] = {}
    for position, ref in enumerate(refs):
        by_list.setdefault((ref.country, ref.doctype, ref.list_id), []).append((position, ref))
    with contextlib.ExitStack() as locks:
        for country, doctype in sorted({(country, doctype) for country, doctype, _ in by_list}):
            locks.enter_context(storage.country_doctype_lock(country, doctype))
        entries = []
        for (country, doctype, list_id), items in by_list.items():
            position = items[0][0]
            try:
                entry = storage.load_entry(country, doctype, list_id)
                by_identifier = _indices_by_identifier(entry)
                indices: dict[int, None] = {}
                for position, ref in items:
                    index = _resolve(entry, by_identifier, ref.index, ref.identifier)
                    if not entry["token_status_list"].allocator.allocated.get(index):
                        raise UnknownEntry("Unknown entry")
                    indices[index] = None
            except REF_ERRORS as e:
                e.position = position
                raise
            entries.append((entry, list(indices)))
        for entry, indices in entries:
            for index in indices:
                entry["token_status_list"].status_list.set(index, 1)
                entry["identifier_list"]["identifiers"][_identifier_of(entry, index)] = {}
            storage.save_entry(entry)
            logger.info(
                "Revoked indices %s of list %s/%s/%s", indices, entry["country"], entry["doctype"], entry["rand"]
            )
    return sum(len(indices) for _, indices in entries)


def read_status(
    kind: str, country: str, doctype: str, list_id: str, index: int | None = None, identifier: str | None = None
) -> int:
    """Status of one entry: the status list value, or 1 when the identifier list holds its id.

    Files are replaced atomically, so no lock is needed.

    Raises:
        ListNotFound, CorruptList, IndexOutOfRange, UnknownIdentifier,
        ConflictingRef: As for :func:`revoke`.
    """
    entry = storage.load_entry(country, doctype, list_id)
    index = _resolve(entry, _indices_by_identifier(entry), index, identifier)
    if kind == TOKEN_LIST:
        return entry["token_status_list"].status_list.get(index)
    if kind == IDENTIFIER_LIST:
        return 1 if _identifier_of(entry, index) in entry["identifier_list"]["identifiers"] else 0
    raise ValueError(f"unknown list kind {kind}")
