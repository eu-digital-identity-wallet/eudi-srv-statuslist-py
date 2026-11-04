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
"""Periodic renewal of the lists: re-signing, backups and expiry."""

from __future__ import annotations

import logging
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app import storage
from app.config import CONFIGURATION
from app.storage import IDENTIFIER_LIST, TOKEN_LIST, CorruptList, ListNotFound

logger = logging.getLogger(__name__)


def _backup(entry_dirs: list[Path], timestamp: str) -> None:
    """Copies the files of one list to ``backup_dir/<timestamp>/`` (same relative paths)."""
    base = storage.base_dir()
    for directory in entry_dirs:
        if not directory.is_dir():
            continue
        target = Path(CONFIGURATION["backup_dir"]) / timestamp / directory.relative_to(base)
        for f in directory.iterdir():
            if f.is_file() and not f.name.startswith("."):
                storage.atomic_write(target / f.name, f.read_bytes())


def _renew_one(country: str, doctype: str, list_id: str, timestamp: str, report: dict[str, list]) -> None:
    name = f"{country}/{doctype}/{list_id}"
    dirs = [storage.list_dir(kind, country, doctype, list_id) for kind in (TOKEN_LIST, IDENTIFIER_LIST)]
    with storage.country_doctype_lock(country, doctype):
        try:
            entry = storage.load_entry(country, doctype, list_id)
        except ListNotFound:
            return  # removed meanwhile
        except CorruptList:
            logger.exception("Cannot renew %s: its full_list.json is unreadable", name)
            report["corrupt"].append(name)
            return
        expires = entry.get("expires")
        # Credentials are valid until the end of their (UTC) expiry day.
        if expires and datetime.strptime(expires, "%Y-%m-%d").date() < datetime.now(timezone.utc).date():
            logger.info("Removing %s: expired on %s", name, expires)
            for directory in dirs:
                shutil.rmtree(directory, ignore_errors=True)
            if storage.current_list_id(country, doctype) == list_id:
                storage.set_current_list_id(country, doctype, None)
            report["removed"].append(name)
            return
        _backup(dirs, timestamp)
        storage.save_entry(entry)
        report["renewed"].append(name)


def renew_lists() -> dict[str, list[str]]:
    """Re-signs every list, backs it up first and removes expired lists.

    Each list is rewritten from its ``full_list.json`` under its lock, so a
    damaged JWT / CWT file is repaired. A list that fails is logged and
    skipped; the others are still renewed.

    Returns:
        ``renewed``, ``removed``, ``corrupt`` (unreadable ``full_list.json``)
        and ``failed`` lists, as ``CC/doctype/id``.
    """
    report: dict[str, list[str]] = {"renewed": [], "removed": [], "corrupt": [], "failed": []}
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    for path in sorted((storage.base_dir() / TOKEN_LIST).glob("*/*/*/full_list.json")):
        list_id, doctype, country = path.parent.name, path.parent.parent.name, path.parent.parent.parent.name
        try:
            _renew_one(country, doctype, list_id, timestamp, report)
        except Exception:
            logger.exception("Cannot renew %s/%s/%s", country, doctype, list_id)
            report["failed"].append(f"{country}/{doctype}/{list_id}")
    logger.info(
        "Renewal: %d renewed, %d removed, %d corrupt, %d failed",
        *(len(report[k]) for k in ("renewed", "removed", "corrupt", "failed")),
    )
    return report


def renewal_pass() -> dict[str, Any] | None:
    """Runs :func:`renew_lists` unless another process is renewing.

    Returns:
        The report, or ``None`` when the pass was skipped.
    """
    with storage.file_lock(storage.base_dir() / "state" / "renewal.lock", blocking=False) as held:
        if not held:
            logger.info("Another process is renewing the lists; skipping this pass")
            return None
        return renew_lists()


def next_renewal(now: datetime) -> datetime:
    """Returns the next renewal time after ``now``.

    Renewals run at the hours listed in ``renewal.hours`` (local time).

    Args:
        now: Current time.

    Returns:
        The next renewal time, today or tomorrow.
    """
    hours = sorted({int(h) for h in CONFIGURATION["renewal"]["hours"]})
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    for day in (0, 1):
        for hour in hours:
            candidate = midnight + timedelta(days=day, hours=hour)
            if candidate > now:
                return candidate
    raise RuntimeError("renewal.hours must list at least one hour (0-23)")


def daily_renewal():
    """Renews the lists at every ``renewal.hours``, forever: no error stops the loop."""
    while True:
        try:
            now = datetime.now()
            next_execution = next_renewal(now)

            seconds_until_execution = (next_execution - now).total_seconds()

            logger.info(
                f"Renewing in {int(seconds_until_execution // 3600):02}:{int((seconds_until_execution % 3600) // 60):02}:{round(seconds_until_execution % 60):02}"
            )

            time.sleep(seconds_until_execution)

            logger.info("Renewing Revocation Lists")

            renewal_pass()
        except Exception:
            logger.exception("List renewal failed")
            time.sleep(60)


def start_renewal_thread():
    task_thread = threading.Thread(target=daily_renewal, daemon=True)
    task_thread.start()
