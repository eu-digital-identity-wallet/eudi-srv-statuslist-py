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
"""Logging configuration for Flask and Werkzeug."""

from __future__ import annotations

import logging
import os
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Mapping

from flask import Flask


class LineBreakEscapeFilter(logging.Filter):
    """Escapes CR / LF in every log message (log injection).

    :func:`app.log_utils.safe` escapes request values where they are logged;
    this filter, installed on the handlers, also covers any message that
    misses it, so no record can start a forged log line.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Rewrites ``record`` with its final message escaped.

        Args:
            record: The log record.

        Returns:
            Always ``True`` (records are never dropped).
        """
        message = record.getMessage()
        if "\r" in message or "\n" in message:
            record.msg = message.replace("\r", "\\r").replace("\n", "\\n")
            record.args = None
        return True


class SafeTracebackFormatter(logging.Formatter):
    """Indents every traceback line (log injection).

    :class:`LineBreakEscapeFilter` escapes the message only; the traceback of
    ``logger.exception`` is appended by the formatter. Indented, no traceback
    line can pass for a new log record (records start with a timestamp).
    """

    def formatException(self, ei: Any) -> str:
        """Formats an exception traceback with every line indented.

        Args:
            ei: ``sys.exc_info()`` tuple.

        Returns:
            The indented traceback.
        """
        return _indent(super().formatException(ei))

    def formatStack(self, stack_info: str) -> str:
        """Formats ``stack_info`` with every line indented.

        Args:
            stack_info: Stack text.

        Returns:
            The indented stack.
        """
        return _indent(super().formatStack(stack_info))


def _indent(text: str) -> str:
    """Prefixes every line of ``text`` (split on CR or LF) with ``    | ``.

    Args:
        text: Multi-line text.

    Returns:
        The indented text.
    """
    return "\n".join(f"    | {line}" for line in text.replace("\r", "\n").split("\n"))


def configure_logging(app: Flask, config: Mapping[str, Any]) -> None:
    """Configures file + console logging for the app, its modules and Werkzeug.

    The log file rotates at midnight and ``backup_count`` files are kept.

    Args:
        app: The Flask application.
        config: The ``logging`` configuration section (``path``,
            ``log_level``, ``backup_count``).
    """
    log_file_path = config["path"]
    log_level = getattr(logging, str(config.get("log_level", "INFO")).upper(), logging.INFO)

    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    log_formatter = SafeTracebackFormatter("%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s")

    file_handler = TimedRotatingFileHandler(
        filename=log_file_path,
        when="midnight",
        interval=1,
        backupCount=int(config.get("backup_count", 7)),
        encoding="utf-8",
    )
    console_handler = logging.StreamHandler()

    line_break_filter = LineBreakEscapeFilter()
    for handler in (file_handler, console_handler):
        handler.setFormatter(log_formatter)
        handler.setLevel(log_level)
        handler.addFilter(line_break_filter)

    for logger in (logging.getLogger(), app.logger, logging.getLogger("werkzeug")):
        for old in logger.handlers:
            old.close()
        logger.handlers.clear()
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.setLevel(log_level)
        logger.propagate = False

    app.logger.info("Logging initialized. Outputting to console and %s", log_file_path)
