# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
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
"""Helpers to log request data safely.

:func:`safe` neutralizes log injection (CR / LF and other control
characters) and bounds the length of any value taken from a request.
Request headers (they carry ``X-Api-Key``) must never be logged.
"""

from __future__ import annotations

import re
from typing import Any

DEFAULT_LIMIT = 200

#: Control characters left after CR / LF / TAB are escaped.
_OTHER_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def safe(value: Any, limit: int = DEFAULT_LIMIT) -> str:
    """Renders a value for a log line without allowing log injection.

    Args:
        value: Any value (typically request-supplied).
        limit: Maximum number of characters kept.

    Returns:
        A single-line string: CR / LF / TAB are escaped, other control
        characters replaced by ``?``, and long values truncated with the
        number of omitted characters.
    """
    # Line breaks first, with str.replace: no request value can start a new log line.
    text = str(value).replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    text = _OTHER_CONTROL_CHARS.sub("?", text)
    if len(text) > limit:
        return f"{text[:limit]}...(+{len(text) - limit} chars)"
    return text
