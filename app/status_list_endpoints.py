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
import hmac
import logging
import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, jsonify, request, send_file, send_from_directory

from app import list_management
from app.config import CONFIGURATION
from app.list_management import REF_ERRORS, ConflictingRef, IndexOutOfRange, Ref, UnknownEntry, UnknownIdentifier
from app.log_utils import safe
from app import storage
from app.storage import IDENTIFIER_LIST, LIST_KINDS, TOKEN_LIST, CorruptList, ListNotFound

token = Blueprint("token_status_list", __name__, url_prefix="/token_status_list")
identifier = Blueprint("identifier_list", __name__, url_prefix="/identifier_list")
logger = logging.getLogger(__name__)

_LIST_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

#: A non-negative decimal number as written by the issuer: ASCII digits, no
#: sign, spaces or leading zeros.
_NUMBER = re.compile(r"0|[1-9]\d*", re.ASCII)


#: Longest identifier list ``id`` accepted (the service hands out 32 characters).
MAX_IDENTIFIER = 64

#: Media types of the published lists (draft-ietf-oauth-status-list-12 section 8.1).
STATUS_JWT_TYPE = "application/statuslist+jwt"
STATUS_CWT_TYPE = "application/statuslist+cwt"
IDENTIFIER_CWT_TYPE = "application/identifierlist+cwt"

#: Largest request body, in bytes (``MAX_CONTENT_LENGTH``, 413 beyond it).
MAX_BODY = 1024 * 1024

#: Message answered (401) when ``X-Api-Key`` is missing or wrong.
UNAUTHORIZED = "Unauthorized access"


class BadRequest(ValueError):
    """A request value the service rejects with 400."""


class TooLarge(ValueError):
    """A batch the service rejects with 413."""


def api_key_valid() -> bool:
    """Tells whether the request carries the configured ``X-Api-Key``.

    The comparison takes constant time.
    """
    sent = request.headers.get("X-Api-Key", "")
    return hmac.compare_digest(sent.encode(), CONFIGURATION["api_key"].encode())


def _unauthorized():
    """Logs a failed ``X-Api-Key`` check and answers 401."""
    logger.warning("%s: %s %s", UNAUTHORIZED, safe(request.method), safe(request.path))
    return jsonify({"message": UNAUTHORIZED}), 401


def _form():
    """The request form; a malformed body (bad chunked framing) is a :class:`BadRequest`."""
    try:
        return request.form
    except OSError as e:
        raise BadRequest("Malformed request body") from e


def _text(body: str) -> Response:
    """A plain-text success body (``0`` / ``1``, ``Status Changed``)."""
    return Response(body, mimetype="text/plain")


def validate_doctype(user_input):
    """Validate doctype and return the allowed value"""
    if user_input not in CONFIGURATION["allowed_doctypes"]:
        raise ValueError("Invalid document type")

    return next(dt for dt in CONFIGURATION["allowed_doctypes"] if dt == user_input)


def validate_country(user_input):
    """Validate country code and return clean value"""
    if user_input not in CONFIGURATION["countries"]:
        raise ValueError("Invalid country")

    return next(key for key in CONFIGURATION["countries"].keys() if key == user_input)


def validate_expiry_date(user_input):
    """Validate and sanitize expiry date

    Dates are UTC days: today is accepted (the credential is valid until the
    end of the day), and so is any day up to ``max_expiry_days`` from today.
    """
    try:
        parsed_date = datetime.strptime(user_input, "%Y-%m-%d")
    except (ValueError, TypeError):
        raise ValueError("Invalid expiry date format. Use YYYY-MM-DD.")

    today = datetime.now(timezone.utc).date()
    if parsed_date.date() < today:
        raise ValueError("Expiry date must be in the future.")
    if parsed_date.date() > today + timedelta(days=CONFIGURATION["max_expiry_days"]):
        raise ValueError(f"Expiry date must be at most {CONFIGURATION['max_expiry_days']} days from today.")

    # Return clean date string from parsed date
    return parsed_date.strftime("%Y-%m-%d")


def parse_list_uri(uri) -> tuple[str, str, str, str]:
    """Splits a list URI handed out by this service.

    It must be ``<service_url><kind>/<CC>/<doctype>/<id>``: a configured
    country, an allowed doctype and a list id, nothing else, spelled as
    ``/take`` handed it out (no percent-encoding).

    Returns:
        ``(kind, country, doctype, list_id)``.

    Raises:
        BadRequest: Any other URI.
    """
    prefix = CONFIGURATION["service_url"]
    if not isinstance(uri, str) or not uri.startswith(prefix) or "?" in uri or "#" in uri:
        raise BadRequest("uri is not a list of this service")
    parts = uri[len(prefix):].split("/")
    if len(parts) != 4 or parts[0] not in LIST_KINDS or not _LIST_ID.fullmatch(parts[3]):
        raise BadRequest("uri is not a list of this service")
    kind, country, doctype, list_id = parts
    try:
        return kind, validate_country(country), validate_doctype(doctype), list_id
    except ValueError as e:
        raise BadRequest(str(e)) from e


def parse_number(value) -> int | None:
    """A non-negative integer: a JSON integer or a canonical decimal string, else ``None``."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if value >= 0 else None
    if isinstance(value, str) and _NUMBER.fullmatch(value):
        return int(value)
    return None


def parse_index(value) -> int:
    """A non-negative integer index (the upper bound is checked against the list)."""
    index = parse_number(value)
    if index is None:
        raise BadRequest("'idx' must be a non-negative integer")
    return index


def parse_identifier(value) -> str:
    """An identifier list ``id``: an opaque string, not an index."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_IDENTIFIER:
        raise BadRequest(f"'id' must be a string of 1 to {MAX_IDENTIFIER} characters")
    return value


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _entry_error(error: Exception) -> tuple[str, int]:
    """Message and status code of an error naming an entry."""
    if isinstance(error, (BadRequest, IndexOutOfRange, ConflictingRef)):
        return str(error), 400
    if isinstance(error, ListNotFound):
        return "Unknown list", 404
    if isinstance(error, (UnknownIdentifier, UnknownEntry)):
        return str(error), 404
    return "List unavailable", 500


def _form_pointer(values) -> tuple[int | None, str | None]:
    """``idx`` and ``id`` of a form or query (empty values count as absent)."""
    index = values.get("idx") or None
    identifier = values.get("id") or None
    return None if index is None else parse_index(index), None if identifier is None else parse_identifier(identifier)


def _batch_body() -> dict:
    """The JSON object of a batch request (at most :data:`MAX_BODY` bytes, else 413)."""
    if not request.is_json:
        raise BadRequest("Content-Type must be application/json")
    try:
        body = request.get_json(silent=True)
    except RecursionError:
        body = None
    except OSError as e:
        raise BadRequest("Malformed request body") from e
    if not isinstance(body, dict):
        raise BadRequest("body must be a JSON object")
    return body


def _batch_size(size: int, name: str) -> None:
    """Rejects an empty batch (400) or one over ``batch_max_size`` (413)."""
    if size < 1:
        raise BadRequest(f"{name} must be at least 1")
    if size > CONFIGURATION["batch_max_size"]:
        raise TooLarge(f"{name} must be at most {CONFIGURATION['batch_max_size']}")


def _take_fields(values) -> tuple[str, str, str]:
    """``(doctype, country, expiry_date)`` of a take request, validated.

    Raises:
        ValueError: A missing or invalid field.
    """
    fields = []
    for name in ("doctype", "country", "expiry_date"):
        value = values.get(name)
        if not isinstance(value, str):
            raise ValueError(f"Missing {name}")
        fields.append(value)
    doctype, country, expiry_date = fields
    return validate_doctype(doctype), validate_country(country), validate_expiry_date(expiry_date)


@token.route("/take", methods=["POST"])
def take_index():
    # The key is checked before the body is read.
    if not api_key_valid():
        return _unauthorized()

    try:
        form = _form()
        logger.info("Take request, payload: %s", safe(form.to_dict()))
        doctype, country, expiry_date = _take_fields(form)
    except ValueError as e:
        logger.warning(str(e))
        return _error(str(e), 400)

    status_info = list_management.take(country, doctype, expiry_date)
    logger.debug("Status info: %s", status_info)
    return jsonify(status_info)


@token.route("/take/batch", methods=["POST"])
def take_batch():
    """Takes ``count`` indices of one country, doctype and expiry date (JSON body)."""
    if not api_key_valid():
        return _unauthorized()

    try:
        body = _batch_body()
        logger.info("Take batch request, payload: %s", safe(body))
        doctype, country, expiry_date = _take_fields(body)
        count = body.get("count")
        if isinstance(count, bool) or not isinstance(count, int):
            raise BadRequest("count must be an integer")
        _batch_size(count, "count")
    except TooLarge as e:
        return _error(str(e), 413)
    except ValueError as e:
        logger.warning(str(e))
        return _error(str(e), 400)

    items = list_management.take_many(country, doctype, expiry_date, count)
    logger.debug("Took %s indices", len(items))
    return jsonify({"items": items})


@token.route("/get", methods=["GET"])
def get_index():

    logger.debug("Get request, args: %s", safe(request.args.to_dict()))

    uri = request.args.get("uri")
    if uri is None or not (request.args.get("id") or request.args.get("idx")):
        return _error("Missing URI or idx/id", 400)

    try:
        index, identifier = _form_pointer(request.args)
        kind, country, doctype, list_id = parse_list_uri(uri)
        return _text(str(list_management.read_status(kind, country, doctype, list_id, index, identifier)))
    except (BadRequest, *REF_ERRORS) as e:
        message, status = _entry_error(e)
        if status == 500:
            logger.exception("Unreadable list %s", safe(uri))
        return _error(message, status)


@token.route("/set", methods=["POST"])
def set_index():
    if not api_key_valid():
        return _unauthorized()

    try:
        form = _form()
    except BadRequest as e:
        return _error(str(e), 400)
    uri = form.get("uri")
    status = form.get("status")
    if uri is None or not (form.get("id") or form.get("idx")) or status is None:
        return _error("Missing URI/index/status", 400)

    try:
        index, identifier = _form_pointer(form)
        # Only revocation (1) is supported, written exactly as "1".
        if status != "1":
            return _error("Wrong Status Change", 400)
        # Either URI of a list (token or identifier list) names the same entries.
        _, country, doctype, list_id = parse_list_uri(uri)
        list_management.revoke(country, doctype, list_id, index, identifier)
    except (BadRequest, *REF_ERRORS) as e:
        message, status = _entry_error(e)
        if status == 500:
            logger.exception("Unreadable list %s", safe(uri))
        else:
            logger.warning(message)
        return _error(message, status)

    return _text("Status Changed\n")


def _parse_ref(ref) -> Ref:
    """The entry one ref of a revoke batch names."""
    if not isinstance(ref, dict):
        raise BadRequest("must be an object with 'uri' and 'idx' or 'id'")
    uri, index, identifier = ref.get("uri"), ref.get("idx"), ref.get("id")
    if uri is None or (index is None and identifier is None):
        raise BadRequest("Missing URI or idx/id")
    if index is not None:
        index = parse_index(index)
    if identifier is not None:
        identifier = parse_identifier(identifier)
    # Either URI of a list (token or identifier list) names the same entries.
    _, country, doctype, list_id = parse_list_uri(uri)
    return Ref(country, doctype, list_id, index, identifier)


@token.route("/set/batch", methods=["POST"])
def set_batch():
    """Revokes every entry of ``refs``, all or none (JSON body)."""
    if not api_key_valid():
        return _unauthorized()

    try:
        refs = _batch_body().get("refs")
        if not isinstance(refs, list):
            raise BadRequest("refs must be a list")
        _batch_size(len(refs), "refs")
        parsed = []
        for position, ref in enumerate(refs):
            try:
                parsed.append(_parse_ref(ref))
            except BadRequest as e:
                raise BadRequest(f"refs[{position}]: {e}") from e
        revoked = list_management.revoke_many(parsed)
    except TooLarge as e:
        return _error(str(e), 413)
    except BadRequest as e:
        logger.warning(str(e))
        return _error(str(e), 400)
    except REF_ERRORS as e:
        message, status = _entry_error(e)
        if status == 500:
            logger.exception("Unreadable list in refs[%s]", e.position)
        else:
            logger.warning("refs[%s]: %s", e.position, message)
        return _error(f"refs[{e.position}]: {message}", status)

    return jsonify({"revoked": revoked})


def _published_list(kind: str, country: str, doctype: str, list_id: str, name: str, media_type: str):
    """Answers one signed list from ``status_list_dir`` (404 when it is not published).

    Only the published JWT / CWT files are served, never ``full_list.json``
    or ``state/``. ``ETag`` / ``Last-Modified`` allow 304 answers; the list's
    own ``ttl`` tells clients how long to cache it.
    """
    try:
        validate_country(country)
        validate_doctype(doctype)
    except ValueError:
        return _error("Unknown list", 404)
    path = storage.list_dir(kind, country, doctype, list_id) / name
    if not _LIST_ID.fullmatch(list_id) or not path.is_file():
        return _error("Unknown list", 404)
    response = send_file(path, mimetype=media_type, conditional=True)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@token.route("/<country>/<doctype>/<list_id>", methods=["GET"])
def token_status_list(country, doctype, list_id):
    """The status list: a JWT, or a CWT when ``Accept`` asks for it."""
    if STATUS_CWT_TYPE in request.headers.get("Accept", ""):
        name, media_type = storage.STATUS_CWT, STATUS_CWT_TYPE
    else:
        name, media_type = storage.STATUS_JWT, STATUS_JWT_TYPE
    response = _published_list(TOKEN_LIST, country, doctype, list_id, name, media_type)
    if isinstance(response, Response):
        response.vary.add("Accept")
    return response


@identifier.route("/<country>/<doctype>/<list_id>", methods=["GET"])
def identifier_list(country, doctype, list_id):
    """The identifier list, a CWT."""
    return _published_list(IDENTIFIER_LIST, country, doctype, list_id, storage.IDENTIFIER_CWT, IDENTIFIER_CWT_TYPE)


@token.route("/static/swagger.json", methods=["GET"])
def swagger_static():
    return send_from_directory("static", "swagger.json")
