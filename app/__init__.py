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
"""Flask application factory of the Status List service."""

import click
from flask import Flask, jsonify
from flask_swagger_ui import get_swaggerui_blueprint
from werkzeug.exceptions import HTTPException

from app import config as app_config
from app.config import CONFIGURATION
from app.lists_renewal import renew_lists, start_renewal_thread
from app.logging_setup import configure_logging

#: Publicly known or example API keys rejected at start-up.
WEAK_API_KEYS = frozenset({"test", "dev", "change-me", "changeme", "secret"})
_MIN_API_KEY_LENGTH = 32


def _check_api_key() -> None:
    """Makes sure ``api_key`` (sent by the issuer as ``X-Api-Key``) is a real secret.

    Raises:
        RuntimeError: Outside tests, when the key is missing, publicly known
            or shorter than 32 characters.
    """
    key = CONFIGURATION.get("api_key")
    if isinstance(key, str) and key not in WEAK_API_KEYS and len(key) >= _MIN_API_KEY_LENGTH:
        return
    if app_config.IS_TEST_ENV and isinstance(key, str) and key:
        return
    raise RuntimeError(
        f"api_key must be set in the configuration to a random value of at least {_MIN_API_KEY_LENGTH} characters"
    )


def create_app():
    """Creates the application.

    Returns:
        The configured Flask application. Outside tests it also starts the
        list renewal thread. The lists are kept on disk under a lock, so
        several processes may serve the same ``status_list_dir``.
    """
    from app import status_list_endpoints

    app = Flask(__name__)
    app.debug = bool(CONFIGURATION["debug"])
    # Every body is bounded (413 beyond it), whether or not it is read.
    app.config["MAX_CONTENT_LENGTH"] = status_list_endpoints.MAX_BODY

    configure_logging(app, CONFIGURATION["logging"])
    _check_api_key()

    SWAGGER_URL = "/token_status_list/swagger"
    API_URL = CONFIGURATION["service_url"] + "token_status_list/static/swagger.json"
    swagger_ui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL, API_URL,
        config={"app_name": "Status List API"}
    )

    # Register blueprints
    app.register_blueprint(status_list_endpoints.token)
    app.register_blueprint(status_list_endpoints.identifier)
    app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

    @app.errorhandler(HTTPException)
    def http_error(error):
        """Errors as JSON (``{"error": ...}``), never an HTML page.

        The exception's own headers (``Allow`` on a 405, ...) are kept.
        """
        headers = [(name, value) for name, value in error.get_headers() if name.lower() != "content-type"]
        return jsonify({"error": error.description or error.name}), error.code, headers

    @app.errorhandler(Exception)
    def server_error(error):
        app.logger.exception("Unhandled error")
        return jsonify({"error": "Internal server error"}), 500

    @app.cli.command("renew-lists")
    def renew_lists_command():
        """Re-signs every list now (repairs damaged JWT / CWT files)."""
        report = renew_lists()
        for key in ("renewed", "removed", "corrupt", "failed"):
            click.echo(f"{key}: {len(report[key])}")
            for name in report[key] if key in ("corrupt", "failed") else ():
                click.echo(f"  {name}")
        if report["corrupt"] or report["failed"]:
            raise SystemExit(1)

    if not app_config.IS_TEST_ENV:
        start_renewal_thread()

    return app
