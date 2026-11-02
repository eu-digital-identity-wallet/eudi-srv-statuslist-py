"""Application factory, logging and log helpers."""

from __future__ import annotations

import logging
import re

import pytest

import app as app_package
from app import config as app_config
from app.log_utils import safe
from app.logging_setup import LineBreakEscapeFilter, SafeTracebackFormatter


class TestCreateApp:
    def test_debug_off_by_default(self, client):
        assert client.application.debug is False

    def test_debug_from_configuration(self, configuration, client_factory):
        configuration["debug"] = True
        assert client_factory().debug is True

    def test_swagger_points_to_service_url(self, client):
        response = client.get("/token_status_list/swagger/")
        assert response.status_code == 200
        assert b"https://statuslist.test/token_status_list/static/swagger.json" in response.data

    def test_swagger_json(self, client):
        response = client.get("/token_status_list/static/swagger.json")
        assert response.status_code == 200
        assert "/token_status_list/take" in response.json["paths"]

    def test_swagger_json_documents_every_route(self, client):
        """Every route is documented with the statuses it answers, and every $ref resolves."""
        spec = client.get("/token_status_list/static/swagger.json").json
        assert "servers" not in spec  # relative to the host serving it
        routes = {
            (re.sub(r"<(\w+)>", r"{\1}", rule.rule), method.lower())
            for rule in client.application.url_map.iter_rules()
            if rule.rule.startswith(("/token_status_list/", "/identifier_list/"))
            and "static" not in rule.rule
            and "swagger" not in rule.rule
            for method in rule.methods - {"HEAD", "OPTIONS"}
        }
        documented = {(path, method) for path, item in spec["paths"].items() for method in item}
        assert documented == routes
        statuses = {
            "/token_status_list/get": {"200", "400", "404", "500"},
            "/token_status_list/take": {"200", "400", "401", "413", "500"},
            "/token_status_list/take/batch": {"200", "400", "401", "413", "500"},
            "/token_status_list/set": {"200", "400", "401", "404", "413", "500"},
            "/token_status_list/set/batch": {"200", "400", "401", "404", "413", "500"},
            "/token_status_list/{country}/{doctype}/{list_id}": {"200", "304", "404"},
            "/identifier_list/{country}/{doctype}/{list_id}": {"200", "304", "404"},
        }
        for path, method in routes:
            operation = spec["paths"][path][method]
            assert set(operation["responses"]) == statuses[path], path
            if "401" in statuses[path]:
                assert {"$ref": "#/components/parameters/ApiKey"} in operation["parameters"]

        def refs(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    yield value["$ref"]
                for item in value.values():
                    yield from refs(item)
            elif isinstance(value, list):
                for item in value:
                    yield from refs(item)

        for target in refs(spec):
            node = spec
            for part in target.removeprefix("#/").split("/"):
                node = node[part]

    @pytest.mark.parametrize("key", [None, "", "test", "secret", "short-key"])
    def test_weak_api_key_rejected_outside_tests(self, configuration, monkeypatch, key):
        configuration["api_key"] = key
        monkeypatch.setattr(app_config, "IS_TEST_ENV", False)
        with pytest.raises(RuntimeError, match="api_key must be set"):
            app_package.create_app()

    def test_weak_api_key_accepted_in_tests(self, configuration, client_factory):
        configuration["api_key"] = "test"
        assert client_factory()

    def test_missing_api_key_rejected_in_tests(self, configuration, client_factory):
        configuration["api_key"] = ""
        with pytest.raises(RuntimeError, match="api_key must be set"):
            client_factory()

    def test_renewal_thread_only_outside_tests(self, monkeypatch):
        started = []
        monkeypatch.setattr(app_package, "start_renewal_thread", lambda: started.append(True))
        monkeypatch.setattr(app_config, "IS_TEST_ENV", True)
        app_package.create_app()
        assert started == []
        monkeypatch.setattr(app_config, "IS_TEST_ENV", False)
        app_package.create_app()
        assert started == [True]


@pytest.fixture
def client_factory(monkeypatch):
    monkeypatch.setattr(app_config, "IS_TEST_ENV", True)
    return app_package.create_app


class TestLogging:
    def test_log_file_created_and_written(self, configuration, client):
        logging.getLogger("app.test").info("hello\nforged")
        for handler in logging.getLogger().handlers:
            handler.flush()
        text = open(configuration["logging"]["path"]).read()
        assert "Logging initialized" in text
        assert "hello\\nforged" in text

    def test_level_from_configuration(self, configuration, client_factory):
        configuration["logging"]["log_level"] = "warning"
        client_factory()
        assert logging.getLogger().level == logging.WARNING

    def test_line_break_filter(self):
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "a %s", ("b\r\nc",), None)
        assert LineBreakEscapeFilter().filter(record) is True
        assert record.getMessage() == "a b\\r\\nc"

    def test_line_break_filter_leaves_plain_messages(self):
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "a %s", ("b",), None)
        LineBreakEscapeFilter().filter(record)
        assert record.args == ("b",)

    def test_tracebacks_are_indented(self):
        formatter = SafeTracebackFormatter("%(message)s")
        try:
            raise ValueError("bad\nline")
        except ValueError:
            record = logging.LogRecord("x", logging.ERROR, __file__, 1, "m", None, __import__("sys").exc_info())
        lines = formatter.format(record).split("\n")
        assert lines[0] == "m"
        assert all(line.startswith("    | ") for line in lines[1:])
        assert formatter.formatStack("a\nb") == "    | a\n    | b"


class TestSafe:
    def test_escapes_line_breaks_and_controls(self):
        assert safe("a\r\nb\tc\x00") == "a\\r\\nb\\tc?"

    def test_truncates(self):
        assert safe("x" * 10, limit=4) == "xxxx...(+6 chars)"
