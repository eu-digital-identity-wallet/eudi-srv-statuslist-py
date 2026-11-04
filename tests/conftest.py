"""Shared fixtures: a configuration with temporary directories and a signer."""

from __future__ import annotations

import pytest

from app import config as app_config
from tests.config_helpers import set_configuration
from tests.pki_helpers import Signer, make_signer

API_KEY = "k" * 40
PID = "eu.europa.ec.eudi.pid.1"
MDL = "org.iso.18013.5.1.mDL"


@pytest.fixture(scope="session")
def signer(tmp_path_factory) -> Signer:
    """One signer for the whole run (key generation is the slow part)."""
    return make_signer(tmp_path_factory.mktemp("pki"), "lu")


@pytest.fixture(autouse=True)
def configuration(monkeypatch, tmp_path, signer):
    """Configuration of every test: FC and LU share one signer, lists in tmp_path.

    Every test starts with an empty ``status_list_dir``.

    Yields:
        The configuration dictionary (tests may change it).
    """
    config = app_config.apply_defaults(
        {
            "service_url": "https://statuslist.test",
            "api_key": API_KEY,
            "status_list_dir": str(tmp_path / "lists"),
            "backup_dir": str(tmp_path / "backup"),
            "logging": {"path": str(tmp_path / "log" / "status_lists.log")},
            # Most tests take indices expiring in 2099.
            "max_expiry_days": 36500,
            "countries": {
                cc: {"private_key_path": str(signer.key_path), "certificate_path": str(signer.cert_path)}
                for cc in ("FC", "LU")
            },
        }
    )
    app_config.process_config(config)
    set_configuration(monkeypatch, config)
    yield config


@pytest.fixture
def client(monkeypatch):
    """Test client of a fresh application (renewal thread never started)."""
    monkeypatch.setattr(app_config, "IS_TEST_ENV", True)
    from app import create_app

    application = create_app()
    application.testing = True
    return application.test_client()


@pytest.fixture
def headers():
    """Headers with the configured API key."""
    return {"X-Api-Key": API_KEY}
