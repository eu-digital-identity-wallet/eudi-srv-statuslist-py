"""YAML configuration loading (app/config.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from app import config as app_config
from app.config import apply_defaults, load_config, mock_config, resolve_variables
from tests.pki_helpers import make_signer

EXAMPLE = Path(__file__).resolve().parent.parent / "app" / "config_statuslist_example.yaml"


def write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return str(path)


def signer_yaml(signer, country: str = "FC") -> str:
    return (
        "countries:\n"
        f"  {country}:\n"
        f"    private_key_path: {signer.key_path}\n"
        f"    certificate_path: {signer.cert_path}\n"
    )


class TestResolveVariables:
    def test_substitutes_nested_values_and_earlier_variables(self):
        config = resolve_variables(
            {
                "variables": {"base": "/keys", "lu": "${base}/lu.pem"},
                "countries": {"FC": {"private_key_path": "${lu}"}},
                "list": ["${base}/a", 3],
            }
        )
        assert "variables" not in config
        assert config["countries"]["FC"]["private_key_path"] == "/keys/lu.pem"
        assert config["list"] == ["/keys/a", 3]

    def test_undefined_variable(self):
        with pytest.raises(RuntimeError, match=r"Undefined config variable: \$\{missing\}"):
            resolve_variables({"service_url": "${missing}"})

    def test_variables_must_be_a_mapping(self):
        with pytest.raises(RuntimeError, match="must be a mapping"):
            resolve_variables({"variables": ["a"]})

    def test_variables_must_be_strings(self):
        with pytest.raises(RuntimeError, match="'port' must be a string"):
            resolve_variables({"variables": {"port": 5000}})


class TestApplyDefaults:
    def test_defaults_fill_missing_keys(self):
        config = apply_defaults({})
        assert config["debug"] is False
        assert config["token_status_list_size"] == 10000
        assert config["renewal"] == {"hours": [0, 12]}
        assert config["service_url"] == "https://dev.issuer.eudiw.dev/"

    def test_sections_are_merged_and_url_gets_a_slash(self):
        config = apply_defaults({"service_url": "http://x", "logging": {"log_level": "DEBUG"}})
        assert config["service_url"] == "http://x/"
        assert config["logging"]["log_level"] == "DEBUG"
        assert config["logging"]["backup_count"] == 7

    def test_defaults_are_not_shared(self):
        apply_defaults({})["logging"]["path"] = "/changed"
        assert apply_defaults({})["logging"]["path"] != "/changed"

    def test_tax_doctypes_are_separate(self):
        doctypes = apply_defaults({})["allowed_doctypes"]
        assert "urn:eu.europa.ec.eudi:tax:1" in doctypes
        assert "urn:eu.europa.ec.eudi:tax:1:1" in doctypes

    def test_doctypes_the_issuer_offers(self):
        doctypes = apply_defaults({})["allowed_doctypes"]
        assert "urn:eu.europa.ec.eudi:learning:credential:1" in doctypes
        assert "org.iso.7367.2.1.mVC" in doctypes

    @pytest.mark.parametrize("doctype", ["key-attestation+jwt", "wrprc", "oauth-client-attestation+jwt"])
    def test_attestation_types(self, doctype):
        assert doctype in apply_defaults({})["allowed_doctypes"]


class TestLoadConfig:
    def test_loads_keys_and_certificate(self, tmp_path, signer):
        path = write(tmp_path, "api_key: abc\n" + signer_yaml(signer))
        config = load_config(path)
        entry = config["countries"]["FC"]
        assert entry["certificate"] == signer.certificate.public_bytes(serialization.Encoding.DER)
        assert entry["private_key"].public_key().public_numbers() == signer.private_key.public_key().public_numbers()

    def test_path_from_environment(self, tmp_path, signer, monkeypatch):
        monkeypatch.setenv("STATUS_LIST_CONFIG_PATH", write(tmp_path, signer_yaml(signer, "LU")))
        assert list(load_config()["countries"]) == ["LU"]

    def test_encrypted_key_and_pem_certificate(self, tmp_path):
        signer = make_signer(tmp_path, "enc", password="pw", pem_certificate=True)
        path = write(tmp_path, signer_yaml(signer) + "    private_key_password: pw\n")
        assert load_config(path)["countries"]["FC"]["certificate"] == signer.certificate.public_bytes(
            serialization.Encoding.DER
        )

    def test_wrong_password(self, tmp_path):
        signer = make_signer(tmp_path, "enc", password="pw")
        path = write(tmp_path, signer_yaml(signer) + "    private_key_password: other\n")
        with pytest.raises(RuntimeError, match="Cannot load the private key of country FC"):
            load_config(path)

    def test_missing_key_file(self, tmp_path, signer):
        path = write(tmp_path, signer_yaml(signer).replace(str(signer.key_path), "/nonexistent.pem"))
        with pytest.raises(RuntimeError, match="Cannot load the private key"):
            load_config(path)

    def test_certificate_not_a_certificate(self, tmp_path, signer):
        path = write(tmp_path, signer_yaml(signer).replace(str(signer.cert_path), str(signer.key_path)))
        with pytest.raises(RuntimeError, match="Cannot load the certificate of country FC"):
            load_config(path)

    def test_incomplete_country(self, tmp_path):
        path = write(tmp_path, "countries:\n  FC:\n    private_key_path: /a\n")
        with pytest.raises(RuntimeError, match="Country FC needs private_key_path and certificate_path"):
            load_config(path)

    @pytest.mark.parametrize("text", ["service_url: http://x\n", "countries: {}\n", "countries: [FC]\n"])
    def test_countries_required(self, tmp_path, text):
        with pytest.raises(RuntimeError, match="'countries' must map at least one country"):
            load_config(write(tmp_path, text))

    def test_missing_file(self, tmp_path):
        with pytest.raises(RuntimeError, match="Config file not found"):
            load_config(str(tmp_path / "absent.yaml"))

    def test_invalid_yaml(self, tmp_path):
        with pytest.raises(RuntimeError, match="Invalid YAML"):
            load_config(write(tmp_path, "a: [1,\n"))

    def test_empty_file(self, tmp_path):
        with pytest.raises(RuntimeError, match="Config file is empty"):
            load_config(write(tmp_path, ""))

    def test_not_a_mapping(self, tmp_path):
        with pytest.raises(RuntimeError, match="must hold a mapping"):
            load_config(write(tmp_path, "- a\n- b\n"))

    def test_example_configuration_parses(self, tmp_path, signer, monkeypatch):
        """The example only fails on its (absent) production key files."""
        with pytest.raises(RuntimeError, match="Cannot load the private key of country FC: /etc/eudiw/pid-issuer/privKey/PID-DS-0001_LU.pem"):
            load_config(str(EXAMPLE))


def test_mock_config():
    config = mock_config()
    assert config["countries"] == {}
    assert config["service_url"] == "https://statuslist.test/"
    assert config["api_key"]


@pytest.mark.parametrize("value,expected", [("true", True), ("1", False), ("", False)])
def test_detect_test_env(monkeypatch, value, expected):
    monkeypatch.setenv(app_config.TEST_ENV_VARIABLE, value)
    assert app_config._detect_test_env() is expected


class TestCheckSettings:
    @pytest.mark.parametrize(
        "setting",
        [
            {"status_list_ttl": True},
            {"max_expiry_days": 0},
            {"status_list_validity": "1d"},
            {"status_list_validity": 13 * 3600},  # 12 h between [0, 12] renewals + 1 h
            {"renewal": {"hours": [6, 6]}},
            {"renewal": {"hours": [1.5]}},
            {"renewal": {"hours": "0,12"}},
            {"token_status_list_size": -8},
        ],
    )
    def test_invalid(self, setting):
        with pytest.raises(RuntimeError, match="Config '"):
            app_config.check_settings(apply_defaults(setting))

    def test_validity_follows_the_renewal_hours(self):
        app_config.check_settings(apply_defaults({"status_list_validity": 13 * 3600 + 1}))
        with pytest.raises(RuntimeError, match="status_list_validity"):
            app_config.check_settings(apply_defaults({"renewal": {"hours": [3]}}))  # 24 h gap
        app_config.check_settings(apply_defaults({"renewal": {"hours": [3]}, "status_list_validity": 25 * 3600 + 1}))

    @pytest.mark.parametrize("hours,gap", [([0, 12], 12), ([3], 24), ([22, 2, 10], 12), ([0, 1, 23], 22)])
    def test_longest_renewal_gap(self, hours, gap):
        assert app_config.longest_renewal_gap(hours) == gap


def test_expired_certificate_is_only_a_warning(tmp_path, caplog):
    signer = make_signer(tmp_path, "old", expired=True)
    entry = {"private_key_path": str(signer.key_path), "certificate_path": str(signer.cert_path)}
    app_config.load_signer("XX", entry)
    assert entry["certificate"]
    assert "The certificate of country XX is not valid now" in caplog.text
