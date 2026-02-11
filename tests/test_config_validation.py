"""Tests for secret name validation in config loading."""

import json
import tempfile
from pathlib import Path

import pytest

from secrets_proxy.config import load_config, validate_secret_name


class TestValidateSecretName:
    """Test the validate_secret_name helper directly."""

    @pytest.mark.parametrize(
        "name",
        [
            "MY_API_KEY",
            "_SECRET",
            "key123",
            "A",
            "_",
            "_123",
            "OPENAI_API_KEY",
            "a_b_c_d",
        ],
    )
    def test_valid_names(self, name: str) -> None:
        # Should not raise
        validate_secret_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "MY KEY",       # space
            "key;rm",       # semicolon (shell injection)
            "123key",       # starts with digit
            "key=val",      # equals sign
            "key\nval",     # newline
            "",             # empty
            "key$(cmd)",    # command substitution
            "key`cmd`",     # backtick command substitution
            "key|pipe",     # pipe
            "key&bg",       # background
        ],
    )
    def test_invalid_names(self, name: str) -> None:
        with pytest.raises(ValueError, match="Invalid secret name"):
            validate_secret_name(name)


def _write_config(secrets_dict: dict, tmp_path: Path) -> Path:
    """Helper: write a secrets.json config file and return its path."""
    config_path = tmp_path / "secrets.json"
    config_path.write_text(json.dumps(secrets_dict))
    return config_path


class TestLoadConfigValidation:
    """Test that load_config rejects invalid secret names."""

    def test_load_config_valid_name(self, tmp_path: Path) -> None:
        config_path = _write_config(
            {
                "MY_API_KEY": {
                    "value": "sk-test-12345",
                    "hosts": ["api.example.com"],
                }
            },
            tmp_path,
        )
        config = load_config(config_path)
        assert "MY_API_KEY" in config.secrets

    def test_load_config_rejects_shell_injection(self, tmp_path: Path) -> None:
        config_path = _write_config(
            {
                "MY_KEY; rm -rf /": {
                    "value": "sk-test-12345",
                    "hosts": ["api.example.com"],
                }
            },
            tmp_path,
        )
        with pytest.raises(ValueError, match="Invalid secret name"):
            load_config(config_path)

    def test_load_config_rejects_space_in_name(self, tmp_path: Path) -> None:
        config_path = _write_config(
            {
                "MY KEY": {
                    "value": "sk-test-12345",
                    "hosts": ["api.example.com"],
                }
            },
            tmp_path,
        )
        with pytest.raises(ValueError, match="Invalid secret name"):
            load_config(config_path)

    def test_load_config_rejects_digit_start(self, tmp_path: Path) -> None:
        config_path = _write_config(
            {
                "123key": {
                    "value": "sk-test-12345",
                    "hosts": ["api.example.com"],
                }
            },
            tmp_path,
        )
        with pytest.raises(ValueError, match="Invalid secret name"):
            load_config(config_path)

    def test_load_config_rejects_equals(self, tmp_path: Path) -> None:
        config_path = _write_config(
            {
                "key=val": {
                    "value": "sk-test-12345",
                    "hosts": ["api.example.com"],
                }
            },
            tmp_path,
        )
        with pytest.raises(ValueError, match="Invalid secret name"):
            load_config(config_path)
