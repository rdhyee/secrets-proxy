"""Tests for addon_entry.py env loading and config roundtrip (#36)."""

from __future__ import annotations

import json
import os

import pytest

from secrets_proxy.config import (
    ProxyConfig,
    SecretEntry,
    load_config_from_dict,
)


class TestToEnvJson:
    """Test ProxyConfig.to_env_json() serialization."""

    def test_roundtrip_single_secret(self):
        raw = {
            "MY_KEY": {
                "value": "sk-real",
                "hosts": ["api.example.com"],
            }
        }
        config = load_config_from_dict(raw)
        env_json = config.to_env_json()
        data = json.loads(env_json)

        assert "secrets" in data
        assert "allowed_hosts" in data
        assert "api.example.com" in data["allowed_hosts"]

        # Exactly one secret, keyed by placeholder
        assert len(data["secrets"]) == 1
        placeholder = list(data["secrets"].keys())[0]
        assert placeholder.startswith("SECRETS_PROXY_PLACEHOLDER_")
        info = data["secrets"][placeholder]
        assert info["name"] == "MY_KEY"
        assert info["value"] == "sk-real"
        assert info["hosts"] == ["api.example.com"]

    def test_roundtrip_multiple_secrets(self):
        raw = {
            "KEY_A": {"value": "val-a", "hosts": ["a.com"]},
            "KEY_B": {"value": "val-b", "hosts": ["b.com", "*.b.com"]},
        }
        config = load_config_from_dict(raw)
        data = json.loads(config.to_env_json())
        assert len(data["secrets"]) == 2
        names = {s["name"] for s in data["secrets"].values()}
        assert names == {"KEY_A", "KEY_B"}

    def test_allowed_hosts_sorted(self):
        raw = {
            "Z": {"value": "v", "hosts": ["z.com"]},
            "A": {"value": "v", "hosts": ["a.com"]},
        }
        config = load_config_from_dict(raw)
        data = json.loads(config.to_env_json())
        assert data["allowed_hosts"] == sorted(data["allowed_hosts"])


class TestLoadConfigFromDict:
    """Test load_config_from_dict matches load_config behavior."""

    def test_basic_load(self):
        raw = {
            "SECRET": {
                "value": "real-value",
                "hosts": ["api.example.com"],
            }
        }
        config = load_config_from_dict(raw)
        assert "SECRET" in config.secrets
        assert config.secrets["SECRET"].value == "real-value"
        assert "api.example.com" in config.allowed_hosts

    def test_preserves_placeholder(self):
        raw = {
            "KEY": {
                "value": "val",
                "hosts": ["h.com"],
                "placeholder": "CUSTOM_PLACEHOLDER_123",
            }
        }
        config = load_config_from_dict(raw)
        assert config.secrets["KEY"].placeholder == "CUSTOM_PLACEHOLDER_123"

    def test_invalid_name_rejected(self):
        raw = {"bad;name": {"value": "v", "hosts": ["h.com"]}}
        with pytest.raises(ValueError, match="Invalid secret name"):
            load_config_from_dict(raw)

    def test_missing_hosts_rejected(self):
        raw = {"KEY": {"value": "v"}}
        with pytest.raises(ValueError, match="missing required key 'hosts'"):
            load_config_from_dict(raw)

    def test_allow_net_extra_hosts(self):
        raw = {"KEY": {"value": "v", "hosts": ["a.com"]}}
        config = load_config_from_dict(raw, allow_net=["extra.com"])
        assert "extra.com" in config.allowed_hosts
        assert "a.com" in config.allowed_hosts


class TestAddonEntryLoadConfig:
    """Test _load_config_from_env from addon_entry.

    Note: addon_entry.py runs _load_config_from_env() at module level on
    first import. We need to set the env var *before* triggering import,
    and we need to reimport for each test that needs fresh module state.
    """

    def _fresh_load(self, monkeypatch, env_json: str) -> ProxyConfig:
        """Set env var and reimport addon_entry to get a fresh _load_config_from_env call."""
        import sys
        import importlib

        monkeypatch.setenv("SECRETS_PROXY_CONFIG_JSON", env_json)

        # Remove cached module so reimport triggers module-level code
        for mod_name in list(sys.modules):
            if mod_name == "secrets_proxy.addon_entry" or mod_name.startswith("secrets_proxy.addon_entry."):
                del sys.modules[mod_name]

        mod = importlib.import_module("secrets_proxy.addon_entry")
        # The module-level config is what _load_config_from_env produced
        return mod.config

    def test_loads_from_env_and_clears(self, monkeypatch):
        raw = {
            "MY_KEY": {"value": "sk-real", "hosts": ["api.example.com"]}
        }
        config = load_config_from_dict(raw)
        env_json = config.to_env_json()

        loaded = self._fresh_load(monkeypatch, env_json)

        # Env var should be cleared after module init
        assert "SECRETS_PROXY_CONFIG_JSON" not in os.environ

        # Config should match
        assert "MY_KEY" in loaded.secrets
        assert loaded.secrets["MY_KEY"].value == "sk-real"
        assert loaded.secrets["MY_KEY"].hosts == ["api.example.com"]
        assert "api.example.com" in loaded.allowed_hosts

    def test_placeholder_preserved_in_roundtrip(self, monkeypatch):
        raw = {
            "KEY": {
                "value": "val",
                "hosts": ["h.com"],
            }
        }
        config = load_config_from_dict(raw)
        original_placeholder = config.secrets["KEY"].placeholder
        env_json = config.to_env_json()

        loaded = self._fresh_load(monkeypatch, env_json)
        assert loaded.secrets["KEY"].placeholder == original_placeholder

    def test_missing_env_var_raises(self, monkeypatch):
        import sys
        import importlib

        monkeypatch.delenv("SECRETS_PROXY_CONFIG_JSON", raising=False)

        for mod_name in list(sys.modules):
            if mod_name == "secrets_proxy.addon_entry":
                del sys.modules[mod_name]

        with pytest.raises(KeyError):
            importlib.import_module("secrets_proxy.addon_entry")
