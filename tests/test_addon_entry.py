"""Tests for addon_entry.py env loading and config roundtrip (#36)."""

from __future__ import annotations

import json
import os

import pytest

from secrets_proxy.config import (
    ProxyConfig,
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

    def test_allow_ip_literals_preserved(self):
        raw = {"KEY": {"value": "v", "hosts": ["1.2.3.4"]}}
        config = load_config_from_dict(raw, allow_ip_literals=True)
        data = json.loads(config.to_env_json())
        assert data["allow_ip_literals"] is True

        config2 = load_config_from_dict(raw, allow_ip_literals=False)
        data2 = json.loads(config2.to_env_json())
        assert data2["allow_ip_literals"] is False

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

    def test_duplicate_placeholder_rejected(self):
        raw = {
            "KEY_A": {"value": "a", "hosts": ["a.com"], "placeholder": "SAME"},
            "KEY_B": {"value": "b", "hosts": ["b.com"], "placeholder": "SAME"},
        }
        with pytest.raises(ValueError, match="Duplicate placeholder"):
            load_config_from_dict(raw)

    def test_non_string_host_rejected(self):
        raw = {"KEY": {"value": "v", "hosts": ["a.com", 123]}}
        with pytest.raises(TypeError, match="hosts"):
            load_config_from_dict(raw)

    def test_non_string_value_rejected(self):
        raw = {"KEY": {"value": 123, "hosts": ["a.com"]}}
        with pytest.raises(TypeError, match="'value' must be a string"):
            load_config_from_dict(raw)


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

    def test_allow_ip_literals_roundtrip(self, monkeypatch):
        raw = {"KEY": {"value": "v", "hosts": ["1.2.3.4"]}}
        config = load_config_from_dict(raw, allow_ip_literals=True)
        env_json = config.to_env_json()

        loaded = self._fresh_load(monkeypatch, env_json)
        assert loaded.allow_ip_literals is True

    def test_missing_env_var_raises(self, monkeypatch):
        import sys
        import importlib

        monkeypatch.delenv("SECRETS_PROXY_CONFIG_JSON", raising=False)

        for mod_name in list(sys.modules):
            if mod_name == "secrets_proxy.addon_entry":
                del sys.modules[mod_name]

        with pytest.raises(KeyError):
            importlib.import_module("secrets_proxy.addon_entry")


class TestAddonEntryScriptMode:
    """Test addon_entry.py loads correctly via runpy.run_path (mitmdump -s mode)."""

    def test_run_path_succeeds(self, monkeypatch):
        """Regression test: addon_entry must work when loaded as a file script,
        not just as a package import. mitmdump -s uses file execution."""
        import runpy
        from pathlib import Path

        raw = {"KEY": {"value": "val", "hosts": ["h.com"]}}
        config = load_config_from_dict(raw)
        env_json = config.to_env_json()

        monkeypatch.setenv("SECRETS_PROXY_CONFIG_JSON", env_json)

        addon_path = str(
            Path(__file__).resolve().parents[1]
            / "src" / "secrets_proxy" / "addon_entry.py"
        )
        ns = runpy.run_path(addon_path)

        assert "addons" in ns
        assert len(ns["addons"]) == 1
        assert "SECRETS_PROXY_CONFIG_JSON" not in os.environ


class TestInitSandboxEnvSafety:
    """Test that init subcommand writes shell-safe sandbox env files."""

    def test_placeholder_with_shell_metacharacters_is_escaped(self, tmp_path):
        """Placeholders containing $, ", backticks must be shell-escaped."""
        import subprocess

        raw = {
            "KEY": {
                "value": "v",
                "hosts": ["a.com"],
                "placeholder": '$(touch /tmp/pwned)',
            }
        }
        env_file = tmp_path / "sandbox_env.sh"

        from secrets_proxy.__main__ import main
        main(["init", "--config-json", json.dumps(raw), "--sandbox-env", str(env_file)])

        content = env_file.read_text()
        # shlex.quote wraps in single quotes, so the $() is not interpreted
        assert "'$(touch /tmp/pwned)'" in content

        # Sourcing should set the variable literally, not execute the command
        result = subprocess.run(
            ["bash", "-c", f'source {env_file} && printf "%s" "$KEY"'],
            capture_output=True, text=True,
        )
        assert result.stdout == "$(touch /tmp/pwned)"

    def test_sandbox_env_write_does_not_follow_symlink(self, tmp_path):
        """init should replace the symlink path itself, not overwrite the symlink target."""
        sensitive = tmp_path / "sensitive.txt"
        sensitive.write_text("do-not-touch")
        env_file = tmp_path / "sandbox_env.sh"
        env_file.symlink_to(sensitive)

        raw = {"KEY": {"value": "v", "hosts": ["a.com"]}}
        from secrets_proxy.__main__ import main

        rc = main(["init", "--config-json", json.dumps(raw), "--sandbox-env", str(env_file)])
        assert rc == 0
        assert sensitive.read_text() == "do-not-touch"
        assert not env_file.is_symlink()
        assert "export KEY=" in env_file.read_text()


class TestFromEnvJson:
    """Test ProxyConfig.from_env_json() classmethod."""

    def test_roundtrip_via_classmethod(self):
        raw = {
            "MY_KEY": {"value": "sk-real", "hosts": ["api.example.com"]},
            "OTHER": {"value": "other-val", "hosts": ["b.com"]},
        }
        config = load_config_from_dict(raw)
        env_json = config.to_env_json()

        restored = ProxyConfig.from_env_json(env_json)
        assert "MY_KEY" in restored.secrets
        assert restored.secrets["MY_KEY"].value == "sk-real"
        assert restored.secrets["MY_KEY"].hosts == ["api.example.com"]
        assert "OTHER" in restored.secrets
        assert "api.example.com" in restored.allowed_hosts
        assert "b.com" in restored.allowed_hosts

    def test_placeholder_to_secret_populated(self):
        raw = {"KEY": {"value": "v", "hosts": ["h.com"]}}
        config = load_config_from_dict(raw)
        env_json = config.to_env_json()

        restored = ProxyConfig.from_env_json(env_json)
        placeholder = restored.secrets["KEY"].placeholder
        assert placeholder in restored._placeholder_to_secret
        assert restored._placeholder_to_secret[placeholder].name == "KEY"

    def test_allow_ip_literals_roundtrip(self):
        raw = {"KEY": {"value": "v", "hosts": ["1.2.3.4"]}}
        config = load_config_from_dict(raw, allow_ip_literals=True)
        restored = ProxyConfig.from_env_json(config.to_env_json())
        assert restored.allow_ip_literals is True

    def test_duplicate_secret_name_rejected(self):
        env_json = json.dumps(
            {
                "secrets": {
                    "PLACEHOLDER_A": {
                        "name": "DUP",
                        "value": "a",
                        "hosts": ["a.com"],
                    },
                    "PLACEHOLDER_B": {
                        "name": "DUP",
                        "value": "b",
                        "hosts": ["b.com"],
                    },
                },
                "allowed_hosts": ["a.com", "b.com"],
            }
        )
        with pytest.raises(ValueError, match="duplicate secret name"):
            ProxyConfig.from_env_json(env_json)

    def test_non_list_allowed_hosts_rejected(self):
        env_json = json.dumps(
            {
                "secrets": {
                    "PLACEHOLDER_A": {
                        "name": "KEY",
                        "value": "a",
                        "hosts": ["a.com"],
                    }
                },
                "allowed_hosts": "a.com",
            }
        )
        with pytest.raises(TypeError, match="allowed_hosts"):
            ProxyConfig.from_env_json(env_json)


class TestInitErrorHandling:
    """Test that init subcommand handles errors gracefully."""

    def test_invalid_json_returns_error(self, capsys):
        from secrets_proxy.__main__ import main

        result = main(["init", "--config-json", "not-valid-json"])
        assert result == 1
        assert "invalid JSON" in capsys.readouterr().err

    def test_invalid_config_returns_error(self, capsys):
        from secrets_proxy.__main__ import main

        # Missing required 'hosts' key
        result = main(["init", "--config-json", '{"KEY": {"value": "v"}}'])
        assert result == 1
        assert "invalid config" in capsys.readouterr().err

    def test_invalid_secret_name_returns_error(self, capsys):
        from secrets_proxy.__main__ import main

        result = main(["init", "--config-json", '{"bad;name": {"value": "v", "hosts": ["h.com"]}}'])
        assert result == 1
        assert "invalid config" in capsys.readouterr().err
