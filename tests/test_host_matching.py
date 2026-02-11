"""Tests for host matching, config sanitization, and placeholder substitution context."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from secrets_proxy.config import (
    ProxyConfig,
    SecretEntry,
    _is_ip_literal,
    _matches_host_pattern,
    _sanitize_host,
    _validate_host_pattern,
    load_config,
)


# ---------------------------------------------------------------------------
# _sanitize_host
# ---------------------------------------------------------------------------

class TestSanitizeHost:
    def test_strips_https_prefix(self):
        assert _sanitize_host("https://api.example.com") == "api.example.com"

    def test_strips_http_prefix(self):
        assert _sanitize_host("http://api.example.com") == "api.example.com"

    def test_strips_trailing_path(self):
        assert _sanitize_host("https://api.example.com/v1/chat") == "api.example.com"

    def test_strips_port(self):
        assert _sanitize_host("api.example.com:443") == "api.example.com"

    def test_lowercases(self):
        assert _sanitize_host("API.Example.COM") == "api.example.com"

    def test_combined_prefix_path_port(self):
        assert _sanitize_host("https://API.Example.COM:8080/v1") == "api.example.com"

    def test_plain_hostname_unchanged(self):
        assert _sanitize_host("api.example.com") == "api.example.com"

    def test_wildcard_preserved(self):
        assert _sanitize_host("*.example.com") == "*.example.com"


# ---------------------------------------------------------------------------
# _validate_host_pattern
# ---------------------------------------------------------------------------

class TestValidateHostPattern:
    def test_valid_exact_host(self):
        _validate_host_pattern("api.github.com")  # Should not raise

    def test_valid_wildcard(self):
        _validate_host_pattern("*.github.com")  # Should not raise

    def test_rejects_bare_star(self):
        with pytest.raises(ValueError, match="wildcards must start with"):
            _validate_host_pattern("*example.com")

    def test_rejects_star_alone(self):
        with pytest.raises(ValueError, match="wildcards must start with"):
            _validate_host_pattern("*")

    def test_rejects_empty_domain_after_wildcard(self):
        with pytest.raises(ValueError, match="domain part is invalid"):
            _validate_host_pattern("*.")

    def test_rejects_double_dots(self):
        with pytest.raises(ValueError, match="domain part is invalid"):
            _validate_host_pattern("*..example.com")


# ---------------------------------------------------------------------------
# _is_ip_literal
# ---------------------------------------------------------------------------

class TestIsIpLiteral:
    def test_ipv4(self):
        assert _is_ip_literal("192.168.1.1") is True

    def test_ipv6(self):
        assert _is_ip_literal("::1") is True

    def test_ipv6_bracketed(self):
        assert _is_ip_literal("[::1]") is True

    def test_hostname(self):
        assert _is_ip_literal("api.github.com") is False

    def test_empty_string(self):
        assert _is_ip_literal("") is False


# ---------------------------------------------------------------------------
# _matches_host_pattern (strict dot-boundary matching)
# ---------------------------------------------------------------------------

class TestMatchesHostPattern:
    def test_wildcard_matches_subdomain(self):
        assert _matches_host_pattern("api.github.com", "*.github.com") is True

    def test_wildcard_matches_nested_subdomain(self):
        assert _matches_host_pattern("foo.bar.github.com", "*.github.com") is True

    def test_wildcard_matches_bare_domain(self):
        assert _matches_host_pattern("github.com", "*.github.com") is True

    def test_wildcard_does_not_match_evil_suffix(self):
        """*.github.com must NOT match github.com.evil.com"""
        assert _matches_host_pattern("github.com.evil.com", "*.github.com") is False

    def test_wildcard_does_not_match_partial(self):
        """*.github.com must NOT match notgithub.com"""
        assert _matches_host_pattern("notgithub.com", "*.github.com") is False

    def test_exact_match(self):
        assert _matches_host_pattern("api.openai.com", "api.openai.com") is True

    def test_exact_no_match(self):
        assert _matches_host_pattern("other.openai.com", "api.openai.com") is False


# ---------------------------------------------------------------------------
# SecretEntry.matches_host
# ---------------------------------------------------------------------------

class TestSecretEntryMatchesHost:
    def _make_entry(self, hosts: list[str]) -> SecretEntry:
        return SecretEntry(
            name="TEST",
            placeholder="PLACEHOLDER",
            value="secret",
            hosts=hosts,
        )

    def test_exact_match(self):
        entry = self._make_entry(["api.openai.com"])
        assert entry.matches_host("api.openai.com") is True

    def test_exact_no_match(self):
        entry = self._make_entry(["api.openai.com"])
        assert entry.matches_host("evil.com") is False

    def test_wildcard_subdomain(self):
        entry = self._make_entry(["*.github.com"])
        assert entry.matches_host("api.github.com") is True

    def test_wildcard_rejects_evil_suffix(self):
        entry = self._make_entry(["*.github.com"])
        assert entry.matches_host("github.com.evil.com") is False

    def test_case_insensitive(self):
        entry = self._make_entry(["api.openai.com"])
        assert entry.matches_host("API.OPENAI.COM") is True


# ---------------------------------------------------------------------------
# ProxyConfig.is_host_allowed (including IP literal blocking)
# ---------------------------------------------------------------------------

class TestProxyConfigIsHostAllowed:
    def test_exact_host_allowed(self):
        config = ProxyConfig(allowed_hosts={"api.openai.com"})
        assert config.is_host_allowed("api.openai.com") is True

    def test_unknown_host_blocked(self):
        config = ProxyConfig(allowed_hosts={"api.openai.com"})
        assert config.is_host_allowed("evil.com") is False

    def test_wildcard_allowed(self):
        config = ProxyConfig(allowed_hosts={"*.github.com"})
        assert config.is_host_allowed("api.github.com") is True

    def test_wildcard_evil_suffix_blocked(self):
        config = ProxyConfig(allowed_hosts={"*.github.com"})
        assert config.is_host_allowed("github.com.evil.com") is False

    def test_ip_literal_blocked_by_default(self):
        config = ProxyConfig(
            allowed_hosts={"192.168.1.1"},
            allow_ip_literals=False,
        )
        assert config.is_host_allowed("192.168.1.1") is False

    def test_ip_literal_allowed_when_enabled(self):
        config = ProxyConfig(
            allowed_hosts={"192.168.1.1"},
            allow_ip_literals=True,
        )
        assert config.is_host_allowed("192.168.1.1") is True

    def test_ip_literal_ipv6_blocked_by_default(self):
        config = ProxyConfig(
            allowed_hosts={"::1"},
            allow_ip_literals=False,
        )
        assert config.is_host_allowed("::1") is False

    def test_case_insensitive(self):
        config = ProxyConfig(allowed_hosts={"API.OpenAI.com"})
        # The pattern is stored as-is, but matching lowercases the host
        # Since we sanitize at load time, patterns should already be lowercase.
        # But is_host_allowed lowercases the incoming host.
        config2 = ProxyConfig(allowed_hosts={"api.openai.com"})
        assert config2.is_host_allowed("API.OPENAI.COM") is True


# ---------------------------------------------------------------------------
# load_config — host sanitization
# ---------------------------------------------------------------------------

class TestLoadConfigSanitization:
    def _write_config(self, data: dict) -> Path:
        """Write a config dict to a temp file and return the path."""
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        json.dump(data, f)
        f.close()
        return Path(f.name)

    def test_https_prefix_stripped(self):
        path = self._write_config({
            "MY_KEY": {
                "value": "secret",
                "hosts": ["https://api.example.com"],
            }
        })
        config = load_config(path)
        entry = config.secrets["MY_KEY"]
        assert entry.hosts == ["api.example.com"]
        assert "api.example.com" in config.allowed_hosts

    def test_http_prefix_stripped(self):
        path = self._write_config({
            "MY_KEY": {
                "value": "secret",
                "hosts": ["http://api.example.com/v1"],
            }
        })
        config = load_config(path)
        entry = config.secrets["MY_KEY"]
        assert entry.hosts == ["api.example.com"]

    def test_hosts_lowercased(self):
        path = self._write_config({
            "MY_KEY": {
                "value": "secret",
                "hosts": ["API.Example.COM"],
            }
        })
        config = load_config(path)
        entry = config.secrets["MY_KEY"]
        assert entry.hosts == ["api.example.com"]

    def test_invalid_wildcard_rejected(self):
        path = self._write_config({
            "MY_KEY": {
                "value": "secret",
                "hosts": ["*example.com"],
            }
        })
        with pytest.raises(ValueError, match="wildcards must start with"):
            load_config(path)

    def test_allow_net_sanitized(self):
        path = self._write_config({
            "MY_KEY": {
                "value": "secret",
                "hosts": ["api.example.com"],
            }
        })
        config = load_config(path, allow_net=["https://Extra.Host.COM/path"])
        assert "extra.host.com" in config.allowed_hosts

    def test_allow_ip_literals_flag(self):
        path = self._write_config({
            "MY_KEY": {
                "value": "secret",
                "hosts": ["api.example.com"],
            }
        })
        config = load_config(path, allow_ip_literals=True)
        assert config.allow_ip_literals is True

        config2 = load_config(path, allow_ip_literals=False)
        assert config2.allow_ip_literals is False
