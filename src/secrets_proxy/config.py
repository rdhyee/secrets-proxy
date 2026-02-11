"""Secret configuration parsing and placeholder generation."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecretEntry:
    """A single secret with its placeholder, real value, and approved hosts."""

    name: str
    placeholder: str
    value: str
    hosts: list[str]
    inject_header: str = "Authorization"
    inject_format: str = "Bearer {value}"

    def matches_host(self, host: str) -> bool:
        """Check if a host is approved for this secret."""
        for pattern in self.hosts:
            if pattern.startswith("*."):
                # Wildcard: *.example.com matches foo.example.com
                suffix = pattern[1:]  # .example.com
                if host.endswith(suffix) or host == pattern[2:]:
                    return True
            elif host == pattern:
                return True
        return False


@dataclass
class ProxyConfig:
    """Full proxy configuration."""

    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    allowed_hosts: set[str] = field(default_factory=set)
    proxy_port: int = 8080
    # All placeholder values, for quick lookup during substitution
    _placeholder_to_secret: dict[str, SecretEntry] = field(
        default_factory=dict, repr=False
    )

    def get_env_vars(self) -> dict[str, str]:
        """Return env vars to set in the sandboxed process (placeholder values)."""
        return {entry.name: entry.placeholder for entry in self.secrets.values()}

    def find_secret_for_placeholder(
        self, text: str
    ) -> list[tuple[str, SecretEntry]]:
        """Find all placeholder strings present in the given text."""
        found = []
        for placeholder, entry in self._placeholder_to_secret.items():
            if placeholder in text:
                found.append((placeholder, entry))
        return found


def generate_placeholder(name: str) -> str:
    """Generate a unique, recognizable placeholder for a secret."""
    random_hex = secrets.token_hex(16)
    return f"SECRETS_PROXY_PLACEHOLDER_{random_hex}"


def load_config(config_path: str | Path, allow_net: list[str] | None = None) -> ProxyConfig:
    """Load secret configuration from a JSON file.

    Config format:
    {
        "OPENAI_API_KEY": {
            "value": "sk-real-key",
            "hosts": ["api.openai.com"],
            "inject": {
                "header": "Authorization",
                "format": "Bearer {value}"
            }
        }
    }

    The "inject" field is optional (defaults to Authorization: Bearer).
    Placeholders are auto-generated at load time.
    """
    path = Path(config_path)
    with open(path) as f:
        raw = json.load(f)

    config = ProxyConfig()

    for name, entry_data in raw.items():
        if isinstance(entry_data, str):
            # Simple format: {"OPENAI_API_KEY": "sk-real-key"}
            # No host restriction, no injection config
            raise ValueError(
                f"Secret '{name}' must be a dict with 'value' and 'hosts' keys, "
                f"not a plain string. Secrets without host restrictions are not allowed."
            )

        inject = entry_data.get("inject", {})
        placeholder = entry_data.get("placeholder", generate_placeholder(name))

        entry = SecretEntry(
            name=name,
            placeholder=placeholder,
            value=entry_data["value"],
            hosts=entry_data["hosts"],
            inject_header=inject.get("header", "Authorization"),
            inject_format=inject.get("format", "Bearer {value}"),
        )

        config.secrets[name] = entry
        config._placeholder_to_secret[entry.placeholder] = entry

        # Add hosts to the global allowlist
        for host in entry.hosts:
            config.allowed_hosts.add(host)

    # Add any extra allowed hosts (non-secret-bearing, but reachable)
    if allow_net:
        for host in allow_net:
            config.allowed_hosts.add(host)

    return config
