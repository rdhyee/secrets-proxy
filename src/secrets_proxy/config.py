"""Secret configuration parsing and placeholder generation."""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

# Valid environment variable name: starts with letter or underscore,
# followed by letters, digits, or underscores.
_VALID_SECRET_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def validate_secret_name(name: str) -> None:
    """Validate that a secret name is safe for use as an environment variable.

    Raises ValueError if the name contains shell metacharacters or is otherwise
    not a valid POSIX environment variable name.
    """
    if not _VALID_SECRET_NAME_RE.match(name):
        raise ValueError(
            f"Invalid secret name {name!r}: must match [a-zA-Z_][a-zA-Z0-9_]* "
            f"(no spaces, semicolons, or other shell metacharacters)"
        )


def _sanitize_host(host: str) -> str:
    """Sanitize a hostname entry from config.

    - Strip https:// and http:// prefixes
    - Lowercase the hostname
    - Strip trailing slashes and paths
    - Strip port numbers
    """
    if host.startswith("https://"):
        host = host[len("https://"):]
    elif host.startswith("http://"):
        host = host[len("http://"):]

    host = host.split("/")[0]

    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]

    host = host.lower()

    return host


def _validate_host_pattern(pattern: str) -> None:
    """Validate a host pattern.

    Raises ValueError if the pattern is invalid:
    - Wildcards must start with '*.' (not just '*')
    - Hostname must use valid characters
    """
    if pattern.startswith("*"):
        if not pattern.startswith("*."):
            raise ValueError(
                f"Invalid wildcard pattern '{pattern}': wildcards must start with '*.' "
                f"(e.g., '*.example.com'), not just '*'."
            )
        domain_part = pattern[2:]
        if not domain_part or ".." in domain_part or domain_part.startswith("."):
            raise ValueError(
                f"Invalid wildcard pattern '{pattern}': domain part is invalid."
            )

    bare = pattern.lstrip("*.")
    if bare and not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', bare):
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            raise ValueError(
                f"Invalid hostname pattern '{pattern}': contains invalid characters."
            )


def _is_ip_literal(host: str) -> bool:
    """Check if a host string is an IP address literal (IPv4 or IPv6)."""
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        return False


def _matches_host_pattern(host: str, pattern: str) -> bool:
    """Check if a host matches a single pattern with strict dot-boundary matching.

    Wildcard matching rules:
    - *.github.com matches api.github.com (subdomain)
    - *.github.com matches foo.bar.github.com (nested subdomain)
    - *.github.com matches github.com (bare domain)
    - *.github.com does NOT match github.com.evil.com (suffix trick)
    """
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        base_domain = pattern[2:]  # example.com
        if host == base_domain:
            return True
        if host.endswith(suffix) and len(host) > len(suffix):
            return True
        return False
    else:
        return host == pattern


@dataclass
class SecretEntry:
    """A single secret with its placeholder, real value, and approved hosts."""

    name: str
    placeholder: str
    value: str
    hosts: list[str]

    def matches_host(self, host: str) -> bool:
        """Check if a host is approved for this secret."""
        host = host.lower()
        for pattern in self.hosts:
            if _matches_host_pattern(host, pattern):
                return True
        return False


@dataclass
class ProxyConfig:
    """Full proxy configuration."""

    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    allowed_hosts: set[str] = field(default_factory=set)
    proxy_port: int = 8080
    allow_ip_literals: bool = False
    _placeholder_to_secret: dict[str, SecretEntry] = field(
        default_factory=dict, repr=False
    )

    def get_env_vars(self) -> dict[str, str]:
        """Return env vars to set in the sandboxed process (placeholder values)."""
        return {entry.name: entry.placeholder for entry in self.secrets.values()}

    def to_env_json(self) -> str:
        """Serialize config to JSON for SECRETS_PROXY_CONFIG_JSON env var.

        Format consumed by addon_entry.py:
        {
            "secrets": {
                "PLACEHOLDER_HEX": {
                    "name": "SECRET_NAME",
                    "value": "real-value",
                    "hosts": ["api.example.com"]
                }
            },
            "allowed_hosts": ["api.example.com", ...]
        }
        """
        secrets_data = {}
        for _name, entry in self.secrets.items():
            secrets_data[entry.placeholder] = {
                "name": entry.name,
                "value": entry.value,
                "hosts": entry.hosts,
            }
        return json.dumps({
            "secrets": secrets_data,
            "allowed_hosts": sorted(self.allowed_hosts),
            "allow_ip_literals": self.allow_ip_literals,
        })

    def find_secret_for_placeholder(
        self, text: str
    ) -> list[tuple[str, SecretEntry]]:
        """Find all placeholder strings present in the given text."""
        found = []
        for placeholder, entry in self._placeholder_to_secret.items():
            if placeholder in text:
                found.append((placeholder, entry))
        return found

    def is_host_allowed(self, host: str) -> bool:
        """Check if a host is allowed by the allowlist."""
        host = host.lower()

        if _is_ip_literal(host) and not self.allow_ip_literals:
            return False

        for pattern in self.allowed_hosts:
            if _matches_host_pattern(host, pattern):
                return True
        return False


def generate_placeholder(name: str) -> str:
    """Generate a unique, recognizable placeholder for a secret."""
    random_hex = secrets.token_hex(16)
    return f"SECRETS_PROXY_PLACEHOLDER_{random_hex}"


def _build_config_from_dict(
    raw: dict,
    allow_net: list[str] | None = None,
    allow_ip_literals: bool = False,
) -> ProxyConfig:
    """Build a ProxyConfig from a raw config dict.

    Shared implementation for load_config() and load_config_from_dict().
    All validation (secret names, host patterns) is applied here.
    """
    config = ProxyConfig(allow_ip_literals=allow_ip_literals)

    for name, entry_data in raw.items():
        validate_secret_name(name)

        if isinstance(entry_data, str):
            raise ValueError(
                f"Secret '{name}' must be a dict with 'value' and 'hosts' keys, "
                f"not a plain string. Secrets without host restrictions are not allowed."
            )

        if not isinstance(entry_data, dict):
            raise TypeError(
                f"Secret '{name}': expected a dict, got {type(entry_data).__name__}"
            )

        if "value" not in entry_data:
            raise ValueError(
                f"Secret '{name}' is missing required key 'value'."
            )
        if "hosts" not in entry_data:
            raise ValueError(
                f"Secret '{name}' is missing required key 'hosts'. "
                f"Every secret must be scoped to specific destination hosts."
            )
        if not isinstance(entry_data["hosts"], list):
            raise TypeError(
                f"Secret '{name}': 'hosts' must be a list of hostnames, "
                f"got {type(entry_data['hosts']).__name__}"
            )
        if not entry_data["hosts"]:
            raise ValueError(
                f"Secret '{name}': 'hosts' list cannot be empty."
            )

        placeholder = entry_data.get("placeholder", generate_placeholder(name))

        raw_hosts = entry_data["hosts"]
        sanitized_hosts = []
        for h in raw_hosts:
            h = _sanitize_host(h)
            _validate_host_pattern(h)
            sanitized_hosts.append(h)

        entry = SecretEntry(
            name=name,
            placeholder=placeholder,
            value=entry_data["value"],
            hosts=sanitized_hosts,
        )

        config.secrets[name] = entry
        config._placeholder_to_secret[entry.placeholder] = entry

        for host in entry.hosts:
            config.allowed_hosts.add(host)

    if allow_net:
        for host in allow_net:
            host = _sanitize_host(host)
            _validate_host_pattern(host)
            config.allowed_hosts.add(host)

    return config


def load_config(
    config_path: str | Path,
    allow_net: list[str] | None = None,
    allow_ip_literals: bool = False,
) -> ProxyConfig:
    """Load secret configuration from a JSON file.

    Config format:
    {
        "OPENAI_API_KEY": {
            "value": "sk-real-key",
            "hosts": ["api.openai.com"]
        }
    }

    Placeholders are auto-generated at load time.
    """
    path = Path(config_path)
    with open(path) as f:
        raw = json.load(f)

    return _build_config_from_dict(raw, allow_net=allow_net, allow_ip_literals=allow_ip_literals)


def load_config_from_dict(
    raw: dict,
    allow_net: list[str] | None = None,
    allow_ip_literals: bool = False,
) -> ProxyConfig:
    """Build a ProxyConfig from an already-parsed dict.

    Same validation as load_config() but skips file I/O.
    Useful for loading config from environment variables or other non-file sources.

    The dict format matches the JSON file format:
    {
        "SECRET_NAME": {
            "value": "real-value",
            "hosts": ["api.example.com"],
            "placeholder": "optional-pre-assigned-placeholder"
        }
    }
    """
    return _build_config_from_dict(raw, allow_net=allow_net, allow_ip_literals=allow_ip_literals)
