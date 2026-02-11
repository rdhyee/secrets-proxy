"""Thin mitmproxy entry point for secrets-proxy.

Loaded by: mitmdump -s addon_entry.py

Reads SECRETS_PROXY_CONFIG_JSON from the environment, builds a ProxyConfig,
and instantiates the production SecretsProxyAddon.
This ensures all deployment paths (launcher, Docker, Sprites) use the same
addon code with full security features (compression, JSON escaping, URL
encoding, WebSocket blocking, Brotli fail-closed, decompression limits).
"""

from __future__ import annotations

import json
import logging
import os

from secrets_proxy.addon import SecretsProxyAddon
from secrets_proxy.config import ProxyConfig, SecretEntry

logger = logging.getLogger("secrets-proxy")


def _load_config_from_env() -> ProxyConfig:
    """Load ProxyConfig from the SECRETS_PROXY_CONFIG_JSON env var.

    Expected JSON format (produced by ProxyConfig.to_env_json()):
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

    The env var is popped immediately so child processes don't inherit it.
    """
    raw_json = os.environ.pop("SECRETS_PROXY_CONFIG_JSON")
    data = json.loads(raw_json)

    config = ProxyConfig(allow_ip_literals=data.get("allow_ip_literals", False))
    secrets_data = data.get("secrets", {})
    for placeholder, info in secrets_data.items():
        entry = SecretEntry(
            name=info["name"],
            placeholder=placeholder,
            value=info["value"],
            hosts=info["hosts"],
        )
        config.secrets[info["name"]] = entry
        config._placeholder_to_secret[placeholder] = entry
        for host in info["hosts"]:
            config.allowed_hosts.add(host)

    for host in data.get("allowed_hosts", []):
        config.allowed_hosts.add(host)

    return config


config = _load_config_from_env()
addons = [SecretsProxyAddon(config)]
