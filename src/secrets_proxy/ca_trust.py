"""CA certificate trust setup for making sandboxed code trust the MITM proxy."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# mitmproxy's default CA cert location
MITMPROXY_CA_DIR = Path.home() / ".mitmproxy"
MITMPROXY_CA_CERT = MITMPROXY_CA_DIR / "mitmproxy-ca-cert.pem"

# System CA bundle locations (Linux and macOS)
SYSTEM_CA_BUNDLES = [
    Path("/etc/ssl/certs/ca-certificates.crt"),  # Debian/Ubuntu
    Path("/etc/pki/tls/certs/ca-bundle.crt"),  # RHEL/CentOS
    Path("/etc/ssl/cert.pem"),  # Alpine / macOS
]

# Environment variables that HTTP libraries check for CA bundles
CA_ENV_VARS = [
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "CURL_CA_BUNDLE",
    "DENO_CERT",
    "GIT_SSL_CAINFO",
]


def find_system_ca_bundle() -> Path | None:
    """Find the system CA bundle."""
    for path in SYSTEM_CA_BUNDLES:
        if path.exists():
            return path
    return None


def ensure_mitmproxy_ca() -> Path:
    """Ensure mitmproxy's CA cert exists.

    Returns the path to the CA cert PEM file.
    """
    if not MITMPROXY_CA_CERT.exists():
        raise FileNotFoundError(
            f"mitmproxy CA cert not found at {MITMPROXY_CA_CERT}. "
            "Run mitmproxy once to generate it, or run `secrets-proxy setup-ca`."
        )
    return MITMPROXY_CA_CERT


def create_combined_ca_bundle(output_path: Path | None = None) -> Path:
    """Create a CA bundle that includes both the system CAs and the mitmproxy CA.

    This is the key to transparency -- any language's TLS library that
    respects SSL_CERT_FILE will trust both real CAs and our proxy.

    If no output_path is given, creates a temp file (no root needed).
    """
    if output_path is not None:
        output = output_path
        output.parent.mkdir(parents=True, exist_ok=True)
    else:
        fd, tmp_path = tempfile.mkstemp(suffix=".pem", prefix="secrets_proxy_ca_")
        os.close(fd)
        output = Path(tmp_path)

    mitm_ca = ensure_mitmproxy_ca()
    system_ca = find_system_ca_bundle()

    with open(output, "w") as out:
        if system_ca:
            with open(system_ca) as f:
                content = f.read()
            out.write(content)
            if content and not content.endswith("\n"):
                out.write("\n")

        out.write("# secrets-proxy MITM CA\n")
        with open(mitm_ca) as f:
            out.write(f.read())

    return output


def get_ca_trust_env(ca_bundle_path: Path) -> dict[str, str]:
    """Return environment variables that make HTTP libraries trust our CA bundle."""
    path_str = str(ca_bundle_path)
    return {var: path_str for var in CA_ENV_VARS}


def setup_ca_trust(ca_bundle_path: Path | None = None) -> tuple[Path, dict[str, str]]:
    """Full CA trust setup: create combined bundle and return env vars.

    Returns (bundle_path, env_vars_dict).
    """
    bundle = create_combined_ca_bundle(ca_bundle_path)
    env_vars = get_ca_trust_env(bundle)
    return bundle, env_vars
