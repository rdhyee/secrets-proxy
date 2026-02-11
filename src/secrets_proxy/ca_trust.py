"""CA certificate trust setup for making sandboxed code trust the MITM proxy."""

from __future__ import annotations

from pathlib import Path

# mitmproxy's default CA cert location
MITMPROXY_CA_DIR = Path.home() / ".mitmproxy"
MITMPROXY_CA_CERT = MITMPROXY_CA_DIR / "mitmproxy-ca-cert.pem"

# Where we install the combined CA bundle
PROXY_CA_DIR = Path("/etc/secrets-proxy")
PROXY_CA_BUNDLE = PROXY_CA_DIR / "ca-bundle.pem"

# System CA bundle locations (Linux)
SYSTEM_CA_BUNDLES = [
    Path("/etc/ssl/certs/ca-certificates.crt"),  # Debian/Ubuntu
    Path("/etc/pki/tls/certs/ca-bundle.crt"),  # RHEL/CentOS
    Path("/etc/ssl/cert.pem"),  # Alpine
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
    """Find the system CA bundle on this Linux system."""
    for path in SYSTEM_CA_BUNDLES:
        if path.exists():
            return path
    return None


def ensure_mitmproxy_ca() -> Path:
    """Ensure mitmproxy's CA cert exists (generates on first mitmproxy run).

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

    This is the key to transparency — any language's TLS library that
    respects SSL_CERT_FILE will trust both real CAs and our proxy.
    """
    output = output_path or PROXY_CA_BUNDLE

    # Ensure output directory exists
    output.parent.mkdir(parents=True, exist_ok=True)

    mitm_ca = ensure_mitmproxy_ca()
    system_ca = find_system_ca_bundle()

    with open(output, "w") as out:
        # Start with system CAs
        if system_ca:
            with open(system_ca) as f:
                out.write(f.read())
            if not out.tell() or not f.read().endswith("\n"):
                out.write("\n")

        # Append mitmproxy CA
        out.write(f"# secrets-proxy MITM CA\n")
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
