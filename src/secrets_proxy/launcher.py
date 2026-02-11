"""Process launcher: starts mitmproxy, sets up environment, runs sandboxed command."""

from __future__ import annotations

import logging
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .ca_trust import setup_ca_trust, MITMPROXY_CA_CERT, MITMPROXY_CA_DIR
from .config import ProxyConfig

logger = logging.getLogger("secrets-proxy")

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080


def _generate_mitmproxy_ca_if_needed() -> None:
    """Run mitmproxy briefly to generate CA certs if they don't exist."""
    if MITMPROXY_CA_CERT.exists():
        return

    logger.info("Generating mitmproxy CA certificate (first run)...")
    MITMPROXY_CA_DIR.mkdir(parents=True, exist_ok=True)

    # Run mitmdump briefly to trigger CA generation
    proc = subprocess.Popen(
        ["mitmdump", "--listen-port", "0", "-q"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Give it a moment to generate certs
    time.sleep(2)
    proc.terminate()
    proc.wait(timeout=5)

    if MITMPROXY_CA_CERT.exists():
        logger.info("CA certificate generated at %s", MITMPROXY_CA_CERT)
    else:
        raise RuntimeError("Failed to generate mitmproxy CA certificate")


def _setup_nftables(sandbox_uid: int, proxy_port: int) -> bool:
    """Set up nftables to redirect outbound traffic through the proxy.

    Returns True if nftables was set up, False if not available.
    Only works on Linux with root/CAP_NET_ADMIN.
    """
    if platform.system() != "Linux":
        logger.info("Not on Linux, skipping nftables (using proxy env vars instead)")
        return False

    try:
        # Redirect HTTP and HTTPS from the sandboxed user through the proxy
        cmds = [
            # Redirect HTTPS (443) to proxy
            [
                "nft", "add", "rule", "ip", "nat", "OUTPUT",
                "meta", "skuid", str(sandbox_uid),
                "tcp", "dport", "443",
                "redirect", "to", f":{proxy_port}",
            ],
            # Redirect HTTP (80) to proxy
            [
                "nft", "add", "rule", "ip", "nat", "OUTPUT",
                "meta", "skuid", str(sandbox_uid),
                "tcp", "dport", "80",
                "redirect", "to", f":{proxy_port}",
            ],
        ]
        for cmd in cmds:
            subprocess.run(cmd, check=True, capture_output=True)
        logger.info("nftables rules set for UID %d → port %d", sandbox_uid, proxy_port)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("nftables setup failed: %s. Falling back to proxy env vars.", e)
        return False


def _teardown_nftables(sandbox_uid: int, proxy_port: int) -> None:
    """Remove nftables rules. Best-effort."""
    if platform.system() != "Linux":
        return
    try:
        subprocess.run(
            ["nft", "flush", "chain", "ip", "nat", "OUTPUT"],
            capture_output=True,
        )
        logger.info("nftables rules cleaned up")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


def start_proxy(config: ProxyConfig, addon_path: str) -> subprocess.Popen:
    """Start mitmproxy in transparent mode with the secrets addon."""
    cmd = [
        "mitmdump",
        "--mode", "regular",
        "--listen-host", PROXY_HOST,
        "--listen-port", str(config.proxy_port or PROXY_PORT),
        "--set", "connection_strategy=lazy",
        "-s", addon_path,
        "-q",  # quiet mode
    ]

    logger.info("Starting mitmproxy: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for proxy to be ready
    time.sleep(1)
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        raise RuntimeError(f"mitmproxy failed to start: {stderr}")

    logger.info("mitmproxy started (PID %d) on %s:%d", proc.pid, PROXY_HOST, config.proxy_port or PROXY_PORT)
    return proc


def run(
    config: ProxyConfig,
    command: list[str],
    *,
    ca_bundle_path: Path | None = None,
) -> int:
    """Run a command with secrets-proxy wrapping.

    1. Generate mitmproxy CA if needed
    2. Create combined CA bundle
    3. Write mitmproxy addon script with config
    4. Start mitmproxy
    5. Set up nftables (Linux) or proxy env vars (macOS)
    6. Run the sandboxed command with placeholder env vars
    7. Clean up

    Returns the sandboxed command's exit code.
    """
    port = config.proxy_port or PROXY_PORT

    # Step 1: Ensure CA exists
    _generate_mitmproxy_ca_if_needed()

    # Step 2: Create combined CA bundle
    bundle_path, ca_env = setup_ca_trust(ca_bundle_path)
    logger.info("CA bundle created at %s", bundle_path)

    # Step 3: Write addon script (secrets passed via env var, not in file)
    addon_script = _create_addon_script(config)

    # Step 4: Start mitmproxy
    proxy_proc = start_proxy(config, addon_script)

    # Track cleanup state for signal handlers
    used_nftables = False
    uid = os.getuid()

    def _cleanup() -> None:
        """Best-effort cleanup of all resources."""
        # Stop mitmproxy
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
        logger.info("mitmproxy stopped")

        # Clean up nftables
        if used_nftables:
            _teardown_nftables(uid, port)

        # Clean up temp files
        for path in [addon_script, str(bundle_path)]:
            try:
                os.unlink(path)
            except OSError:
                pass

        # Clear secrets from env
        os.environ.pop("SECRETS_PROXY_CONFIG_JSON", None)

    # Install signal handlers so cleanup runs on SIGTERM/SIGINT
    def _signal_handler(signum: int, frame: object) -> None:
        logger.info("Received signal %d, cleaning up...", signum)
        _cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        # Step 5: Build environment for sandboxed process
        sandbox_env = os.environ.copy()

        # Placeholder env vars (secrets)
        sandbox_env.update(config.get_env_vars())

        # CA trust env vars
        sandbox_env.update(ca_env)

        # Remove the config JSON from child env (addon already read it)
        sandbox_env.pop("SECRETS_PROXY_CONFIG_JSON", None)

        # Proxy env vars (for macOS / non-nftables mode)
        proxy_url = f"http://{PROXY_HOST}:{port}"
        sandbox_env["HTTP_PROXY"] = proxy_url
        sandbox_env["HTTPS_PROXY"] = proxy_url
        sandbox_env["http_proxy"] = proxy_url
        sandbox_env["https_proxy"] = proxy_url

        # Try nftables (Linux strong mode)
        used_nftables = _setup_nftables(uid, port)

        # Step 6: Run the sandboxed command
        logger.info("Running: %s", " ".join(command))
        try:
            result = subprocess.run(command, env=sandbox_env)
            return result.returncode
        finally:
            # Step 7: Clean up
            if used_nftables:
                _teardown_nftables(uid, port)

    finally:
        _cleanup()


def _create_addon_script(config: ProxyConfig) -> str:
    """Create a temporary mitmproxy addon script.

    Secrets are passed via the SECRETS_PROXY_CONFIG_JSON environment variable
    (not embedded in the script file) so that real credentials are never
    written to disk.
    """
    import json as _json

    allowed_hosts = list(config.allowed_hosts)

    # Build the secrets config to pass via env var
    secrets_data = {}
    for name, entry in config.secrets.items():
        secrets_data[entry.placeholder] = {
            "name": name,
            "value": entry.value,
            "hosts": entry.hosts,
        }
    # Store in env var for the addon to read at import time
    os.environ["SECRETS_PROXY_CONFIG_JSON"] = _json.dumps({
        "secrets": secrets_data,
        "allowed_hosts": allowed_hosts,
    })

    script_content = '''"""Auto-generated mitmproxy addon for secrets-proxy.

Reads config from SECRETS_PROXY_CONFIG_JSON env var (secrets never touch disk).
"""
import json
import logging
import os

from mitmproxy import http

logger = logging.getLogger("secrets-proxy-addon")

_config = json.loads(os.environ["SECRETS_PROXY_CONFIG_JSON"])
SECRETS = _config["secrets"]
ALLOWED_HOSTS = _config["allowed_hosts"]
# Clear from env immediately so child processes don't inherit it
del os.environ["SECRETS_PROXY_CONFIG_JSON"]


def _host_allowed(host: str) -> bool:
    for pattern in ALLOWED_HOSTS:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) or host == pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def _host_matches_secret(host: str, hosts: list) -> bool:
    for pattern in hosts:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) or host == pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    if not _host_allowed(host):
        flow.response = http.Response.make(
            403,
            f"secrets-proxy: host '{host}' not in allowlist".encode(),
            {"Content-Type": "text/plain"},
        )
        logger.info("Blocked: %s", host)
        return

    def substitute(text: str) -> tuple[str, int]:
        count = 0
        for placeholder, info in SECRETS.items():
            if placeholder in text and _host_matches_secret(host, info["hosts"]):
                text = text.replace(placeholder, info["value"])
                count += 1
                logger.info("Injected secret '%s' for %s", info["name"], host)
        return text, count

    # Substitute in headers
    for hname in list(flow.request.headers.keys()):
        hval = flow.request.headers[hname]
        new_val, n = substitute(hval)
        if n > 0:
            flow.request.headers[hname] = new_val

    # Substitute in URL
    if flow.request.url:
        new_url, n = substitute(flow.request.url)
        if n > 0:
            flow.request.url = new_url

    # Substitute in body
    if flow.request.content:
        try:
            body = flow.request.content.decode("utf-8")
            new_body, n = substitute(body)
            if n > 0:
                flow.request.content = new_body.encode("utf-8")
        except UnicodeDecodeError:
            logger.warning("Binary body to %s, skipping substitution", host)
'''

    # Write to temp file (no secrets in the script — they're in env var)
    fd, path = tempfile.mkstemp(suffix=".py", prefix="secrets_proxy_addon_")
    with os.fdopen(fd, "w") as f:
        f.write(script_content)

    return path
