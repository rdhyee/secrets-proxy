"""Process launcher: starts mitmproxy, sets up environment, runs sandboxed command.

Network enforcement (Linux/nftables):
    All TCP egress from the sandbox UID is redirected to the proxy port via a
    dedicated nftables chain ("secrets_proxy"). The proxy's own outbound packets
    are exempted using packet marks (SO_MARK / mitmproxy ``--set mark=0x1``), so
    they reach upstream hosts directly without looping back.

    UDP egress (including DNS-over-UDP and HTTP/3 QUIC) is blocked entirely for
    the sandbox UID. HTTP/3 (QUIC) is **not supported** -- clients that attempt
    QUIC will fall back to HTTP/2 or HTTP/1.1 over TCP, which the proxy handles
    normally.

macOS / fallback:
    On macOS (or when nftables is unavailable), the launcher sets HTTP_PROXY /
    HTTPS_PROXY environment variables. This is a weaker enforcement suitable for
    local development only.
"""

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

# Packet mark used by mitmproxy to tag its own outbound connections.
# nftables rules skip packets carrying this mark so the proxy can reach
# upstream hosts without being redirected back to itself.
_PROXY_MARK = 0x1

# Name of the dedicated nftables chain managed by secrets-proxy.  Using a
# dedicated chain avoids collisions with other rules in "ip nat OUTPUT" and
# makes teardown safe (we only flush our own chain).
_NFT_CHAIN = "secrets_proxy"


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
    """Set up nftables to redirect **all** sandbox TCP through the proxy.

    Creates a dedicated chain ``secrets_proxy`` in the ``ip nat`` table so that
    teardown only removes our rules (not anyone else's).

    The rules implement a default-deny egress policy for the sandbox UID:

    1. Skip packets that carry ``_PROXY_MARK`` (these are mitmproxy's own
       upstream connections -- without this exemption the proxy's traffic would
       loop back to itself).
    2. Allow traffic to localhost (the proxy listener itself).
    3. Redirect **all** remaining TCP from ``sandbox_uid`` to ``proxy_port``.
    4. Drop **all** UDP from ``sandbox_uid`` (blocks DNS-over-UDP exfiltration
       and HTTP/3 QUIC bypass).

    Returns True if nftables was set up, False if not available.
    Only works on Linux with root/CAP_NET_ADMIN.

    Note: HTTP/3 (QUIC over UDP) is intentionally blocked.  Well-behaved HTTP
    clients will fall back to TCP-based HTTP/2 or HTTP/1.1 automatically.
    """
    if platform.system() != "Linux":
        logger.info("Not on Linux, skipping nftables (using proxy env vars instead)")
        return False

    try:
        cmds = [
            # --- Create dedicated chain in ip nat ---
            ["nft", "add", "chain", "ip", "nat", _NFT_CHAIN,
             "{ type nat hook output priority -1 ; }"],

            # 1. Skip marked packets (proxy's own upstream traffic)
            ["nft", "add", "rule", "ip", "nat", _NFT_CHAIN,
             "meta", "mark", hex(_PROXY_MARK), "accept"],

            # 2. Allow traffic to loopback (sandbox -> proxy listener)
            ["nft", "add", "rule", "ip", "nat", _NFT_CHAIN,
             "meta", "skuid", str(sandbox_uid),
             "ip", "daddr", "127.0.0.0/8", "accept"],

            # 3. Redirect all remaining TCP from sandbox UID to proxy port
            ["nft", "add", "rule", "ip", "nat", _NFT_CHAIN,
             "meta", "skuid", str(sandbox_uid),
             "ip", "protocol", "tcp",
             "redirect", "to", f":{proxy_port}"],

            # --- Block UDP egress for sandbox UID (separate filter chain) ---
            ["nft", "add", "chain", "ip", "filter", f"{_NFT_CHAIN}_filter",
             "{ type filter hook output priority 0 ; }"],

            # 4. Drop all UDP from sandbox UID (DNS exfil + QUIC bypass)
            ["nft", "add", "rule", "ip", "filter", f"{_NFT_CHAIN}_filter",
             "meta", "skuid", str(sandbox_uid),
             "ip", "protocol", "udp",
             "drop"],
        ]
        for cmd in cmds:
            subprocess.run(cmd, check=True, capture_output=True)
        logger.info(
            "nftables rules set for UID %d -> port %d (mark 0x%x exempt, UDP blocked)",
            sandbox_uid, proxy_port, _PROXY_MARK,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("nftables setup failed: %s. Falling back to proxy env vars.", e)
        return False


def _teardown_nftables(sandbox_uid: int, proxy_port: int) -> None:
    """Remove only the nftables chains created by secrets-proxy. Best-effort.

    Flushes and deletes the dedicated ``secrets_proxy`` and
    ``secrets_proxy_filter`` chains without touching any other rules.
    """
    if platform.system() != "Linux":
        return
    for table, chain in [("nat", _NFT_CHAIN), ("filter", f"{_NFT_CHAIN}_filter")]:
        try:
            subprocess.run(
                ["nft", "flush", "chain", "ip", table, chain],
                capture_output=True,
            )
            subprocess.run(
                ["nft", "delete", "chain", "ip", table, chain],
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    logger.info("nftables rules cleaned up")


def start_proxy(config: ProxyConfig, addon_path: str, *, use_transparent: bool = False) -> subprocess.Popen:
    """Start mitmproxy with the secrets addon.

    Args:
        config: Proxy configuration.
        addon_path: Path to the auto-generated mitmproxy addon script.
        use_transparent: If True, use ``--mode transparent`` (required when
            nftables redirects raw TCP to the proxy port). If False, use
            ``--mode regular`` (for macOS / env-var proxy mode).
    """
    mode = "transparent" if use_transparent else "regular"
    port = config.proxy_port or PROXY_PORT

    cmd = [
        "mitmdump",
        "--mode", mode,
        "--listen-host", PROXY_HOST,
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "-s", addon_path,
        "-q",  # quiet mode
    ]

    # When using transparent mode on Linux, tell mitmproxy to mark its own
    # outbound packets so nftables can exempt them from redirection.
    if use_transparent:
        cmd.extend(["--set", f"mark={_PROXY_MARK}"])

    logger.info("Starting mitmproxy (%s mode): %s", mode, " ".join(cmd))
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

    logger.info("mitmproxy started (PID %d) on %s:%d", proc.pid, PROXY_HOST, port)
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
    4. Set up nftables (Linux) or prepare proxy env vars (macOS)
    5. Start mitmproxy (transparent mode if nftables, regular otherwise)
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

    # Step 3: Write addon script with embedded config
    addon_script = _create_addon_script(config)

    # Step 4: Try nftables (Linux strong mode) *before* starting the proxy
    # so we know which mitmproxy mode to use.
    uid = os.getuid()
    used_nftables = _setup_nftables(uid, port)

    # Step 5: Start mitmproxy -- transparent mode when nftables is active
    # (raw redirected TCP requires transparent mode), regular mode otherwise.
    proxy_proc = start_proxy(config, addon_script, use_transparent=used_nftables)

    try:
        # Step 6: Build environment for sandboxed process
        sandbox_env = os.environ.copy()

        # Placeholder env vars (secrets)
        sandbox_env.update(config.get_env_vars())

        # CA trust env vars
        sandbox_env.update(ca_env)

        # Proxy env vars (for macOS / non-nftables mode).
        # Set them unconditionally -- they are harmless when nftables is active
        # and serve as the primary enforcement mechanism on macOS.
        proxy_url = f"http://{PROXY_HOST}:{port}"
        sandbox_env["HTTP_PROXY"] = proxy_url
        sandbox_env["HTTPS_PROXY"] = proxy_url
        sandbox_env["http_proxy"] = proxy_url
        sandbox_env["https_proxy"] = proxy_url

        # Step 7: Run the sandboxed command
        logger.info("Running: %s", " ".join(command))
        try:
            result = subprocess.run(command, env=sandbox_env)
            return result.returncode
        finally:
            # Step 8: Clean up nftables
            if used_nftables:
                _teardown_nftables(uid, port)

    finally:
        # Stop mitmproxy
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
        logger.info("mitmproxy stopped")

        # Clean up addon script
        try:
            os.unlink(addon_script)
        except OSError:
            pass


def _create_addon_script(config: ProxyConfig) -> str:
    """Create a temporary mitmproxy addon script with embedded config.

    We serialize the config into the script so mitmproxy can load it
    as a standalone addon without needing to import secrets_proxy.
    """
    # Serialize the minimal config needed by the addon
    secrets_data = {}
    for name, entry in config.secrets.items():
        secrets_data[entry.placeholder] = {
            "name": name,
            "value": entry.value,
            "hosts": entry.hosts,
        }

    allowed_hosts = list(config.allowed_hosts)

    script_content = f'''"""Auto-generated mitmproxy addon for secrets-proxy."""
import logging
from mitmproxy import http

logger = logging.getLogger("secrets-proxy-addon")

SECRETS = {secrets_data!r}
ALLOWED_HOSTS = {allowed_hosts!r}


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
            f"secrets-proxy: host '{{host}}' not in allowlist".encode(),
            {{"Content-Type": "text/plain"}},
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
            pass
'''

    # Write to temp file
    fd, path = tempfile.mkstemp(suffix=".py", prefix="secrets_proxy_addon_")
    with os.fdopen(fd, "w") as f:
        f.write(script_content)

    return path
