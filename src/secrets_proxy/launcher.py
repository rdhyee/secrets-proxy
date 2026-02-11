"""Process launcher: starts mitmproxy, sets up environment, runs sandboxed command.

Network enforcement (Linux/nftables):
    All TCP egress from the sandbox UID is redirected to the proxy port via a
    dedicated nftables chain ("secrets_proxy"). The proxy's own outbound packets
    are exempted using packet marks (SO_MARK / mitmproxy ``--set mark=0x1``), so
    they reach upstream hosts directly without looping back.

    UDP egress is blocked for the sandbox UID, except DNS (UDP port 53) which is
    allowed so name resolution works. HTTP/3 (QUIC over UDP) is **not supported**
    -- clients that attempt QUIC will fall back to HTTP/2 or HTTP/1.1 over TCP.

macOS / fallback:
    On macOS (or when nftables is unavailable), the launcher sets HTTP_PROXY /
    HTTPS_PROXY environment variables. This is a weaker enforcement suitable for
    local development only.
"""

from __future__ import annotations

import json as _json
import logging
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
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


def _check_mitmdump() -> None:
    """Verify that mitmdump is available on PATH.

    Raises RuntimeError with a clear message if not found.
    """
    if shutil.which("mitmdump") is None:
        raise RuntimeError(
            "mitmdump not found on PATH. Install mitmproxy: "
            "pip install mitmproxy  or  brew install mitmproxy"
        )


def _check_config_permissions(config_path: str | Path) -> None:
    """Warn if the secrets config file has overly permissive permissions."""
    try:
        st = os.stat(config_path)
        mode = st.st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            logger.warning(
                "Config file %s is readable by group/others (mode %o). "
                "Consider: chmod 600 %s",
                config_path, stat.S_IMODE(mode), config_path,
            )
    except OSError:
        pass


def _generate_mitmproxy_ca_if_needed() -> None:
    """Run mitmproxy briefly to generate CA certs if they don't exist."""
    if MITMPROXY_CA_CERT.exists():
        return

    _check_mitmdump()

    logger.info("Generating mitmproxy CA certificate (first run)...")
    MITMPROXY_CA_DIR.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        ["mitmdump", "--listen-port", "0", "-q"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    proc.terminate()
    proc.wait(timeout=5)

    if MITMPROXY_CA_CERT.exists():
        logger.info("CA certificate generated at %s", MITMPROXY_CA_CERT)
    else:
        raise RuntimeError("Failed to generate mitmproxy CA certificate")


def _setup_nftables(sandbox_uid: int, proxy_port: int) -> bool:
    """Set up nftables to redirect **all** sandbox TCP through the proxy.

    Creates dedicated chains in the ``inet`` family (covers both IPv4 and
    IPv6) so that teardown only removes our rules (not anyone else's).

    The rules implement a default-deny egress policy for the sandbox UID:

    1. Skip packets that carry ``_PROXY_MARK`` (these are mitmproxy's own
       upstream connections -- without this exemption the proxy's traffic would
       loop back to itself).
    2. Allow traffic to the proxy listener only (127.0.0.1:proxy_port).
    3. Redirect **all** remaining IPv4 TCP from ``sandbox_uid`` to ``proxy_port``.
    4. Drop **all** IPv6 TCP from ``sandbox_uid`` (proxy listens on IPv4 only).
    5. Drop **all** UDP from ``sandbox_uid`` except DNS (port 53).

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
            # --- Create inet tables (covers both IPv4 and IPv6) ---
            ["nft", "add", "table", "inet", _NFT_CHAIN],

            # --- NAT chain (IPv4 redirect) ---
            # Note: redirect target in inet NAT chains applies to IPv4 traffic.
            # IPv6 TCP is handled by the filter chain (dropped).
            ["nft", "add", "chain", "inet", _NFT_CHAIN, "nat_output",
             "{ type nat hook output priority -1 ; }"],

            # 1. Skip marked packets (proxy's own upstream traffic)
            ["nft", "add", "rule", "inet", _NFT_CHAIN, "nat_output",
             "meta", "mark", hex(_PROXY_MARK), "accept"],

            # 2. Allow sandbox -> proxy listener ONLY (not all of localhost)
            ["nft", "add", "rule", "inet", _NFT_CHAIN, "nat_output",
             "meta", "skuid", str(sandbox_uid),
             "ip", "daddr", "127.0.0.1", "tcp", "dport", str(proxy_port), "accept"],

            # 3. Redirect all remaining IPv4 TCP from sandbox UID to proxy port
            ["nft", "add", "rule", "inet", _NFT_CHAIN, "nat_output",
             "meta", "skuid", str(sandbox_uid),
             "meta", "nfproto", "ipv4",
             "meta", "l4proto", "tcp",
             "redirect", "to", f":{proxy_port}"],

            # --- Filter chain (blocks IPv6 TCP + all UDP except DNS) ---
            ["nft", "add", "chain", "inet", _NFT_CHAIN, "filter_output",
             "{ type filter hook output priority 0 ; }"],

            # 4. Drop ALL IPv6 TCP from sandbox (proxy only listens on IPv4)
            ["nft", "add", "rule", "inet", _NFT_CHAIN, "filter_output",
             "meta", "skuid", str(sandbox_uid),
             "meta", "nfproto", "ipv6",
             "meta", "l4proto", "tcp",
             "drop"],

            # 5a. Allow DNS (UDP port 53) so name resolution works
            ["nft", "add", "rule", "inet", _NFT_CHAIN, "filter_output",
             "meta", "skuid", str(sandbox_uid),
             "udp", "dport", "53", "accept"],

            # 5b. Drop all other UDP from sandbox UID (QUIC bypass prevention)
            ["nft", "add", "rule", "inet", _NFT_CHAIN, "filter_output",
             "meta", "skuid", str(sandbox_uid),
             "meta", "l4proto", "udp",
             "drop"],
        ]
        for cmd in cmds:
            subprocess.run(cmd, check=True, capture_output=True)
        logger.info(
            "nftables rules set for UID %d -> port %d (mark 0x%x exempt, "
            "IPv6 TCP blocked, UDP blocked except DNS)",
            sandbox_uid, proxy_port, _PROXY_MARK,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("nftables setup failed: %s. Falling back to proxy env vars.", e)
        return False


def _teardown_nftables(sandbox_uid: int, proxy_port: int) -> None:
    """Remove only the nftables table created by secrets-proxy. Best-effort.

    Deletes the dedicated ``inet secrets_proxy`` table (which contains both
    the NAT and filter chains) without touching any other rules.
    """
    if platform.system() != "Linux":
        return
    try:
        subprocess.run(
            ["nft", "delete", "table", "inet", _NFT_CHAIN],
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    logger.info("nftables rules cleaned up")


def start_proxy(
    config: ProxyConfig,
    addon_path: str,
    *,
    use_transparent: bool = False,
    addon_env: dict[str, str] | None = None,
) -> subprocess.Popen:
    """Start mitmproxy with the secrets addon.

    Args:
        config: Proxy configuration.
        addon_path: Path to the auto-generated mitmproxy addon script.
        use_transparent: If True, use ``--mode transparent`` (required when
            nftables redirects raw TCP to the proxy port). If False, use
            ``--mode regular`` (for macOS / env-var proxy mode).

    Uses subprocess.DEVNULL for stdout/stderr to avoid pipe deadlock.
    """
    _check_mitmdump()

    mode = "transparent" if use_transparent else "regular"
    port = config.proxy_port or PROXY_PORT

    cmd = [
        "mitmdump",
        "--mode", mode,
        "--listen-host", PROXY_HOST,
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "-s", addon_path,
        "-q",
    ]

    # When using transparent mode on Linux, tell mitmproxy to mark its own
    # outbound packets so nftables can exempt them from redirection.
    if use_transparent:
        cmd.extend(["--set", f"mark={_PROXY_MARK}"])

    logger.info("Starting mitmproxy (%s mode): %s", mode, " ".join(cmd))
    proxy_env = os.environ.copy()
    if addon_env:
        proxy_env.update(addon_env)

    proc = subprocess.Popen(
        cmd,
        env=proxy_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(1)
    if proc.poll() is not None:
        raise RuntimeError(
            f"mitmproxy exited immediately (code {proc.returncode}). "
            "Check that the port is available and the addon script is valid."
        )

    logger.info("mitmproxy started (PID %d) on %s:%d", proc.pid, PROXY_HOST, port)
    return proc


def run(
    config: ProxyConfig,
    command: list[str],
    *,
    ca_bundle_path: Path | None = None,
) -> int:
    """Run a command with secrets-proxy wrapping.

    1. Check dependencies (mitmdump on PATH)
    2. Generate mitmproxy CA if needed
    3. Create combined CA bundle (temp file, no root needed)
    4. Write mitmproxy addon script (secrets via env var, not on disk)
    5. Set up nftables (Linux) or prepare proxy env vars (macOS)
    6. Start mitmproxy (transparent if nftables, regular otherwise)
    7. Run the sandboxed command with placeholder env vars
    8. Clean up (nftables, proxy, temp files)

    Returns the sandboxed command's exit code.
    """
    port = config.proxy_port or PROXY_PORT

    # Step 1: Check dependencies
    _check_mitmdump()

    # Step 2: Ensure CA exists
    _generate_mitmproxy_ca_if_needed()

    # Step 3: Create combined CA bundle (temp file — no root needed)
    bundle_path, ca_env = setup_ca_trust(ca_bundle_path)
    logger.info("CA bundle created at %s", bundle_path)

    # Step 4: Write addon script (secrets passed via env var, not in file)
    addon_script, addon_env = _create_addon_script(config)

    # Step 5: Try nftables (Linux strong mode) BEFORE starting proxy
    # so we know which mitmproxy mode to use.
    uid = os.getuid()
    used_nftables = _setup_nftables(uid, port)

    # Step 6: Start mitmproxy — transparent mode when nftables is active
    proxy_proc = start_proxy(
        config, addon_script, use_transparent=used_nftables, addon_env=addon_env,
    )

    # Sandbox process reference for health monitor
    sandbox_proc: subprocess.Popen | None = None
    sandbox_ready = threading.Event()
    shutting_down = threading.Event()

    def _proxy_health_monitor() -> None:
        """Background thread: kill sandbox if proxy dies unexpectedly."""
        sandbox_ready.wait()
        while not shutting_down.is_set():
            if shutting_down.wait(timeout=1):
                return
            if proxy_proc.poll() is not None:
                if shutting_down.is_set():
                    return
                logger.error(
                    "mitmproxy died (exit %d) — killing sandbox for fail-closed safety",
                    proxy_proc.returncode,
                )
                if sandbox_proc and sandbox_proc.poll() is None:
                    sandbox_proc.kill()
                return

    def _cleanup() -> None:
        """Best-effort cleanup of all resources."""
        # Prevent monitor from killing sandbox during intentional shutdown.
        shutting_down.set()
        sandbox_ready.set()
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
        logger.info("mitmproxy stopped")

        if used_nftables:
            _teardown_nftables(uid, port)

        for path in [addon_script, str(bundle_path)]:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _signal_handler(signum: int, frame: object) -> None:
        logger.info("Received signal %d, cleaning up...", signum)
        _cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        # Step 7: Build environment for sandboxed process
        sandbox_env = os.environ.copy()

        # Placeholder env vars (secrets)
        sandbox_env.update(config.get_env_vars())

        # CA trust env vars
        sandbox_env.update(ca_env)

        # Proxy env vars (harmless when nftables is active,
        # primary enforcement mechanism on macOS)
        proxy_url = f"http://{PROXY_HOST}:{port}"
        sandbox_env["HTTP_PROXY"] = proxy_url
        sandbox_env["HTTPS_PROXY"] = proxy_url
        sandbox_env["http_proxy"] = proxy_url
        sandbox_env["https_proxy"] = proxy_url

        # Start health monitor
        monitor = threading.Thread(target=_proxy_health_monitor, daemon=True)
        monitor.start()

        # Step 8: Run the sandboxed command
        logger.info("Running: %s", " ".join(command))
        try:
            sandbox_proc = subprocess.Popen(command, env=sandbox_env)
            sandbox_ready.set()
            sandbox_proc.wait()
            return sandbox_proc.returncode
        finally:
            if sandbox_proc and sandbox_proc.poll() is None:
                sandbox_proc.terminate()
                try:
                    sandbox_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    sandbox_proc.kill()

    finally:
        _cleanup()


def _create_addon_script(config: ProxyConfig) -> tuple[str, dict[str, str]]:
    """Create a temporary mitmproxy addon script.

    Secrets are passed via the SECRETS_PROXY_CONFIG_JSON environment variable
    (not embedded in the script file) so that real credentials are never
    written to disk.
    """
    allowed_hosts = list(config.allowed_hosts)

    secrets_data = {}
    for name, entry in config.secrets.items():
        secrets_data[entry.placeholder] = {
            "name": name,
            "value": entry.value,
            "hosts": entry.hosts,
        }
    addon_env = {"SECRETS_PROXY_CONFIG_JSON": _json.dumps({
        "secrets": secrets_data,
        "allowed_hosts": allowed_hosts,
    })}

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
    host = host.lower()
    for pattern in ALLOWED_HOSTS:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            base = pattern[2:]
            if host == base or (host.endswith(suffix) and len(host) > len(suffix)):
                return True
        elif host == pattern:
            return True
    return False


def _host_matches_secret(host: str, hosts: list) -> bool:
    host = host.lower()
    for pattern in hosts:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            base = pattern[2:]
            if host == base or (host.endswith(suffix) and len(host) > len(suffix)):
                return True
        elif host == pattern:
            return True
    return False


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    if not _host_allowed(host):
        flow.response = http.Response.make(
            403,
            f"secrets-proxy: host \\'{host}\\' not in allowlist".encode(),
            {"Content-Type": "text/plain"},
        )
        logger.info("audit action=block host=%s path=%s method=%s", host, flow.request.path, flow.request.method)
        return

    def substitute(text: str) -> tuple[str, int]:
        count = 0
        for placeholder, info in SECRETS.items():
            if placeholder in text and _host_matches_secret(host, info["hosts"]):
                text = text.replace(placeholder, info["value"])
                count += 1
                logger.info("Injected secret \\'%s\\' for %s", info["name"], host)
        return text, count

    total_subs = 0

    # Substitute in headers
    for hname in list(flow.request.headers.keys()):
        hval = flow.request.headers[hname]
        new_val, n = substitute(hval)
        if n > 0:
            flow.request.headers[hname] = new_val
            total_subs += n

    # Substitute in URL (query params)
    if flow.request.url:
        new_url, n = substitute(flow.request.url)
        if n > 0:
            flow.request.url = new_url
            total_subs += n

    # Substitute in body
    if flow.request.content:
        try:
            body = flow.request.content.decode("utf-8")
            new_body, n = substitute(body)
            if n > 0:
                flow.request.content = new_body.encode("utf-8")
                # Let mitmproxy recalculate Content-Length
                if "Content-Length" in flow.request.headers:
                    flow.request.headers["Content-Length"] = str(len(flow.request.content))
                total_subs += n
        except UnicodeDecodeError:
            logger.warning("audit action=skip_body host=%s path=%s reason=binary_content", host, flow.request.path)

    if total_subs > 0:
        logger.info("audit action=substitute host=%s path=%s secrets_injected=%d method=%s", host, flow.request.path, total_subs, flow.request.method)
    else:
        logger.debug("audit action=pass host=%s path=%s method=%s", host, flow.request.path, flow.request.method)


def _redact_secret_values(text: str) -> tuple[str, int]:
    """Replace real secret values with redaction markers."""
    count = 0
    for placeholder, info in SECRETS.items():
        if info["value"] in text:
            text = text.replace(info["value"], f"[REDACTED:{info['name']}]")
            count += 1
            logger.warning("audit action=redact_response secret=%s reason=reflection_prevention", info["name"])
    return text, count


def response(flow: http.HTTPFlow) -> None:
    """Scrub real secret values from responses to prevent reflection attacks."""
    if flow.response is None:
        return

    total_redactions = 0

    # Scrub response headers
    for hname in list(flow.response.headers.keys()):
        hval = flow.response.headers[hname]
        new_val, n = _redact_secret_values(hval)
        if n > 0:
            flow.response.headers[hname] = new_val
            total_redactions += n

    # Scrub response body
    if flow.response.content:
        try:
            body = flow.response.content.decode("utf-8")
            new_body, n = _redact_secret_values(body)
            if n > 0:
                flow.response.content = new_body.encode("utf-8")
                if "Content-Length" in flow.response.headers:
                    flow.response.headers["Content-Length"] = str(len(flow.response.content))
                total_redactions += n
        except UnicodeDecodeError:
            pass

    if total_redactions > 0:
        logger.warning("audit action=redact_response host=%s path=%s redactions=%d", flow.request.pretty_host, flow.request.path, total_redactions)
'''

    fd, path = tempfile.mkstemp(suffix=".py", prefix="secrets_proxy_addon_")
    with os.fdopen(fd, "w") as f:
        f.write(script_content)

    return path, addon_env
