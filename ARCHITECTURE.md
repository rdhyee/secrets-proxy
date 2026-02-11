# Architecture

## Design Goals

1. **Transparency**: Sandboxed code should not need modification to work with the proxy. Any language, any HTTP library.
2. **Secret isolation**: Real credentials never appear in the sandbox's environment, memory, or filesystem.
3. **Host-scoped injection**: Each secret is bound to specific destination hosts. Sending a placeholder to an unapproved host leaks only the useless placeholder string.
4. **Network policy**: Non-allowlisted hosts are blocked entirely (defense in depth).
5. **Deployable**: Easy to run inside Sprites, Docker containers, or local dev.

## Components

### 1. Secret Configuration

A JSON file (or env-based config) mapping secret names to their configuration:

```json
{
  "OPENAI_API_KEY": {
    "placeholder": "SECRETS_PROXY_PLACEHOLDER_<random>",
    "value": "sk-real-key-here",
    "hosts": ["api.openai.com"],
    "inject": {
      "header": "Authorization",
      "format": "Bearer {value}"
    }
  },
  "GITHUB_TOKEN": {
    "placeholder": "SECRETS_PROXY_PLACEHOLDER_<random>",
    "value": "ghp_real-token",
    "hosts": ["api.github.com", "*.github.com"],
    "inject": {
      "header": "Authorization",
      "format": "token {value}"
    }
  }
}
```

**Placeholder generation**: Placeholders are generated at proxy startup with random suffixes. They're set as environment variables in the sandboxed process. The proxy knows the mapping from placeholder → real value and which hosts each applies to.

### 2. MITM Proxy (mitmproxy-based)

The core is a [mitmproxy](https://mitmproxy.org/) addon that:

1. **Intercepts HTTPS requests** via mitmproxy's TLS termination
2. **Checks the destination host** against the allowlist
3. **Scans request headers and body** for placeholder strings
4. **Substitutes placeholders with real secrets** for approved hosts
5. **Blocks requests to non-allowlisted hosts**

```python
# Simplified addon logic
class SecretsProxyAddon:
    def __init__(self, config):
        self.secrets = config  # placeholder → (real_value, allowed_hosts)
        self.allowed_hosts = set(...)

    def request(self, flow):
        host = flow.request.pretty_host

        # Block non-allowlisted hosts
        if host not in self.allowed_hosts:
            flow.response = Response.make(403, b"Host not allowed")
            return

        # Substitute placeholders in headers
        for header, value in flow.request.headers.items():
            for placeholder, (real_value, hosts) in self.secrets.items():
                if placeholder in value and host_matches(host, hosts):
                    flow.request.headers[header] = value.replace(
                        placeholder, real_value
                    )
```

**Why mitmproxy?**
- Mature, battle-tested HTTPS interception
- Python addon system — easy to extend
- Handles CA cert generation automatically
- Supports transparent proxy mode (required for nftables redirect)

### 3. Traffic Enforcement (nftables)

On Linux (Sprites, Docker), nftables rules redirect all outbound traffic through the proxy. Rules are installed in a dedicated chain (`secrets_proxy`) so that teardown only removes our rules.

```bash
# Dedicated NAT chain (output hook, priority -1)
nft add chain ip nat secrets_proxy '{ type nat hook output priority -1 ; }'

# 1. Skip packets marked by the proxy (prevents infinite redirect loop)
nft add rule ip nat secrets_proxy meta mark 0x1 accept

# 2. Allow sandbox -> loopback (so it can reach the proxy listener)
nft add rule ip nat secrets_proxy meta skuid $SANDBOX_UID ip daddr 127.0.0.0/8 accept

# 3. Redirect ALL remaining TCP from sandbox UID to proxy port
nft add rule ip nat secrets_proxy meta skuid $SANDBOX_UID ip protocol tcp redirect to :$PROXY_PORT

# 4. Block ALL UDP from sandbox UID (prevents DNS exfil + QUIC bypass)
nft add chain ip filter secrets_proxy_filter '{ type filter hook output priority 0 ; }'
nft add rule ip filter secrets_proxy_filter meta skuid $SANDBOX_UID ip protocol udp drop
```

**Key design decisions:**

- **Packet marking to prevent self-loop**: mitmproxy is started with `--set mark=0x1`. Its outbound connections carry this mark in the IP header, which the first nftables rule matches and accepts. Without this, the proxy's upstream traffic would be redirected back to itself in an infinite loop.
- **All TCP, not just 443/80**: Redirecting only ports 443 and 80 would miss API calls on non-standard ports. All TCP is redirected.
- **UDP blocked entirely**: HTTP/3 (QUIC) runs over UDP and would bypass the MITM proxy. Blocking all UDP forces clients to fall back to TCP-based HTTP/2 or HTTP/1.1. DNS-over-UDP exfiltration is also blocked.
- **Dedicated chain**: Using a dedicated `secrets_proxy` chain (rather than adding rules to the system `OUTPUT` chain) means teardown only flushes our rules without disrupting other nftables configuration.
- **Transparent mode**: nftables redirect sends raw TCP (not HTTP CONNECT) to the proxy port, so mitmproxy must run in `--mode transparent` (not `--mode regular`).

This is the "strong jail" -- the sandboxed process literally cannot bypass the proxy at the kernel level. (Inspired by httpjail's Linux enforcement.)

On macOS (local dev), falls back to `HTTP_PROXY`/`HTTPS_PROXY` environment variables (weaker, but fine for testing). mitmproxy runs in `--mode regular` in this case.

### 4. CA Trust Setup

The proxy's CA certificate must be trusted by the sandboxed code. The launcher script:

1. Generates mitmproxy's CA cert (or uses existing)
2. Copies it to a known location (e.g., `/etc/secrets-proxy/ca.pem`)
3. Sets environment variables for the sandboxed process:

```bash
export SSL_CERT_FILE=/etc/secrets-proxy/ca.pem
export REQUESTS_CA_BUNDLE=/etc/secrets-proxy/ca.pem
export NODE_EXTRA_CA_CERTS=/etc/secrets-proxy/ca.pem
export CURL_CA_BUNDLE=/etc/secrets-proxy/ca.pem
# Also append to system CA bundle for languages that use it
cat /etc/secrets-proxy/ca.pem >> /etc/ssl/certs/ca-certificates.crt
```

This is the key to **transparency** — the sandboxed code's HTTP libraries automatically trust the proxy's MITM certificates without any code changes.

### 5. Launcher (`secrets-proxy run`)

The CLI entry point that orchestrates everything:

```
secrets-proxy run --config secrets.json --allow-net api.openai.com -- python my_script.py
```

Steps:
1. Parse secret configuration
2. Generate placeholder values (random per session)
3. Start mitmproxy in transparent mode with the secrets addon
4. Set up nftables rules (Linux) or proxy env vars (macOS)
5. Set up CA trust (env vars + system CA bundle)
6. Set placeholder env vars for the sandboxed process
7. Exec the sandboxed command
8. On exit: tear down nftables rules, stop proxy

## Security Model

### Threat: Sandbox code tries to read secrets
**Mitigation**: Secrets are never in the sandbox's environment. Only placeholders.

### Threat: Sandbox code sends placeholder to attacker-controlled host
**Mitigation**: `allow_net` blocks non-allowlisted hosts. Even if an allowed host receives a placeholder, it's a useless random string — the proxy only substitutes for host-scoped secrets.

### Threat: Sandbox code tries to bypass the proxy
**Mitigation (Linux)**: nftables rules at kernel level — cannot be bypassed by userspace code without root.
**Mitigation (macOS)**: Weaker — relies on proxy env vars. Acceptable for local dev/testing only.

### Threat: Sandbox code inspects proxy process memory
**Mitigation**: The proxy runs as a different user. On Sprites, the sandboxed process runs as an unprivileged user that cannot ptrace or read /proc of the proxy process.

### Threat: DNS-based exfiltration
**Mitigation**: (Future) DNS filtering or forwarding through the proxy.

### What this does NOT protect against
- Sandbox code with root access (can modify nftables, read proxy memory)
- Side-channel attacks (timing, etc.)
- The proxy itself being compromised

This is "practical security for AI agent sandboxing" — not a high-assurance enclave. The goal is to prevent accidental or injection-driven secret exfiltration, not to resist a sophisticated attacker with root.

## Deployment Patterns

### Pattern 1: Inside a Sprite

```bash
# On sprite setup (golden image):
pip install secrets-proxy
# Checkpoint here

# At task time:
sprite exec -- secrets-proxy run \
  --config /tmp/secrets.json \
  --allow-net api.openai.com \
  -- python /tmp/task.py
```

The secret config is passed in at task time (not baked into the image). The proxy starts, wraps the task, and tears down.

### Pattern 2: Docker sidecar

```yaml
# docker-compose.yml
services:
  proxy:
    image: secrets-proxy
    environment:
      - SECRETS_CONFIG=...
    networks:
      - isolated

  worker:
    image: python:3.13
    network_mode: "service:proxy"  # shares network namespace
    depends_on: [proxy]
    environment:
      - OPENAI_API_KEY=SECRETS_PROXY_PLACEHOLDER_xxx
      - HTTP_PROXY=http://proxy:8080
      - HTTPS_PROXY=http://proxy:8080
```

### Pattern 3: Local development

```bash
# macOS — weak mode (proxy env vars, no nftables)
secrets-proxy run --config secrets.json -- python my_script.py
```

## MVP Scope

The MVP focuses on the simplest useful implementation:

1. **mitmproxy addon** that does placeholder → secret substitution
2. **Shell launcher script** (`secrets-proxy-run.sh`) that:
   - Starts mitmproxy in transparent mode
   - Sets up CA trust env vars
   - Sets placeholder env vars
   - Runs the sandboxed command
   - Cleans up on exit
3. **JSON config format** for secrets
4. **Linux support only** for nftables enforcement (macOS falls back to env vars)
5. **Test inside a Sprite** to validate end-to-end

### Not in MVP
- PyPI packaging
- Docker sidecar mode
- DNS filtering
- Web UI / monitoring
- Encrypted secret config (secrets.json is plaintext — protect it with file permissions)
- Windows support
- Wildcard host patterns

## File Structure

```
secrets-proxy/
├── README.md
├── ARCHITECTURE.md
├── pyproject.toml
├── src/
│   └── secrets_proxy/
│       ├── __init__.py
│       ├── cli.py          # CLI entry point
│       ├── config.py       # Secret config parsing
│       ├── addon.py        # mitmproxy addon
│       ├── launcher.py     # Process launcher + nftables setup
│       └── ca_trust.py     # CA certificate trust setup
├── scripts/
│   └── secrets-proxy-run.sh  # Standalone shell launcher (no pip needed)
└── tests/
    ├── test_addon.py
    ├── test_config.py
    └── test_e2e.py
```
