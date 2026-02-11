# secrets-proxy

A transparent HTTP/HTTPS proxy that injects secrets into sandboxed code's outbound requests — without the sandbox ever seeing the real credentials.

## The Problem

When running untrusted or semi-trusted code in sandboxes (Sprites, Docker, VMs), that code often needs to call external APIs that require authentication. The naive approach — injecting API keys as environment variables — means the sandbox code can read and exfiltrate those secrets.

**The secret-injecting proxy pattern** solves this: sandboxed code sees only placeholder tokens. A proxy outside the sandbox's trust boundary intercepts outbound HTTPS requests and swaps placeholders for real secrets, but only for approved destination hosts.

```
┌─────────────────────────────┐
│  Sandboxed code             │
│  OPENAI_KEY=PLACEHOLDER_x   │
│  fetch("api.openai.com",    │
│    headers: {Bearer PLCHLDR})│
│         │                   │
│    [traffic forced through  │
│     proxy via nftables]     │
│         ▼                   │
│  secrets-proxy              │
│  ┌─────────────────────┐   │
│  │ if host in approved: │   │
│  │   swap PLCHLDR→real  │   │
│  │ if host not allowed: │   │
│  │   block request      │   │
│  └─────────────────────┘   │
└─────────────┬───────────────┘
              │ HTTPS (real secret in header)
              ▼
         External APIs
```

## Key Properties

| Property | How |
|----------|-----|
| **Code is oblivious** | Transparent proxy via nftables — code doesn't know it's proxied |
| **Any language works** | Auto-trusted CA cert via `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` |
| **Secrets never in sandbox** | Placeholder tokens only; real values injected at proxy layer |
| **Host-scoped secrets** | Each secret specifies which hosts it can be sent to |
| **Network allowlist** | Non-approved hosts are blocked entirely |

## Prior Art

This project builds on ideas from:

- **[Deno Sandbox](https://deno.com/deploy/sandbox)** — Built-in placeholder→secret substitution on outbound HTTPS, but only works with Deno's `fetch` (Python/other languages fail due to MITM cert issues)
- **[Fly Tokenizer](https://github.com/superfly/tokenizer)** — HTTP proxy with encrypted secret injection, but requires client code to use proxy protocol (not transparent)
- **[httpjail](https://github.com/coder/httpjail)** — Transparent HTTPS filtering proxy with nftables enforcement and auto CA trust, but filters only (no secret injection)
- **[mitmproxy](https://mitmproxy.org/)** — Extensible Python MITM proxy with addon system

`secrets-proxy` combines httpjail's transparent interception + auto CA trust with Deno's placeholder→secret substitution pattern.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Quick Start

```bash
# Install
pip install secrets-proxy  # future

# Configure secrets
cat > secrets.json <<'EOF'
{
  "OPENAI_API_KEY": {
    "placeholder": "SECRETS_PROXY_PLACEHOLDER_openai",
    "value": "sk-real-key-here",
    "hosts": ["api.openai.com"]
  }
}
EOF

# Run sandboxed code with secrets-proxy
secrets-proxy run \
  --config secrets.json \
  --allow-net api.openai.com \
  -- python my_script.py
```

Inside `my_script.py`, `os.environ["OPENAI_API_KEY"]` returns the placeholder. But when `requests.post("https://api.openai.com/...")` sends it in a header, the proxy swaps in the real key.

## Target Environments

| Environment | How secrets-proxy runs |
|-------------|----------------------|
| **Sprites** (Fly.io) | Inside the Sprite VM, wrapping the sandboxed process |
| **Docker** | On the host or as a sidecar, with `--network` isolation |
| **Local dev** | Wrapping a process for testing |

## Status

**Pre-alpha** — Architecture and MVP in progress.

## License

MIT
