#!/bin/bash
# secrets-proxy Docker entrypoint
#
# INIT TIME: This script runs as root. It builds the jail:
#   1. Starts mitmproxy with packet marking
#   2. Sets up nftables to redirect sandbox user's traffic
#   3. Sets up CA trust
#   4. Drops to sandbox user and runs the command
#
# RUN TIME: The sandboxed command runs as uid=sandbox inside the jail.

set -euo pipefail

PROXY_PORT="${SECRETS_PROXY_PORT:-8080}"
PROXY_MARK=1
SANDBOX_USER="sandbox"
SANDBOX_UID=$(id -u "$SANDBOX_USER")
NFT_CHAIN="secrets_proxy"

# ── Validate ──────────────────────────────────────────────────

if [[ -z "${SECRETS_PROXY_CONFIG_JSON:-}" ]]; then
    echo "[secrets-proxy] ERROR: SECRETS_PROXY_CONFIG_JSON env var is required" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "[secrets-proxy] ERROR: No command specified" >&2
    echo "Usage: docker run ... <image> <command>" >&2
    exit 1
fi

echo "[secrets-proxy] Starting (proxy_port=$PROXY_PORT, sandbox_uid=$SANDBOX_UID)"

# ── Generate addon script from config ─────────────────────────

ADDON_SCRIPT=$(mktemp /tmp/secrets_proxy_addon_XXXXXX.py)

python3 -c "
import json, os, sys

config_json = os.environ['SECRETS_PROXY_CONFIG_JSON']
raw = json.loads(config_json)

secrets_map = {}
env_lines = []
allowed_hosts = []

for name, entry in raw.items():
    import secrets as s
    placeholder = f'SECRETS_PROXY_PLACEHOLDER_{s.token_hex(16)}'
    secrets_map[placeholder] = {
        'name': name,
        'value': entry['value'],
        'hosts': entry['hosts'],
    }
    env_lines.append(f'{name}={placeholder}')
    for h in entry['hosts']:
        allowed_hosts.append(h)

# Write env file for sandbox
with open('/tmp/sandbox_env.sh', 'w') as f:
    for line in env_lines:
        f.write(f'export {line}\n')

# Write addon
addon = '''
import logging
from mitmproxy import http

logger = logging.getLogger(\"secrets-proxy-addon\")

SECRETS = ''' + repr(secrets_map) + '''
ALLOWED_HOSTS = ''' + repr(allowed_hosts) + '''

def _host_allowed(host):
    host = host.lower()
    for p in ALLOWED_HOSTS:
        if p.startswith(\"*.\"):
            if host.endswith(p[1:]) or host == p[2:]:
                return True
        elif host == p.lower():
            return True
    return False

def _host_matches(host, hosts):
    host = host.lower()
    for p in hosts:
        if p.startswith(\"*.\"):
            if host.endswith(p[1:]) or host == p[2:]:
                return True
        elif host == p.lower():
            return True
    return False

def request(flow):
    host = flow.request.pretty_host
    if not _host_allowed(host):
        flow.response = http.Response.make(403, f\"blocked: {host}\".encode())
        logger.info(\"Blocked: %s\", host)
        return
    for hname in list(flow.request.headers.keys()):
        hval = flow.request.headers[hname]
        for placeholder, info in SECRETS.items():
            if placeholder in hval and _host_matches(host, info[\"hosts\"]):
                flow.request.headers[hname] = hval.replace(placeholder, info[\"value\"])
                logger.info(\"Injected %s for %s\", info[\"name\"], host)
                hval = flow.request.headers[hname]
    if flow.request.content:
        try:
            body = flow.request.content.decode()
            for placeholder, info in SECRETS.items():
                if placeholder in body and _host_matches(host, info[\"hosts\"]):
                    body = body.replace(placeholder, info[\"value\"])
            flow.request.content = body.encode()
        except:
            pass
'''
print(addon)
" > "$ADDON_SCRIPT"

echo "[secrets-proxy] Addon script generated"

# ── Create combined CA bundle ──────────────────────────────────

MITM_CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
CA_BUNDLE=$(mktemp /tmp/secrets_proxy_ca_XXXXXX.pem)

# System CA + mitmproxy CA
if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    cat /etc/ssl/certs/ca-certificates.crt > "$CA_BUNDLE"
    echo "" >> "$CA_BUNDLE"
fi
cat "$MITM_CA" >> "$CA_BUNDLE"

# Append to system CA store so all libraries trust it
if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
    cat "$MITM_CA" >> /etc/ssl/certs/ca-certificates.crt
fi

# Append to certifi's bundle (Python uses this, not system store)
CERTIFI_BUNDLE=$(python3 -c "import certifi; print(certifi.where())" 2>/dev/null || true)
if [[ -n "$CERTIFI_BUNDLE" && -f "$CERTIFI_BUNDLE" ]]; then
    cat "$MITM_CA" >> "$CERTIFI_BUNDLE"
    echo "[secrets-proxy] Appended CA to certifi bundle: $CERTIFI_BUNDLE"
fi

# Make CA bundle readable by sandbox user
chmod 644 "$CA_BUNDLE"

echo "[secrets-proxy] CA bundle created at $CA_BUNDLE"

# ── Start mitmproxy (INIT TIME — runs as root with packet marking) ──

mitmdump \
    --mode transparent \
    --listen-host 127.0.0.1 \
    --listen-port "$PROXY_PORT" \
    --set connection_strategy=lazy \
    --set mark="$PROXY_MARK" \
    -s "$ADDON_SCRIPT" \
    -q &
PROXY_PID=$!

sleep 2
if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "[secrets-proxy] ERROR: mitmproxy failed to start" >&2
    exit 1
fi
echo "[secrets-proxy] mitmproxy started (PID $PROXY_PID, mark=0x$PROXY_MARK)"

# ── Set up nftables (INIT TIME — the "concrete walls") ────────

# Create tables first (may not exist in minimal container)
nft add table ip nat 2>/dev/null || true
nft add table ip filter 2>/dev/null || true

# NAT chain: redirect sandbox traffic
nft add chain ip nat "$NFT_CHAIN" '{ type nat hook output priority -1 ; }'

# 1. Skip packets marked by proxy (prevent self-loop)
nft add rule ip nat "$NFT_CHAIN" meta mark 0x$PROXY_MARK accept

# 2. Allow sandbox → proxy port only (not all of localhost)
nft add rule ip nat "$NFT_CHAIN" meta skuid "$SANDBOX_UID" ip daddr 127.0.0.1 tcp dport "$PROXY_PORT" accept

# 3. Redirect ALL remaining TCP from sandbox to proxy
nft add rule ip nat "$NFT_CHAIN" meta skuid "$SANDBOX_UID" ip protocol tcp redirect to :"$PROXY_PORT"

# Filter chain: block UDP except DNS
nft add chain ip filter "${NFT_CHAIN}_filter" '{ type filter hook output priority 0 ; }'
nft add rule ip filter "${NFT_CHAIN}_filter" meta skuid "$SANDBOX_UID" udp dport 53 accept
nft add rule ip filter "${NFT_CHAIN}_filter" meta skuid "$SANDBOX_UID" ip protocol udp drop

echo "[secrets-proxy] nftables rules installed"
nft list ruleset

# ── Cleanup handler ────────────────────────────────────────────

cleanup() {
    echo "[secrets-proxy] Cleaning up..."
    kill $PROXY_PID 2>/dev/null || true
    wait $PROXY_PID 2>/dev/null || true
    nft delete chain ip nat "$NFT_CHAIN" 2>/dev/null || true
    nft delete chain ip filter "${NFT_CHAIN}_filter" 2>/dev/null || true
    rm -f "$ADDON_SCRIPT" "$CA_BUNDLE" /tmp/sandbox_env.sh
    echo "[secrets-proxy] Done"
}
trap cleanup EXIT

# ── RUN TIME: Execute sandboxed command as unprivileged user ───

echo "[secrets-proxy] Running as '$SANDBOX_USER': $*"
echo "────────────────────────────────────────"

# Source env vars and run as sandbox user
su "$SANDBOX_USER" -c "
    source /tmp/sandbox_env.sh
    export SSL_CERT_FILE=$CA_BUNDLE
    export REQUESTS_CA_BUNDLE=$CA_BUNDLE
    export NODE_EXTRA_CA_CERTS=$CA_BUNDLE
    export CURL_CA_BUNDLE=$CA_BUNDLE
    $*
"
EXIT_CODE=$?

echo "────────────────────────────────────────"
echo "[secrets-proxy] Command exited with code $EXIT_CODE"
exit $EXIT_CODE
