#!/bin/bash
# secrets-proxy on Sprites — proof of concept
#
# Usage: sudo bash sprite_secrets_proxy.sh <config_json> -- <command>
#
# Runs as root for init time (nftables, proxy), drops to 'sprite' for sandbox.

set -euo pipefail

PROXY_PORT=8080
PROXY_MARK=1
SANDBOX_USER="sandbox"
SANDBOX_UID=$(id -u "$SANDBOX_USER")
NFT_CHAIN="secrets_proxy"
MITMDUMP="/.sprite/languages/python/pyenv/versions/3.13.7/bin/mitmdump"
PYTHON3="/.sprite/languages/python/pyenv/versions/3.13.7/bin/python3"

CONFIG_JSON="$1"
shift
if [[ "$1" == "--" ]]; then shift; fi

echo "[secrets-proxy] Starting on Sprite (proxy_port=$PROXY_PORT, sandbox_uid=$SANDBOX_UID)"

# ── Generate mitmproxy CA if needed ───────────────────────────

MITM_CA="/root/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ ! -f "$MITM_CA" ]]; then
    echo "[secrets-proxy] Generating mitmproxy CA..."
    $MITMDUMP --listen-port 0 -q &
    GENPID=$!
    sleep 2
    kill $GENPID 2>/dev/null || true
    wait $GENPID 2>/dev/null || true
fi

# ── Generate addon script ─────────────────────────────────────

ADDON_SCRIPT=$(mktemp /tmp/secrets_proxy_addon_XXXXXX.py)

$PYTHON3 -c "
import json, os, sys, secrets as s

config_json = sys.argv[1]
raw = json.loads(config_json)

secrets_map = {}
env_lines = []
allowed_hosts = []

for name, entry in raw.items():
    placeholder = f'SECRETS_PROXY_PLACEHOLDER_{s.token_hex(16)}'
    secrets_map[placeholder] = {
        'name': name,
        'value': entry['value'],
        'hosts': entry['hosts'],
    }
    env_lines.append(f'{name}={placeholder}')
    for h in entry['hosts']:
        allowed_hosts.append(h)

with open('/tmp/sandbox_env.sh', 'w') as f:
    for line in env_lines:
        f.write(f'export {line}\n')

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
" "$CONFIG_JSON" > "$ADDON_SCRIPT"

echo "[secrets-proxy] Addon generated"

# ── CA trust setup ─────────────────────────────────────────────

CA_BUNDLE=$(mktemp /tmp/secrets_proxy_ca_XXXXXX.pem)
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [[ -f "$f" ]]; then
        cat "$f" > "$CA_BUNDLE"
        echo "" >> "$CA_BUNDLE"
        # Also append to system store
        cat "$MITM_CA" >> "$f"
        break
    fi
done
cat "$MITM_CA" >> "$CA_BUNDLE"
chmod 644 "$CA_BUNDLE"

# Append to certifi if available
CERTIFI_BUNDLE=$($PYTHON3 -c "import certifi; print(certifi.where())" 2>/dev/null || true)
if [[ -n "$CERTIFI_BUNDLE" && -f "$CERTIFI_BUNDLE" ]]; then
    cat "$MITM_CA" >> "$CERTIFI_BUNDLE"
fi

echo "[secrets-proxy] CA trust configured"

# ── Start mitmproxy (transparent mode, as root for SO_MARK) ───

# Use regular mode (not transparent) because Sprite kernel lacks
# SO_ORIGINAL_DST support needed for transparent mode.
# nftables still enforces that all TCP goes through the proxy.
$MITMDUMP \
    --mode regular \
    --listen-host 127.0.0.1 \
    --listen-port "$PROXY_PORT" \
    --set connection_strategy=lazy \
    --set mark="$PROXY_MARK" \
    -s "$ADDON_SCRIPT" \
    -q &
PROXY_PID=$!

# Wait for mitmproxy to fully load (addon + listener)
echo "[secrets-proxy] Waiting for mitmproxy to be ready..."
for i in $(seq 1 15); do
    if $PYTHON3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('127.0.0.1', $PROXY_PORT))
    s.close()
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
        echo "[secrets-proxy] Proxy ready after ${i}s"
        break
    fi
    sleep 1
done

if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "[secrets-proxy] ERROR: mitmproxy failed to start" >&2
    exit 1
fi
echo "[secrets-proxy] mitmproxy started (PID $PROXY_PID)"

# ── nftables setup (the "concrete walls") ──────────────────────

# Create tables first (may not exist on fresh Sprite)
nft add table ip nat 2>/dev/null || true
nft add table ip filter 2>/dev/null || true

# NAT chain — redirect sandbox traffic
nft add chain ip nat "$NFT_CHAIN" '{ type nat hook output priority -1 ; }'
nft add rule ip nat "$NFT_CHAIN" meta mark 0x$PROXY_MARK accept
nft add rule ip nat "$NFT_CHAIN" meta skuid "$SANDBOX_UID" ip daddr 127.0.0.1 tcp dport "$PROXY_PORT" accept
nft add rule ip nat "$NFT_CHAIN" meta skuid "$SANDBOX_UID" ip protocol tcp redirect to :"$PROXY_PORT"

# Filter chain — block UDP except DNS
nft add chain ip filter "${NFT_CHAIN}_filter" '{ type filter hook output priority 0 ; }'
nft add rule ip filter "${NFT_CHAIN}_filter" meta skuid "$SANDBOX_UID" udp dport 53 accept
nft add rule ip filter "${NFT_CHAIN}_filter" meta skuid "$SANDBOX_UID" ip protocol udp drop

echo "[secrets-proxy] nftables installed:"
nft list chain ip nat "$NFT_CHAIN"
nft list chain ip filter "${NFT_CHAIN}_filter"

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

# ── Drop to sandbox user and run ───────────────────────────────

echo "[secrets-proxy] Running as '$SANDBOX_USER': $*"
echo "────────────────────────────────────────"

PROXY_URL="http://127.0.0.1:$PROXY_PORT"
su "$SANDBOX_USER" -c "
    source /tmp/sandbox_env.sh
    export SSL_CERT_FILE=$CA_BUNDLE
    export REQUESTS_CA_BUNDLE=$CA_BUNDLE
    export NODE_EXTRA_CA_CERTS=$CA_BUNDLE
    export CURL_CA_BUNDLE=$CA_BUNDLE
    export HTTP_PROXY=$PROXY_URL
    export HTTPS_PROXY=$PROXY_URL
    export http_proxy=$PROXY_URL
    export https_proxy=$PROXY_URL
    $*
"
EXIT_CODE=$?

echo "────────────────────────────────────────"
echo "[secrets-proxy] Exit code: $EXIT_CODE"
exit $EXIT_CODE
