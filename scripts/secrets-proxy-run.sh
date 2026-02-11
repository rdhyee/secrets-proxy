#!/usr/bin/env bash
# secrets-proxy-run.sh — Standalone launcher for secrets-proxy
#
# Usage:
#   ./secrets-proxy-run.sh --config secrets.json --allow-net api.openai.com -- python my_script.py
#
# This is a standalone shell script that doesn't require pip-installing secrets-proxy.
# It requires: mitmproxy (mitmdump), jq, python3
#
# The script:
# 1. Reads secrets config JSON
# 2. Generates placeholder env vars
# 3. Creates a mitmproxy addon script for secret injection
# 4. Starts mitmdump with the addon
# 5. Runs the sandboxed command with proxy env vars
# 6. Cleans up on exit

set -euo pipefail

PROXY_HOST="127.0.0.1"
PROXY_PORT=8080
VERBOSE=0

usage() {
    echo "Usage: $0 --config <secrets.json> [--allow-net <host>]... [--port <port>] -- <command>"
    echo ""
    echo "Options:"
    echo "  --config <file>    Path to secrets configuration JSON"
    echo "  --allow-net <host> Additional allowed hosts (repeatable)"
    echo "  --port <port>      Proxy port (default: 8080)"
    echo "  -v, --verbose      Verbose output"
    echo "  -- <command>       Command to run in the sandbox"
    exit 1
}

# Parse arguments
CONFIG_FILE=""
ALLOW_NET=()
COMMAND=()
PARSING_COMMAND=0

while [[ $# -gt 0 ]]; do
    if [[ $PARSING_COMMAND -eq 1 ]]; then
        COMMAND+=("$1")
        shift
        continue
    fi

    case "$1" in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --allow-net)
            ALLOW_NET+=("$2")
            shift 2
            ;;
        --port)
            PROXY_PORT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --)
            PARSING_COMMAND=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -z "$CONFIG_FILE" ]]; then
    echo "Error: --config is required"
    usage
fi

if [[ ${#COMMAND[@]} -eq 0 ]]; then
    echo "Error: no command specified after --"
    usage
fi

log() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo "[secrets-proxy] $*" >&2
    fi
}

# Check dependencies
for dep in mitmdump jq python3; do
    if ! command -v "$dep" &>/dev/null; then
        echo "Error: $dep is required but not found"
        exit 1
    fi
done

# Read config and generate placeholders
log "Reading config from $CONFIG_FILE"

# Generate the mitmproxy addon script
ADDON_SCRIPT=$(mktemp /tmp/secrets_proxy_addon_XXXXXX.py)

# Use Python to process config and generate addon + env vars
ENV_FILE=$(mktemp /tmp/secrets_proxy_env_XXXXXX.sh)

python3 -c "
import json, secrets, sys

config_path = sys.argv[1]
allow_net_extra = sys.argv[2:]

with open(config_path) as f:
    raw = json.load(f)

secrets_map = {}
env_lines = []
allowed_hosts = set(allow_net_extra)

for name, entry in raw.items():
    placeholder = f'SECRETS_PROXY_PLACEHOLDER_{secrets.token_hex(16)}'
    secrets_map[placeholder] = {
        'name': name,
        'value': entry['value'],
        'hosts': entry['hosts'],
    }
    env_lines.append(f'export {name}=\"{placeholder}\"')
    for h in entry['hosts']:
        allowed_hosts.add(h)

allowed_hosts_list = list(allowed_hosts)

# Write env file
with open(sys.argv[-1] if sys.argv[-1].endswith('.sh') else '/dev/null', 'w') as f:
    f.write('\n'.join(env_lines) + '\n')

# Write addon script
addon = '''
import logging
from mitmproxy import http

logger = logging.getLogger(\"secrets-proxy-addon\")

SECRETS = ''' + repr(secrets_map) + '''
ALLOWED_HOSTS = ''' + repr(allowed_hosts_list) + '''

def _host_allowed(host):
    for p in ALLOWED_HOSTS:
        if p.startswith(\"*.\"):
            if host.endswith(p[1:]) or host == p[2:]:
                return True
        elif host == p:
            return True
    return False

def _host_matches(host, hosts):
    for p in hosts:
        if p.startswith(\"*.\"):
            if host.endswith(p[1:]) or host == p[2:]:
                return True
        elif host == p:
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
" "$CONFIG_FILE" "${ALLOW_NET[@]}" "$ENV_FILE" > "$ADDON_SCRIPT"

log "Addon script: $ADDON_SCRIPT"
log "Env file: $ENV_FILE"

# Ensure mitmproxy CA exists
MITM_CA="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ ! -f "$MITM_CA" ]]; then
    log "Generating mitmproxy CA certificate..."
    mitmdump --listen-port 0 -q &
    GENPID=$!
    sleep 2
    kill $GENPID 2>/dev/null || true
    wait $GENPID 2>/dev/null || true
    if [[ ! -f "$MITM_CA" ]]; then
        echo "Error: Failed to generate mitmproxy CA" >&2
        exit 1
    fi
    log "CA generated at $MITM_CA"
fi

# Create combined CA bundle
CA_BUNDLE=$(mktemp /tmp/secrets_proxy_ca_XXXXXX.pem)
SYSTEM_CA=""
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [[ -f "$f" ]]; then
        SYSTEM_CA="$f"
        break
    fi
done

if [[ -n "$SYSTEM_CA" ]]; then
    cat "$SYSTEM_CA" > "$CA_BUNDLE"
    echo "" >> "$CA_BUNDLE"
fi
cat "$MITM_CA" >> "$CA_BUNDLE"
log "CA bundle: $CA_BUNDLE"

# Start mitmproxy
QUIET_FLAG=""
if [[ $VERBOSE -eq 0 ]]; then
    QUIET_FLAG="-q"
fi

mitmdump \
    --mode regular \
    --listen-host "$PROXY_HOST" \
    --listen-port "$PROXY_PORT" \
    --set connection_strategy=lazy \
    -s "$ADDON_SCRIPT" \
    $QUIET_FLAG &
PROXY_PID=$!
log "mitmproxy started (PID $PROXY_PID) on $PROXY_HOST:$PROXY_PORT"

# Wait for proxy to be ready
sleep 1
if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "Error: mitmproxy failed to start" >&2
    exit 1
fi

# Cleanup on exit
cleanup() {
    log "Cleaning up..."
    kill $PROXY_PID 2>/dev/null || true
    wait $PROXY_PID 2>/dev/null || true
    rm -f "$ADDON_SCRIPT" "$ENV_FILE" "$CA_BUNDLE"
    log "Done"
}
trap cleanup EXIT

# Source placeholder env vars
source "$ENV_FILE"

# Set CA trust env vars
export SSL_CERT_FILE="$CA_BUNDLE"
export REQUESTS_CA_BUNDLE="$CA_BUNDLE"
export NODE_EXTRA_CA_CERTS="$CA_BUNDLE"
export CURL_CA_BUNDLE="$CA_BUNDLE"
export DENO_CERT="$CA_BUNDLE"
export GIT_SSL_CAINFO="$CA_BUNDLE"

# Set proxy env vars
PROXY_URL="http://$PROXY_HOST:$PROXY_PORT"
export HTTP_PROXY="$PROXY_URL"
export HTTPS_PROXY="$PROXY_URL"
export http_proxy="$PROXY_URL"
export https_proxy="$PROXY_URL"

log "Running: ${COMMAND[*]}"

# Run the sandboxed command
"${COMMAND[@]}"
EXIT_CODE=$?

log "Command exited with code $EXIT_CODE"
exit $EXIT_CODE
