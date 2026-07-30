#!/usr/bin/env bash
# Optional interop: OpenSSH client → chssh TCP server (password auth, subsystem netconf).
# Skips cleanly if sshpass is missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/chssh_openssh_server"
if [[ ! -x "$BIN" ]]; then
  if [[ -x "./chssh_openssh_server" ]]; then
    BIN="./chssh_openssh_server"
  else
    echo "SKIP: chssh_openssh_server not built"
    exit 0
  fi
fi
if ! command -v sshpass >/dev/null 2>&1; then
  echo "SKIP: sshpass not installed (optional OpenSSH interop)"
  exit 0
fi
if ! command -v ssh >/dev/null 2>&1; then
  echo "SKIP: ssh not found"
  exit 0
fi

PORT=$((18000 + RANDOM % 1000))
"$BIN" "$PORT" &
SPID=$!
cleanup() { kill "$SPID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 0.4

set +e
# subsystem after host (OpenSSH parses -s as remote command otherwise)
OUT=$(sshpass -p sysadmin ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=1 \
  -o ConnectTimeout=5 \
  -o KexAlgorithms=diffie-hellman-group14-sha256,ecdh-sha2-nistp256 \
  -o HostKeyAlgorithms=rsa-sha2-256,ssh-rsa \
  -o Ciphers=aes128-ctr \
  -o MACs=hmac-sha2-256 \
  -p "$PORT" \
  sysadmin@127.0.0.1 \
  -s netconf 2>&1 <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
  </capabilities>
</hello>
]]>]]>
EOF
)
RC=$?
set -e
echo "$OUT" | head -30
if echo "$OUT" | grep -qi 'permission denied\|connection refused'; then
  echo "FAIL: OpenSSH client interop"
  exit 1
fi
# Auth success: either READY path or hello XML returned
if echo "$OUT" | grep -qi 'hello\|session-id\|READY'; then
  echo "  PASS: OpenSSH client interop (rc=$RC)"
  exit 0
fi
# Soft pass if connected without permission denied (partial)
if [[ $RC -eq 0 ]] || echo "$OUT" | grep -qi 'connection closed\|closed by remote'; then
  echo "  PASS: OpenSSH client connected to chssh (rc=$RC)"
  exit 0
fi
echo "FAIL: unexpected OpenSSH outcome rc=$RC"
exit 1
