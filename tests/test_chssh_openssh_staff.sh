#!/usr/bin/env bash
# OpenSSH interactive client → production chssh staff face (pty-req + shell).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/chssh_openssh_staff_server"
if [[ ! -x "$BIN" ]]; then
  if [[ -x "./chssh_openssh_staff_server" ]]; then
    BIN="./chssh_openssh_staff_server"
  else
    echo "SKIP: chssh_openssh_staff_server not built"
    exit 0
  fi
fi
if ! command -v sshpass >/dev/null 2>&1 || ! command -v ssh >/dev/null 2>&1; then
  echo "SKIP: ssh/sshpass not installed"
  exit 0
fi

PORT=$((19000 + RANDOM % 1000))
"$BIN" "$PORT" &
SPID=$!
cleanup() { kill "$SPID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 0.5

set +e
# Force a short PTY session; server prints STAFF_SHELL_OK on shell/exec ready.
OUT=$(sshpass -p 'staff-lab' ssh \
  -tt \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o NumberOfPasswordPrompts=1 \
  -o ConnectTimeout=8 \
  -o KexAlgorithms=diffie-hellman-group14-sha256,ecdh-sha2-nistp256 \
  -o HostKeyAlgorithms=rsa-sha2-256,ssh-rsa \
  -o Ciphers=aes128-ctr \
  -o MACs=hmac-sha2-256 \
  -p "$PORT" \
  staff@127.0.0.1 \
  'cat' </dev/null 2>&1)
RC=$?
set -e
echo "$OUT" | head -40
if echo "$OUT" | grep -q 'STAFF_SHELL_OK'; then
  echo "  PASS: OpenSSH staff interactive shell (rc=$RC)"
  exit 0
fi
if echo "$OUT" | grep -qi 'permission denied\|connection refused\|no matching'; then
  echo "FAIL: OpenSSH staff interop crypto/auth"
  exit 1
fi
echo "FAIL: unexpected OpenSSH staff outcome rc=$RC"
exit 1
