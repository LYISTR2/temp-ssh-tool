#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ${EUID} -ne 0 ]]; then exec sudo bash "$SCRIPT_DIR/start.sh" "$@"; fi
cd -- "$SCRIPT_DIR"
if [[ ! -x /usr/local/sbin/harness-ssh ]] || ! cmp -s ./harness-ssh.py /usr/local/sbin/harness-ssh; then
  python3 ./harness-ssh.py install
fi
exec /usr/local/sbin/harness-ssh "$@"
