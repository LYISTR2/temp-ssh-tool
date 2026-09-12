#!/usr/bin/env bash
# Download first; keep stdin attached to the terminal for the interactive menu.
set -euo pipefail
command -v curl >/dev/null || { printf '需要安装 curl\n' >&2; exit 1; }
command -v python3 >/dev/null || { printf '需要安装 python3\n' >&2; exit 1; }
tmp="$(mktemp -d -t harness-ssh-install.XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
base='https://raw.githubusercontent.com/LYISTR2/temp-ssh-tool/main'
for file in start.sh harness-ssh.py; do
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 --retry 2 "$base/$file" -o "$tmp/$file"
done
bash -n "$tmp/start.sh"
python3 -c 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")' "$tmp/harness-ssh.py"
bash "$tmp/start.sh" "$@"
