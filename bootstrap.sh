#!/usr/bin/env bash
# Download first; keep stdin attached to the terminal for the interactive menu.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
if [[ ${EUID} -ne 0 ]]; then
    command -v sudo >/dev/null || { printf '需要 root 权限；本机尚未安装 sudo，请切换 root 后运行。\n' >&2; exit 1; }
    exec sudo bash "${BASH_SOURCE[0]}" "$@"
fi
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) printf '自动安装依赖仅支持 Debian / Ubuntu。\n' >&2; exit 1 ;;
esac
[[ -d /run/systemd/system ]] || { printf '需要正在运行的 systemd；普通 Docker 容器不支持到期自动回收。\n' >&2; exit 1; }

# The downloader must be available before the rest of the project can be fetched.
packages=()
command -v curl >/dev/null || packages+=(curl)
if [[ "$(dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null || true)" != 'install ok installed' ]]; then
    packages+=(ca-certificates)
fi
if (( ${#packages[@]} )); then
    printf '首次使用，正在安装下载工具：%s\n' "${packages[*]}"
    if ! apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update || \
       ! DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${packages[@]}"; then
        printf '下载工具安装失败；请检查网络和 apt 软件源后重试。\n' >&2
        exit 1
    fi
fi
tmp="$(mktemp -d -t harness-ssh-install.XXXXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
base='https://raw.githubusercontent.com/LYISTR2/temp-ssh-tool/main'
for file in start.sh harness-ssh.py; do
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 --retry 2 "$base/$file" -o "$tmp/$file"
done
bash -n "$tmp/start.sh"
# start.sh installs Python and validates the program before executing it.
bash "$tmp/start.sh" "$@"
