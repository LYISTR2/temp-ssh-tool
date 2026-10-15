#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ${EUID} -ne 0 ]]; then
    command -v sudo >/dev/null || { printf '需要 root 权限；本机尚未安装 sudo，请切换 root 后运行。\n' >&2; exit 1; }
    exec sudo bash "$SCRIPT_DIR/start.sh" "$@"
fi

# Do not alter an unsupported machine or install packages in a non-systemd shell.
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) printf '自动安装依赖仅支持 Debian / Ubuntu。\n' >&2; exit 1 ;;
esac
[[ -d /run/systemd/system ]] || { printf '需要正在运行的 systemd；普通 Docker 容器不支持到期自动回收。\n' >&2; exit 1; }
command -v apt-get >/dev/null || { printf '缺少 apt-get，无法自动安装依赖。\n' >&2; exit 1; }

packages=()
required_tools=(
    python3:python3 curl:curl systemctl:systemd sshd:openssh-server
    useradd:passwd usermod:passwd userdel:passwd groupadd:passwd chpasswd:passwd
    pkill:procps ip:iproute2 sudo:sudo visudo:sudo
)
new_ssh=0
command -v sshd >/dev/null || new_ssh=1
for entry in "${required_tools[@]}"; do
    tool="${entry%%:*}"
    package="${entry#*:}"
    if ! command -v "$tool" >/dev/null && [[ " ${packages[*]} " != *" $package "* ]]; then
        packages+=("$package")
    fi
done
if [[ "$(dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null || true)" != 'install ok installed' ]]; then
    packages+=(ca-certificates)
fi
if (( ${#packages[@]} )); then
    printf '首次使用，正在安装缺失依赖：%s\n' "${packages[*]}"
    if ! apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update; then
        printf '更新软件源失败，未安装 TempSSH；请检查网络和 apt 软件源后重试。\n' >&2
        exit 1
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${packages[@]}"; then
        printf '安装依赖失败，未安装 TempSSH；请解决 apt 错误后重试。\n' >&2
        exit 1
    fi
fi
for entry in "${required_tools[@]}"; do
    command -v "${entry%%:*}" >/dev/null || { printf '依赖安装后仍缺少：%s\n' "${entry%%:*}" >&2; exit 1; }
done
python3 -c 'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")' "$SCRIPT_DIR/harness-ssh.py"

# Only start SSH when this invocation installed a previously absent server.
# Existing SSH configuration, password policy and service state are preserved.
if (( new_ssh )); then
    install -d -m 0755 /run/sshd
    sshd -t
    systemctl enable --now ssh.service
fi
cd -- "$SCRIPT_DIR"
if [[ ! -x /usr/local/sbin/harness-ssh ]] || ! cmp -s ./harness-ssh.py /usr/local/sbin/harness-ssh; then
    python3 ./harness-ssh.py install
fi
exec /usr/local/sbin/harness-ssh "$@"
