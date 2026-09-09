#!/usr/bin/env bash
set -euo pipefail

# ── config ────────────────────────────────────────────────────
PREFIX=""
DRY=1
UNINSTALL=0

usage() {
  cat <<'EOF'
临时 SSH 账号管理器一键安装

用法:
  sudo bash install-temp-ssh.sh [--prefix /usr/local/sbin]

功能:
  1. 安装 give-ssh / revoke-ssh 到系统 PATH (--prefix 指定目录)
  2. 创建 tempssh 用户组
  3. 写入 sshd Match 配置 (仅 tempssh 组允许密码登录)
  4. 校验并重启 sshd

用法示例:
  give-ssh alice 2        # 创建 2 小时有效的临时账号
  revoke-ssh alice        # 立即撤销
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --prefix=*) PREFIX="${arg#*=}" ;;
    *) echo "unknown arg: $arg" >&2; usage; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "need root" >&2; exit 1; }

PREFIX="${PREFIX:-/usr/local/sbin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── checks ────────────────────────────────────────────────────
for cmd in openssl usermod systemctl sshd; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing: $cmd" >&2; exit 1; }
done
# some distros: ssh is the unit name, sshd the binary — accept both
SSH_UNIT="sshd"
systemctl list-unit-files 2>/dev/null | grep -q '^ssh.service' && SSH_UNIT="ssh"

# ── install scripts ───────────────────────────────────────────
install -m 0755 "$SCRIPT_DIR/give-ssh"   "$PREFIX/give-ssh"
install -m 0755 "$SCRIPT_DIR/revoke-ssh" "$PREFIX/revoke-ssh"

# ── sshd match config (idempotent) ───────────────────────────
CONF=/etc/ssh/sshd_config.d/20-temp-ssh.conf
mkdir -p /etc/ssh/sshd_config.d
if [ -f "$CONF" ] && grep -q 'Match Group tempssh' "$CONF"; then
  echo "→ sshd 配置已存在，跳过"
else
  install -m 0644 "$SCRIPT_DIR/20-temp-ssh.conf" "$CONF"
  echo "→ 已写入 $CONF"
fi

# ── group ────────────────────────────────────────────────────
groupadd -f tempssh 2>/dev/null || true
echo "→ tempssh 组已就绪"

# ── validate & restart sshd ─────────────────────────────────
if sshd -t 2>/dev/null || ssh -t 2>/dev/null; then
  echo "→ sshd 配置校验通过"
else
  echo "sshd 配置校验失败，撤销本次修改" >&2
  rm -f "$CONF"
  exit 1
fi
systemctl restart "$SSH_UNIT"
systemctl is-active "$SSH_UNIT" >/dev/null || { echo "sshd 启动失败!" >&2; exit 1; }
echo "→ sshd 已重启 ($SSH_UNIT)"

echo
echo "✓ 安装完成"
echo "  用法: $PREFIX/give-ssh <username> <hours>"
echo "  撤销: $PREFIX/revoke-ssh <username>"