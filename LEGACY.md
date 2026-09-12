# temp-ssh-tool — 临时 SSH 账号管理器

一句话给同事/朋友/工单人员一次性 SSH 访问权：**随机密码 + 小时级有效期 + 到点自动删除**。

```bash
give-ssh alice 2      # 2 小时有效
revoke-ssh alice      # 提前撤销
```

## 解决什么问题

临时需要给某人 root 之外的服务器访问权限，但不想：
- 永久建账号后忘记删
- 手动生成/回收密码
- 交出自己的主账号

## 安装

```bash
git clone https://github.com/LYISTR2/temp-ssh-tool
cd temp-ssh-tool
sudo bash install-temp-ssh.sh
```

要求：Debian/Ubuntu 系（`sshd_config.d` 支持）、OpenSSL 可用、root 权限。

## 使用

```bash
# 创建有效期 2 小时的账号
give-ssh alice 2
give-ssh bob 1        # 1 小时
give-ssh carl 8       # 8 小时

# 输出示例
# ✓ 临时 SSH 账号已创建
#   用户名: alice
#   密码:   Abcd1234EFGH5678901x
#   有效期: 2小时 (至 2026-09-09T06:20:02 UTC, 超时自动封禁)
#   登录:   ssh alice@100.113.1.108
#   手动立即撤销: revoke-ssh alice

# 手动立即撤销（杀会话+删号+删家目录+清元数据）
revoke-ssh alice
```

## 自动失效机制

双保险：

1. **精确到小时** — `systemd-run --on-active` 挂定时器到点自动 revoke（杀进程、userdel -r、删 `/var/lib/temp-ssh-*.meta`）
2. **保底层** — shadow 账号过期日（chage，日粒度+1 天兜底），即使计时器漏了，登录也被 PAM 拒绝

## 安全边界

- 密码登录 **只对 `tempssh` 组成员开放**（sshd Match 块），主账号/root 的 key-only 策略不受影响
- 密码 20 位 CSPRNG 随机
- 家目录随账号一起删除，无残留
- 创建即写 `.meta`，可随时审计

## 文件

| 文件 | 说明 |
|---|---|
| `give-ssh` | 创建临时账号，用法见 --help |
| `revoke-ssh` | 手动撤销 |
| `20-temp-ssh.conf` | sshd Match 块（tempssh 组允许密码登录） |
| `install-temp-ssh.sh` | 一键安装（幂等） |

## 前提

- Linux + OpenSSH，`sshd_config.d` 可用（Debian 12+/Ubuntu 22+）
- root 执行

## 卸载

```bash
sudo rm /usr/local/sbin/give-ssh /usr/local/sbin/revoke-ssh
sudo rm /etc/ssh/sshd_config.d/20-temp-ssh.conf
sudo systemctl restart ssh
# 删除残留元数据： sudo rm /var/lib/temp-ssh-*.meta
```

## License

MIT