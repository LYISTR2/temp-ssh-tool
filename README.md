# TempSSH · 临时 SSH 密码账号

一键生成限时账号及随机密码，按需开关**服务器的 SSH 密码认证**。适用于 Debian 12/13、Ubuntu 22.04/24.04，依赖 Python 3、OpenSSH、systemd、curl、iproute2；高权限账号还需要 sudo/visudo；需要 root 或 sudo 执行。默认生成普通用户，可选限时高权限 sudo 用户。

## 一键安装 / 打开菜单

```bash
bash -c 'f=$(mktemp) || exit; trap '\''rm -f -- "$f"'\'' EXIT; curl -fsSL --connect-timeout 15 --max-time 120 https://raw.githubusercontent.com/LYISTR2/temp-ssh-tool/main/bootstrap.sh -o "$f" && bash "$f"'
```

脚本先下载 `start.sh` 和 `harness-ssh.py`，检查语法后安装并打开菜单。以后直接输入 `hssh`。若从仓库克隆安装，运行 `sudo bash start.sh`；更新时运行 `git pull --ff-only && sudo bash start.sh`。

菜单只有三个入口：

1. 生成临时密码登录信息：选择 1、2、3 小时或自定义时长，再选普通账号（默认、无 sudo）或高权限账号（须二次确认、可通过密码使用 sudo）；自动识别服务器公网 IPv4，默认 SSH 端口 22。密码只显示一次。
2. 开关服务器 SSH 密码登录：修改 `sshd_config` 的全局 `PasswordAuthentication`；关闭时也关闭 `KbdInteractiveAuthentication`，避免绕过密码开关。
3. 查看 / 提前撤销账号：撤销时终止该账号的进程并删除家目录。

命令行也可直接使用：

```bash
hssh password on
hssh create 2h                  # 普通用户（默认）
hssh create 90m --role sudo     # 高权限用户，sudo 要输入账号密码
# NAT、反向代理或非标准 SSH 端口时显式覆盖显示地址：
hssh create 2h --host example.com --port 2222
hssh list
hssh revoke hs_1234abcd
hssh password off
```

自定义时长格式为 `Nm`、`Nh` 或 `Nd`，范围 1 分钟至 30 天。有效期从创建账号时开始，不会因重连或改密延长。自动地址取系统到公网的 IPv4 路由源地址，拒绝私网地址；NAT、代理或非标准 SSH 端口环境请在命令行使用 `--host` / `--port` 覆盖并从外部验证。地址和端口仅用于打印连接信息，不会改动服务器监听设置或防火墙。

高权限账号是普通 Linux 用户加专属 `/etc/sudoers.d/harness-ssh-<账号>` 规则（由 `visudo` 校验），**不是 root 直接登录，也不是免密 sudo**。到期自动清理或提前撤销时删除账号和专属 sudo 规则；已获得的 root shell/后台进程等不能仅靠删除账号可靠撤销，因此只把高权限账号发给可信的人，机密泄露时还应轮换相关凭据。

## SSH 开关与到期回收

安装时保留服务器当前的全局密码认证状态。手动切换时先备份 `/etc/ssh/sshd_config` 至 `/var/lib/harness-ssh`，再执行 `sshd -t` 和有效配置检查，通过后才 reload SSH；失败时尝试回滚。不要关闭当前管理会话，先在另一终端测试新连接。

开关作用于服务器的全局密码认证，但现有 `Match`、`AuthenticationMethods`、`AllowUsers`、PAM 等规则仍可能影响某些账号。尤其 root 密码登录还取决于 `PermitRootLogin`，本工具不会自动改该选项。关闭密码认证不会断开已有会话；需要立即撤销临时账号可在菜单操作。

后台 systemd 定时器约每 15 秒检查到期账号，拒绝新登录、断开现有会话并删除账号及家目录。重启后定时器会重新检查。shadow 的日级账号过期只是兜底，精确到期取决于定时器正常运行：

```bash
systemctl status harness-ssh-cleanup.timer
journalctl -u harness-ssh-cleanup.service
```

升级旧版时，一键入口会移除之前由本工具写入的 `Match Group harness-temp` 块，并保留服务器当前的全局密码认证状态。旧版账号记录仍可通过 `hssh list` 查看、到期回收或手动撤销。旧版 `give-ssh` 脚本创建的账号不受新版管理器接管，升级前请先用旧版 `revoke-ssh` 清理。

测试：`python3 test.py`。尚未在目标 VPS 上执行真实 SSH 登录测试；实际认证还需从客户端验证。
