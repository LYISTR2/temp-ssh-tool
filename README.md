# Harness SSH v2 — 交互式临时账号管理

参考 LYISTR2/temp-ssh-tool 的工作流，独立 Python 实现，Bash 一键入口。适用 Debian/Ubuntu、Python3、OpenSSH、运行中的 systemd，需要 sudo/root。

## 首次启动 / 升级

从 GitHub 获取并启动：
```bash
git clone https://github.com/LYISTR2/temp-ssh-tool.git
cd temp-ssh-tool
bash start.sh
```

已克隆的项目升级：`git pull --ff-only && bash start.sh`。如果使用压缩包，解压后进入包含 `start.sh` 的目录运行 `bash start.sh`。

旧版 `give-ssh` / `revoke-ssh` 等脚本保持原样，旧说明见 [LEGACY.md](LEGACY.md)。新版本不会自动接管旧版账号，升级前请用对应旧工具撤销旧账号。
自动安装或升级管理器、回收器和快捷命令，随后进入循环菜单。无需 pip。缺少系统依赖时会报错，不自动安装软件包。

再次启动，无需进入项目目录：
```bash
hssh
```

菜单：
1. 创建账号 → 密钥/随机密码 → 15分钟/1小时/4小时/8小时/24小时 → 地址与端口
2. 查看账号记录
3. 撤销（确认后终止进程、删除账号及家目录）
4. 开启临时账号密码登录
5. 关闭临时账号密码登录
6. 安装/修复
0. 退出

密钥模式可输入公钥文件路径，留空自动生成 Ed25519 密钥。私钥存放 root 专用状态目录，需通过可信渠道交给 harness。密码模式生成随机密码，仅在创建时打印，不写管理元数据；不要将终端输出公开。无自定义弱密码输入。

## 密码开关范围与风险

**开关只影响 harness-temp 组，不是全服务器密码开关，不改 root 或其他普通账号的规则。**密码关闭后，密码账号不能以密码发起新连接，但既有连接不会断开。立即撤权请用“撤销”。用户能在自己的家目录添加公钥，因此“密码模式”是凭据发放方式，不保证账号永远不能使用公钥。

安装默认关闭临时账号密码认证；创建密码账号时提示确认开启。安装会在 /etc/ssh/sshd_config 末尾添加带标记 Match Group 块。写前备份到 /var/lib/harness-ssh，sshd -t 通过后 reload，不 restart；失败尝试恢复原文件并重载。应保留现有管理员连接，客户端验证新连接后再关闭旧连接。

对已有管理账号用 sshd -T -C 检查本地来源的最终策略；每次创建也检查新账号。已有更早 Match、AuthenticationMethods 冲突会拒绝继续，不能保证所有来源 IP、AllowUsers、PAM 等策略均允许连接。无管理账号时只能校验配置语法，实际认证有效性在创建后检查。配置备份不等于已经验证远程可登录。

两种模式均无 sudo；禁用 PTY、端口/agent/X11 转发，支持非交互命令。需要 PTY 的 harness 不兼容。普通账号并非沙箱，可访问权限允许的文件与网络。

首次创建 harness-temp 组；请勿将其他账号加入此专用组。v1 旧账号不自动迁移到该组，升级前应撤销旧账号并重新创建。

## CLI（也可全部使用菜单）

```bash
hssh password on
hssh create 1h --auth password --host SERVER_IP
hssh create 4h --auth key --pubkey /path/to/key.pub --host SERVER_IP
hssh list
hssh revoke hs_abcdef12
hssh password off
```

host/port 只生成连接信息，不修改监听或防火墙。不会自动发布脚本到 GitHub。

## 到期及运维

持久 systemd 单元约每 15 秒检查记录，启动时恢复检查。撤销先使账号过期，再杀进程，删账号、家目录和本工具生成的服务端密钥副本。复制到客户端的私钥不会被远程擦除。存在调度延迟和启动竞态，服务失效时不保证准时回收，shadow 日级过期只是兜底。

```bash
sudo systemctl status harness-ssh-cleanup.timer
sudo journalctl -u harness-ssh-cleanup.service
```

菜单等待输入不持有清理锁。安装失败可能留下已安装的文件/单元，SSH 配置事务尝试单独回滚；不要将安装视为完全原子的系统事务。

卸载前撤销全部账号，再停止禁用 timer；删除管理器、hssh、对应 service/timer 并 daemon-reload。移除 SSH 管理块前备份，并运行 sshd -t 后重载。不要先删回收器留下临时账号。

## 验证边界

已运行 9 项单元测试：认证参数、菜单返回、密码规则切换及原规则保留、用户名、同名保护、身份不符拒绝、未知账号拒绝、到期派发与时长预设。已实际运行菜单退出路径及 Bash 语法检查。单元测试中的系统修改命令使用 mock。

已在授权的远程测试机实际安装，验证密钥登录、密码登录、关闭密码后拒绝密码连接且保留密钥/root连接、手动撤销、systemd 自动回收和家目录删除。自动回收测试将专用测试账号的到期记录提前，而非等待完整 15 分钟。测试账号已删除，临时组密码认证最终关闭。修复实测发现的账号备注冒号不合法和 SSH reload/回收服务排序死锁。未验证重启回收或配置失败回滚；当前单元测试为 10 项。

测试：`python3 test.py`。
