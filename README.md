# TempSSH

限时 SSH 密码账号，到期自动回收。支持 Debian 12/13、Ubuntu 22.04/24.04。

## 一键安装 / 更新

需 `curl`，以 root 或有 sudo 权限的账号运行：

```bash
curl -fsSLO https://raw.githubusercontent.com/LYISTR2/temp-ssh-tool/main/bootstrap.sh && bash bootstrap.sh
```

## 使用

运行 `hssh` 打开菜单，或直接使用命令：

```bash
hssh password on                       # 开启服务器密码登录
hssh create 2h                         # 普通账号
hssh create 90m --role sudo             # sudo 账号，需密码
hssh create 2h --host example.com --port 2222
hssh list                              # 查看账号
hssh revoke hs_1234abcd                 # 提前撤销
hssh password off                      # 关闭服务器密码登录
```

- 时长：`Nm` / `Nh` / `Nd`，1 分钟至 30 天；密码只显示一次。
- 地址自动识别；NAT / 自定义端口用 `--host` / `--port` 指定连接信息，不修改网络配置。
- 密码开关影响整台服务器；保留当前管理连接。
