#!/usr/bin/env python3
"""Temporary password SSH accounts for Debian/Ubuntu + systemd."""
import argparse, datetime, fcntl, ipaddress, json, os, pathlib, pwd, re, secrets, shutil, subprocess, sys, time
BASE=pathlib.Path('/var/lib/harness-ssh')
APP=pathlib.Path('/usr/local/sbin/harness-ssh')
PRESETS={'1h':3600,'2h':7200,'3h':10800}
CONFIG=pathlib.Path('/etc/ssh/sshd_config')
SUDOERS_DIR=pathlib.Path('/etc/sudoers.d')
BEGIN='# BEGIN HARNESS-SSH MANAGED'
END='# END HARNESS-SSH MANAGED'

def policy_text(original,enabled):
    if original.count(BEGIN)!=original.count(END) or original.count(BEGIN)>1:raise ValueError('SSH 配置管理标记异常')
    if BEGIN in original:
        original=re.sub(re.escape(BEGIN)+r'.*?'+re.escape(END)+r'\n?', '', original, flags=re.S)
    # Global directives must precede Include and Match blocks. Also removes the
    # previous version's Match Group block without altering other SSH options.
    policy=BEGIN+'\nPasswordAuthentication '+('yes' if enabled else 'no')+'\n'
    if not enabled:policy+='KbdInteractiveAuthentication no\n'
    return policy+END+'\n'+original.lstrip('\n')

def effective(name=None):
    args=['sshd','-T']
    if name:args+=['-C',f'user={name},host=localhost,addr=127.0.0.1']
    return dict(line.split(None,1) for line in run(*args,capture_output=True).stdout.splitlines() if ' ' in line)

def verify_auth(name,enabled):
    fields=effective(name)
    expected={'passwordauthentication':'yes' if enabled else 'no'}
    if not enabled:expected['kbdinteractiveauthentication']='no'
    if any(fields.get(k)!=v for k,v in expected.items()):raise RuntimeError('已有 Match 规则优先或策略冲突，无法应用临时账号策略')
    if enabled and fields.get('authenticationmethods','any') not in ('any','password'):
        raise RuntimeError('AuthenticationMethods 不允许独立密码登录；保留原策略')
    if enabled and fields.get('permittty')=='no':raise RuntimeError('SSH 策略禁止交互式终端登录')

def password_policy(enabled):
    run('sshd','-t')
    service=None
    for unit in ['ssh.service','sshd.service']:
        if subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0:service=unit;break
    if not service:raise RuntimeError('找不到运行中的 SSH systemd 服务')
    original=CONFIG.read_text();mode=CONFIG.stat().st_mode & 0o777
    backup=BASE/('sshd_config.backup-'+str(time.time_ns()));shutil.copy2(CONFIG,backup)
    try:
        write(CONFIG,policy_text(original,enabled),mode);run('sshd','-t')
        if password_enabled()!=enabled:raise RuntimeError('已有 SSH 规则优先于服务器密码开关')
        if not enabled and effective().get('kbdinteractiveauthentication')!='no':
            raise RuntimeError('键盘交互认证仍然开启，拒绝关闭密码登录')
        for f in BASE.glob('hs_*.json'):verify_auth(f.stem,enabled)
        run('systemctl','reload',service);run('systemctl','is-active','--quiet',service)
    except Exception:
        try:
            write(CONFIG,original,mode);run('sshd','-t');run('systemctl','reload',service)
        except Exception as restore_error:
            raise RuntimeError('SSH 配置应用失败，且回滚也失败，请检查 '+str(backup)) from restore_error
        raise
    print('服务器 SSH 密码登录已'+('开启' if enabled else '关闭')+'；备份：'+str(backup))
    print('root 仍受 PermitRootLogin 等规则限制；已有连接不会断开。')

def password_enabled():
    return effective().get('passwordauthentication')=='yes'

def detect_public_ip():
    """Use the kernel's outbound IPv4 route; never guess a NAT or proxy address."""
    result=run('ip','-j','-4','route','get','1.1.1.1',capture_output=True).stdout
    routes=json.loads(result)
    if not routes or not (routes[0].get('prefsrc') or routes[0].get('src')):
        raise RuntimeError('无法识别服务器出口 IP；请用 --host 指定实际可连接地址')
    address=routes[0].get('prefsrc') or routes[0].get('src')
    if not ipaddress.ip_address(address).is_global:
        raise RuntimeError('出口 IP 不是公网地址（可能位于 NAT 后）；请用 --host 指定实际可连接地址')
    return address

def duration_seconds(value):
    match=re.fullmatch(r'([1-9][0-9]*)([mhd])',value)
    if not match:raise ValueError('有效期格式：1h、2h、3h，或 90m、4h、2d')
    seconds=int(match[1])*{'m':60,'h':3600,'d':86400}[match[2]]
    if not 60<=seconds<=30*86400:raise ValueError('有效期范围：1 分钟至 30 天')
    return seconds

def run(*args,**kw):
    return subprocess.run(args,check=True,text=True,**kw)
def valid_name(name):
    if not re.fullmatch(r'hs_[a-z0-9]{6,20}',name): raise ValueError('账号必须为 hs_ + 6–20 位小写字母或数字')
    return name

def write(path,text,mode=0o600):
    path=pathlib.Path(path); tmp=path.with_name(path.name+'.tmp')
    with open(tmp,'w') as f:
        os.chmod(tmp,mode);f.write(text);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
def meta(name): return BASE/(valid_name(name)+'.json')
def sudoers_path(name): return SUDOERS_DIR/('harness-ssh-'+valid_name(name))
def grant_sudo(name):
    path=sudoers_path(name)
    if path.exists():raise ValueError('sudoers 规则已存在，拒绝覆盖: '+str(path))
    if not shutil.which('visudo'):raise RuntimeError('缺少 visudo，无法创建高权限账号')
    # Explicit user-only rule, authenticated sudo; no NOPASSWD and no system sudo group.
    write(path, f'{name} ALL=(ALL:ALL) ALL\n', 0o440)
    try:run('visudo','-cf',str(path),stdout=subprocess.DEVNULL)
    except Exception:
        path.unlink()
        raise

def revoke(name):
    p=meta(name)
    if not p.exists(): raise ValueError('不是本工具管理的账号；拒绝删除')
    m=json.loads(p.read_text())
    rule=sudoers_path(name)
    try: u=pwd.getpwnam(name)
    except KeyError:
        if rule.exists():rule.unlink()
        p.unlink();return
    if u.pw_uid!=m['uid'] or u.pw_dir!=m['home'] or not u.pw_gecos.startswith('harness-ssh-'):
        raise ValueError('账号身份与记录不符，拒绝删除')
    run('usermod','--expiredate','1970-01-02','--shell','/usr/sbin/nologin',name)
    # Drop sudo immediately, even if terminating processes or userdel later fails.
    if rule.exists():rule.unlink()
    result=subprocess.run(['pkill','-KILL','-u',str(u.pw_uid)])
    if result.returncode not in (0,1):raise RuntimeError('终止账号进程失败')
    time.sleep(.15)
    run('userdel','--remove',name)
    p.unlink()
    keydir=BASE/('key-'+name)
    if keydir.exists():shutil.rmtree(keydir)
    print('已撤销:',name)
def cleanup():
    failed=False
    for p in BASE.glob('hs_*.json'):
        try:
            m=json.loads(p.read_text())
            if m['expires']<=time.time():revoke(p.stem)
        except Exception as e:failed=True;print(str(e),file=sys.stderr)
    if failed:raise RuntimeError('部分到期账号清理失败，下一轮重试；请检查 journalctl -u harness-ssh-cleanup')
def install():
    for tool in ['systemctl','useradd','usermod','userdel','sshd','pkill','chpasswd','ip']:
        if not shutil.which(tool):raise RuntimeError('缺少依赖: '+tool)
    if not pathlib.Path('/run/systemd/system').exists():raise RuntimeError('需要正在运行的 systemd')
    run('sshd','-t')
    source=pathlib.Path(__file__).resolve()
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    service=pathlib.Path('/etc/systemd/system/harness-ssh-cleanup.service')
    timer=pathlib.Path('/etc/systemd/system/harness-ssh-cleanup.timer')
    for p in [APP,service,timer]:
        if p.exists() and p.resolve()!=source:shutil.copy2(p,BASE/(p.name+'.backup-'+stamp))
    if source!=APP:write(APP,source.read_text(),0o700)
    write(service,'[Unit]\nDescription=Revoke expired harness SSH accounts\nAfter=local-fs.target\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/harness-ssh cleanup\n',0o644)
    write(timer,'[Unit]\nDescription=Temporary SSH expiry check\n[Timer]\nOnBootSec=1s\nOnUnitActiveSec=15s\nAccuracySec=1s\nUnit=harness-ssh-cleanup.service\n[Install]\nWantedBy=timers.target\n',0o644)
    run('systemctl','daemon-reload');run('systemctl','enable','--now',timer.name)
    run('systemctl','is-active','--quiet',timer.name)
    run('groupadd','--force','harness-temp')
    shortcut=pathlib.Path('/usr/local/bin/hssh')
    if shortcut.exists():shutil.copy2(shortcut,BASE/('hssh.backup-'+stamp))
    write(shortcut,'#!/bin/sh\nif [ "$(id -u)" -ne 0 ]; then exec sudo /usr/local/sbin/harness-ssh "$@"; fi\nexec /usr/local/sbin/harness-ssh "$@"\n',0o755)
    # On upgrade, remove the old group-specific Match block while preserving
    # the server's current global password authentication setting.
    current=CONFIG.read_text()
    if BEGIN in current and 'Match Group harness-temp' in current:
        password_policy(password_enabled())
    cleanup();print('安装完成，再次启动输入：hssh')
def create(args):
    if not APP.exists():raise RuntimeError('请先运行 install')
    run('systemctl','is-active','--quiet','harness-ssh-cleanup.timer')
    name=valid_name(args.name or 'hs_'+secrets.token_hex(4))
    try:pwd.getpwnam(name)
    except KeyError:pass
    else:raise ValueError('同名账号已存在；拒绝覆盖')
    if meta(name).exists():raise ValueError('已有同名管理记录；请先检查或撤销')
    if not password_enabled():raise ValueError('服务器密码登录已关闭，请先在菜单开启')
    if args.role=='sudo' and not shutil.which('visudo'):
        raise RuntimeError('缺少 sudo/visudo，无法创建高权限账号')
    host=args.host or detect_public_ip()
    seconds=duration_seconds(args.duration)
    # Record creation immediately after useradd; failure rolls back the new account.
    created=False
    try:
        run('useradd','--create-home','--user-group','--shell','/bin/bash','--comment','harness-ssh-'+name,name);created=True
        u=pwd.getpwnam(name)
        expires=int(time.time())+seconds
        write(meta(name),json.dumps({'uid':u.pw_uid,'home':u.pw_dir,'expires':expires,'duration':args.duration,'auth':'password','role':args.role}))
        run('usermod','--append','--groups','harness-temp',name)
        verify_auth(name,True)
        password=secrets.token_urlsafe(24)
        run('chpasswd',input=name+':'+password+'\n',stdout=subprocess.DEVNULL)
        # Day-granularity backstop; timer is responsible for sub-day deadlines.
        day=datetime.datetime.fromtimestamp(expires,datetime.timezone.utc).date()+datetime.timedelta(days=1)
        run('usermod','--expiredate',str(day),name)
        if args.role=='sudo':grant_sudo(name)
    except Exception:
        if created:
            if meta(name).exists():revoke(name)
            else:run('userdel','--remove',name)
        raise
    print('\n临时 SSH 登录信息（密码只显示一次）')
    print('地址：'+host+':'+str(args.port))
    print('账号：'+name)
    print('密码：'+password)
    print('到期：'+datetime.datetime.fromtimestamp(expires,datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    print('登录：ssh -p '+str(args.port)+' '+name+'@'+host)
    print('提前撤销：hssh revoke '+name)
    print(('高权限用户，可使用 sudo（需输入该账号密码）。' if args.role=='sudo' else '普通用户，无 sudo。')+'请从另一终端验证新连接。')

def list_accounts():
    records=sorted(BASE.glob('hs_*.json'))
    if not records:print('暂无临时账号')
    for record in records:
        info=json.loads(record.read_text())
        expiry=datetime.datetime.fromtimestamp(info['expires'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(record.stem+'  '+('高权限 sudo' if info.get('role')=='sudo' else '普通用户')+'  到期 '+expiry+('  已到期，待清理' if info['expires']<=time.time() else ''))

def parser():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action')
    for a in ['install','list','cleanup']:s.add_parser(a)
    r=s.add_parser('revoke');r.add_argument('name')
    q=s.add_parser('password');q.add_argument('state',choices=['on','off'])
    c=s.add_parser('create');c.add_argument('duration',help='1h、2h、3h 或自定义 90m/4h/2d');c.add_argument('--name');c.add_argument('--host');c.add_argument('--port',type=int,default=22);c.add_argument('--role',choices=['normal','sudo'],default='normal')
    return p

def menu(p):
    while True:
        print('\n=== 临时 SSH 管理 ===\n1 生成临时密码登录信息\n2 开关服务器 SSH 密码登录（当前：'+('开' if password_enabled() else '关')+'）\n3 查看 / 提前撤销临时账号\n0 退出')
        try:
            choice=input('选择: ').strip()
            if choice=='0':return
            if choice=='1':
                if not password_enabled():
                    if input('密码登录已关闭，输入 yes 开启后继续: ').strip()!='yes':continue
                    subprocess.run([sys.executable,str(APP),'password','on'],check=True)
                duration=input('时长 1=1小时 2=2小时 3=3小时 4=自定义 [1]: ').strip() or '1'
                if duration=='4':duration=input('输入时长（例如 90m / 4h / 2d）: ').strip()
                else:duration={'1':'1h','2':'2h','3':'3h'}.get(duration,'')
                duration_seconds(duration)
                role=input('账号权限 1=普通用户（默认） 2=高权限 sudo: ').strip() or '1'
                if role not in ('1','2'):raise ValueError('无效账号权限选项')
                if role=='2' and input('高权限账号可通过 sudo 管理整台服务器，输入 yes 确认: ').strip()!='yes':continue
                argv=['create',duration,'--role','sudo' if role=='2' else 'normal']
            elif choice=='2':
                target='off' if password_enabled() else 'on'
                if input('将'+('关闭' if target=='off' else '开启')+'服务器 SSH 密码登录，输入 yes 确认: ').strip()!='yes':continue
                argv=['password',target]
            elif choice=='3':
                subprocess.run([sys.executable,str(APP),'list'],check=True)
                name=input('输入账号名提前撤销，回车返回: ').strip()
                if not name:continue
                valid_name(name)
                if input('将断开连接并删除账号，输入 yes 确认: ').strip()!='yes':continue
                argv=['revoke',name]
            else:raise ValueError('无效选项')
            # Run each operation separately: never hold the cleanup lock while waiting for input.
            subprocess.run([sys.executable,str(pathlib.Path(__file__).resolve()),*argv],check=True)
        except (EOFError,KeyboardInterrupt):print('\n退出');return
        except Exception as e:print('错误:',e)

def main():
    p=parser();args=p.parse_args()
    if os.geteuid()!=0:raise PermissionError('请使用 sudo 或 root 运行')
    os.umask(0o077);BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not args.action:return menu(p)
    with open(BASE/'.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='install':install()
        elif args.action=='create':
            if not 1<=args.port<=65535:raise ValueError('端口范围 1–65535')
            create(args)
        elif args.action=='revoke':revoke(args.name)
        elif args.action=='cleanup':cleanup()
        elif args.action=='password':password_policy(args.state=='on')
        else:list_accounts()
if __name__=='__main__':
    try:main()
    except Exception as e:print('错误:',e,file=sys.stderr);sys.exit(1)
