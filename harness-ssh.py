#!/usr/bin/env python3
"""Temporary SSH key accounts for Debian/Ubuntu + systemd. No sudo grants."""
import argparse, datetime, fcntl, json, os, pathlib, pwd, re, secrets, shutil, subprocess, sys, time
BASE=pathlib.Path('/var/lib/harness-ssh')
APP=pathlib.Path('/usr/local/sbin/harness-ssh')
PRESETS={'15m':900,'1h':3600,'4h':14400,'8h':28800,'24h':86400}
CONFIG=pathlib.Path('/etc/ssh/sshd_config')
BEGIN='# BEGIN HARNESS-SSH MANAGED'
END='# END HARNESS-SSH MANAGED'

def policy_text(original,enabled):
    if original.count(BEGIN)!=original.count(END) or original.count(BEGIN)>1:raise ValueError('SSH 配置管理标记异常')
    if BEGIN in original:
        original=re.sub(re.escape(BEGIN)+r'.*?'+re.escape(END)+r'\n?', '', original, flags=re.S)
    return original.rstrip()+'\n\n'+BEGIN+'\nMatch Group harness-temp\n    PasswordAuthentication '+('yes' if enabled else 'no')+'\n    KbdInteractiveAuthentication no\n    PubkeyAuthentication yes\n    DisableForwarding yes\n    PermitTTY no\n'+END+'\n'

def verify_auth(name,enabled):
    text=run('sshd','-T','-C',f'user={name},host=localhost,addr=127.0.0.1',capture_output=True).stdout
    fields=dict(line.split(None,1) for line in text.splitlines() if ' ' in line)
    expected={'passwordauthentication':'yes' if enabled else 'no','kbdinteractiveauthentication':'no','pubkeyauthentication':'yes','disableforwarding':'yes','permittty':'no'}
    if any(fields.get(k)!=v for k,v in expected.items()):raise RuntimeError('已有 Match 规则优先或策略冲突，无法应用临时账号策略')
    if enabled and fields.get('authenticationmethods','any') not in ('any','password'):
        raise RuntimeError('AuthenticationMethods 不允许独立密码登录；保留原策略，不强行放宽')

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
        for f in BASE.glob('hs_*.json'):verify_auth(f.stem,enabled)
        run('systemctl','reload',service);run('systemctl','is-active','--quiet',service)
        write(BASE/'policy.json',json.dumps({'password':enabled}))
    except Exception:
        write(CONFIG,original,mode);run('sshd','-t');run('systemctl','reload',service);raise
    print('临时账号密码登录已'+('开启' if enabled else '关闭')+'；备份：'+str(backup))
    print('仅影响 harness-temp 组；不终止已有连接。地址相关 Match 和真实登录仍需客户端验证。')

def password_enabled():
    p=BASE/'policy.json'
    return p.exists() and json.loads(p.read_text()).get('password',False)

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
def revoke(name):
    p=meta(name)
    if not p.exists(): raise ValueError('不是本工具管理的账号；拒绝删除')
    m=json.loads(p.read_text())
    try: u=pwd.getpwnam(name)
    except KeyError: p.unlink();return
    if u.pw_uid!=m['uid'] or u.pw_dir!=m['home'] or not u.pw_gecos.startswith('harness-ssh-'):
        raise ValueError('账号身份与记录不符，拒绝删除')
    run('usermod','--expiredate','1970-01-02','--shell','/usr/sbin/nologin',name)
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
    for tool in ['systemctl','useradd','usermod','userdel','ssh-keygen','sshd','pkill','chpasswd']:
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
    keydir=None
    if args.auth=='password':
        if args.pubkey:raise ValueError('密码模式不能同时传入公钥')
        if not password_enabled():raise ValueError('请先在菜单开启临时账号密码登录')
        public=None
    elif args.pubkey:
        public=pathlib.Path(args.pubkey).read_text().strip()
        if '\n' in public or not re.match(r'^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+(?: .*)?$',public):raise ValueError('请提供单行 OpenSSH 公钥，不能是私钥或 authorized_keys 选项')
        run('ssh-keygen','-l','-f',str(pathlib.Path(args.pubkey).resolve()),stdout=subprocess.DEVNULL)
    else:
        keydir=BASE/('key-'+name);keydir.mkdir(mode=0o700)
        run('ssh-keygen','-q','-t','ed25519','-N','','-C',name,'-f',str(keydir/'id_ed25519'))
        public=(keydir/'id_ed25519.pub').read_text().strip()
    expires=int(time.time())+PRESETS[args.mode]
    # Record creation immediately after useradd; failure rolls back the new account.
    created=False
    try:
        run('useradd','--create-home','--user-group','--shell','/bin/bash','--comment','harness-ssh-'+name,name);created=True
        u=pwd.getpwnam(name)
        write(meta(name),json.dumps({'uid':u.pw_uid,'home':u.pw_dir,'expires':expires,'mode':args.mode,'auth':args.auth}))
        run('usermod','--append','--groups','harness-temp',name)
        verify_auth(name,password_enabled())
        password=secrets.token_urlsafe(24)
        run('chpasswd',input=name+':'+password+'\n',stdout=subprocess.DEVNULL)
        if public:
            ssh=pathlib.Path(u.pw_dir)/'.ssh';ssh.mkdir(mode=0o700)
            write(ssh/'authorized_keys','restrict '+public+'\n')
            for p in [ssh,ssh/'authorized_keys']:os.chown(p,u.pw_uid,u.pw_gid)
        # Day-granularity backstop; timer is responsible for sub-day deadlines.
        day=datetime.datetime.fromtimestamp(expires,datetime.timezone.utc).date()+datetime.timedelta(days=1)
        run('usermod','--expiredate',str(day),name)
    except Exception:
        if created:
            if meta(name).exists():revoke(name)
            else:run('userdel','--remove',name)
        if keydir:shutil.rmtree(keydir)
        raise
    keyinfo=str(keydir/'id_ed25519') if keydir else ('使用所提供公钥对应的私钥' if args.auth=='key' else None)
    options='-i <私钥路径>' if args.auth=='key' else '-o PreferredAuthentications=password -o PubkeyAuthentication=no'
    if args.auth=='password':print('临时密码（只显示一次，不写元数据）:',password)
    print(json.dumps({'auth':args.auth,'username':name,'host':args.host or '填写服务器可达IP或域名','port':args.port,'expires_utc':datetime.datetime.fromtimestamp(expires,datetime.timezone.utc).isoformat(),'private_key_file':keyinfo,'ssh_command':f'ssh -T -p {args.port} {options} {name}@{args.host or "<服务器地址>"}','permissions':'普通用户，无 sudo；禁止 PTY/端口转发/agent 转发；允许非交互命令','revoke':f'sudo harness-ssh revoke {name}'},ensure_ascii=False,indent=2))
    print('注意：尚未验证远程 SSH 登录。防火墙、AllowUsers/Match/认证策略可能阻止连接；请从 harness 端测试。')

def parser():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='action')
    for a in ['install','list','cleanup']:s.add_parser(a)
    r=s.add_parser('revoke');r.add_argument('name')
    q=s.add_parser('password');q.add_argument('state',choices=['on','off'])
    c=s.add_parser('create');c.add_argument('mode',choices=PRESETS);c.add_argument('--auth',choices=['key','password'],default='key');c.add_argument('--name');c.add_argument('--pubkey');c.add_argument('--host');c.add_argument('--port',type=int,default=22)
    return p

def menu(p):
    while True:
        print('\n=== Harness SSH v2 · 再次启动：hssh ===\n1 创建临时账号\n2 查看账号\n3 撤销账号\n4 开启临时账号密码登录\n5 关闭临时账号密码登录\n6 安装/修复\n0 退出')
        try:
            choice=input('选择: ').strip()
            if choice=='0':return
            if choice=='1':
                auth=input('认证方式 1=密钥 / 2=随机密码 [1]: ').strip() or '1'
                if auth not in ('1','2'):raise ValueError('无效认证方式')
                mode=input('时长 1=15分钟 2=1小时 3=4小时 4=8小时 5=24小时 [2]: ').strip() or '2'
                if mode not in ('1','2','3','4','5'):raise ValueError('无效时长')
                host=input('服务器可达 IP/域名: ').strip();port=input('SSH 端口 [22]: ').strip() or '22'
                if not port.isdigit() or not 1<=int(port)<=65535:raise ValueError('无效端口')
                argv=['create',list(PRESETS)[int(mode)-1],'--auth','key' if auth=='1' else 'password','--host',host,'--port',port]
                if auth=='1':
                    key=input('公钥文件路径（留空生成临时密钥）: ').strip()
                    if key:argv+=['--pubkey',key]
                elif not password_enabled():
                    if input('密码登录未开启，是否仅为临时账号组开启？输入 yes: ').strip()!='yes':continue
                    if subprocess.run([sys.executable,str(APP),'password','on']).returncode:continue
            elif choice=='2':argv=['list']
            elif choice=='3':
                name=valid_name(input('撤销账号名: ').strip())
                if input('将杀会话并删除家目录，输入 yes 确认: ').strip()!='yes':continue
                argv=['revoke',name]
            elif choice in ('4','5'):
                if input('仅影响临时账号组，不断开已有会话。输入 yes 确认: ').strip()!='yes':continue
                argv=['password','on' if choice=='4' else 'off']
            elif choice=='6':argv=['install']
            else:raise ValueError('无效选项')
            # Run each operation separately: never hold the cleanup lock while waiting for input.
            subprocess.run([sys.executable,str(pathlib.Path(__file__).resolve()),*argv])
        except (EOFError,KeyboardInterrupt):print('\n退出');return
        except Exception as e:print('错误:',e)

def main():
    p=parser();args=p.parse_args()
    if not args.action:return menu(p)
    if os.geteuid()!=0:raise PermissionError('请使用 sudo 或 root 运行')
    os.umask(0o077);BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open(BASE/'.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='install':install()
        elif args.action=='create':
            if not 1<=args.port<=65535:raise ValueError('端口范围 1–65535')
            create(args)
        elif args.action=='revoke':revoke(args.name)
        elif args.action=='cleanup':cleanup()
        elif args.action=='password':password_policy(args.state=='on')
        else:
            for f in sorted(BASE.glob('hs_*.json')):print(f.stem,f.read_text())
if __name__=='__main__':
    try:main()
    except Exception as e:print('错误:',e,file=sys.stderr);sys.exit(1)
