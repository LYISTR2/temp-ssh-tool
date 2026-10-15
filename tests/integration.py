#!/usr/bin/env python3
"""Real first-run/systemd/OpenSSH tests in disposable Ubuntu/Debian containers.

Requires Linux, rootful Docker, openssl, ssh-keygen, ssh and sshpass on the test
host. Only the containers receive package installation or SSH policy changes.
The TLS fixture serves the checked-out candidate; apt and SSH are not mocked.
"""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
DISTROS = {
    'ubuntu-22.04': 'ubuntu:22.04',
    'ubuntu-24.04': 'ubuntu:24.04',
    'debian-12': 'debian:12-slim',
    'debian-13': 'debian:13-slim',
}


def command(*args, check=True, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args) + '\n' + result.stdout + result.stderr)
    return result


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


class Suite:
    def __init__(self, distro, entry, output):
        self.distro, self.entry = distro, entry
        self.output = output
        self.name = 'temp-ssh-test-' + uuid.uuid4().hex[:12]
        self.results = []
        self.secrets = []
        self.children = []
        self.server = None
        self.work = Path('.')

    def record(self, name, passed=True, detail=None):
        self.results.append({'name': name, 'passed': bool(passed), 'detail': detail})
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        if not passed:
            raise AssertionError(name + ': ' + str(detail))

    def execute(self, *args, check=True, **kwargs):
        options = ['-i'] if 'input' in kwargs else []
        return command('docker', 'exec', *options, self.name, *args, check=check, **kwargs)

    def hssh(self, *args, **kwargs):
        return self.execute('hssh', *args, **kwargs)

    def wait_ready(self):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            result = self.execute('systemctl', 'is-active', '--quiet', 'basic.target', check=False)
            if result.returncode == 0:
                return
            time.sleep(.25)
        raise RuntimeError('The container init system did not become ready')

    def setup_fixture(self, temp):
        public = temp / 'public'
        public.mkdir()
        key, cert = temp / 'fixture.key', public / 'fixture.pem'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', str(key), '-out', str(cert), '-subj', '/CN=temp-ssh-fixture.test',
                '-addext', 'subjectAltName=DNS:temp-ssh-fixture.test')
        gateway = command('docker', 'network', 'inspect', 'bridge',
                          '--format', '{{ (index .IPAM.Config 0).Gateway }}').stdout.strip()
        for name in ('start.sh', 'harness-ssh.py'):
            shutil.copy2(ROOT / name, public / name)
        self.server = http.server.ThreadingHTTPServer(
            (gateway, 0), functools.partial(QuietHandler, directory=str(public)))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert), str(key))
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f'https://temp-ssh-fixture.test:{self.server.server_port}'
        bootstrap = (ROOT / 'bootstrap.sh').read_text()
        old = "base='https://raw.githubusercontent.com/LYISTR2/temp-ssh-tool/main'"
        assert bootstrap.count(old) == 1
        (public / 'bootstrap.sh').write_text(bootstrap.replace(old, f"base='{self.base}'"))
        (public / 'broken-download.sh').write_text(bootstrap.replace(old, f"base='{self.base}/missing'"))
        command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(temp / 'login-key'))
        return public

    def refresh_ssh_target(self):
        # Docker may allocate a new ephemeral host port on each container restart.
        self.port = int(json.loads(command('docker', 'inspect', self.name).stdout)[0]
                        ['NetworkSettings']['Ports']['22/tcp'][0]['HostPort'])
        known_hosts = self.work / 'known_hosts'
        if known_hosts.exists():
            public_key = known_hosts.read_text().split(' ', 1)[1]
            known_hosts.write_text(f'[127.0.0.1]:{self.port} {public_key}')

    def ssh_args(self, name, password=None, key=False):
        args = []
        if password is not None:
            secret = self.work / ('password-' + name)
            secret.write_text(password)
            secret.chmod(0o600)
            args += ['sshpass', '-f', str(secret)]
        args += ['ssh', '-T', '-p', str(self.port),
                 '-o', 'StrictHostKeyChecking=yes',
                 '-o', 'UserKnownHostsFile=' + str(self.work / 'known_hosts'),
                 '-o', 'GlobalKnownHostsFile=/dev/null',
                 '-o', 'ConnectTimeout=8', '-o', 'NumberOfPasswordPrompts=1',
                 '-o', 'LogLevel=ERROR']
        if key:
            args += ['-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                     '-i', str(self.work / 'login-key')]
        else:
            args += ['-o', 'PubkeyAuthentication=no',
                     '-o', 'PreferredAuthentications=password',
                     '-o', 'KbdInteractiveAuthentication=no']
        return args + [name + '@127.0.0.1']

    def ssh(self, name, password, remote, key=False):
        return command(*self.ssh_args(name, None if key else password, key), remote,
                       check=False, timeout=20)

    def create(self, name, duration, role):
        result = self.hssh('create', duration, '--name', name, '--role', role,
                          '--host', '127.0.0.1', '--port', str(self.port))
        match = re.search(r'^密码：(\S+)$', result.stdout, re.M)
        assert match is not None
        password = match.group(1)
        self.secrets.append(password)
        return password

    def rejected(self, name, password):
        result = self.ssh(name, password, 'id -u')
        return result.returncode != 0 and 'Permission denied' in result.stderr

    def run(self):
        for tool in ('docker', 'openssl', 'ssh-keygen', 'sshpass', 'ssh'):
            if not shutil.which(tool):
                raise RuntimeError('Missing test-host tool: ' + tool)
        temp_context = tempfile.TemporaryDirectory(prefix='hermes-temp-ssh-integration-')
        session = None
        try:
            self.work = Path(temp_context.name)
            public = self.setup_fixture(self.work)
            image = 'temp-ssh-test:' + self.distro
            command('docker', 'run', '-d', '--name', self.name, '--privileged',
                    '--cgroupns=private', '--tmpfs', '/run', '--tmpfs', '/run/lock',
                    '--add-host', 'temp-ssh-fixture.test:host-gateway',
                    '-v', str(ROOT) + ':/src:ro', '-v', str(public) + ':/fixture:ro',
                    '-p', '127.0.0.1::22', image)
            self.wait_ready()
            os_release = self.execute('bash', '-c', '. /etc/os-release; printf "%s %s" "$ID" "$VERSION_ID"').stdout
            expected = self.distro.replace('-', ' ', 1)
            self.record('correct_distribution', os_release == expected, os_release)
            probe = self.execute('bash', '-c',
                                 'for x in python3 curl sshd ip sudo visudo; do command -v "$x" || true; done')
            self.record('clean_first_run_dependencies', probe.stdout == '', probe.stdout)
            unprivileged = command('docker', 'exec', '--user', '65534:65534', self.name,
                                   'bash', '/src/start.sh', 'list', check=False)
            self.record('no_sudo_non_root_fails_clearly', unprivileged.returncode != 0 and '切换 root' in unprivileged.stderr)
            self.execute('bash', '-c', 'printf "#!/bin/sh\\nexit 42\\n" > /usr/local/bin/apt-get; chmod 755 /usr/local/bin/apt-get')
            failed_start = self.execute('bash', '/src/start.sh', 'list', check=False)
            failed_bootstrap = self.execute('bash', '/src/bootstrap.sh', 'list', check=False)
            uninstalled = self.execute('test', '-e', '/usr/local/sbin/harness-ssh', check=False)
            self.record('apt_failure_stops_before_install', failed_start.returncode != 0 and
                        failed_bootstrap.returncode != 0 and '更新软件源失败' in failed_start.stderr and
                        '下载工具安装失败' in failed_bootstrap.stderr and uninstalled.returncode != 0)
            self.execute('rm', '-f', '/usr/local/bin/apt-get')
            if self.entry == 'bootstrap':
                installed = command('docker', 'exec', '-e', 'CURL_CA_BUNDLE=/fixture/fixture.pem',
                                    self.name, 'bash', '/fixture/bootstrap.sh', 'list', timeout=420)
            elif self.entry in ('launcher', 'remote'):
                # Run the README launcher; the candidate fixture only substitutes its URL.
                text = (ROOT / 'README.md').read_text()
                match = re.search(r'```bash\n([^\n]+)\n```', text)
                assert match is not None
                launcher = match.group(1)
                options = []
                if self.entry == 'launcher':
                    launcher = launcher.replace('https://raw.githubusercontent.com/LYISTR2/temp-ssh-tool/main/bootstrap.sh',
                                                self.base + '/bootstrap.sh')
                    options = ['-e', 'CURL_CA_BUNDLE=/fixture/fixture.pem']
                installed = command('docker', 'exec', *options, self.name, 'bash', '-c', launcher, timeout=420)
            else:
                installed = self.execute('bash', '/src/start.sh', 'list', timeout=420)
            self.record('first_run_auto_installs', installed.returncode == 0 and '首次使用' in installed.stdout)
            installed_hash = self.execute('sha256sum', '/usr/local/sbin/harness-ssh').stdout.split()[0]
            self.record('cli_installed', self.hssh('list').returncode == 0 and
                        installed_hash == hashlib.sha256((ROOT / 'harness-ssh.py').read_bytes()).hexdigest())
            self.record('ssh_and_expiry_timer_active', self.execute(
                'systemctl', 'is-active', '--quiet', 'ssh.service', 'harness-ssh-cleanup.timer').returncode == 0)
            state = self.execute('bash', '-c', 'sha256sum /etc/ssh/sshd_config; stat -c %Y /usr/local/sbin/harness-ssh').stdout
            second = self.execute('bash', '/src/start.sh', 'list', timeout=30)
            after = self.execute('bash', '-c', 'sha256sum /etc/ssh/sshd_config; stat -c %Y /usr/local/sbin/harness-ssh').stdout
            self.record('second_run_is_idempotent', state == after and '首次使用' not in second.stdout)
            bad = command('docker', 'exec', '-e', 'CURL_CA_BUNDLE=/fixture/fixture.pem',
                          self.name, 'bash', '/fixture/broken-download.sh', 'list', check=False, timeout=30)
            self.record('download_failure_leaves_install_intact', bad.returncode != 0 and
                        '404' in bad.stderr and state == self.execute('bash', '-c',
                        'sha256sum /etc/ssh/sshd_config; stat -c %Y /usr/local/sbin/harness-ssh').stdout)
            self.refresh_ssh_target()
            hostkey = self.execute('bash', '-c', 'read -r kind value _ < /etc/ssh/ssh_host_ed25519_key.pub; printf "%s %s" "$kind" "$value"').stdout
            (self.work / 'known_hosts').write_text(f'[127.0.0.1]:{self.port} {hostkey}\n')
            self.hssh('password', 'on')
            normal, admin = 'hs_normaltest', 'hs_sudotest'
            password = self.create(normal, '2h', 'normal')
            uid = self.execute('id', '-u', normal).stdout.strip()
            login = self.ssh(normal, password, 'id -u')
            self.record('real_password_ssh_login', login.returncode == 0 and login.stdout.strip() == uid)
            denial = self.ssh(normal, password, 'sudo -n id -u')
            self.record('normal_user_has_no_sudo', denial.returncode != 0 and
                        self.execute('test', '-e', '/etc/sudoers.d/harness-ssh-' + normal, check=False).returncode != 0)
            self.execute('install', '-d', '-m', '700', '-o', normal, '-g', normal,
                         '/home/' + normal + '/.ssh')
            self.execute('bash', '-c', 'umask 077; read -r line; printf "%s\n" "$line" > /home/hs_normaltest/.ssh/authorized_keys; chown hs_normaltest:hs_normaltest /home/hs_normaltest/.ssh/authorized_keys',
                         input=(self.work / 'login-key.pub').read_text())
            self.record('real_key_ssh_login', self.ssh(normal, password, 'id -u', key=True).returncode == 0)
            self.hssh('password', 'off')
            self.record('password_off_rejects_real_login', self.rejected(normal, password))
            self.record('password_off_preserves_key_login', self.ssh(normal, password, 'id -u', key=True).returncode == 0)
            saved_config = self.execute('sha256sum', '/etc/ssh/sshd_config').stdout
            self.execute('bash', '/src/start.sh', 'list')
            self.record('relaunch_preserves_disabled_password_policy', saved_config == self.execute('sha256sum', '/etc/ssh/sshd_config').stdout)
            self.hssh('password', 'on')
            self.record('password_on_restores_real_login', self.ssh(normal, password, 'id -u').returncode == 0)
            admin_password = self.create(admin, '1m', 'sudo')
            admin_login = self.ssh(admin, admin_password, 'id -u')
            self.record('sudo_account_real_ssh_login', admin_login.returncode == 0)
            no_password = self.ssh(admin, admin_password, 'sudo -k -n id -u')
            self.record('sudo_requires_password', no_password.returncode != 0 and 'password' in no_password.stderr)
            # Test-generated password travels over encrypted SSH stdin, never argv or logs.
            authenticated = command(*self.ssh_args(admin, admin_password),
                                    "sudo -k -S -p '' id -u", check=False,
                                    input=admin_password + '\n', timeout=20)
            self.record('authenticated_sudo_returns_root', authenticated.returncode == 0 and authenticated.stdout.strip() == '0')
            expiry = int(self.execute('python3', '-c',
                         "import json; print(json.load(open('/var/lib/harness-ssh/hs_sudotest.json'))['expires'])").stdout)
            session = subprocess.Popen(self.ssh_args(admin, admin_password) + ['printf "SESSION_READY\\n"; exec sleep 180'],
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.children.append(session)
            assert session.stdout is not None
            assert session.stdout.readline().strip() == 'SESSION_READY'
            # Let a real one-minute account expire; do not mutate its deadline or run cleanup manually.
            deadline = time.monotonic() + max(0, expiry - time.time()) + 35
            while time.monotonic() < deadline:
                exists = self.execute('getent', 'passwd', admin, check=False)
                if exists.returncode != 0:
                    break
                time.sleep(.5)
            self.record('real_one_minute_timer_expiry', self.execute('getent', 'passwd', admin, check=False).returncode != 0)
            session.wait(timeout=10)
            self.record('expiry_disconnects_existing_ssh_session', session.returncode != 0)
            removed = self.execute('bash', '-c',
                       'test ! -e /etc/sudoers.d/harness-ssh-hs_sudotest && test ! -e /var/lib/harness-ssh/hs_sudotest.json && test ! -d /home/hs_sudotest', check=False)
            self.record('expiry_removes_home_record_and_sudo', removed.returncode == 0)
            self.record('expired_password_cannot_login', self.rejected(admin, admin_password))
            command('docker', 'restart', self.name, timeout=40)
            self.wait_ready()
            self.refresh_ssh_target()
            deadline = time.monotonic() + 15
            while self.execute('systemctl', 'is-active', '--quiet', 'ssh.service', check=False).returncode != 0 and time.monotonic() < deadline:
                time.sleep(.25)
            self.record('timer_persists_after_restart', self.execute('systemctl', 'is-active', '--quiet', 'harness-ssh-cleanup.timer').returncode == 0)
            restart_login = self.ssh(normal, password, 'id -u')
            self.record('existing_account_survives_restart', restart_login.returncode == 0,
                        {'code': restart_login.returncode, 'stderr': restart_login.stderr})
            self.hssh('revoke', normal)
            self.record('manual_revoke_removes_account', self.execute('getent', 'passwd', normal, check=False).returncode != 0)
            self.record('revoked_password_cannot_login', self.rejected(normal, password))
            self.record('service_remains_healthy_after_revoke', self.execute('systemctl', 'is-active', '--quiet', 'ssh.service', 'harness-ssh-cleanup.timer').returncode == 0)
        except Exception as error:
            message = str(error)
            for secret in self.secrets:
                message = message.replace(secret, '[REDACTED]')
            self.results.append({'name': 'suite_error', 'passed': False, 'detail': message})
            print('FAIL ' + message, flush=True)
        finally:
            for child in self.children:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
            command('docker', 'rm', '-f', self.name, check=False)
            if self.server:
                self.server.shutdown()
                self.server.server_close()
            temp_context.cleanup()
            self.output.parent.mkdir(parents=True, exist_ok=True)
            data = {'distro': self.distro, 'entry': self.entry,
                    'passed': all(item['passed'] for item in self.results),
                    'checks': self.results,
                    'source_commit': command('git', '-C', str(ROOT), 'rev-parse', 'HEAD').stdout.strip(),
                    'source_files': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                     for name in ('README.md', 'bootstrap.sh', 'start.sh', 'harness-ssh.py',
                                                  'tests/Dockerfile.systemd', 'tests/integration.py')}}
            self.output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
        return data['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distro', choices=DISTROS, required=True)
    parser.add_argument('--entry', choices=('start', 'bootstrap', 'launcher', 'remote'), default='launcher')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build', action='store_true')
    args = parser.parse_args()
    if args.build:
        built = command('docker', 'build', '--build-arg', 'BASE=' + DISTROS[args.distro],
                        '-f', str(ROOT / 'tests/Dockerfile.systemd'),
                        '-t', 'temp-ssh-test:' + args.distro, str(ROOT), timeout=600)
        print(built.stdout + built.stderr)
    raise SystemExit(0 if Suite(args.distro, args.entry, args.output).run() else 1)


if __name__ == '__main__':
    main()
