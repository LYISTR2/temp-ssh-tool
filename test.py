import importlib.util
import contextlib
import io
import json
import pathlib
import tempfile
import time
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('app', pathlib.Path(__file__).with_name('harness-ssh.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class Tests(unittest.TestCase):
    def test_duration(self):
        for value, seconds in [('1h', 3600), ('2h', 7200), ('3h', 10800), ('90m', 5400), ('2d', 172800)]:
            self.assertEqual(a.duration_seconds(value), seconds)
        for value in ('0h', '31d', '2', '1s', '-1h'):
            with self.assertRaises(ValueError):
                a.duration_seconds(value)

    def test_duration_boundaries(self):
        for value, seconds in [('1m', 60), ('30d', 2592000), ('720h', 2592000)]:
            self.assertEqual(a.duration_seconds(value), seconds)
        for value in ('0m', '43201m', '721h', '1H', ' 1h', '1h ', '01h', '1.5h'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                a.duration_seconds(value)

    def test_public_ip_rejects_invalid_or_nonpublic_addresses(self):
        for value in (None, 42, {}, '', 'localhost', '127.0.0.1', '10.1.2.3',
                      '100.64.0.1', '169.254.1.1', '192.0.2.1', '224.0.0.1'):
            with self.subTest(value=value):
                self.assertIsNone(a.public_ip(value, 4))
        for value in ('::', '::1', 'fe80::1', 'fd00::1', 'ff02::1',
                      '2606:4700:4700::1111%eth0', '2001:db8::1'):
            with self.subTest(value=value):
                self.assertIsNone(a.public_ip(value, 6))
        self.assertEqual(a.public_ip(' 160.236.110.78\n', 4), '160.236.110.78')
        self.assertEqual(a.public_ip('2606:4700:4700:0:0:0:0:1111', 6),
                         '2606:4700:4700::1111')
        self.assertIsNone(a.public_ip('160.236.110.78', 6))
        self.assertIsNone(a.public_ip('2606:4700:4700::1111', 4))

    def test_global_policy_and_legacy_migration(self):
        original = ('Include /etc/ssh/sshd_config.d/*.conf\n'
                    'PermitRootLogin prohibit-password\n'
                    + a.BEGIN + '\nMatch Group harness-temp\n    PasswordAuthentication yes\n'
                    '    PermitTTY no\n' + a.END + '\n')
        enabled = a.policy_text(original, True)
        disabled = a.policy_text(enabled, False)
        self.assertTrue(enabled.startswith(a.BEGIN + '\nPasswordAuthentication yes\n'))
        self.assertTrue(disabled.startswith(a.BEGIN + '\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'))
        self.assertNotIn('Match Group harness-temp', disabled)
        self.assertIn('PermitRootLogin prohibit-password', disabled)
        self.assertEqual(disabled.count(a.BEGIN), 1)
        self.assertEqual(disabled.count('Include /etc/ssh'), 1)

    def test_unbalanced_markers_fail(self):
        with self.assertRaises(ValueError):
            a.policy_text(a.BEGIN + '\n', True)

    def test_names(self):
        for name in ('root', 'hs_../../etc', 'hs_abc;id', 'hs_ABCDEF'):
            with self.assertRaises(ValueError):
                a.valid_name(name)
        self.assertEqual(a.valid_name('hs_abcdef'), 'hs_abcdef')

    def test_cli_defaults_to_password(self):
        parsed = a.parser().parse_args(['create', '2h'])
        self.assertEqual(parsed.duration, '2h')
        self.assertIsNone(parsed.host)
        self.assertEqual(parsed.port, 22)
        self.assertEqual(parsed.role, 'normal')
        self.assertEqual(a.parser().parse_args(['create', '1h', '--role', 'sudo']).role, 'sudo')
        self.assertFalse(hasattr(parsed, 'auth'))

    def test_detect_public_ip(self):
        for field in ('prefsrc', 'src'):
            with self.subTest(field=field), mock.patch.object(a, 'run', return_value=types.SimpleNamespace(
                    stdout=json.dumps([{field: '160.236.110.78'}]))) as run:
                self.assertEqual(a.detect_public_ip(), '160.236.110.78')
                run.assert_called_once_with('ip', '-j', '-4', 'route', 'get', '1.1.1.1',
                                            capture_output=True, timeout=2)

    def test_detect_nat_uses_direct_https(self):
        with mock.patch.object(a, 'run', side_effect=[
                types.SimpleNamespace(stdout='[{"prefsrc":"100.113.1.108"}]'),
                types.SimpleNamespace(stdout='160.236.110.78\n')]) as run:
            self.assertEqual(a.detect_public_ip(), '160.236.110.78')
            args, options = run.call_args
            self.assertEqual(args[:2], ('curl', '-q'))
            self.assertIn('-4', args)
            for flag, value in (('--noproxy', '*'), ('--proto', '=https'),
                                ('--connect-timeout', '2'), ('--max-time', '3'),
                                ('--max-filesize', '64')):
                self.assertEqual(args[args.index(flag) + 1], value)
            self.assertTrue(args[-1].startswith('https://'))
            self.assertNotIn('-k', args)
            self.assertEqual(options, {'capture_output': True, 'timeout': 4})

    def test_detect_retries_another_service(self):
        for first in (a.subprocess.TimeoutExpired('curl', 4),
                      a.subprocess.CalledProcessError(22, ['curl']),
                      types.SimpleNamespace(stdout='<html>blocked</html>'),
                      types.SimpleNamespace(stdout='10.0.0.1'),
                      types.SimpleNamespace(stdout='100.64.0.1'),
                      types.SimpleNamespace(stdout='224.0.0.1'),
                      types.SimpleNamespace(stdout='2606:4700:4700::1111'),
                      types.SimpleNamespace(stdout='160.236.110.78\n160.236.110.79')):
            with self.subTest(first=first), mock.patch.object(a, 'run', side_effect=[
                    types.SimpleNamespace(stdout='[{"prefsrc":"10.0.0.1"}]'), first,
                    types.SimpleNamespace(stdout='160.236.110.78\n')]) as run:
                self.assertEqual(a.detect_public_ip(), '160.236.110.78')
                self.assertNotEqual(run.call_args_list[1].args[-1], run.call_args_list[2].args[-1])

    def test_detect_handles_unavailable_or_malformed_routes(self):
        for route in (FileNotFoundError('ip'), a.subprocess.CalledProcessError(2, ['ip']),
                      a.subprocess.TimeoutExpired('ip', 2),
                      types.SimpleNamespace(stdout='not json'), types.SimpleNamespace(stdout='null'),
                      types.SimpleNamespace(stdout='{}'), types.SimpleNamespace(stdout='[null, {}]'),
                      types.SimpleNamespace(stdout='[{"prefsrc":"invalid"}]'),
                      types.SimpleNamespace(stdout='[{"prefsrc":"224.0.0.1"}]')):
            with self.subTest(route=route), mock.patch.object(a, 'run', side_effect=[
                    route, types.SimpleNamespace(stdout='160.236.110.78')]):
                self.assertEqual(a.detect_public_ip(), '160.236.110.78')

    def test_detect_ipv6_only_route(self):
        failure = a.subprocess.CalledProcessError(7, ['curl'])
        with mock.patch.object(a, 'run', side_effect=[failure, failure, failure,
                types.SimpleNamespace(stdout='[{"src":"2606:4700:4700::1111"}]')]) as run:
            self.assertEqual(a.detect_public_ip(), '2606:4700:4700::1111')
            run.assert_called_with('ip', '-j', '-6', 'route', 'get', '2606:4700:4700::1111',
                                   capture_output=True, timeout=2)

    def test_detect_ipv6_https_fallback(self):
        failure = a.subprocess.CalledProcessError(7, ['curl'])
        with mock.patch.object(a, 'run', side_effect=[failure] * 4 + [
                types.SimpleNamespace(stdout='2606:4700:4700::1111\n')]) as run:
            self.assertEqual(a.detect_public_ip(), '2606:4700:4700::1111')
            self.assertIn('-6', run.call_args.args)

    def test_detect_all_sources_fail_with_actionable_error(self):
        for response in (a.subprocess.TimeoutExpired('probe', 4),
                         types.SimpleNamespace(stdout=''), types.SimpleNamespace(stdout='10.0.0.1')):
            with self.subTest(response=response), mock.patch.object(a, 'run', side_effect=(
                    response if isinstance(response, Exception) else None), return_value=response):
                with self.assertRaisesRegex(RuntimeError, '--host'):
                    a.detect_public_ip()

    def test_connection_host_override_skips_detection(self):
        with mock.patch.object(a, 'detect_public_ip') as detect:
            self.assertEqual(a.connection_host('example.com'), 'example.com')
            detect.assert_not_called()

    def test_connection_host_interactive_fallback(self):
        with mock.patch.object(a, 'detect_public_ip', side_effect=RuntimeError('no public IP')), \
                mock.patch.object(a.sys.stdin, 'isatty', return_value=True), \
                mock.patch('builtins.input', return_value=' example.com ') as prompt:
            self.assertEqual(a.connection_host(None), 'example.com')
            prompt.assert_called_once()

    def test_connection_host_empty_input_cancels(self):
        with mock.patch.object(a, 'detect_public_ip', side_effect=RuntimeError('no public IP')), \
                mock.patch.object(a.sys.stdin, 'isatty', return_value=True), \
                mock.patch('builtins.input', return_value='  '):
            with self.assertRaisesRegex(ValueError, '取消'):
                a.connection_host(None)

    def test_connection_host_noninteractive_never_prompts(self):
        with mock.patch.object(a, 'detect_public_ip', side_effect=RuntimeError('no public IP')), \
                mock.patch.object(a.sys.stdin, 'isatty', return_value=False), \
                mock.patch('builtins.input') as prompt:
            with self.assertRaisesRegex(RuntimeError, 'no public IP'):
                a.connection_host(None)
            prompt.assert_not_called()

    def test_menu_create_does_not_ask_for_host_or_port(self):
        with mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch('builtins.input', side_effect=['1', '', '', '0']) as ask, \
                mock.patch.object(a.subprocess, 'run') as run:
            a.menu(a.parser())
            self.assertEqual(ask.call_count, 4)
            self.assertEqual(run.call_args.args[0][-4:], ['create', '1h', '--role', 'normal'])

    def test_menu_sudo_requires_confirmation(self):
        with mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch('builtins.input', side_effect=['1', '', '2', 'no', '0']), \
                mock.patch.object(a.subprocess, 'run') as run:
            a.menu(a.parser())
            run.assert_not_called()
        with mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch('builtins.input', side_effect=['1', '', '2', 'yes', '0']), \
                mock.patch.object(a.subprocess, 'run') as run:
            a.menu(a.parser())
            self.assertEqual(run.call_args.args[0][-4:], ['create', '1h', '--role', 'sudo'])

    def test_menu_account_list_and_return(self):
        with mock.patch.object(a, 'password_enabled', return_value=False), \
                mock.patch('builtins.input', side_effect=['3', '', '0']), \
                mock.patch.object(a.subprocess, 'run') as run:
            a.menu(a.parser())
            run.assert_called_once()
            self.assertIn('list', run.call_args.args[0])

    def test_existing_user_not_deleted(self):
        args = a.parser().parse_args(['create', '1h', '--name', 'hs_abcdef'])
        with mock.patch.object(a.APP.__class__, 'exists', return_value=True), \
                mock.patch.object(a, 'run') as run, \
                mock.patch.object(a.pwd, 'getpwnam', return_value=object()):
            with self.assertRaises(ValueError):
                a.create(args)
            self.assertEqual(run.call_count, 1)

    def test_create_prints_password_and_creation_deadline(self):
        args = a.parser().parse_args(['create', '2h', '--name', 'hs_abcdef', '--host', 'example.com'])
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a, 'run'), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=[KeyError(), user]), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a, 'effective', return_value={'passwordauthentication': 'yes', 'permittty': 'yes'}), \
                mock.patch.object(a.time, 'time', return_value=1_800_000_000):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                a.create(args)
            record = json.loads(a.meta('hs_abcdef').read_text())
            self.assertEqual(record['expires'], 1_800_007_200)
            self.assertEqual(record['role'], 'normal')
            self.assertIn('密码：', output.getvalue())
            self.assertIn('普通用户，无 sudo', output.getvalue())
            self.assertIn('ssh -p 22 hs_abcdef@example.com', output.getvalue())

    def test_create_auto_detects_address(self):
        args = a.parser().parse_args(['create', '2h', '--name', 'hs_abcdef'])
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a, 'detect_public_ip', return_value='160.236.110.78') as detect, \
                mock.patch.object(a, 'run'), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=[KeyError(), user]), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a, 'effective', return_value={'passwordauthentication': 'yes', 'permittty': 'yes'}), \
                mock.patch.object(a.time, 'time', return_value=1_800_000_000):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                a.create(args)
            detect.assert_called_once_with()
            self.assertIn('ssh -p 22 hs_abcdef@160.236.110.78', output.getvalue())

    def test_create_ipv6_displays_unambiguous_address(self):
        args = a.parser().parse_args(['create', '1h', '--name', 'hs_abcdef',
                                      '--host', '2606:4700:4700::1111', '--port', '2222'])
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a, 'run'), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=[KeyError(), user]), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a, 'effective', return_value={'passwordauthentication': 'yes'}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            a.create(args)
            self.assertIn('地址：[2606:4700:4700::1111]:2222', output.getvalue())
            self.assertIn('ssh -p 2222 hs_abcdef@2606:4700:4700::1111', output.getvalue())

    def test_main_resolves_address_without_holding_cleanup_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)

            def resolve(host):
                with open(base / '.lock', 'w') as lock:
                    a.fcntl.flock(lock, a.fcntl.LOCK_EX | a.fcntl.LOCK_NB)
                return '160.236.110.78'

            with mock.patch.object(a, 'BASE', base), \
                    mock.patch.object(a.os, 'geteuid', return_value=0), \
                    mock.patch.object(a.os, 'umask'), \
                    mock.patch.object(a.sys, 'argv', ['hssh', 'create', '1h']), \
                    mock.patch.object(a, 'connection_host', side_effect=resolve), \
                    mock.patch.object(a, 'create') as create:
                a.main()
                self.assertEqual(create.call_args.args[0].host, '160.236.110.78')

    def test_detect_failure_does_not_create_account(self):
        args = a.parser().parse_args(['create', '1h', '--name', 'hs_abcdef'])
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=KeyError()), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a, 'detect_public_ip', side_effect=RuntimeError('no public IP')), \
                mock.patch.object(a.sys.stdin, 'isatty', return_value=False), \
                mock.patch.object(a, 'run') as run:
            with self.assertRaises(RuntimeError):
                a.create(args)
            run.assert_called_once()

    def test_create_sudo_grants_only_selected_account(self):
        args = a.parser().parse_args(['create', '1h', '--role', 'sudo', '--name', 'hs_abcdef', '--host', 'example.com'])
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a.shutil, 'which', return_value='/usr/sbin/visudo'), \
                mock.patch.object(a, 'run'), \
                mock.patch.object(a, 'grant_sudo') as grant, \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=[KeyError(), user]), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a, 'effective', return_value={'passwordauthentication': 'yes', 'permittty': 'yes'}):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                a.create(args)
            grant.assert_called_once_with('hs_abcdef')
            self.assertEqual(json.loads(a.meta('hs_abcdef').read_text())['role'], 'sudo')
            self.assertIn('sudo（需输入该账号密码）', output.getvalue())

    def test_grant_sudo_rule_is_password_protected(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'SUDOERS_DIR', pathlib.Path(directory)), \
                mock.patch.object(a.shutil, 'which', return_value='/usr/sbin/visudo'), \
                mock.patch.object(a, 'run') as run:
            a.grant_sudo('hs_abcdef')
            rule = a.sudoers_path('hs_abcdef')
            self.assertEqual(rule.read_text(), 'hs_abcdef ALL=(ALL:ALL) ALL\n')
            self.assertEqual(rule.stat().st_mode & 0o777, 0o440)
            run.assert_called_once_with('visudo', '-cf', str(rule), stdout=a.subprocess.DEVNULL)
            with self.assertRaises(ValueError):
                a.grant_sudo('hs_abcdef')

    def test_grant_sudo_invalid_rule_is_removed(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'SUDOERS_DIR', pathlib.Path(directory)), \
                mock.patch.object(a.shutil, 'which', return_value='/usr/sbin/visudo'), \
                mock.patch.object(a, 'run', side_effect=RuntimeError('invalid')):
            with self.assertRaises(RuntimeError):
                a.grant_sudo('hs_abcdef')
            self.assertFalse(a.sudoers_path('hs_abcdef').exists())

    def test_revoke_removes_sudo_rule(self):
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef', pw_gecos='harness-ssh-hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'SUDOERS_DIR', pathlib.Path(directory)), \
                mock.patch.object(a, 'run'), \
                mock.patch.object(a.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1)), \
                mock.patch.object(a.pwd, 'getpwnam', return_value=user):
            a.meta('hs_abcdef').write_text(json.dumps({'uid': 1234, 'home': '/home/hs_abcdef'}))
            a.sudoers_path('hs_abcdef').write_text('hs_abcdef ALL=(ALL:ALL) ALL\n')
            a.revoke('hs_abcdef')
            self.assertFalse(a.sudoers_path('hs_abcdef').exists())
            self.assertFalse(a.meta('hs_abcdef').exists())

    def test_identity_mismatch_rejects_delete(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'run') as run, \
                mock.patch.object(a.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=999)):
            a.meta('hs_abcdef').write_text(json.dumps({'uid': 123, 'home': '/home/hs_abcdef'}))
            with self.assertRaises(ValueError):
                a.revoke('hs_abcdef')
            run.assert_not_called()

    def test_expiry_dispatch(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'revoke') as revoke:
            a.meta('hs_abcdef').write_text(json.dumps({'expires': time.time() - 1}))
            a.meta('hs_ghijkl').write_text(json.dumps({'expires': time.time() + 1000}))
            a.cleanup()
            revoke.assert_called_once_with('hs_abcdef')

    def test_invalid_port_fails_before_detection_or_create(self):
        for port in ('0', '-1', '65536'):
            with self.subTest(port=port), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                    mock.patch.object(a.os, 'geteuid', return_value=0), \
                    mock.patch.object(a.os, 'umask'), \
                    mock.patch.object(a.sys, 'argv', ['hssh', 'create', '1h', '--port', port]), \
                    mock.patch.object(a, 'connection_host') as detect, \
                    mock.patch.object(a, 'create') as create:
                with self.assertRaisesRegex(ValueError, '端口范围'):
                    a.main()
                detect.assert_not_called()
                create.assert_not_called()

    def test_create_failed_auth_verification_rolls_back_account(self):
        args = a.parser().parse_args(['create', '1h', '--name', 'hs_abcdef', '--host', 'example.com'])
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=[KeyError(), user]), \
                mock.patch.object(a, 'run') as run, \
                mock.patch.object(a, 'verify_auth', side_effect=RuntimeError('policy conflict')), \
                mock.patch.object(a, 'revoke') as revoke:
            with self.assertRaisesRegex(RuntimeError, 'policy conflict'):
                a.create(args)
            revoke.assert_called_once_with('hs_abcdef')
            self.assertNotIn('chpasswd', [call.args[0] for call in run.call_args_list])

    def test_create_failed_metadata_write_removes_new_user(self):
        args = a.parser().parse_args(['create', '1h', '--name', 'hs_abcdef', '--host', 'example.com'])
        user = types.SimpleNamespace(pw_uid=1234, pw_dir='/home/hs_abcdef')
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=[KeyError(), user]), \
                mock.patch.object(a, 'run') as run, \
                mock.patch.object(a, 'write', side_effect=OSError('disk full')), \
                mock.patch.object(a, 'revoke') as revoke:
            with self.assertRaisesRegex(OSError, 'disk full'):
                a.create(args)
            run.assert_any_call('userdel', '--remove', 'hs_abcdef')
            revoke.assert_not_called()

    def test_password_policy_failure_restores_original_config(self):
        original = 'PasswordAuthentication no\nPermitRootLogin prohibit-password\n'
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'sshd_config'
            config.write_text(original)
            config.chmod(0o640)
            base = pathlib.Path(directory) / 'state'
            base.mkdir()
            with mock.patch.object(a, 'BASE', base), mock.patch.object(a, 'CONFIG', config), \
                    mock.patch.object(a.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)), \
                    mock.patch.object(a, 'run') as run, \
                    mock.patch.object(a, 'password_enabled', return_value=False):
                with self.assertRaisesRegex(RuntimeError, '密码开关'):
                    a.password_policy(True)
            self.assertEqual(config.read_text(), original)
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            backups = list(base.glob('sshd_config.backup-*'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), original)
            run.assert_any_call('systemctl', 'reload', 'ssh.service')

    def test_cleanup_continues_after_corrupt_record(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'revoke') as revoke, \
                contextlib.redirect_stderr(io.StringIO()):
            a.meta('hs_abcdef').write_text('not json')
            a.meta('hs_ghijkl').write_text(json.dumps({'expires': time.time() - 1}))
            with self.assertRaisesRegex(RuntimeError, '下一轮重试'):
                a.cleanup()
            revoke.assert_called_once_with('hs_ghijkl')

    def test_list_shows_roles_and_expiry_without_passwords(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            a.list_accounts()
            self.assertIn('暂无临时账号', output.getvalue())
            a.meta('hs_abcdef').write_text(json.dumps({'expires': time.time() - 1, 'role': 'sudo'}))
            a.meta('hs_ghijkl').write_text(json.dumps({'expires': time.time() + 100, 'role': 'normal'}))
            a.list_accounts()
            self.assertIn('高权限 sudo', output.getvalue())
            self.assertIn('普通用户', output.getvalue())
            self.assertIn('已到期，待清理', output.getvalue())
            self.assertNotIn('密码', output.getvalue())

    def test_unknown_account_rejects_delete(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)):
            with self.assertRaises(ValueError):
                a.revoke('hs_abcdef')


if __name__ == '__main__':
    unittest.main(verbosity=2)
