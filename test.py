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
        with mock.patch.object(a, 'run', return_value=types.SimpleNamespace(stdout='[{"dst":"1.1.1.1","prefsrc":"160.236.110.78"}]')) as run:
            self.assertEqual(a.detect_public_ip(), '160.236.110.78')
            run.assert_called_once_with('ip', '-j', '-4', 'route', 'get', '1.1.1.1', capture_output=True)
        with mock.patch.object(a, 'run', return_value=types.SimpleNamespace(stdout='[{"src":"10.0.0.1"}]')):
            with self.assertRaisesRegex(RuntimeError, 'NAT'):
                a.detect_public_ip()
        with mock.patch.object(a, 'run', return_value=types.SimpleNamespace(stdout='[]')):
            with self.assertRaisesRegex(RuntimeError, '--host'):
                a.detect_public_ip()

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

    def test_detect_failure_does_not_create_account(self):
        args = a.parser().parse_args(['create', '1h', '--name', 'hs_abcdef'])
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)), \
                mock.patch.object(a, 'APP', types.SimpleNamespace(exists=lambda: True)), \
                mock.patch.object(a.pwd, 'getpwnam', side_effect=KeyError()), \
                mock.patch.object(a, 'password_enabled', return_value=True), \
                mock.patch.object(a, 'detect_public_ip', side_effect=RuntimeError('no public IP')), \
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

    def test_unknown_account_rejects_delete(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(a, 'BASE', pathlib.Path(directory)):
            with self.assertRaises(ValueError):
                a.revoke('hs_abcdef')


if __name__ == '__main__':
    unittest.main(verbosity=2)
