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
        parsed = a.parser().parse_args(['create', '2h', '--host', 'example.com'])
        self.assertEqual(parsed.duration, '2h')
        self.assertFalse(hasattr(parsed, 'auth'))

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
            self.assertIn('密码：', output.getvalue())
            self.assertIn('ssh -p 22 hs_abcdef@example.com', output.getvalue())

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
