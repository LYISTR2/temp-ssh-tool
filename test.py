import importlib.util, pathlib, tempfile, unittest, unittest.mock as mock, types, json, time
spec=importlib.util.spec_from_file_location('app',pathlib.Path(__file__).with_name('harness-ssh.py'));a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class Tests(unittest.TestCase):
 def test_names(self):
  for n in ['root','hs_../../etc','hs_abc;id','hs_ABCDEF']:
   with self.assertRaises(ValueError):a.valid_name(n)
  self.assertEqual(a.valid_name('hs_abcdef'),'hs_abcdef')
 def test_policy_toggle(self):
  original='PasswordAuthentication no\nPermitRootLogin prohibit-password\n'
  enabled=a.policy_text(original,True);disabled=a.policy_text(enabled,False)
  self.assertIn(original.strip(),disabled);self.assertEqual(disabled.count(a.BEGIN),1)
  self.assertIn('PasswordAuthentication yes',enabled);self.assertNotIn('PasswordAuthentication yes',disabled)
 def test_linux_comment_and_no_reload_order_deadlock(self):
  source=pathlib.Path(a.__file__).read_text()
  self.assertNotIn("'harness-ssh:'",source)
  self.assertNotIn('Before=ssh.service sshd.service',source)
 def test_auth_cli(self):
  self.assertEqual(a.parser().parse_args(['create','1h','--auth','password']).auth,'password')
 def test_menu_returns(self):
  with mock.patch('builtins.input',side_effect=['2','0']),mock.patch.object(a.subprocess,'run') as run:a.menu(a.parser());self.assertEqual(run.call_count,1)
 def test_presets(self):self.assertEqual(list(a.PRESETS.values()),[900,3600,14400,28800,86400])
 def test_existing_user_not_deleted(self):
  args=a.parser().parse_args(['create','15m','--name','hs_abcdef'])
  with mock.patch.object(a.APP.__class__,'exists',return_value=True),mock.patch.object(a,'run') as run,mock.patch.object(a.pwd,'getpwnam',return_value=object()):
   with self.assertRaises(ValueError):a.create(args)
   self.assertEqual(run.call_count,1)
 def test_identity_mismatch(self):
  with tempfile.TemporaryDirectory() as d,mock.patch.object(a,'BASE',pathlib.Path(d)),mock.patch.object(a,'run') as run,mock.patch.object(a.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=999)):
   a.meta('hs_abcdef').write_text(json.dumps({'uid':123,'home':'/home/hs_abcdef'}))
   with self.assertRaises(ValueError):a.revoke('hs_abcdef')
   run.assert_not_called()
 def test_expiry_dispatch(self):
  with tempfile.TemporaryDirectory() as d,mock.patch.object(a,'BASE',pathlib.Path(d)),mock.patch.object(a,'revoke') as revoke:
   a.meta('hs_abcdef').write_text(json.dumps({'expires':time.time()-1}));a.meta('hs_ghijkl').write_text(json.dumps({'expires':time.time()+1000}));a.cleanup();revoke.assert_called_once_with('hs_abcdef')
 def test_unknown_account(self):
  with tempfile.TemporaryDirectory() as d,mock.patch.object(a,'BASE',pathlib.Path(d)):
   with self.assertRaises(ValueError):a.revoke('hs_abcdef')
if __name__=='__main__':unittest.main(verbosity=2)
