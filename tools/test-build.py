#!/usr/bin/env python3
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
import warnings
import zipfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('normalize',HERE/'normalize-apk.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
class BuildBoundaryTests(unittest.TestCase):
 def script(self,name,values):
  env={k:v for k,v in os.environ.items() if k not in ('KEYSTORE','KEYSTORE_PASS','KEYSTORE_PASS_FILE','KEY_ALIAS','UNSIGNED','DEBUG')};env.update(values)
  return subprocess.run(['sh',str(HERE/name)],env=env,capture_output=True,text=True)
 def test_worker_refuses_signing_configuration_before_reading_it(self):
  r=self.script('build-apk.sh',{'UNSIGNED':'1','KEYSTORE':'/not-a-key'})
  self.assertNotEqual(r.returncode,0);self.assertIn('must receive no signing configuration',r.stderr)
 def test_unsigned_debug_and_missing_signer_fail_closed(self):
  r=self.script('build-apk.sh',{'UNSIGNED':'1','DEBUG':'1'});self.assertIn('must not be debug',r.stderr)
  r=self.script('build-apk.sh',{});self.assertNotEqual(r.returncode,0);self.assertIn('set KEYSTORE',r.stderr)
 def test_release_rejects_shell_repository_and_non_https_feed(self):
  r=self.script('release.sh',{'RELEASE_CORE_REPO':'bad;command'});self.assertNotEqual(r.returncode,0);self.assertIn('invalid release repository',r.stderr)
  r=self.script('release.sh',{'RELEASE_UPDATE_URL':'http://example.invalid'});self.assertNotEqual(r.returncode,0);self.assertIn('HTTPS',r.stderr)
 def test_fork_plan_records_repo_and_feed_without_network(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);app=root/'app';(app/'tools').mkdir(parents=True);shutil.copyfile(HERE/'release.sh',app/'tools/release.sh')
   core=root/'core';(core/'echod/internal/layout').mkdir(parents=True);(core/'echod/internal/layout/device_panel.go').write_text('package layout')
   def git(*a):return subprocess.check_output(['git','-C',str(core),*a],stderr=subprocess.DEVNULL,text=True).strip()
   git('init');git('add','.');git('-c','user.name=fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','commit','-m','fixture')
   git('remote','add','origin','https://github.com/example/core.git');git('update-ref','refs/remotes/origin/main',git('rev-parse','HEAD'))
   env=dict(os.environ,RELEASE_CORE_REPO='example/core',RELEASE_PANEL_REPO='example/panel',RELEASE_UPDATE_URL='https://updates.example.invalid/panel')
   r=subprocess.run(['sh',str(app/'tools/release.sh'),str(core)],env=env,capture_output=True,text=True)
   self.assertEqual(r.returncode,0,r.stderr)
   plan=(app/'build/release-plan').read_text();self.assertIn('core example/core',plan);self.assertIn('feed https://updates.example.invalid/panel',plan)
 def test_normalization_reproducible_and_preserves_payload(self):
  with tempfile.TemporaryDirectory() as d:
   paths=[Path(d)/'a.apk',Path(d)/'b.apk']
   for i,p in enumerate(paths):
    with zipfile.ZipFile(p,'w') as z:
     for name in (['x','y'] if i==0 else ['y','x']):
      info=zipfile.ZipInfo(name,(2020+i,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,name.encode())
    n.normalize(p,1767225600)
    with zipfile.ZipFile(p) as z:self.assertEqual(z.read('x'),b'x')
   self.assertEqual(paths[0].read_bytes(),paths[1].read_bytes())
 def test_signed_and_duplicate_archives_are_not_replaced(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'bad.apk'
   for duplicate in (False,True):
    with warnings.catch_warnings():
     warnings.simplefilter('ignore')
     with zipfile.ZipFile(p,'w') as z:
      z.writestr('x',b'x');z.writestr('x' if duplicate else 'META-INF/CERT.RSA',b'y')
    original=p.read_bytes()
    with self.assertRaises(ValueError):n.normalize(p,1767225600)
    self.assertEqual(p.read_bytes(),original)
if __name__=='__main__':unittest.main()
