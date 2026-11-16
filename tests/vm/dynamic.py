#!/usr/bin/env python3
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

"""0.2 dynamic issuance and real 0.1 migration; only disposable guest VMs."""
from guest import *

def main():
 def positional():
  r=front(['agent','60']);assert r.returncode==0 and run(r.stdout.strip().decode()).returncode==0
 check('positional-new-eligible-account',positional)
 def missing_minutes():
  code,out,used=pty_call(['other'],[(b'Minutes [',b'2'),(b'password for',b'VmOnly-TestPassword-9274')]);assert code==0 and used==2
 check('username-only-prompts-minutes-and-real-sudo',missing_minutes)
 def bounds():
  for args in [['root','60'],['agent','0'],['agent','1441'],['agent','-1'],['no-such-local-user','60']]:assert front(args).returncode!=0
 check('positional-root-unknown-and-duration-bounds',bounds)
 def dynamic():
  names=['dynamicone','dynamictwo']
  try:
   for n in names:subprocess.run(['useradd','-m',n],check=True,capture_output=True)
   # Creating accounts does not require installation, policy changes, or generation changes.
   before=(CONTROL/'config').read_bytes();policy=POLICY.read_bytes();t,i=grant(names[0]);saved=(STATE/('g-'+i)).read_bytes();other,j=grant(names[1])
   assert before==(CONTROL/'config').read_bytes() and policy==POLICY.read_bytes() and saved==(STATE/('g-'+i)).read_bytes()
   assert run(t,who=names[0]).returncode==0 and run(other,who=names[1]).returncode==0
   assert run(t,who=names[1]).returncode!=0
   assert front(['revoke',i],names[1]).returncode!=0
   assert front(['revoke',i],names[0]).returncode==0 and run(t,who=names[0]).returncode!=0 and run(other,who=names[1]).returncode==0
   # Another administrator: independent existing NOPASSWD policy authorizes grant.
   f=pathlib.Path('/etc/sudoers.d/01-dynamic-admin');f.write_text(names[0]+' ALL=(root) NOPASSWD: ALL\n');f.chmod(0o440);reinstall()
   r=front([names[1],'3'],names[0]);assert r.returncode==0 and run(r.stdout.strip().decode(),who=names[1]).returncode==0
   # Nonadministrator cannot use recipient rules to issue or self-register.
   assert front([names[1],'3'],names[1]).returncode!=0
   # Root coordinator simulates consistent sudo metadata. Even a privileged
   # launch cannot attribute administrative issuance to an unauthorized actor.
   a=pwd.getpwnam(names[1]);env=os.environ.copy();env.update(SUDO_USER=a.pw_name,SUDO_UID=str(a.pw_uid),SUDO_GID=str(a.pw_gid))
   r=subprocess.run([HELP,'grant'],input=b'',capture_output=True,env=env)
   assert r.returncode!=0 and r.stdout[:1]!=b'R'
   for op in ['grant','admin-list','admin-revoke','admin-revoke-created','install','uninstall','cleanup','probe']:
    c=subprocess.run(['/usr/bin/sudo','-n','--',HELP,op],capture_output=True,**userargs(names[1]));assert c.returncode!=0 and c.stdout[:1]!=b'R'
  finally:
   pathlib.Path('/etc/sudoers.d/01-dynamic-admin').unlink(missing_ok=True);reinstall()
   for n in names:subprocess.run(['userdel','-r',n],capture_output=True)
 check('dynamic-two-recipients-preservation-another-admin-and-nonadmin-denial',dynamic)
 def concurrent_grants():
  with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:
   grants=list(pool.map(lambda n:(n,grant(n)),['agent','other']*4))
  assert all(run(t,who=n).returncode==0 for n,(t,i)in grants)
  assert len({i for n,(t,i)in grants})==8
 check('concurrent-issuance-preserves-independent-recipients',concurrent_grants)
 def removal():
  n='dynamicgone';subprocess.run(['useradd','-m',n],check=True,capture_output=True)
  t,i=grant(n);a=pwd.getpwnam(n);subprocess.run(['userdel',n],check=True)
  assert subprocess.run([HELP,'cleanup'],capture_output=True).returncode==0 and not(STATE/('g-'+i)).exists()
  # Recreated after observed deletion cannot recover the removed grant.
  subprocess.run(['useradd','-u',str(a.pw_uid),n],check=True,capture_output=True)
  try:assert run(t,who=n).returncode!=0
  finally:subprocess.run(['userdel','-r',n],capture_output=True)
 check('observed-account-removal-prunes-registration-before-uid-reuse',removal)
 def no_grant():
  reinstall();a=pwd.getpwnam('other')
  # sudo permits exact status but helper independently denies before READY.
  c=subprocess.run(['/usr/bin/sudo','-n','--',HELP,'status'],input=b'',capture_output=True,**userargs('other'));assert c.returncode!=0 and c.stdout[:1]!=b'R'
  assert len(list(STATE.iterdir())) <= 673
 check('unregistered-account-denied-before-ready-bounded-slot-namespace',no_grant)
 def bounded_lock_waiters():
  reinstall();lock=open(CONTROL/'lock','r');fcntl.flock(lock,fcntl.LOCK_EX);cs=[]
  try:
   cs=[req('status',None,who='other') for _ in range(12)]
   time.sleep(1)
   assert sum(c.poll() is None for c in cs)<=4
  finally:
   fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
   for c in cs:
    out,err=c.communicate(timeout=8);assert c.returncode!=0 and out[:1]!=b'R'
 check('unregistered-local-flood-bounded-before-maintenance-lock',bounded_lock_waiters)
 def default_ui():
  import re,datetime
  code,out,used=pty_call([],[(b'Username [humanadmin]:',b''),(b'Minutes [10]:',b''),(b'password for',b'VmOnly-TestPassword-9274')],env_updates={'USER':'other','LOGNAME':'other','TZ':'America/New_York'})
  assert code==0 and used==3 and b'Grant humanadmin full root access for 10 minutes.'in out and b'Access granted'in out
  assert b'Account: humanadmin'in out and b'Copy and paste this line to your agent:'in out and b'agent-sudo admin revoke'in out
  assert b'Already running commands can continue.'in out and b'host "'not in out and b'VmOnly-TestPassword-9274'not in out
  m=re.search(rb'v2\.[A-Za-z0-9_-]{64}',out);assert m
  handoff=b'see: https://simple-help.com/tools/agent-sudo | '+m.group(0)
  assert out.splitlines().count(handoff)==1
  g=json.loads((STATE/('g-'+token_id(m.group(0).decode()))).read_bytes());assert g['user']=='humanadmin'and g['expires']-g['created']==600
  from zoneinfo import ZoneInfo
  expected=datetime.datetime.fromtimestamp(g['expires'],ZoneInfo('America/New_York')).strftime('%Y-%m-%d %H:%M %Z (%z)').encode();assert expected in out
 check('default-username-real-uid-10minutes-local-timezone-readable-tty',default_ui)
 def username_default_minutes():
  import re
  code,out,used=pty_call(['other'],[(b'Minutes [10]:',b''),(b'password for',b'VmOnly-TestPassword-9274')]);assert code==0 and used==2 and b'Username ['not in out
  m=re.search(rb'v2\.[A-Za-z0-9_-]{64}',out);assert m;g=json.loads((STATE/('g-'+token_id(m.group(0).decode()))).read_bytes());assert g['user']=='other'and g['expires']-g['created']==600
 check('username-only-enter-selects-10minutes',username_default_minutes)
 def script_output():
  r=front(['other','7']);assert r.returncode==0 and len(r.stdout)==68 and r.stdout.startswith(b'v2.')
  t=r.stdout.strip().decode();g=json.loads((STATE/('g-'+token_id(t))).read_bytes());assert g['expires']-g['created']==420
  assert b'Account: other'in r.stderr and b'in 7 minutes'in r.stderr and b'agent-sudo admin revoke'in r.stderr and t.encode()not in r.stderr
  assert b'Give this token privately'in r.stderr and b'Copy and paste'not in r.stderr
  assert b'https://'not in r.stdout
  assert front(['admin','revoke',g['id']]).returncode==0 and run(t,who='other').returncode!=0
 check('explicit-duration-token-only-stdout-private-output-and-admin-revoke',script_output)
 def upgrade02():
  old=pathlib.Path('/root/old02-payload');old.mkdir(exist_ok=True)
  subprocess.run(['tar','-xzf','/root/old-0.2.0.tar.gz','-C',str(old)],check=True)
  r=subprocess.run([str(old/'install.sh')],capture_output=True);assert r.returncode==0
  t,i=grant();assert run(t).returncode==0
  reinstall();assert run(t).returncode!=0 and front(['--version']).stdout==b'agent-sudo 1.0.4\n'
  t,i=grant();assert run(t).returncode==0
 check('published-0.2.0-upgrade-invalidates-grants-and-issues-new',upgrade02)
 def upgrade10():
  old=pathlib.Path('/root/old10-payload');old.mkdir(exist_ok=True)
  subprocess.run(['tar','-xzf','/root/old-1.0.0.tar.gz','-C',str(old)],check=True)
  assert subprocess.run([str(old/'install.sh')],capture_output=True).returncode==0
  t,i=grant();assert run(t).returncode==0
  reinstall();assert run(t).returncode!=0 and front(['--version']).stdout==b'agent-sudo 1.0.4\n'
  t,i=grant();r=front(['revoke','all']);assert r.returncode==0 and b'Revoked 1 grant(s)'in r.stdout and run(t).returncode!=0
 check('published-1.0.0-upgrade-and-creator-revoke-command',upgrade10)
 def migration():
  old=pathlib.Path('/root/old-payload');old.mkdir(exist_ok=True)
  subprocess.run(['tar','-xzf','/root/old-0.1.0.tar.gz','-C',str(old)],check=True)
  r=subprocess.run([str(old/'install.sh'),'--user','agent'],capture_output=True);assert r.returncode==0,r.stderr[:100]
  t,i=grant();assert run(t).returncode==0 and json.loads((CONTROL/'config').read_bytes())['v']==1
  c=req('run',None);assert frame(c.stdout)==(b'R',b'')
  reinstall();assert json.loads((CONTROL/'config').read_bytes())['v']==2 and run(t).returncode!=0
  send(c,json.dumps({'v':1,'token':t,'argv':['/usr/bin/id']}).encode());assert frame(c.stdout)[0]==b'X' and c.wait(timeout=8)!=0
  # Actual old copied binary cannot operate using new schema or installed inode.
  r=subprocess.run([str(old/'agent-sudo-helper'),'grant'],input=b'',capture_output=True);assert r.returncode!=0 and r.stdout[:1]!=b'R'
  fresh,j=grant('other');assert run(fresh,who='other').returncode==0
 check('actual-0.1.0-upgrade-invalidates-old-grant-and-stale-pending-helper',migration)
 def partial():
  t,i=grant();p=CONTROL/'config';saved=p.read_bytes()
  try:
   x=json.loads(saved);x['v']=1;p.write_text(json.dumps(x));assert run(t).returncode!=0 and front(['agent','60']).returncode!=0
  finally:p.write_bytes(saved)
  assert run(t).returncode==0
 check('root-injected-partial-schema-migration-fails-closed',partial)
 pathlib.Path('/root/dynamic-results.json').write_text(json.dumps({'results':RESULTS,'frontend_sha256':hashlib.file_digest(open(FRONT,'rb'),'sha256').hexdigest(),'helper_sha256':hashlib.file_digest(open(HELP,'rb'),'sha256').hexdigest()},indent=2)+'\n')
if __name__=='__main__':main()
