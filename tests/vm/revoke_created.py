#!/usr/bin/env python3
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

"""Creator-scoped revocation against actual installed disposable-VM binaries."""
from guest import *
import re

def human_grant(who):
 code,out,used=pty_call([who,'10'],[(b'password for',b'VmOnly-TestPassword-9274')])
 assert code==0 and used==1
 token=re.search(rb'v2\.[A-Za-z0-9_-]{64}',out).group().decode()
 return token,token_id(token)

def human_revoke():
 code,out,used=pty_call(['revoke','all'],[(b'password for',b'VmOnly-TestPassword-9274')],env_updates={'USER':'root','LOGNAME':'root'})
 assert code==0 and used==1 and b'Already running commands can continue.'in out
 return out

def main():
 reinstall()
 def mixed():
  root_agent,ra=grant();root_human,rh=grant('humanadmin')
  issued=[human_grant(n)for n in ['agent','other','humanadmin']]
  assert all(json.loads((STATE/('g-'+i)).read_bytes())['creator']==pwd.getpwnam('humanadmin').pw_uid for t,i in issued)
  assert all(run(t,who=n).returncode==0 for n,(t,i)in zip(['agent','other','humanadmin'],issued))
  out=human_revoke();assert b'Revoked 3 grant(s)'in out
  assert all(not(STATE/('g-'+i)).exists()for t,i in issued)
  assert all(run(t,who=n).returncode!=0 for n,(t,i)in zip(['agent','other','humanadmin'],issued))
  assert run(root_agent).returncode==0 and run(root_human,who='humanadmin').returncode==0
 check('creator-scope-multiple-recipients-preserves-other-issuer-including-own-recipient',mixed)
 def no_self():
  reinstall();t,i=human_grant('other');assert not any(json.loads(p.read_bytes())['uid']==pwd.getpwnam('humanadmin').pw_uid for p in STATE.glob('g-*'))
  assert b'Revoked 1 grant(s)'in human_revoke() and run(t,who='other').returncode!=0
  assert b'Revoked 0 grant(s)'in human_revoke()
 check('fresh-auth-without-self-grant-and-empty-repeat',no_self)
 def root_scope():
  other,j=human_grant('other');a,i=grant();b,k=grant('humanadmin')
  r=front(['revoke','all']);assert r.returncode==0 and b'Revoked 2 grant(s)'in r.stdout
  assert run(a).returncode!=0 and run(b,who='humanadmin').returncode!=0 and run(other,who='other').returncode==0
 check('root-caller-revokes-only-root-created-grants',root_scope)
 def nonadmin():
  t,i=grant();before={p.name:p.read_bytes()for p in STATE.glob('g-*')}
  assert front(['revoke','all'],'agent').returncode!=0
  c=req('admin-revoke-created',None);out,err=c.communicate(timeout=8);assert c.returncode!=0 and out[:1]!=b'R'
  a=pwd.getpwnam('agent');env=os.environ.copy();env.update(SUDO_USER=a.pw_name,SUDO_UID=str(a.pw_uid),SUDO_GID=str(a.pw_gid))
  r=subprocess.run([HELP,'admin-revoke-created'],input=b'',capture_output=True,env=env)
  assert r.returncode!=0 and r.stdout[:1]!=b'R'
  assert before=={p.name:p.read_bytes()for p in STATE.glob('g-*')}and run(t).returncode==0
 check('nonadmin-sudo-and-independent-helper-denial-no-mutation',nonadmin)
 def fields():
  t,i=grant();before={p.name:p.read_bytes()for p in STATE.glob('g-*')}
  for raw in [b'{"v":1,"id":"'+i.encode()+b'"}',b'{"v":1,"creator":0}',b'{"v":1,"user":"root"}',b'{"v":1,"v":1}',b'{"v":2}']:
   rows,code=wire('admin-revoke-created',None,who='root',raw=raw);assert code!=0 and rows[-1][0]==b'X'
  assert before=={p.name:p.read_bytes()for p in STATE.glob('g-*')}and run(t).returncode==0
 check('direct-helper-rejects-selection-injection-and-invalid-schema',fields)
 def recipient_compat():
  reinstall();own,i=human_grant('agent');other,j=grant();third,k=human_grant('other')
  assert front(['revoke','--all'],'agent').returncode==0 and run(own).returncode!=0 and run(other).returncode!=0 and run(third,who='other').returncode==0
 check('recipient-double-dash-all-keeps-existing-semantics',recipient_compat)
 def expired():
  reinstall();t,i=human_grant('agent');p=STATE/('g-'+i);g=json.loads(p.read_bytes());g['deadline']=0;p.write_text(json.dumps(g))
  assert b'Revoked 1 grant(s)'in human_revoke()and not p.exists()
 check('expired-stored-grants-included-root-injected-deadline-fixture',expired)
 def ordering():
  reinstall();t,i=grant();c=req('admin-revoke-created',None,who='root');assert frame(c.stdout)==(b'R',b'')
  # READY must not hold the lock. A new issuance before batch admission is included.
  fresh,j=grant('other');send(c,b'{"v":1}');kind,b=frame(c.stdout);assert kind==b'J'and json.loads(b)['revoked']==2
  assert frame(c.stdout)[0]==b'X'and c.wait(timeout=8)==0
  assert run(t).returncode!=0 and run(fresh,who='other').returncode!=0
  later,k=grant();assert run(later).returncode==0
 check('batch-lock-orders-issuance-before-and-after-admission',ordering)
 def concurrent_batches():
  reinstall();other,j=human_grant('other');tokens=[grant()[0]for _ in range(6)]
  with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:rows=list(pool.map(lambda _:front(['revoke','all']),range(2)))
  assert all(r.returncode==0 for r in rows)
  counts=sorted(int(re.search(rb'Revoked (\d+)',r.stdout).group(1))for r in rows);assert counts==[0,6]
  assert all(run(t).returncode!=0 for t in tokens)and run(other,who='other').returncode==0
 check('concurrent-batches-serialized-without-cross-creator-deletion',concurrent_batches)
 def stale():
  t,i=grant();c=req('admin-revoke-created',None,who='root');assert frame(c.stdout)==(b'R',b'');reinstall();fresh,j=grant()
  send(c,b'{"v":1}');assert frame(c.stdout)[0]==b'X'and c.wait(timeout=8)!=0 and run(fresh).returncode==0
 check('maintenance-generation-denies-pending-batch-preserves-new-grant',stale)
 def narrow_admin():
  path=pathlib.Path('/etc/sudoers.d/01-batch-test')
  try:
   path.write_text('other ALL=(root) NOPASSWD: '+HELP+' grant\n');path.chmod(0o440);reinstall()
   r=front(['agent','10'],'other');assert r.returncode==0;t=r.stdout.strip().decode();assert run(t).returncode==0
   assert front(['revoke','all'],'other').returncode!=0 and run(t).returncode==0
   a=pwd.getpwnam('other');env=os.environ.copy();env.update(SUDO_USER=a.pw_name,SUDO_UID=str(a.pw_uid),SUDO_GID=str(a.pw_gid))
   r=subprocess.run([HELP,'admin-revoke-created'],input=b'',capture_output=True,env=env);assert r.returncode!=0 and r.stdout[:1]!=b'R'
  finally:path.unlink(missing_ok=True);reinstall()
 check('grant-only-sudo-policy-does-not-authorize-batch-operation',narrow_admin)
 pathlib.Path('/root/revoke_created-results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
if __name__=='__main__':main()
