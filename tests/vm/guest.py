#!/usr/bin/env python3
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

"""Run ONLY as root inside disposable VMs. Test secrets stay in memory."""
import base64,re,os,sys,json,subprocess,struct,time,pathlib,signal,threading,pty,select,pwd,hashlib,fcntl,concurrent.futures
FRONT='/usr/local/bin/agent-sudo';HELP='/usr/local/libexec/agent-sudo-helper';STATE=pathlib.Path('/run/agent-sudo');CONTROL=pathlib.Path('/var/lib/agent-sudo');POLICY=pathlib.Path('/etc/sudoers.d/agent-sudo')
RESULTS=[]
def check(name,fn):
 start=time.monotonic()
 try:fn()
 except Exception as e:
  print('FAIL',name,type(e).__name__,str(e)[:500],flush=True);raise
 RESULTS.append({'check':name,'pass':True,'seconds':round(time.monotonic()-start,3)});print('PASS',name,flush=True)
def userargs(name):
 a=pwd.getpwnam(name)
 return dict(user=a.pw_uid,group=a.pw_gid,extra_groups=[],env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':a.pw_dir,'USER':name,'LANG':'C.UTF-8'})
def front(args,who='root',data=b'',**kw):return subprocess.run([FRONT]+args,input=data,capture_output=True,timeout=20,**userargs(who),**kw)
def token_id(t):
 if re.fullmatch(r'v2\.[A-Za-z0-9_-]{64}',t):return base64.urlsafe_b64decode(t[3:])[:16].hex()
 assert re.fullmatch(r'v1\.[a-f0-9]{32}\.[a-f0-9]{64}',t)
 return t.split('.')[1]
def grant(who='agent',minutes=60):
 r=front(['grant','--user',who,'--minutes',str(minutes)])
 assert r.returncode==0,('grant failed',r.returncode,r.stderr[:200])
 t=r.stdout.strip().decode()
 return t,token_id(t)
def run(t,args=['/usr/bin/id'],who='agent',data=b'',**kw):
 rd,wr=os.pipe();os.write(wr,(t+'\n').encode());os.close(wr)
 try:
  return subprocess.run([FRONT,'run','--key-fd',str(rd),'--json-result','--']+args,input=data,capture_output=True,timeout=20,pass_fds=(rd,),**userargs(who),**kw)
 finally:os.close(rd)
def req(op,request,who='agent'):
 c=subprocess.Popen(['/usr/bin/sudo','-n','--',HELP,op],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**userargs(who));return c

def readn(r,n):
 b=b''
 while len(b)<n:
  x=r.read(n-len(b));assert x,'truncated helper response';b+=x
 return b
def frame(r):
 h=readn(r,5);n=struct.unpack('>I',h[1:])[0];assert n<=65536;return h[0:1],readn(r,n)
def send(c,b):c.stdin.write(struct.pack('>I',len(b))+b);c.stdin.flush()
def wire(op,obj,who='agent',raw=None,ack=True):
 c=req(op,obj,who)
 f=frame(c.stdout);assert f==(b'R',b''),'no readiness'
 send(c,raw if raw is not None else json.dumps(obj,separators=(',',':')).encode())
 out=[]
 while True:
  k,b=frame(c.stdout);out.append((k,b))
  if k==b'J' and op=='grant' and ack:c.stdin.write(b'\x06');c.stdin.flush()
  if k==b'X':break
 c.stdin.close();c.wait(timeout=10);return out,c.returncode

def rejected(op,raw):
 o,c=wire(op,None,raw=raw);assert c!=0 and o[-1][0]==b'X' and json.loads(o[-1][1])['kind']=='error'
def reinstall(users=['agent','other','humanadmin'],success=True):
 c=subprocess.run(['/root/payload/agent-sudo-helper','install','--from','/root/payload'],capture_output=True,timeout=30)
 assert (c.returncode==0)==success,('install failed',c.stderr[:200]);return c

def pty_call(args,inputs,who='humanadmin',env_updates=None):
 pid,fd=pty.fork()
 if pid==0:
  a=pwd.getpwnam(who);os.setgroups([27] if who=='humanadmin' else []);os.setgid(a.pw_gid);os.setuid(a.pw_uid);os.environ['USER']=who;os.environ['HOME']=a.pw_dir;os.environ.update(env_updates or {});os.execv(FRONT,[FRONT]+args)
 buf=b'';index=0;end=time.monotonic()+20
 while time.monotonic()<end:
  if select.select([fd],[],[],.1)[0]:
   try:b=os.read(fd,4096)
   except OSError:break
   if not b:break
   buf+=b
   while index<len(inputs) and (inputs[index][0] in buf or (inputs[index][0]==b'password for' and b'Password:' in buf)):
    os.write(fd,inputs[index][1]+b'\n');index+=1
  result=os.waitpid(pid,os.WNOHANG)
  if result[0]:os.close(fd);return os.waitstatus_to_exitcode(result[1]),buf,index
 os.kill(pid,signal.SIGKILL)
 try:_,status=os.waitpid(pid,0)
 finally:os.close(fd)
 return os.waitstatus_to_exitcode(status),buf,index

def main():
 global TOKEN,ID
 check('public-help-version-no-elevation',lambda: (assertok(front(['--help'],'agent').returncode==0),assertok(front(['--version'],'other').stdout.startswith(b'agent-sudo'))))
 TOKEN,ID=grant()
 check('root-id-gid',lambda:assertok(run(TOKEN).returncode==0 and b'uid=0(root) gid=0(root)' in run(TOKEN).stdout))
 check('exact-argv-no-shell',lambda:assertok(json.loads(run(TOKEN,['/usr/bin/python3','-c','import sys,json;print(json.dumps(sys.argv[1:]))','a b','$(touch /tmp/SHOULD-NOT-EXIST)',';*']).stdout)==['a b','$(touch /tmp/SHOULD-NOT-EXIST)',';*'] and not pathlib.Path('/tmp/SHOULD-NOT-EXIST').exists()))
 def binary():
  data=bytes(range(256))*16384;r=run(TOKEN,['/usr/bin/python3','-c','import sys; b=sys.stdin.buffer.read();sys.stdout.buffer.write(b);sys.stderr.buffer.write(b)'],data=data);assert r.returncode==0 and r.stdout==data and r.stderr.startswith(data) and b'"kind":"exit"' in r.stderr[-100:]
 check('binary-4MiB-stdin-stdout-stderr-backpressure',binary)
 for code in [0,1,125,126,127,255]:
  def ex(code=code):
   r=run(TOKEN,['/bin/sh','-c',f'exit {code}']);assert r.returncode==code and json.loads(r.stderr)['kind']=='exit'
  check('child-exit-'+str(code),ex)
 check('child-signal-distinct',lambda:assertok(run(TOKEN,['/bin/sh','-c','kill -TERM $$']).returncode==143))
 check('missing-executable-tool-error',lambda:assertok(run(TOKEN,['/no/such/executable']).returncode==125 and b'"kind":"error"' in run(TOKEN,['/no/such/executable']).stderr))
 def context():
  code='import os,json,resource; print(json.dumps({"uids":os.getresuid(),"gids":os.getresgid(),"groups":os.getgroups(),"cwd":os.getcwd(),"mask":os.umask(0),"env":dict(os.environ),"core":resource.getrlimit(resource.RLIMIT_CORE),"fds":[i for i in range(3,128) if os.path.exists("/proc/self/fd/"+str(i))]}))'
  r=run(TOKEN,['/usr/bin/python3','-c',code]);assert r.returncode==0;x=json.loads(r.stdout);assert x['uids']==[0,0,0] and x['gids']==[0,0,0] and x['groups']==[] and x['cwd']=='/root' and x['mask']==63 and x['core']==[0,0] and x['fds']==[] and set(x['env'])==set(['HOME','USER','LOGNAME','SHELL','PATH','LANG'])
 check('root-context-env-groups-umask-core-fd-hygiene',context)
 for name,t in [('malformed','x'),('modified',TOKEN[:-1]+('a' if TOKEN[-1]!='a' else 'b')),('random','v1.'+'c'*32+'.'+'d'*64)]:check(name+'-token-denied',lambda t=t:assertok(run(t).returncode!=0))
 def compatibility():
  t,i=grant();assert t.startswith('v2.') and len(t)==67
  raw=base64.urlsafe_b64decode(t[3:]);assert len(raw)==48 and raw[:16].hex()==i
  old='v1.'+i+'.'+raw[16:].hex()
  assert run(old).returncode==0 and run(t).returncode==0
  assert run(old,who='other').returncode!=0
  for malformed in [t+'=',t[:-1],t.replace('v2.','v3.'),t[:3]+'+'+t[4:],t[:3]+'/'+t[4:]]:
   assert run(malformed).returncode!=0
  assert front(['revoke',i],'agent').returncode==0
  assert run(t).returncode!=0 and run(old).returncode!=0
 check('v2-length-legacy-equivalence-malformed-and-shared-revocation',compatibility)
 check('wrong-uid-denied',lambda:assertok(run(TOKEN,who='other').returncode!=0))
 check('own-status-no-verifier-token',lambda:assertok(ID.encode() in front(['status'],'agent').stdout and TOKEN.encode() not in front(['status'],'agent').stdout and b'verifier' not in front(['status'],'agent').stdout))
 check('direct-nonroot-helper-denied',lambda:assertok(subprocess.run([HELP,'run'],capture_output=True,**userargs('agent')).returncode!=0))
 check('unauthorized-grant-admin-maintenance-denied',lambda:assertok(all(subprocess.run(['/usr/bin/sudo','-n','--',HELP,op],capture_output=True,**userargs('agent')).returncode!=0 for op in ['grant','admin-list','admin-revoke','admin-revoke-created','install','uninstall','probe','cleanup'])))
 for op in ['run extra','status extra','revoke-all extra']:
  check('exact-operation-'+op,lambda op=op:assertok(subprocess.run(['/usr/bin/sudo','-n','--',HELP]+op.split(),capture_output=True,**userargs('agent')).returncode!=0))
 for name,raw in [('duplicate',b'{"v":1,"v":1}'),('unknown',b'{"v":1,"operation":"grant"}'),('wrong-type',b'{"v":"1"}'),('deep',b'['*200+b']'*200),('nul-argv',b'{"v":1,"token":"x","argv":["/bin/echo","\\u0000"]}'),('path-traversal',b'{"v":1,"id":"../../etc/shadow"}'),('bad-schema',b'{"v":2}'),('fields-for-other-op',b'{"v":1,"user":"agent","minutes":60}')]:check('hostile-header-'+name,lambda raw=raw:rejected('run',raw))
 def size():
  for n in [0,65537,0xffffffff]:
   c=req('run',None);assert frame(c.stdout)==(b'R',b'');c.stdin.write(struct.pack('>I',n));c.stdin.flush();assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=10)!=0
 check('oversized-zero-length-header',size)
 def deadline():
  c=req('run',None);assert frame(c.stdout)==(b'R',b'');start=time.monotonic();assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=8)!=0 and time.monotonic()-start<7
 check('pending-input-5second-deadline',deadline)
 def pending():
  cs=[]
  try:
   for _ in range(4):
    c=req('run',None);assert frame(c.stdout)==(b'R',b'');cs.append(c)
   c=req('run',None);assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=2)!=0
  finally:
   for c in cs:c.stdin.close();c.wait(timeout=8)
 check('per-uid-pending-limit',pending)
 def mutate(change):
  path=STATE/('g-'+ID);original=path.read_bytes();change(path)
  try:assert run(TOKEN).returncode!=0
  finally:
   if path.exists() or path.is_symlink():path.unlink()
   path.write_bytes(original);path.chmod(0o600)
 for name,change in [
  ('mode',lambda p:p.chmod(0o644)),('owner',lambda p:os.chown(p,pwd.getpwnam('agent').pw_uid,0)),
  ('truncated',lambda p:p.write_bytes(b'{')),
  ('symlink',lambda p:(p.unlink(),p.symlink_to('/etc/shadow'))),
  ('hardlink',lambda p:os.link(p,STATE/'evil-link')),
  ('acl',lambda p:subprocess.run(['setfacl','-m','u:agent:r',str(p)],check=True)),
  ('wrong-boot',lambda p:editjson(p,boot='0'*36)),('wrong-host',lambda p:editjson(p,host='0'*32)),
  ('uid-name-mismatch',lambda p:editjson(p,uid=pwd.getpwnam('other').pw_uid)),
  ('exact-deadline-injected',lambda p:editjson(p,deadline=int(time.clock_gettime(time.CLOCK_BOOTTIME)*1e9))),
  ('old-generation',lambda p:editjson(p,generation='0'*32))]:
  check('state-'+name,lambda change=change:mutate(change))
  (STATE/'evil-link').unlink(missing_ok=True)
 def state_directory():
  STATE.chmod(0o777)
  try:assert run(TOKEN).returncode!=0
  finally:STATE.chmod(0o700)
  STATE.rename('/run/agent-sudo-saved');STATE.symlink_to('/run/agent-sudo-saved')
  try:assert run(TOKEN).returncode!=0
  finally:STATE.unlink();pathlib.Path('/run/agent-sudo-saved').rename(STATE)
 check('state-directory-mode-and-symlink-substitution',state_directory)
 def enrollment():
  path=CONTROL/'config';b=path.read_bytes();x=json.loads(b);x['enabled']=False;path.write_text(json.dumps(x))
  try:assert run(TOKEN).returncode!=0
  finally:path.write_bytes(b)
 check('independent-root-disabled-state-gate',enrollment)
 def policy_gate():
  f=pathlib.Path('/etc/sudoers.d/99-irrelevant-test');f.write_text('# changed policy\n');f.chmod(0o440)
  try:assert run(TOKEN).returncode!=0
  finally:f.unlink()
 check('policy-change-denies-before-token-read',policy_gate)
 def revoke():
  t,i=grant();assert front(['revoke',i],'other').returncode!=0;assert run(t).returncode==0
  assert front(['revoke',i],'agent').returncode==0;assert run(t).returncode!=0;assert front(['revoke',i],'agent').returncode==0
 check('own-other-idempotent-revocation',revoke)
 def admin_revoke():
  t,i=grant();assert front(['admin','list']).returncode==0;assert front(['admin','revoke',i]).returncode==0;assert run(t).returncode!=0
 check('admin-list-and-revoke',admin_revoke)
 def receipt():
  before=set(STATE.glob('g-*'));c=req('grant',None,who='root');assert frame(c.stdout)==(b'R',b'');send(c,b'{"v":1,"user":"agent","minutes":60}');assert frame(c.stdout)[0]==b'J';c.stdin.close();c.stdout.read();assert c.wait(timeout=8)!=0;assert set(STATE.glob('g-*'))==before
 check('failed-grant-delivery-revokes',receipt)
 for m in [0,1441,-1]:check('duration-invalid-'+str(m),lambda m=m:assertok(front(['grant','--user','agent','--minutes',str(m)]).returncode!=0))
 check('unknown-and-root-recipient',lambda:assertok(front(['grant','--user','root','--minutes','60']).returncode!=0 and front(['grant','--user','no-such-user','--minutes','60']).returncode!=0))
 def fresh_auth():
  code,output,used=pty_call(['grant','--user','agent','--minutes','60'],[(b'password for',b'VmOnly-TestPassword-9274')]);assert code==0 and used==1 and b'VmOnly-TestPassword-9274' not in output,('pty auth failure',code,used)
  # -k must force a second challenge even after a successful grant.
  code,output,used=pty_call(['grant','--user','agent','--minutes','60'],[(b'password for',b'VmOnly-TestPassword-9274')]);assert code==0 and used==1
 check('real-pam-sudo-fresh-auth-no-app-password',fresh_auth)
 def noarg():
  code,output,used=pty_call([],[(b'Username [',b'agent'),(b'Minutes [',b'1'),(b'password for',b'VmOnly-TestPassword-9274')]);assert code==0 and used==3
 check('no-argument-interactive-grant-prompts',noarg)
 def noarg_invalid():
  code,output,used=pty_call([],[(b'Username [',b'agent'),(b'Minutes [',b'1441')]);assert code!=0 and b'password for' not in output
 check('interactive-invalid-duration-before-auth',noarg_invalid)
 def interrupted():
  rd,wr=os.pipe();os.write(wr,(TOKEN+'\n').encode());os.close(wr)
  try:
   c=subprocess.Popen([FRONT,'run','--key-fd',str(rd),'--json-result','--','/bin/sleep','30'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(rd,),**userargs('agent'));time.sleep(.5);c.send_signal(signal.SIGINT);out,err=c.communicate(timeout=5);assert c.returncode==130,(c.returncode,err[:200])
  finally:os.close(rd)
 check('interrupt-frontend-forwards-to-command',interrupted)
 def race():
  t,i=grant();start=threading.Event()
  def use():start.wait();return run(t).returncode
  with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
   jobs=[pool.submit(use) for _ in range(8)];start.set()
   # Admission cap can reject any contender before it reaches the lock. Retry
   # revocation until admitted, then assert every subsequent use is denied.
   for attempt in range(20):
    if front(['revoke',i],'agent').returncode==0:break
    time.sleep(.05)
   else:raise AssertionError('revocation did not obtain a bounded pending slot')
   results=[f.result()for f in jobs];assert all(c in [0,125]for c in results)
  assert all(run(t).returncode!=0 for _ in range(3))
 check('concurrent-admission-revoke-ordering',race)
 def upgrade():
  c=req('grant',None,who='root');assert frame(c.stdout)==(b'R',b'');reinstall();before=len(list(STATE.glob('g-*')));send(c,b'{"v":1,"user":"agent","minutes":60}');assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=10)!=0;assert len(list(STATE.glob('g-*')))==before;assert run(TOKEN).returncode!=0
 check('upgrade-invalidates-and-stale-pending-grant-denied',upgrade)
 TOKEN,ID=grant()
 def rollback():
  before={p:p.read_bytes() for p in [pathlib.Path(FRONT),pathlib.Path(HELP),POLICY]}
  # policy snapshot changes are deliberate admin revalidation; injected unsupported transport must rollback.
  # Force systemd enable failure after replacement, without application test hooks.
  subprocess.run(['systemctl','disable','--now','agent-sudo-cleanup.timer'],capture_output=True,check=True)
  blocker=pathlib.Path('/etc/systemd/system/timers.target.wants/agent-sudo-cleanup.timer');blocker.mkdir()
  try:reinstall(success=False)
  finally:blocker.rmdir();subprocess.run(['systemctl','enable','--now','agent-sudo-cleanup.timer'],capture_output=True,check=True)
  assert all(p.read_bytes()==b for p,b in before.items());assert run(TOKEN).returncode!=0
  reinstall()
 check('mid-install-rollback-preserves-managed-files-invalidates-grants',rollback)
 TOKEN,ID=grant()
 def logging():
  version=subprocess.check_output(['/usr/bin/sudo','--version']).splitlines()[0]
  if version.startswith(b'Sudo'):
   import shutil;shutil.rmtree('/var/log/agent-sudo-test-io',ignore_errors=True)
   f=pathlib.Path('/etc/sudoers.d/00-recording');f.write_text('Defaults log_input, log_output, iolog_dir="/var/log/agent-sudo-test-io"\n');f.chmod(0o440);reinstall();t,i=grant();assert run(t).returncode==0
   files=list(pathlib.Path('/var/log/agent-sudo-test-io').rglob('*')) if pathlib.Path('/var/log/agent-sudo-test-io').exists() else [];assert not [p for p in files if p.is_file()]
   subprocess.run(['/usr/bin/sudo','/usr/bin/printf','unrelated-audit-canary'],capture_output=True,check=True)
   assert [p for p in pathlib.Path('/var/log/agent-sudo-test-io').rglob('*')if p.is_file()]
   f.unlink();reinstall()
  else:
   f=pathlib.Path('/etc/sudoers.d/00-recording');f.write_text('Defaults log_input\n');f.chmod(0o440)
   try:reinstall(success=False)
   finally:f.unlink()
  # App/journal logs must have no issued raw token or verifier.
  t,i=grant();assert run(t).returncode==0;v=json.loads((STATE/('g-'+i)).read_bytes())['verifier'];logs=subprocess.check_output(['journalctl','--no-pager','-o','cat']);assert t.encode() not in logs and v.encode()not in logs
 check('real-logging-policy-secrecy-and-unrelated-auditing',logging)
 TOKEN,ID=grant()
 check('secrets-never-in-state-files',lambda:assertok(all(TOKEN.encode()not in p.read_bytes() for p in STATE.iterdir() if p.is_file())))
 (pathlib.Path('/root/results.json')).write_text(json.dumps({'results':RESULTS,'versions':subprocess.check_output(['sh','-c','cat /etc/os-release; uname -r; sudo --version | head -1; visudo --version']).decode(),'helper_sha256':hashlib.file_digest(open(HELP,'rb'),'sha256').hexdigest(),'frontend_sha256':hashlib.file_digest(open(FRONT,'rb'),'sha256').hexdigest()},indent=2)+'\n')
 print('TOTAL',len(RESULTS),flush=True)
def assertok(b):assert b,'condition failed'
def editjson(p,**kw):x=json.loads(p.read_bytes());x.update(kw);p.write_text(json.dumps(x))
if __name__=='__main__':main()
