#!/usr/bin/env python3
"""Additional actual-binary integration and labeled root-injected faults in VMs."""
from guest import *
import shutil,re

def main():
 t,i=grant()
 def result_fd():
  for args,expected in [(['/bin/sh','-c','printf \'{"kind":"error"}\\000\\377\' >&2; exit 125'],'exit'),(['/no/such/program'],'error')]:
   kr,kw=os.pipe();rr,rw=os.pipe();os.write(kw,(t+'\n').encode());os.close(kw)
   try:
    r=subprocess.run([FRONT,'run','--key-fd',str(kr),'--result-fd',str(rw),'--']+args,input=b'',capture_output=True,pass_fds=(kr,rw),**userargs('agent'),timeout=10)
    os.close(rw);rw=-1;value=json.loads(os.read(rr,65536));assert value['kind']==expected and r.returncode==125
   finally:
    for fd in [kr,rr,rw]:
     if fd>=0:os.close(fd)
 check('separate-result-fd-distinguishes-forged-binary-stderr',result_fd)
 def nonutf():
  r=subprocess.run([os.fsencode(FRONT),b'run',b'--',b'/bin/echo',b'\xff'],input=b'',capture_output=True,**userargs('agent'));assert r.returncode!=0 and b'non-UTF-8' in r.stderr
 check('non-utf8-argv-explicitly-rejected',nonutf)
 def secret_prompt():
  pid,fd=pty.fork()
  if pid==0:
   a=pwd.getpwnam('agent');os.setgroups([]);os.setgid(a.pw_gid);os.setuid(a.pw_uid);null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null);os.execv(FRONT,[FRONT,'run','--','/usr/bin/id'])
  buf=b'';end=time.monotonic()+15;sent=False;status=None
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],.1)[0]:
     try:b=os.read(fd,4096)
     except OSError:break
     buf+=b
     if not sent and b'Access token (hidden):' in buf:time.sleep(6);os.write(fd,t.encode()+b'\n');sent=True
    p,s=os.waitpid(pid,os.WNOHANG)
    if p:status=s;break
   if status is None:_,status=os.waitpid(pid,0)
   assert os.waitstatus_to_exitcode(status)==0 and t.encode()not in buf and b'uid=0(root)' in buf
  finally:os.close(fd)
 check('hidden-token-prompt-echo-off-human-delay-over-5s',secret_prompt)
 def prompt_interrupt():
  pid,fd=pty.fork()
  if pid==0:
   a=pwd.getpwnam('agent');os.setgroups([]);os.setgid(a.pw_gid);os.setuid(a.pw_uid);null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null);os.execv(FRONT,[FRONT,'run','--','/usr/bin/id'])
  import termios
  buf=b'';deadline=time.monotonic()+10
  try:
   while b'Access token (hidden):' not in buf and time.monotonic()<deadline:
    if select.select([fd],[],[],.1)[0]:buf+=os.read(fd,4096)
   assert b'Access token (hidden):'in buf
   assert not termios.tcgetattr(fd)[3]&termios.ECHO
   os.write(fd,b'\x03');_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)!=0;assert termios.tcgetattr(fd)[3]&termios.ECHO
  finally:os.close(fd)
 check('token-prompt-interrupt-restores-echo',prompt_interrupt)
 def high_fd():
  kr,kw=os.pipe();os.write(kw,(t+'\n').encode());os.close(kw);f=os.open('/dev/null',os.O_RDONLY);os.dup2(f,512,inheritable=True);os.close(f)
  try:
   r=subprocess.run([FRONT,'run','--key-fd',str(kr),'--','/usr/bin/python3','-c','import os;print(os.path.exists("/proc/self/fd/512"))'],input=b'',capture_output=True,pass_fds=(kr,512),**userargs('agent'),timeout=10);assert r.returncode==0 and r.stdout.strip()==b'False'
  finally:os.close(kr);os.close(512)
 check('high-numbered-extra-fd-not-inherited',high_fd)
 def malicious_stream():
  for data in [b'\x00'+struct.pack('>I',32769),b'\x03'+struct.pack('>I',0),b'\x02'+struct.pack('>I',1)+b'\x09',b'\x01'+struct.pack('>I',1)+b'x']:
   c=req('run',None);assert frame(c.stdout)==(b'R',b'');send(c,json.dumps({'v':1,'token':t,'argv':['/bin/cat']}).encode());assert frame(c.stdout)==(b'A',b'');c.stdin.write(data);c.stdin.flush();c.stdin.close();out=c.stdout.read();assert c.wait(timeout=5)!=0 and b'"kind":"error"' in out
 check('hostile-stream-frames-denied',malicious_stream)
 def admin_cached_removal():
  # A test-only broad passwordless policy stands in for already-authenticated ordinary sudo access.
  # Fresh actual PAM/cache tests are separate; helper denial must be independent of this policy.
  f=pathlib.Path('/etc/sudoers.d/01-independent-admin');f.write_text('humanadmin ALL=(root) NOPASSWD: ALL\n');f.chmod(0o440);reinstall();key,id=grant('humanadmin');assert run(key,who='humanadmin').returncode==0
  saved=POLICY.read_bytes();POLICY.unlink()
  try:
   # sudo can still launch helper under its independent policy, yet helper must deny.
   c=subprocess.run(['/usr/bin/sudo','-n','--',HELP,'status'],input=b'',capture_output=True,**userargs('humanadmin'));assert c.returncode!=0 and c.stdout[:1]!=b'R';assert run(key,who='humanadmin').returncode!=0
  finally:POLICY.write_bytes(saved);POLICY.chmod(0o440);f.unlink();reinstall()
 check('recipient-rule-removal-with-independent-sudo-access',admin_cached_removal)
 def real_cache_removal():
  # Same PTY/session establishes a real authentication cache, then removes enrollment via root coordinator.
  marker=pathlib.Path('/tmp/agent-sudo-cache-test-ready');go=pathlib.Path('/tmp/agent-sudo-cache-test-go');done=pathlib.Path('/tmp/agent-sudo-cache-test-done')
  for p in [marker,go,done]:p.unlink(missing_ok=True)
  pid,fd=pty.fork()
  if pid==0:
   a=pwd.getpwnam('humanadmin');os.setgroups([27]);os.setgid(a.pw_gid);os.setuid(a.pw_uid)
   code='import subprocess,pathlib,time,sys; subprocess.run(["sudo","-v"],check=True);pathlib.Path("'+str(marker)+'").touch();\nwhile not pathlib.Path("'+str(go)+'").exists():time.sleep(.05)\na=subprocess.run(["sudo","-n","--","'+HELP+'","status"],input=b"",capture_output=True);b=subprocess.run(["sudo","-n","/usr/bin/true"]);sys.exit(0 if a.returncode!=0 and b.returncode==0 else 1)'
   os.execv('/usr/bin/python3',['python3','-c',code])
  saved=POLICY.read_bytes();buf=b'';end=time.monotonic()+15;sent=False;removed=False;status=None
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],.1)[0]:
     try:b=os.read(fd,4096)
     except OSError:break
     buf+=b
     if not sent and (b'password for' in buf or b'Password:'in buf):os.write(fd,b'VmOnly-TestPassword-9274\n');sent=True
    if marker.exists() and not removed:POLICY.unlink();go.touch();removed=True
    p,s=os.waitpid(pid,os.WNOHANG)
    if p:status=s;break
   if status is None:os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
   assert sent and removed and os.waitstatus_to_exitcode(status)==0
  finally:POLICY.write_bytes(saved);POLICY.chmod(0o440);os.close(fd)
 check('real-cached-auth-cannot-bypass-removed-recipient-policy',real_cache_removal)
 def caller_identity():
  # root-injected metadata exercises helper cross-check, not forged policy privileges.
  e=os.environ.copy();e.update(SUDO_USER='agent',SUDO_UID=str(pwd.getpwnam('other').pw_uid),SUDO_GID=str(pwd.getpwnam('agent').pw_gid))
  r=subprocess.run([HELP,'status'],env=e,capture_output=True);assert r.returncode!=0
 check('inconsistent-sudo-identity-root-injected',caller_identity)
 def grant_limits():
  # Root duplicates valid verifier records to avoid spending test time on 128 random creations.
  key,id=grant();original=json.loads((STATE/('g-'+id)).read_bytes());made=[]
  try:
   for k in range(128-len(list(STATE.glob('g-*')))):
    gid=f'{k:032x}';path=STATE/('g-'+gid)
    if path.exists():continue
    value=dict(original,id=gid);path.write_text(json.dumps(value));path.chmod(0o600);made.append(path)
   r=front(['grant','--user','agent','--minutes','60']);assert r.returncode!=0;assert front(['status'],'agent').returncode==0
  finally:
   for p in made:p.unlink()
 check('128-grant-cap-and-bounded-list-root-fixtures',grant_limits)
 def denial_rate():
  d=STATE/'denials';d.unlink(missing_ok=True)
  for _ in range(16):rejected('run',b'{"v":1}')
  words=d.read_text().split();assert int(words[1])<=10
 check('denial-logging-global-rate-cap',denial_rate)
 def concurrent_maintenance():
  key,id=grant();c=req('run',None);assert frame(c.stdout)==(b'R',b'');reinstall(['agent','humanadmin']);send(c,json.dumps({'v':1,'token':key,'argv':['/usr/bin/id']}).encode());assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=5)!=0;assert run(key).returncode!=0;assert front(['status'],'other').returncode!=0;reinstall()
 check('upgrade-generation-invalidates-pending-admission',concurrent_maintenance)
 def rollback_policy():
  before=POLICY.read_bytes();f=pathlib.Path('/etc/sudoers.d/99-record-tag');f.write_text('root ALL=(root) LOG_OUTPUT: /usr/local/libexec/agent-sudo-helper probe\n');f.chmod(0o440)
  try:reinstall(success=False)
  finally:f.unlink()
  assert POLICY.read_bytes()==before
 check('unsupported-logging-tag-fails-install-unchanged',rollback_policy)
 def write_failure():
  before=set(STATE.glob('g-*'))
  with open('/dev/full','wb')as full:r=subprocess.run([FRONT,'grant','--user','agent','--minutes','60'],stdout=full,stderr=subprocess.PIPE,timeout=10)
  assert r.returncode!=0
  for _ in range(100):
   if set(STATE.glob('g-*'))==before:break
   time.sleep(.05)
  assert set(STATE.glob('g-*'))==before
 check('frontend-token-output-write-failure-revokes',write_failure)
 def immediate_exit():
  key,id=grant();r=run(key,['/usr/bin/true'],data=b'x'*8_000_000);assert r.returncode==0
 check('child-early-exit-while-large-input-pending',immediate_exit)
 def stdout_disconnect():
  key,id=grant();rd,wr=os.pipe();os.write(wr,(key+'\n').encode());os.close(wr)
  try:
   c=subprocess.Popen([FRONT,'run','--key-fd',str(rd),'--','/usr/bin/yes'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(rd,),**userargs('agent'));c.stdout.read(1024);c.stdout.close();assert c.wait(timeout=5)!=0
  finally:os.close(rd)
 check('output-disconnect-no-success',stdout_disconnect)
 def context_env():
  key,id=grant();kr,kw=os.pipe();os.write(kw,(key+'\n').encode());os.close(kw);u=userargs('agent');u['env'].update(PYTHONPATH='/tmp/evil',BASH_ENV='/tmp/evil',SSYNC_PASSWORD='not-a-token',AGENT_SUDO_TOKEN='not-supported')
  try:
   r=subprocess.run([FRONT,'run','--key-fd',str(kr),'--','/usr/bin/env'],input=b'',capture_output=True,pass_fds=(kr,),**u);assert r.returncode==0 and all(s.encode()not in r.stdout for s in ['PYTHONPATH','BASH_ENV','SSYNC_PASSWORD','AGENT_SUDO_TOKEN','SUDO_'])
  finally:os.close(kr)
 check('hostile-caller-environment-not-in-root-command',context_env)
 def global_limit():
  names=['aslot'+str(k)for k in range(9)]
  cs=[]
  try:
   for u in names:subprocess.run(['useradd','-m',u],check=True,capture_output=True)
   reinstall()
   for u in names:grant(u)
   for u in names[:8]:
    for _ in range(4):
     c=req('run',None,who=u);assert frame(c.stdout)==(b'R',b'');cs.append(c)
   c=req('run',None,who=names[8]);assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=3)!=0
  finally:
   for c in cs:c.stdin.close();c.wait(timeout=8)
   reinstall()
   for u in names:subprocess.run(['userdel','-r',u],capture_output=True)
 check('32-global-pending-helper-cap-nine-accounts',global_limit)
 def stale_executable():
  stale=pathlib.Path('/root/stale-helper');shutil.copyfile(HELP,stale);stale.chmod(0o755)
  r=subprocess.run([str(stale),'grant'],capture_output=True,input=b'');assert r.returncode!=0 and r.stdout[:1]!=b'R';stale.unlink()
 check('copied-or-stale-helper-cannot-issue',stale_executable)
 def slow_reader():
  key,id=grant();marker=pathlib.Path('/tmp/agent-sudo-output-complete');marker.unlink(missing_ok=True)
  c=req('run',None);assert frame(c.stdout)==(b'R',b'')
  code='import sys,pathlib;sys.stdout.buffer.write(b"z"*160000);sys.stdout.buffer.flush();pathlib.Path("'+str(marker)+'").touch()'
  send(c,json.dumps({'v':1,'token':key,'argv':['/usr/bin/python3','-c',code]}).encode());assert frame(c.stdout)==(b'A',b'');c.stdin.write(b'\x01\0\0\0\0');c.stdin.flush()
  time.sleep(3);data=b''
  while True:
   k,b=frame(c.stdout)
   if k==b'O':data+=b
   if k==b'X':assert json.loads(b)['kind']=='exit';break
  assert c.wait(timeout=5)==0 and data==b'z'*160000
 check('slow-consumer-after-child-exit-no-buffered-output-loss',slow_reader)
 def scoped_logging():
  before=POLICY.read_bytes();f=pathlib.Path('/etc/sudoers.d/zz-recording-override');f.write_text('Defaults!'+HELP+' log_input, log_output\n');f.chmod(0o440)
  try:reinstall(success=False)
  finally:f.unlink()
  assert POLICY.read_bytes()==before
 check('later-scoped-recording-override-fails-closed',scoped_logging)
 def input_error():
  key,id=grant();kr,kw=os.pipe();os.write(kw,(key+'\n').encode());os.close(kw);bad=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
  try:
   c=subprocess.run([FRONT,'run','--key-fd',str(kr),'--json-result','--','/bin/cat'],stdin=bad,capture_output=True,pass_fds=(kr,),**userargs('agent'),timeout=8);assert c.returncode==125 and b'command input read failed' in c.stderr
  finally:os.close(kr);os.close(bad)
 check('frontend-stdin-read-error-no-hang-no-success',input_error)
 def blocked_status():
  key,id=grant();original=json.loads((STATE/('g-'+id)).read_bytes());made=[];c=None;reader=None;writer=None
  try:
   for k in range(110):
    gid=f'{k+10000:032x}';path=STATE/('g-'+gid);path.write_text(json.dumps(dict(original,id=gid)));path.chmod(0o600);made.append(path)
   reader,writer=os.pipe();fcntl.fcntl(writer,fcntl.F_SETPIPE_SZ,4096)
   c=subprocess.Popen(['/usr/bin/sudo','-n','--',HELP,'status'],stdin=subprocess.PIPE,stdout=writer,stderr=subprocess.PIPE,**userargs('agent'));os.close(writer);writer=None
   assert readn(os.fdopen(os.dup(reader),'rb',buffering=0),5)==b'R\0\0\0\0';send(c,b'{"v":1}');time.sleep(.2)
   start=time.monotonic();r=front(['revoke',id],'agent');assert r.returncode==0 and time.monotonic()-start<2
   assert c.wait(timeout=7)!=0
  finally:
   if c is not None and c.poll()is None:c.kill();c.wait()
   for fd in [reader,writer]:
    if fd is not None:os.close(fd)
   for p in made:p.unlink(missing_ok=True)
 check('blocked-status-output-does-not-hold-maintenance-lock-times-out',blocked_status)
 def same_tty_fresh_auth():
  pid,fd=pty.fork()
  if pid==0:
   a=pwd.getpwnam('humanadmin');os.setgroups([27]);os.setgid(a.pw_gid);os.setuid(a.pw_uid)
   code='import subprocess;\nfor _ in range(2):\n r=subprocess.run(["'+FRONT+'","grant","--user","agent","--minutes","60"],stdout=subprocess.PIPE);assert r.returncode==0;print("issued",flush=True)'
   os.execv('/usr/bin/python3',['python3','-c',code])
  buf=b'';sent=0;status=None;end=time.monotonic()+20
  try:
   while time.monotonic()<end:
    if select.select([fd],[],[],.1)[0]:
     try:buf+=os.read(fd,4096)
     except OSError:break
     prompts=len(re.findall(br'(?:password for[^:]*:|Password:)',buf,re.I))
     if prompts>sent:os.write(fd,b'VmOnly-TestPassword-9274\n');sent+=1
    p,s=os.waitpid(pid,os.WNOHANG)
    if p:status=s;break
   if status is None:
    p,s=os.waitpid(pid,os.WNOHANG)
    if p:status=s
    else:os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
   assert os.waitstatus_to_exitcode(status)==0 and sent==2 and buf.count(b'issued')==2 and b'VmOnly-TestPassword-9274' not in buf
  finally:os.close(fd)
 check('two-grants-same-tty-each-request-fresh-PAM-auth',same_tty_fresh_auth)
 pathlib.Path('/root/extended-results.json').write_text(json.dumps(RESULTS,indent=2)+'\n');print('TOTAL',len(RESULTS),flush=True)
if __name__=='__main__':main()
