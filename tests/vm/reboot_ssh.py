#!/usr/bin/env python3
"""Host-side real SSH/new-session, cross-host, reboot and clean-removal evidence.
All private inputs stay in this process memory and SSH stdin; never argv/files/logs.
"""
from lab import *
import concurrent.futures,hashlib,base64,socket
RESULTS=[]
def mark(n,label):RESULTS.append({'vm':n,'check':label,'pass':True});print(n,'PASS',label,flush=True)
def agentssh(n,command,data):
 return subprocess.run(['ssh','-i',str(LAB/'key'),'-p',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),'-o','LogLevel=ERROR','agent@127.0.0.1',command],input=data,capture_output=True,timeout=20)
def mint(n):
 r=ssh(n,"cd /root; python3 -c 'from guest import grant; t,i=grant();print(t)'",capture_output=True,check=True)
 t=r.stdout.strip();assert t.startswith(b'v1.')and len(t)==100;return t

def reboot(n):
 old=ssh(n,'cat /proc/sys/kernel/random/boot_id',capture_output=True,check=True).stdout
 try:ssh(n,'systemctl reboot',capture_output=True,timeout=10)
 except subprocess.TimeoutExpired:pass
 for _ in range(90):
  try:r=ssh(n,'cat /proc/sys/kernel/random/boot_id; test -d /run/agent-sudo',capture_output=True,timeout=5)
  except subprocess.TimeoutExpired:continue
  if r.returncode==0 and r.stdout!=old:return
  time.sleep(1)
 raise RuntimeError(n+' reboot timeout')
def base(n):
 # Install only a public lab SSH key. Private key remains ignored on host.
 public=(LAB/'key.pub').read_bytes()
 code="import os,pathlib,pwd,sys; a=pwd.getpwnam('agent');p=pathlib.Path(a.pw_dir)/'.ssh';p.mkdir(exist_ok=True);p.chmod(0o700);os.chown(p,a.pw_uid,a.pw_gid);f=p/'authorized_keys';f.write_bytes(sys.stdin.buffer.read());f.chmod(0o600);os.chown(f,a.pw_uid,a.pw_gid)"
 ssh(n,'python3 -c '+__import__('shlex').quote(code),input=public,check=True,capture_output=True)
 t=mint(n);r=agentssh(n,'exec agent-sudo run --key-fd 3 -- /usr/bin/id 3<&0 </dev/null',t+b'\n');assert r.returncode==0 and b'uid=0(root)' in r.stdout
 mark(n,'real-SSH-new-session-secret-via-stdin-no-argv-env-file')
 r=agentssh(n,'exec agent-sudo run --key-fd 3 -- /usr/bin/id 3<&0 </dev/null',b'');assert r.returncode!=0
 mark(n,'new-SSH-session-still-requires-token')
 # Inspect actual argv/environment, journal and histories while another SSH job uses token.
 proc=subprocess.Popen(['ssh','-i',str(LAB/'key'),'-p',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),'-o','LogLevel=ERROR','agent@127.0.0.1','exec agent-sudo run --key-fd 3 -- /bin/sleep 2 3<&0 </dev/null'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 proc.stdin.write(t+b'\n');proc.stdin.flush();time.sleep(.4)
 code="""import pathlib,sys,subprocess
key=sys.stdin.buffer.read().strip()
for p in pathlib.Path('/proc').glob('[0-9]*'):
 for f in ['cmdline','environ']:
  try: assert key not in (p/f).read_bytes()
  except (FileNotFoundError,ProcessLookupError,PermissionError):pass
for p in [pathlib.Path('/root/.bash_history'),pathlib.Path('/home/agent/.bash_history')]:
 if p.exists():assert key not in p.read_bytes()
assert key not in subprocess.check_output(['journalctl','--no-pager','-o','cat'])
"""
 ssh(n,'python3 -c '+__import__('shlex').quote(code),input=t,check=True,capture_output=True);proc.stdin.close();assert proc.wait(timeout=5)==0
 mark(n,'live-process-argv-env-history-journal-secret-scan')
 # Keep preboot record in memory, reinsert after reboot to exercise actual boot mismatch.
 gid=t.decode().split('.')[1];record=ssh(n,'cat /run/agent-sudo/g-'+gid,capture_output=True,check=True).stdout
 reboot(n);r=agentssh(n,'exec agent-sudo run --key-fd 3 -- /usr/bin/id 3<&0 </dev/null',t+b'\n');assert r.returncode!=0
 mark(n,'real-reboot-volatile-grants-lost-timer-independent')
 code="import sys,pathlib; p=pathlib.Path('/run/agent-sudo/g-"+gid+"');p.write_bytes(sys.stdin.buffer.read());p.chmod(0o600)"
 ssh(n,'python3 -c '+__import__('shlex').quote(code),input=record,check=True,capture_output=True)
 r=agentssh(n,'exec agent-sudo run --key-fd 3 -- /usr/bin/id 3<&0 </dev/null',t+b'\n');assert r.returncode!=0
 ssh(n,'rm /run/agent-sudo/g-'+gid,capture_output=True,check=True)
 mark(n,'preboot-record-restored-still-denied-actual-boot-binding')
 return n,mint(n)
def remove(n,t):
 code='''from guest import *
import hashlib
unrelated=pathlib.Path('/etc/sudoers.d/99-preserved-access');unrelated.write_text('other ALL=(root) NOPASSWD: /usr/bin/true\\n');unrelated.chmod(0o440);before=unrelated.read_bytes()
ops=pathlib.Path('/opt/ops');ops.mkdir(exist_ok=True);script=ops/'grant-agent-sudo.sh';script.write_text('# separate mechanism sentinel\\n');saved=script.read_bytes()
reinstall();t,i=grant();c=req('run',None);assert frame(c.stdout)==(b'R',b'')
lock=(CONTROL/'lock').stat().st_ino
r=subprocess.run([HELP,'uninstall'],capture_output=True,timeout=20);assert r.returncode==0
send(c,json.dumps({'v':1,'token':t,'argv':['/usr/bin/id']}).encode());assert frame(c.stdout)[0]==b'X';assert c.wait(timeout=10)!=0
assert all(not pathlib.Path(p).exists() for p in [FRONT,HELP,str(POLICY),'/etc/systemd/system/agent-sudo-cleanup.service','/etc/systemd/system/agent-sudo-cleanup.timer','/etc/tmpfiles.d/agent-sudo.conf','/run/agent-sudo'])
assert (CONTROL/'lock').stat().st_ino==lock and not json.loads((CONTROL/'config').read_bytes())['enabled']
assert unrelated.read_bytes()==before and script.read_bytes()==saved
r=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/true'],capture_output=True,**userargs('other'));assert r.returncode==0
assert subprocess.run(['visudo','-c'],capture_output=True).returncode==0
assert subprocess.run(['systemctl','is-active','--quiet','agent-sudo-cleanup.timer']).returncode!=0
'''
 r=ssh(n,'cd /root; python3 -',input=code.encode(),capture_output=True,timeout=90);assert r.returncode==0,(n,r.stderr[:500])
 for label in ['uninstall-serializes-pending-admission','uninstall-removes-managed-files-state-timer','uninstall-preserves-unrelated-sudo-and-ops-script','uninstall-retains-disabled-stable-lock-tombstone']:mark(n,label)
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:tokens=dict(pool.map(base,PEERS))
 # Existing credential on a different real host is not usable (without any copied state).
 for n in PEERS:
  other=next(x for x in PEERS if x!=n);r=agentssh(other,'exec agent-sudo run --key-fd 3 -- /usr/bin/id 3<&0 </dev/null',tokens[n]+b'\n');assert r.returncode!=0;mark(other,'actual-cross-host-token-denied')
 with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:list(pool.map(lambda n:remove(n,tokens[n]),PEERS))
 (LAB/'reboot-ssh-results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
