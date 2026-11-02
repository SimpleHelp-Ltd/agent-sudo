#!/usr/bin/env python3
"""Actual public installation; run only in existing disposable QEMU lab.
Faults use local PATH shims inside guests; real successful downloads use HTTPS.
"""
import concurrent.futures, hashlib, json, pathlib, subprocess, sys
from lab import ROOT, LAB, PEERS, ssh
GUEST = r'''
import os,sys,pathlib,subprocess,json,time,pty,select,pwd,signal,hashlib
sys.path.insert(0,'/root')
from guest import front,grant,run
BASE='https://tools.simplehelp.io/agent-sudo/'
SCRIPT=pathlib.Path('/home/humanadmin/public-install.sh')
RESULT=[]
def check(name,fn):
 fn();RESULT.append(name);print('PASS',name,flush=True)
def ok(v):assert v

def snapshot():
 paths=['/usr/local/bin/agent-sudo','/usr/local/libexec/agent-sudo-helper','/etc/sudoers.d/agent-sudo','/var/lib/agent-sudo/config','/var/lib/agent-sudo/manifest','/etc/systemd/system/agent-sudo-cleanup.service','/etc/systemd/system/agent-sudo-cleanup.timer','/etc/tmpfiles.d/agent-sudo.conf']
 return {p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() if pathlib.Path(p).exists() else None for p in paths}

def terminal(command,answers):
 pid,fd=pty.fork()
 if pid==0:
  a=pwd.getpwnam('humanadmin');os.setgroups([27]);os.setgid(a.pw_gid);os.setuid(a.pw_uid);os.chdir(a.pw_dir)
  os.execve('/bin/sh',['sh','-c',command],{'HOME':a.pw_dir,'USER':'humanadmin','PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8'})
 buf=b'';idx=0;deadline=time.monotonic()+180;status=None
 try:
  while time.monotonic()<deadline:
   if select.select([fd],[],[],.1)[0]:
    try:b=os.read(fd,16384)
    except OSError:b=b''
    buf+=b
    if idx<len(answers):
     marker,value=answers[idx]
     if marker in buf or (marker==b'password for' and b'Password:'in buf):
      os.write(fd,value+b'\n');idx+=1;buf=b''
   p,s=os.waitpid(pid,os.WNOHANG)
   if p:status=s;break
  if status is None:os.kill(pid,signal.SIGKILL);_,status=os.waitpid(pid,0)
  assert os.waitstatus_to_exitcode(status)==0 and idx==len(answers),('terminal install failed',idx,buf[-800:].decode(errors='replace'))
 finally:os.close(fd)

def fetch():
 subprocess.run(['curl','--fail','--silent','--show-error',BASE+'install.sh','-o',str(SCRIPT)],check=True,timeout=60)
 assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest()==EXPECTED_BOOTSTRAP
 os.chown(SCRIPT,pwd.getpwnam('humanadmin').pw_uid,pwd.getpwnam('humanadmin').pw_gid);SCRIPT.chmod(0o600)
check('actual-public-bootstrap-hash',fetch)
check('exact-page-command-interactive-recipient-and-normal-sudo',lambda:terminal(COMMAND,[(b'Existing account',b'other'),(b'password for',b'VmOnly-TestPassword-9274')]))
check('explicit-recipient-differs-from-admin',lambda:ok([a['name'] for a in json.loads(pathlib.Path('/var/lib/agent-sudo/config').read_bytes())['accounts']]==['other']))

def cycle(who):
 t,i=grant(who);r=run(t,who=who);assert r.returncode==0 and b'uid=0(root)'in r.stdout
 assert i.encode()in front(['status'],who).stdout
 assert front(['revoke',i],who).returncode==0 and run(t,who=who).returncode!=0
check('public-installed-grant-run-status-revoke',lambda:cycle('other'))
check('explicit-complete-multi-recipient-reinstall-with-sudo',lambda:terminal('sh /home/humanadmin/public-install.sh --user agent --user other',[(b'password for',b'VmOnly-TestPassword-9274')]))
check('multi-recipient-enrollment',lambda:ok([a['name'] for a in json.loads(pathlib.Path('/var/lib/agent-sudo/config').read_bytes())['accounts']]==['agent','other']))
check('reinstalled-grant-run-revoke',lambda:cycle('agent'))
check('exact-tested-binary-hashes',lambda:ok(hashlib.sha256(pathlib.Path('/usr/local/bin/agent-sudo').read_bytes()).hexdigest()=='1a500c0c708d6ce889eaadcfb3939af1756236c7b5acd4eecf90e33af6848687' and hashlib.sha256(pathlib.Path('/usr/local/libexec/agent-sudo-helper').read_bytes()).hexdigest()=='114f30b27a96186378797ad1c9981b35d800d2e5633f3f7e16b27a2681fa8a52'))

def fault(kind):
 before=snapshot(); folder=pathlib.Path('/home/humanadmin/fault-bin');folder.mkdir(exist_ok=True)
 for p in folder.iterdir():p.unlink()
 (folder/'sudo').write_text('#!/bin/sh\ntouch /home/humanadmin/UNEXPECTED-SUDO\nexit 99\n');(folder/'sudo').chmod(0o755)
 if kind in ['download','bootstrap-download']: content='#!/bin/sh\nexit 22\n';name='curl'
 elif kind=='checksum': content='#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; printf corrupt > "$1"; exit; fi; shift; done\nexit 2\n';name='curl'
 else:content='#!/bin/sh\ncase "$1" in -s) echo Linux;; *) echo aarch64;; esac\n';name='uname'
 (folder/name).write_text(content);(folder/name).chmod(0o755)
 a=pwd.getpwnam('humanadmin');args=['/bin/sh','-c',COMMAND] if kind=='bootstrap-download' else ['sh',str(SCRIPT),'--user','agent'];r=subprocess.run(args,capture_output=True,user=a.pw_uid,group=a.pw_gid,extra_groups=[27],env={'PATH':str(folder)+':/usr/bin:/bin'},timeout=30)
 assert r.returncode!=0 and snapshot()==before and not pathlib.Path('/home/humanadmin/UNEXPECTED-SUDO').exists()
 assert kind=='bootstrap-download' or (b'Download failed' if kind=='download' else b'Checksum mismatch' if kind=='checksum' else b'Linux amd64 only')in r.stderr
for kind in ['bootstrap-download','download','checksum','platform']:check('injected-'+kind+'-failure-preserves-install-before-sudo',lambda kind=kind:fault(kind))

def missing_user():
 before=snapshot();r=subprocess.run(['sh',str(SCRIPT),'--user','nonexistent-agent-sudo-user'],capture_output=True);assert r.returncode!=0 and b'Account does not exist'in r.stderr and snapshot()==before
check('nonexistent-recipient-denied-without-modification',missing_user)
def unsupported_os():
 p=pathlib.Path('/etc/os-release');saved=p.read_bytes();before=snapshot()
 try:
  p.write_text('ID=debian\nVERSION_ID=13\n')
  r=subprocess.run(['sh',str(SCRIPT),'--user','agent'],capture_output=True)
  assert r.returncode!=0 and b'Ubuntu only' in r.stderr and snapshot()==before
 finally:p.write_bytes(saved)
check('injected-unsupported-os-denied-without-modification',unsupported_os)


def cleanup():
 r=subprocess.run(['/usr/local/libexec/agent-sudo-helper','uninstall'],capture_output=True);assert r.returncode==0 and not pathlib.Path('/usr/local/bin/agent-sudo').exists()
check('clean-removal-after-public-install',cleanup)
pathlib.Path('/root/public-results.json').write_text(json.dumps({'checks':RESULT,'count':len(RESULT),'bootstrap_sha256':EXPECTED_BOOTSTRAP},indent=2))
'''
def one(name):
 result=LAB/(name+'-public-results.json');result.unlink(missing_ok=True)
 code='EXPECTED_BOOTSTRAP='+repr(hashlib.sha256((ROOT/'website/install.sh').read_bytes()).hexdigest())+'\nCOMMAND='+repr((ROOT/'website/install-command.txt').read_text().strip())+'\n'+GUEST
 src=LAB/(name+'-public-test.py');src.write_text(code)
 for local,remote in [(src,'/root/public-test.py'),(ROOT/'tests/vm/guest.py','/root/guest.py')]:
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[name]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(local),'root@127.0.0.1:'+remote],check=True)
 with (LAB/(name+'-public.log')).open('wb')as log:
  r=ssh(name,'rm -f /root/public-results.json; python3 -u /root/public-test.py',stdout=log,stderr=subprocess.STDOUT,timeout=450)
 if r.returncode==0:result.write_bytes(ssh(name,'cat /root/public-results.json',capture_output=True,check=True).stdout)
 print(name,'PASS' if r.returncode==0 else 'FAIL (see ignored VM log)',flush=True)
 return r.returncode
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:codes=list(pool.map(one,sys.argv[1:] or PEERS))
 sys.exit(any(codes))
