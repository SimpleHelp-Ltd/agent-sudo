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
  subprocess.run(['/usr/bin/sudo','-K'],check=True)
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
check('exact-public-pipe-command-normal-sudo-no-recipient-prompt',lambda:terminal(COMMAND,[(b'password for',b'VmOnly-TestPassword-9274')]))
check('machine-wide-schema-no-recipient-list',lambda:ok(json.loads(pathlib.Path('/var/lib/agent-sudo/config').read_bytes())['v']==2 and 'accounts' not in json.loads(pathlib.Path('/var/lib/agent-sudo/config').read_bytes())))

def cycle(who):
 issued=front([who,'60']);assert issued.returncode==0;t=issued.stdout.strip().decode();i=t.split('.')[1];r=run(t,who=who);assert r.returncode==0 and b'uid=0(root)'in r.stdout
 assert i.encode()in front(['status'],who).stdout
 assert front(['revoke',i],who).returncode==0 and run(t,who=who).returncode!=0
check('public-installed-grant-run-status-revoke',lambda:cycle('other'))
check('exact-public-command-reinstallation-with-sudo',lambda:terminal(COMMAND,[(b'password for',b'VmOnly-TestPassword-9274')]))
check('reinstalled-new-recipient-grant-run-revoke',lambda:cycle('agent'))
check('exact-tested-binary-hashes',lambda:ok(all(hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==h for path,h in EXPECTED_BINARIES.items())))

def package_fixture():
 subprocess.run(['curl','-fsSL',BASE+'agent-sudo-0.2.0-linux-amd64.tar.gz','-o','/home/humanadmin/public-package.tar.gz'],check=True,timeout=60)
 assert hashlib.sha256(pathlib.Path('/home/humanadmin/public-package.tar.gz').read_bytes()).hexdigest()==EXPECTED_PACKAGE
check('actual-public-package-hash-for-truncation-fixture',package_fixture)

def prefixes():
 before=snapshot();folder=pathlib.Path('/home/humanadmin/prefix-bin');folder.mkdir(exist_ok=True)
 marker=pathlib.Path('/home/humanadmin/PREFIX-EXECUTED');marker.unlink(missing_ok=True)
 for name in ['uname','id','getent','mktemp','curl','sudo','mkdir','tar','rm','sha256sum']:
  p=folder/name;p.write_text('#!/bin/sh\necho attempted > '+str(marker)+'\nexit 99\n');p.chmod(0o755)
 a=pwd.getpwnam('humanadmin');body=SCRIPT.read_bytes()
 for cut in range(len(body)):
  subprocess.run(['/bin/sh'],input=body[:cut],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,user=a.pw_uid,group=a.pw_gid,extra_groups=[27],env={'PATH':str(folder)+':/usr/bin:/bin'},timeout=5)
  assert not marker.exists(),('truncated script ran',cut)
 assert snapshot()==before
 subprocess.run(['/bin/sh'],input=body,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,user=a.pw_uid,group=a.pw_gid,extra_groups=[27],env={'PATH':str(folder)+':/usr/bin:/bin'},timeout=5)
 assert marker.exists(),'full-script positive control failed'
 marker.unlink();print('PREFIXES',len(body),'proper prefixes had no external side effects',flush=True)
check('every-truncated-bootstrap-prefix-blocked-with-positive-control',prefixes)

def fault(kind):
 before=snapshot(); folder=pathlib.Path('/home/humanadmin/fault-bin');folder.mkdir(exist_ok=True)
 for p in folder.iterdir():p.unlink()
 (folder/'sudo').write_text('#!/bin/sh\ntouch /home/humanadmin/UNEXPECTED-SUDO\nexit 99\n');(folder/'sudo').chmod(0o755)
 if kind in ['download','bootstrap-download']: content='#!/bin/sh\nexit 22\n';name='curl'
 elif kind in ['bootstrap-truncated','package-truncated']:
  if kind=='bootstrap-truncated': content='#!/bin/sh\nhead -c '+str(len(SCRIPT.read_bytes())-1)+' '+str(SCRIPT)+'\nexit 18\n'
  else: content='#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; head -c 128 /home/humanadmin/public-package.tar.gz > "$1"; exit 18; fi; shift; done\nexit 2\n'
  name='curl'
 elif kind=='checksum': content='#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; printf corrupt > "$1"; exit; fi; shift; done\nexit 2\n';name='curl'
 else:content='#!/bin/sh\ncase "$1" in -s) echo Linux;; *) echo aarch64;; esac\n';name='uname'
 (folder/name).write_text(content);(folder/name).chmod(0o755)
 a=pwd.getpwnam('humanadmin');temp=pathlib.Path('/home/humanadmin/bootstrap-tmp');temp.mkdir(exist_ok=True);os.chown(temp,a.pw_uid,a.pw_gid);assert not list(temp.iterdir());args=['/bin/sh','-c',COMMAND] if kind.startswith('bootstrap-') else ['sh',str(SCRIPT)];r=subprocess.run(args,capture_output=True,user=a.pw_uid,group=a.pw_gid,extra_groups=[27],env={'PATH':str(folder)+':/usr/bin:/bin','TMPDIR':str(temp)},timeout=30)
 assert (r.returncode!=0 or kind=='bootstrap-download') and snapshot()==before and not pathlib.Path('/home/humanadmin/UNEXPECTED-SUDO').exists() and not list(temp.iterdir())
 assert kind.startswith('bootstrap-') or (b'Download failed' if kind in ['download','package-truncated'] else b'Checksum mismatch' if kind=='checksum' else b'Linux amd64 only')in r.stderr
for kind in ['bootstrap-download','bootstrap-truncated','download','package-truncated','checksum','platform']:check('injected-'+kind+'-failure-preserves-install-before-sudo',lambda kind=kind:fault(kind))

def removed_option():
 before=snapshot();r=subprocess.run(['sh',str(SCRIPT),'--user','agent'],capture_output=True);assert r.returncode!=0 and b'no recipient options'in r.stderr and snapshot()==before
check('old-installer-recipient-option-refused-before-modification',removed_option)

def unsupported_os():
 p=pathlib.Path('/etc/os-release');saved=p.read_bytes();before=snapshot()
 try:
  p.write_text('ID=debian\nVERSION_ID=13\n')
  r=subprocess.run(['sh',str(SCRIPT)],capture_output=True)
  assert r.returncode!=0 and b'Ubuntu only' in r.stderr and snapshot()==before
 finally:p.write_bytes(saved)
check('injected-unsupported-os-denied-without-modification',unsupported_os)


def cleanup():
 r=subprocess.run(['/usr/local/libexec/agent-sudo-helper','uninstall'],capture_output=True);assert r.returncode==0 and not pathlib.Path('/usr/local/bin/agent-sudo').exists()
check('clean-removal-after-public-install',cleanup)
pathlib.Path('/root/public-results.json').write_text(json.dumps({'checks':RESULT,'count':len(RESULT),'bootstrap_sha256':EXPECTED_BOOTSTRAP,'binary_hashes':EXPECTED_BINARIES,'package_sha256':EXPECTED_PACKAGE,'command':COMMAND,'truncated_prefixes':len(SCRIPT.read_bytes()),'os':pathlib.Path('/etc/os-release').read_text(),'sudo_version':subprocess.check_output(['/usr/bin/sudo','--version'],stderr=subprocess.STDOUT).decode().splitlines()[0]},indent=2))
'''
def one(name):
 result=LAB/(name+'-public-results.json');result.unlink(missing_ok=True)
 code='EXPECTED_PACKAGE='+repr(hashlib.sha256((ROOT/'artifacts/agent-sudo-0.2.0-linux-amd64.tar.gz').read_bytes()).hexdigest())+'\nEXPECTED_BINARIES='+repr({'/usr/local/bin/agent-sudo':hashlib.sha256((ROOT/'target/x86_64-unknown-linux-musl/release/agent-sudo').read_bytes()).hexdigest(),'/usr/local/libexec/agent-sudo-helper':hashlib.sha256((ROOT/'target/x86_64-unknown-linux-musl/release/agent-sudo-helper').read_bytes()).hexdigest()})+'\nEXPECTED_BOOTSTRAP='+repr(hashlib.sha256((ROOT/'website/install.sh').read_bytes()).hexdigest())+'\nCOMMAND='+repr((ROOT/'website/install-command.txt').read_text().strip())+'\n'+GUEST
 src=LAB/(name+'-public-test.py');src.write_text(code)
 for local,remote in [(src,'/root/public-test.py'),(ROOT/'tests/vm/guest.py','/root/guest.py')]:
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[name]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(local),'root@127.0.0.1:'+remote],check=True)
 with (LAB/(name+'-public.log')).open('wb')as log:
  r=ssh(name,'rm -f /root/public-results.json; python3 -u /root/public-test.py',stdout=log,stderr=subprocess.STDOUT,timeout=600)
 if r.returncode==0:result.write_bytes(ssh(name,'cat /root/public-results.json',capture_output=True,check=True).stdout)
 print(name,'PASS' if r.returncode==0 else 'FAIL (see ignored VM log)',flush=True)
 return r.returncode
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:codes=list(pool.map(one,sys.argv[1:] or PEERS))
 sys.exit(any(codes))
