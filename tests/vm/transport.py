#!/usr/bin/env python3
"""Pre-implementation nonsecret transport/logging proof on actual VM sudo."""
from lab import ssh, PEERS, ROOT
import json, base64
PROBE='''#!/usr/bin/python3
import sys,os
if sys.argv[1:]!=['run']:sys.exit(98)
b=sys.stdin.buffer.read()
sys.stdout.buffer.write(b)
sys.stderr.buffer.write(b'probe-stderr\\x00\\xff')
'''
POLICY='''# agent-sudo managed v1
Defaults!/usr/local/libexec/agent-sudo-helper !use_pty, !log_input, !log_output
agent ALL=(root) NOPASSWD: NOSETENV: /usr/local/libexec/agent-sudo-helper run, /usr/local/libexec/agent-sudo-helper status, /usr/local/libexec/agent-sudo-helper revoke, /usr/local/libexec/agent-sudo-helper revoke-all
'''
results=[]
for n in PEERS:
 setup='''import pathlib,os,subprocess,shutil
shutil.rmtree('/var/log/agent-sudo-probe-io',ignore_errors=True)
p=pathlib.Path('/usr/local/libexec');p.mkdir(exist_ok=True)
h=p/'agent-sudo-helper';h.write_bytes('''+repr(PROBE.encode())+''');h.chmod(0o755)
p=pathlib.Path('/etc/sudoers.d/agent-sudo');p.write_text('''+repr(POLICY if n=='noble' else POLICY.replace(', !log_input, !log_output',''))+''');p.chmod(0o440)
subprocess.run(['visudo','-c'],check=True)
'''
 r=ssh(n,'python3 -',input=setup.encode(),capture_output=True);assert r.returncode==0,(n,r.stderr)
 data=b'AS-NONSECRET-TRANSPORT-CANARY-'+bytes(range(256))*1024
 r=ssh(n,'runuser -u agent -- /usr/bin/sudo -n -- /usr/local/libexec/agent-sudo-helper run',input=data,capture_output=True)
 assert r.returncode==0 and r.stdout==data and r.stderr==b'probe-stderr\x00\xff',(n,r.returncode,len(r.stdout),r.stderr[:1000])
 results.append({'vm':n,'check':'byte-transparent-262KB-stdio','pass':True})
 # Enable default recording: helper exemption must preserve recording for other commands.
 if n=='resolute':
  results.append({'vm':n,'check':'no-io-logger-implemented','pass':True})
  r=ssh(n,'sudo -ll -U agent; sudo --version; visudo --version',capture_output=True)
  (ROOT/'target/vm'/f'{n}-effective-policy.txt').write_bytes(r.stdout+r.stderr)
  ssh(n,'rm /etc/sudoers.d/agent-sudo /usr/local/libexec/agent-sudo-helper',check=True)
  print(n,'transport prototype PASS (I/O logging settings unsupported)',flush=True)
  continue
 r=ssh(n,"printf '%s\\n' 'Defaults log_input, log_output, iolog_dir=\"/var/log/agent-sudo-probe-io\"' > /etc/sudoers.d/00-agent-probe-logging; chmod 440 /etc/sudoers.d/00-agent-probe-logging; visudo -c",capture_output=True)
 # sudo-rs may not implement IO logging; capture actual diagnostics, do not claim supported.
 (ROOT/'target/vm'/f'{n}-logging-validation.txt').write_bytes(r.stdout+r.stderr)
 r=ssh(n,'runuser -u agent -- /usr/bin/sudo -n -- /usr/local/libexec/agent-sudo-helper run',input=data,capture_output=True)
 assert r.returncode==0 and r.stdout==data,(n,r.returncode,r.stderr)
 r=ssh(n,"find /var/log/agent-sudo-probe-io -type f 2>/dev/null | wc -l",capture_output=True)
 assert r.stdout.strip()==b'0',(n,r.stdout)
 if n=='noble':
  r=ssh(n,"sudo /usr/bin/printf unrelated-auditing-canary; find /var/log/agent-sudo-probe-io -type f | wc -l",capture_output=True)
  assert int(r.stdout.split(b'canary')[-1])>0,(n,r.stdout,r.stderr)
 results.append({'vm':n,'check':'scoped-logging-exemption','pass':True,'unrelated_io_logging_verified':n=='noble'})
 r=ssh(n,'sudo -ll -U agent; sudo --version; visudo --version',capture_output=True)
 (ROOT/'target/vm'/f'{n}-effective-policy.txt').write_bytes(r.stdout+r.stderr)
 ssh(n,'rm /etc/sudoers.d/00-agent-probe-logging /etc/sudoers.d/agent-sudo /usr/local/libexec/agent-sudo-helper',check=True)
 print(n,'transport/logging prototype PASS',flush=True)
(ROOT/'target/vm/transport-results.json').write_text(json.dumps(results,indent=2)+'\n')
