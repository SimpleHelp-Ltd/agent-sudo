#!/usr/bin/env python3
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

"""Run extended or lifecycle guest checks concurrently in the two disposable VMs."""
from lab import ROOT,LAB,PEERS,ssh
import subprocess,sys,concurrent.futures,json,hashlib
suite=sys.argv[1];assert suite in ['extended','lifecycle','dynamic','revoke_created']
def one(n):
 (LAB/(n+'-'+suite+'-results.json')).unlink(missing_ok=True)
 def hashes():
  out=ssh(n,'sha256sum /usr/local/bin/agent-sudo /usr/local/libexec/agent-sudo-helper',capture_output=True,check=True).stdout.decode().splitlines()
  values={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in out}
  for binary,h in values.items():assert h==hashlib.sha256((ROOT/'target/x86_64-unknown-linux-musl/release'/binary).read_bytes()).hexdigest()
  return values
 expected=hashes()
 if suite=='dynamic':
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(ROOT/'artifacts/agent-sudo-1.0.0-linux-amd64.tar.gz'),'root@127.0.0.1:/root/old-1.0.0.tar.gz'],check=True)
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(ROOT/'artifacts/agent-sudo-0.2.0-linux-amd64.tar.gz'),'root@127.0.0.1:/root/old-0.2.0.tar.gz'],check=True)
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(ROOT/'artifacts/agent-sudo-0.1.0-linux-amd64.tar.gz'),'root@127.0.0.1:/root/old-0.1.0.tar.gz'],check=True)
 for f in ['guest.py',suite+'.py']:
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(ROOT/'tests/vm'/f),'root@127.0.0.1:/root/'+f],check=True)
 with (LAB/(n+'-'+suite+'.log')).open('wb')as out:r=ssh(n,'rm -f /root/'+suite+'-results.json; python3 -u /root/'+suite+'.py',stdout=out,stderr=subprocess.STDOUT,timeout=600)
 if r.returncode==0:
  r2=ssh(n,'cat /root/'+suite+'-results.json',capture_output=True,check=True);assert hashes()==expected
  (LAB/(n+'-'+suite+'-results.json')).write_text(json.dumps({'binary_hashes':expected,'results':json.loads(r2.stdout)},indent=2)+'\n')
 print(n,suite,'PASS' if r.returncode==0 else 'FAIL',flush=True);return r.returncode
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:codes=list(pool.map(one,sys.argv[2:] or PEERS))
sys.exit(any(codes))
