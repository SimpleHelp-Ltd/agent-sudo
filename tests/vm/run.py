#!/usr/bin/env python3
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

from lab import ROOT,LAB,PEERS,ssh
import subprocess,sys,json,concurrent.futures
artifact=ROOT/'artifacts/agent-sudo-1.0.3-linux-amd64.tar.gz'
def one(n):
 (LAB/(n+'-results.json')).unlink(missing_ok=True)
 for src,dst in [(artifact,'/root/agent-sudo.tar.gz'),(ROOT/'tests/vm/guest.py','/root/guest.py')]:
  subprocess.run(['scp','-q','-i',str(LAB/'key'),'-P',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),str(src),'root@127.0.0.1:'+dst],check=True)
 with (LAB/(n+'-matrix.log')).open('wb')as log:
  r=ssh(n,'rm -f /root/results.json /etc/sudoers.d/00-recording /etc/sudoers.d/99-rollback; tar -xzf /root/agent-sudo.tar.gz -C /root/payload && /root/payload/install.sh && python3 -u /root/guest.py',stdout=log,stderr=subprocess.STDOUT,timeout=900)
 r2=ssh(n,'cat /root/results.json',capture_output=True)
 if r.returncode==0 and r2.returncode==0:
  import hashlib
  evidence=json.loads(r2.stdout)
  for binary,field in [('agent-sudo','frontend_sha256'),('agent-sudo-helper','helper_sha256')]:assert evidence[field]==hashlib.sha256((ROOT/'target/x86_64-unknown-linux-musl/release'/binary).read_bytes()).hexdigest()
  (LAB/(n+'-results.json')).write_bytes(r2.stdout)
 print(n,'PASS' if r.returncode==0 else 'FAIL; see '+str(LAB/(n+'-matrix.log')),flush=True)
 return r.returncode
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:
 codes=list(pool.map(one,sys.argv[1:] or PEERS))
sys.exit(any(codes))
