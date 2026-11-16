#!/usr/bin/env python3
# Copyright 2026 SimpleHelp
# SPDX-License-Identifier: Apache-2.0

"""Guest real-clock and long-lived command checks; no fake clock application hooks."""
from guest import *

def main():
 def clock():
  t,i=grant(minutes=1);now=int(time.time());start=time.monotonic()
  try:
   subprocess.run(['date','-s','@'+str(now+86400)],stdout=subprocess.DEVNULL,check=True)
   assert run(t).returncode==0
   subprocess.run(['date','-s','@'+str(now-86400)],stdout=subprocess.DEVNULL,check=True)
   assert run(t).returncode==0
  finally:subprocess.run(['date','-s','@'+str(now+int(time.monotonic()-start))],stdout=subprocess.DEVNULL,check=True)
 check('real-wall-clock-forward-and-back-does-not-extend-or-expire',clock)
 def expiry():
  subprocess.run(['systemctl','stop','agent-sudo-cleanup.timer'],check=True)
  t,i=grant(minutes=1);before=json.loads((STATE/('g-'+i)).read_bytes());new,newid=grant(minutes=1);after=json.loads((STATE/('g-'+i)).read_bytes());assert before==after
  kr,kw=os.pipe();os.write(kw,(t+'\n').encode());os.close(kw)
  try:
   c=subprocess.Popen([FRONT,'run','--key-fd',str(kr),'--','/bin/sh','-c','sleep 65; printf survived'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(kr,),**userargs('agent'))
   # CLOCK_BOOTTIME threshold read from actual issued grant. Keep real test explicit.
   remaining=(before['deadline']/1e9)-time.clock_gettime(time.CLOCK_BOOTTIME)
   time.sleep(max(0,remaining+.1));assert run(t).returncode!=0 and (STATE/('g-'+i)).exists()
   out,err=c.communicate(timeout=10);assert c.returncode==0 and out==b'survived'
   subprocess.run([HELP,'cleanup'],check=True);assert not (STATE/('g-'+i)).exists()
  finally:os.close(kr);subprocess.run(['systemctl','start','agent-sudo-cleanup.timer'],check=True)
 check('real-one-minute-expiry-stopped-cleanup-admitted-root-work-survives',expiry)
 pathlib.Path('/root/lifecycle-results.json').write_text(json.dumps(RESULTS,indent=2)+'\n');print('TOTAL',len(RESULTS),flush=True)
if __name__=='__main__':main()
