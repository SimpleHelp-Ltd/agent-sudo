#!/usr/bin/env python3
"""Actual ACPI S3 suspension via systemctl and QMP wakeup, not a paused VM."""
from lab import *
import socket,concurrent.futures,shlex

def one(n):
 sock=socket.socket(socket.AF_UNIX);sock.connect(str(LAB/n/'qmp.sock'));r=sock.makefile('rb');json.loads(r.readline())
 def qmp(command):
  sock.sendall((json.dumps({'execute':command})+'\n').encode())
  while True:
   value=json.loads(r.readline())
   if 'return'in value:return value['return']
   if 'error'in value:raise RuntimeError(str(value['error']))
 qmp('qmp_capabilities')
 code="from guest import *;subprocess.run(['systemctl','stop','agent-sudo-cleanup.timer'],check=True);t,i=grant(minutes=1);print(json.dumps({'token':t,'id':i,'boottime':time.clock_gettime(time.CLOCK_BOOTTIME)}))"
 result=ssh(n,'cd /root; python3 -c '+shlex.quote(code),capture_output=True,check=True);info=json.loads(result.stdout)
 response=subprocess.Popen(['ssh','-i',str(LAB/'key'),'-p',str(PEERS[n]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),'-o','LogLevel=ERROR','root@127.0.0.1','systemctl suspend'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 for _ in range(40):
  status=qmp('query-status')['status']
  if status=='suspended':break
  time.sleep(.25)
 assert status=='suspended',(n,'actual ACPI suspend unavailable',response.poll(),status)
 print(n,'actual ACPI suspended; waking after 65 seconds',flush=True);time.sleep(65);qmp('system_wakeup')
 for _ in range(30):
  result=ssh(n,'true',capture_output=True)
  if result.returncode==0:break
  time.sleep(.5)
 code="from guest import *;import sys;x=json.loads(sys.stdin.buffer.read());assert time.clock_gettime(time.CLOCK_BOOTTIME)-x['boottime']>=65;assert (STATE/('g-'+x['id'])).exists();assert run(x['token']).returncode!=0;subprocess.run(['systemctl','start','agent-sudo-cleanup.timer'],check=True)"
 result=ssh(n,'cd /root; python3 -c '+shlex.quote(code),input=json.dumps(info).encode(),capture_output=True,timeout=20);assert result.returncode==0,(n,result.stderr[:200]);sock.close()
 response.communicate(timeout=5)
 print(n,'PASS actual suspend expiry with cleanup stopped',flush=True)
 return {'vm':n,'check':'actual-ACPI-suspend-CLOCK_BOOTTIME-expiry-cleanup-stopped','pass':True,'suspend_seconds':65}
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:results=list(pool.map(one,PEERS))
(LAB/'suspend-results.json').write_text(json.dumps(results,indent=2)+'\n')
