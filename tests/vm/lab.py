#!/usr/bin/env python3
"""Local QEMU/KVM lab only. No host sudo, mounts or privileged installation."""
import argparse, pathlib, subprocess, time, json, os
ROOT=pathlib.Path(__file__).resolve().parents[2]; LAB=ROOT/'target/vm'
PEERS={'noble':22451,'resolute':22452}
def ssh(name, command, **kw):
    kw.setdefault('timeout',20)
    return subprocess.run(['ssh','-i',str(LAB/'key'),'-p',str(PEERS[name]),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),'-o','LogLevel=ERROR','-o','ConnectTimeout=3','root@127.0.0.1',command],**kw)
def start(name):
    folder=LAB/name;folder.mkdir(exist_ok=True)
    key=(LAB/'key.pub').read_text().strip()
    (folder/'user-data').write_text('''#cloud-config
ssh_pwauth: false
disable_root: false
users:
  - name: root
    ssh_authorized_keys:
      - '''+key+'''
  - name: humanadmin
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: VmOnly-TestPassword-9274
  - name: agent
    shell: /bin/bash
  - name: other
    shell: /bin/bash
packages: [acl, python3]
write_files:
  - path: /etc/ssh/sshd_config.d/90-agent-test.conf
    content: |
      PermitRootLogin prohibit-password
runcmd:
  - [systemctl, restart, ssh]
''')
    (folder/'meta-data').write_text(f'instance-id: agent-sudo-{name}\nlocal-hostname: agent-sudo-{name}\n')
    subprocess.run(['genisoimage','-quiet','-output',str(folder/'seed.iso'),'-volid','cidata','-joliet','-rock',str(folder/'user-data'),str(folder/'meta-data')],check=True)
    disk=folder/'disk.qcow2'
    if not disk.exists(): subprocess.run(['qemu-img','create','-q','-f','qcow2','-F','qcow2','-b',str(LAB/(name+'.img')),str(disk),'12G'],check=True)
    subprocess.run(['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','2','-m','2048','-drive',f'file={disk},if=virtio','-drive',f'file={folder}/seed.iso,media=cdrom,readonly=on','-netdev',f'user,id=n0,hostfwd=tcp:127.0.0.1:{PEERS[name]}-:22','-device','virtio-net-pci,netdev=n0','-display','none','-qmp',f'unix:{folder}/qmp.sock,server=on,wait=off','-serial',f'file:{folder}/serial.log','-daemonize','-pidfile',str(folder/'qemu.pid')],check=True)
def wait(name):
    for _ in range(180):
        r=ssh(name,'test -f /var/lib/cloud/instance/boot-finished',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if r.returncode==0:return
        time.sleep(2)
    raise RuntimeError(name+' boot timed out')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['start','wait','info','stop']);a=p.parse_args()
    for n in PEERS:
        if a.action=='start':start(n)
        elif a.action=='wait':wait(n)
        elif a.action=='info':ssh(n,'cat /etc/os-release; uname -r; sudo --version | head -3; visudo --version; id agent')
        elif a.action=='stop':os.kill(int((LAB/n/'qemu.pid').read_text()),15)
