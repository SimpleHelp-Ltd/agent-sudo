#!/usr/bin/env python3
"""Build a local, deterministic Linux amd64 tar archive; never publish/install."""
import pathlib,subprocess,os,hashlib,tarfile,io,json,argparse,shutil
root=pathlib.Path(__file__).resolve().parents[1];os.chdir(root)
p=argparse.ArgumentParser();p.add_argument('--skip-build',action='store_true');p.add_argument('--expected-helper');p.add_argument('--expected-frontend');args=p.parse_args()
env=os.environ.copy();env['PATH']=str(pathlib.Path.home()/'.cargo/bin')+':'+env.get('PATH','');env['RUSTFLAGS']='--remap-path-prefix='+str(root)+'=. --remap-path-prefix='+str(pathlib.Path.home()/'.cargo')+'=cargo'
if not args.skip_build:subprocess.run(['cargo','build','--locked','--release','--target','x86_64-unknown-linux-musl'],check=True,env=env)
version=next(l.split('"')[1] for l in (root/'Cargo.toml').read_text().splitlines() if l.startswith('version ='))
out=root/'artifacts'/('agent-sudo-'+version+'-linux-amd64')
if out.exists():shutil.rmtree(out)
out.mkdir(parents=True)
for name,expected in [('agent-sudo',args.expected_frontend),('agent-sudo-helper',args.expected_helper)]:
 b=(root/'target/x86_64-unknown-linux-musl/release'/name).read_bytes();h=hashlib.sha256(b).hexdigest()
 if expected and expected!=h:raise SystemExit('tested binary hash mismatch: '+name)
 (out/name).write_bytes(b);(out/name).chmod(0o755)
for f in ['install.sh','uninstall.sh','README.md','LICENSE']:
 (out/f).write_bytes((root/f).read_bytes());(out/f).chmod(0o755 if f.endswith('.sh') else 0o644)
(out/'docs').mkdir(exist_ok=True)
# Ship user-facing documentation; internal publication history is not release content.
for name in ['BUILD.md','DESIGN.md','OPERATOR.md','SECURITY_REVIEW.md','VALIDATION.md']:
 (out/'docs'/name).write_bytes((root/'docs'/name).read_bytes())
files=sorted(p for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(out))+'\n' for f in files))
archive=out.parent/(out.name+'.tar.gz')
import gzip
with archive.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as tar:
 for f in sorted(out.rglob('*')):
  info=tar.gettarinfo(str(f),str(f.relative_to(out)));info.uid=info.gid=info.mtime=0;info.uname=info.gname='root';info.mode=0o755 if f.is_dir() or f.name in ['agent-sudo','agent-sudo-helper','install.sh','uninstall.sh'] else 0o644
  if f.is_file():
   with f.open('rb') as data:tar.addfile(info,data)
  else:tar.addfile(info)
archive.with_suffix('.gz.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
print(archive)
