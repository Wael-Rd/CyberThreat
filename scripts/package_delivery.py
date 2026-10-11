"""Package source and one verified evidence run; exclude daemon and local state."""
import hashlib,sys,zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
run=(root/sys.argv[1]).resolve(); run.relative_to(root/'evidence')
files=sorted(p for p in run.iterdir() if p.is_file() and p.name!='SHA256SUMS')
(run/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
archive=root/'CyberThreat-Delivery.zip'
def put(z,path,name):
 info=zipfile.ZipInfo.from_file(path,arcname=str(name))
 info.external_attr=(0o100755 if path.suffix=='.sh' else 0o100644)<<16
 info.compress_type=zipfile.ZIP_DEFLATED
 z.writestr(info,path.read_bytes())
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
 for name in ['README.md','SECURITY.md','START-HERE.html','presentation.html','compose.yaml','opencode.json','.gitignore']:
  put(z,root/name,name)
 for folder in ['.github','docs','scripts','station','target','tests','mcp_server','samples']:
  for p in sorted((root/folder).rglob('*')):
   if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc' and (folder!='samples' or p.name=='harmless-training.txt'): put(z,p,p.relative_to(root))
 if (root/'evidence/reference.json').exists(): put(z,root/'evidence/reference.json','evidence/reference.json')
 for p in sorted(run.iterdir()):
  if p.is_file(): put(z,p,p.relative_to(root))
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None
 names=z.namelist()
 assert sum(n.endswith('.pcap') for n in names)==2
 assert sum(n.endswith('.png') for n in names)>=4
 assert not any('.docker-data' in n or '.docker-host' in n or '__pycache__' in n for n in names)
(root/(archive.name+'.sha256')).write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
print(f'PASS archive: {len(names)} files, {archive.stat().st_size} bytes, two PCAP and verified screenshot assets')
