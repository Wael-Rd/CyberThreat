"""Package source and one verified evidence run; exclude daemon and local state."""
import hashlib,sys,zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
run=(root/sys.argv[1]).resolve(); run.relative_to(root/'evidence')
files=sorted(p for p in run.iterdir() if p.is_file() and p.name!='SHA256SUMS')
(run/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
archive=root/'Malware-Analysis-Lab.zip'
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
 for name in ['README.md','START-HERE.html','presentation.html','compose.yaml','opencode.json','.gitignore']:
  z.write(root/name,name)
 for folder in ['docs','scripts','station','target','tests','mcp_server','samples']:
  for p in sorted((root/folder).rglob('*')):
   if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc': z.write(p,p.relative_to(root))
 for p in sorted(run.iterdir()):
  if p.is_file(): z.write(p,p.relative_to(root))
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None
 names=z.namelist()
 assert sum(n.endswith('.pcap') for n in names)==2
 assert sum(n.endswith('.png') for n in names)==4
 assert not any('.docker-data' in n or '.docker-host' in n or '__pycache__' in n for n in names)
(root/(archive.name+'.sha256')).write_text(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name+'\n')
print(f'PASS archive: {len(names)} files, {archive.stat().st_size} bytes, two PCAP and four screenshots')
