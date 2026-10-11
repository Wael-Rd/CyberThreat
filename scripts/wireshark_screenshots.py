import os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; run=Path(sys.argv[1]).resolve()
if run.parent!=(ROOT/'evidence').resolve(): raise ValueError('Invalid run directory')
if (ROOT/'.docker-host').exists(): os.environ['DOCKER_HOST']=(ROOT/'.docker-host').read_text().strip()
for phase in ('vulnerable','hardened'):
    subprocess.run(['docker','compose','exec','-T','--user','1000:1000','station','python3','/app/gui_capture.py','/evidence/'+run.name,phase],cwd=ROOT,check=True,timeout=45)
    raw=run/f'wireshark-{phase}.xwd'
    subprocess.run(['convert',str(raw),str(run/f'wireshark-{phase}.png')],check=True,timeout=30)
    raw.unlink()
print('Two authentic Wireshark screenshots saved')
