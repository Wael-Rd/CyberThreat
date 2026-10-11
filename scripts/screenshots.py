"""Capture the real evidence dashboard with local Chromium, no external assets."""
import hashlib, subprocess, sys, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]; run=Path(sys.argv[1]).resolve()
if run.parent!=(root/'evidence').resolve(): raise ValueError('Expected project evidence run')
with tempfile.TemporaryDirectory(prefix='malab-browser-') as profile:
    for phase in ('vulnerable','hardened'):
        subprocess.run(['chromium','--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--no-first-run','--user-data-dir='+profile,'--window-size=1440,1600','--virtual-time-budget=1500','--screenshot='+str(run/f'dashboard-{phase}.png'),(run/'dashboard.html').as_uri()+'#'+phase],check=True,capture_output=True,timeout=90)
files=sorted(p for p in run.iterdir() if p.is_file() and p.name!='SHA256SUMS')
(run/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
print('Screenshots saved; SHA256SUMS refreshed')
