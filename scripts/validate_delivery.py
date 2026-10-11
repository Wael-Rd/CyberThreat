"""Offline publication validation: links, recorded metadata and integrity."""
import hashlib,json,re,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
reference=json.loads((ROOT/'evidence/reference.json').read_text())['run']
if not re.fullmatch(r'run-[0-9]{8}T[0-9]{6}Z',reference):raise ValueError('Invalid reference identifier')
run=ROOT/'evidence'/reference

def manifest(folder):
    seen=set()
    for line in (folder/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1)
        if Path(name).name!=name or name in seen:raise ValueError('Invalid manifest entry')
        seen.add(name);p=folder/name
        assert p.is_file() and not p.is_symlink(),name
        assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
    return len(seen)
count=manifest(run)+manifest(ROOT/'docs/reports')
s=json.loads((run/'evidence-summary.json').read_text());results=json.loads((run/'results.json').read_text())
assert s['run']==reference
assert s['checks_passed']==sum(results['checks'].values())==7
assert s['alert_count']==len(json.loads((run/'alerts.json').read_text()))==6
assert abs(sum(m['usage_mib'] for m in s['memory_snapshot'])-s['memory_snapshot_total_mib'])<.01
readme=(ROOT/'README.md').read_text()
for path in re.findall(r'\]\(([^)]+)\)',readme)+re.findall(r'src="([^"]+)"',readme):
    if '://' not in path and not path.startswith('#'):assert (ROOT/path).exists(),path
for p in (ROOT/'docs/assets').rglob('*.svg'):ET.parse(p)
assert 'Malware Analysis Lab' not in readme
assert 'WAEL RDIFI' not in readme and 'RIM MENZLI' not in readme
assert (ROOT/'docs/reports/CyberThreat-Technical-Report.pdf').read_bytes().startswith(b'%PDF-')
print(f'PASS delivery: {count} manifest entries, reference consistency, README links, vector assets and report signature')
