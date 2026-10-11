import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=ROOT/'samples/harmless-training.txt'
r=json.loads(subprocess.check_output([sys.executable,str(ROOT/'station/triage.py'),str(p)]))
assert r['sha256']==hashlib.sha256(p.read_bytes()).hexdigest()
assert not r['executed'] and r['network_indicators_untrusted']==['https://telemetry.invalid/training']
with tempfile.TemporaryDirectory() as tmp:
    empty=Path(tmp)/'empty'; empty.touch()
    e=json.loads(subprocess.check_output([sys.executable,str(ROOT/'station/triage.py'),str(empty)]))
    assert e['entropy']==0 and e['bytes']==0
print('PASS triage: known hash, inert indicator, no execution, empty sample')
