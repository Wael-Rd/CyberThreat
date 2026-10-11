"""Validate stored capture metadata and malformed-input rejection."""
import hashlib,json,struct,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'station'))
from evidence_summary import pcap_metrics,build_summary,parse_memory_snapshot
if len(sys.argv)>1:
    run=Path(sys.argv[1])
else:
    run=ROOT/'evidence'/json.loads((ROOT/'evidence/reference.json').read_text())['run']
summary=json.loads((run/'evidence-summary.json').read_text())
for phase in ['vulnerable','hardened']:
    path=run/f'{phase}.pcap';actual=pcap_metrics(path);stored=summary['phases'][phase]['pcap']
    assert actual==stored
    assert actual['sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual['packets']>0 and actual['captured_bytes']<actual['file_bytes']
    assert summary['phases'][phase]['http_requests']==11
    assert summary['phases'][phase]['scan_ports']==[{'port':8080,'state':'open','service':'http-proxy'}]
with tempfile.TemporaryDirectory() as d:
    p=Path(d)/'bad.pcap'
    header=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)
    for invalid in [b'not a capture',header+b'\0',header+struct.pack('<IIII',0,0,10,10)+b'ab']:
        p.write_bytes(invalid)
        try:pcap_metrics(p)
        except ValueError:pass
        else:raise AssertionError('Malformed capture accepted')
memory=parse_memory_snapshot('HEADER\ncyberthreat-station 512KiB / 384MiB\ncyberthreat-target 0.125GiB / 128MiB\n')
assert memory[0]['usage_mib']==0.5 and memory[1]['usage_mib']==128
try:parse_memory_snapshot('HEADER\ncyberthreat-station UNKNOWN / 384MiB')
except ValueError:pass
else:raise AssertionError('Malformed memory record accepted')
print('PASS evidence summary: capture hashes, packet metadata, 11 HTTP requests per phase and malformed PCAP rejection')
