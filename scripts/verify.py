import json, sys
from pathlib import Path
p=Path(sys.argv[1]); r=json.loads((p/'results.json').read_text())
assert all(r['checks'].values()), 'Scenario failure'
a=json.loads((p/'alerts.json').read_text())
for mode in ('vulnerable','hardened'):
    assert {x['rule'] for x in a if x['mode']==mode}=={'SCAN_PORTS','LOGIN_BURST','SQLI_PATTERN'}, 'Missing detection'
    assert (p/f'{mode}.pcap').stat().st_size>24, 'Empty PCAP'
n=json.loads((p/'network.json').read_text())[0]
assert n['Internal'] is True and len(n['Containers'])==2, 'Unexpected topology'
triage=json.loads((p/'triage.json').read_text())
assert triage['executed'] is False and 'Lab_Training_Fixture' in triage['yara_matches']
print('PASS: scénarios, 6 détections, PCAP et réseau interne à 2 conteneurs')
