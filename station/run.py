import json, os, signal, subprocess, time, urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlencode
RUN=os.environ['LAB_RUN']; OUT=Path('/evidence')/RUN; OUT.mkdir(exist_ok=True)
BASE='http://target:8080'
def request(path, data=None):
    req=urllib.request.Request(BASE+path, data=None if data is None else json.dumps(data).encode(),headers={'X-Lab-Run':RUN,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=5) as r: return r.status,json.load(r)
    except urllib.error.HTTPError as e: return e.code,json.load(e)
def command(args,name):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    (OUT/name).write_text(p.stdout+p.stderr)
    if p.returncode: raise RuntimeError(f'{args[0]} failed: {p.returncode}')
results={}
for mode in ('vulnerable','hardened'):
    request('/control',{'mode':mode})
    with (OUT/f'{mode}-capture.log').open('w') as log:
        capture=subprocess.Popen(['dumpcap','-i','eth0','-p','-P','-s','65535','-w',str(OUT/f'{mode}.pcap')],stdout=log,stderr=log)
        try:
            time.sleep(1)
            if capture.poll() is not None: raise RuntimeError('packet capture did not start')
            baseline=request('/'); normal=request('/users?name=labuser')
            command(['nmap','-sT','-Pn','-n','--max-retries','1','--max-rate','30','-p','1-100,8080','target','-oX',str(OUT/f'{mode}-nmap.xml')],f'{mode}-nmap.txt')
            command(['sh','-c',"printf 'GET /health HTTP/1.0\r\nHost: target\r\n\r\n' | nc -w 2 target 8080"],f'{mode}-netcat.txt')
            attempts=[request('/login',{'username':'labuser','password':f'wrong-{i}'})[0] for i in range(6)]
            login=request('/login',{'username':'labuser','password':'LabOnly-2026'})
            injection=request('/users?'+urlencode({'name':"' OR '1'='1"}))
            results[mode]={'baseline':baseline,'normal_lookup':normal,'failed_login_statuses':attempts,'correct_login_after_attempts':login,'sql_injection':injection}
            time.sleep(1)
        finally:
            capture.send_signal(signal.SIGINT)
            capture.wait(timeout=10)
            (OUT/f'{mode}.pcap').chmod(0o644)
results['checks']={
 'baseline_ok':all(results[m]['baseline'][0]==200 for m in ('vulnerable','hardened')),
 'normal_lookup_ok':all(results[m]['normal_lookup'][1]['users']==['labuser'] for m in ('vulnerable','hardened')),
 'sql_injection_reproduced':len(results['vulnerable']['sql_injection'][1]['users'])==2,
 'sql_injection_mitigated':results['hardened']['sql_injection'][1]['users']==[],
 'rate_limit_mitigated':results['hardened']['failed_login_statuses']==[401]*3+[429]*3,
 'vulnerable_login_succeeded':results['vulnerable']['correct_login_after_attempts'][1]['authenticated'] is True,
 'blocked_correct_login':results['hardened']['correct_login_after_attempts'][0]==429}
(OUT/'results.json').write_text(json.dumps(results,indent=2))
if not all(results['checks'].values()): raise RuntimeError('scenario validation failed')
print(json.dumps(results['checks'],indent=2))
