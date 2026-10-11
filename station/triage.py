"""Static only: never imports, executes, or fetches the submitted sample."""
import hashlib, itertools, json, math, re, shutil, subprocess, sys
from collections import Counter
from pathlib import Path
p=Path(sys.argv[1]); data=p.read_bytes()
if len(data)>10*1024*1024: raise ValueError('Sample exceeds 10 MiB')
strings=[m.group()[:512].decode('ascii') for m in itertools.islice(re.finditer(rb'[\x20-\x7e]{6,}',data),200)]
counts=Counter(data); entropy=-sum((n/len(data))*math.log2(n/len(data)) for n in counts.values()) if data else 0
kind='PE candidate' if data.startswith(b'MZ') else 'ELF' if data.startswith(b'\x7fELF') else 'text or unknown'
result={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'type_hint':kind,'entropy':round(entropy,3),'strings_untrusted':strings,'network_indicators_untrusted':sorted(set(re.findall(r'https?://[^\s\"<>]+','\n'.join(strings))))[:30],'verdict':'indeterminate: static indicators alone cannot prove maliciousness','executed':False}
result['yara_matches']=[]
if shutil.which('file'):
    result['file_description']=subprocess.run(['file','-b','--',str(p)],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
rules=Path(__file__).with_name('rules.yar')
if shutil.which('yara'):
    output=subprocess.run(['yara',str(rules),str(p)],capture_output=True,text=True,timeout=15,check=True).stdout
    result['yara_matches']=[line.split(' ',1)[0] for line in output.splitlines()]
    result['yara_status']='completed; indicator rules, not a malware verdict'
else:
    result['yara_status']='unavailable; not executed'
print(json.dumps(result,indent=2))
