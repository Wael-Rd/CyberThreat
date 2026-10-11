"""Derive a compact, reproducible view from fixed run artifacts."""
import csv, hashlib, json, re, struct
from pathlib import Path
import xml.etree.ElementTree as ET

def pcap_metrics(path):
    data=Path(path).read_bytes()
    formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
    if len(data)<24 or data[:4] not in formats:raise ValueError('Expected classic PCAP')
    endian,scale=formats[data[:4]]; offset=24; count=0; times=[]; captured=0
    while offset<len(data):
        if offset+16>len(data):raise ValueError('Truncated packet header')
        sec,fraction,length,original=struct.unpack(endian+'IIII',data[offset:offset+16]);offset+=16
        if length>original or offset+length>len(data):raise ValueError('Invalid packet length')
        times.append(sec+fraction/scale);captured+=length;count+=1;offset+=length
    return {'packets':count,'file_bytes':len(data),'captured_bytes':captured,'duration_seconds':round(max(times)-min(times),3) if times else 0,'sha256':hashlib.sha256(data).hexdigest()}

def parse_memory_snapshot(text):
    units={'B':1/1048576,'KiB':1/1024,'MiB':1,'GiB':1024,'TiB':1048576,'kB':1000/1048576,'MB':1000000/1048576,'GB':1000000000/1048576}
    memory=[]
    for line in text.splitlines()[1:]:
        if not line.strip():continue
        match=re.search(r'([0-9.]+)([A-Za-z]+)\s*/\s*([0-9.]+)([A-Za-z]+)',line)
        if not match or match[2] not in units or match[4] not in units:raise ValueError('Unrecognised memory snapshot units')
        memory.append({'service':'station' if 'station' in line else 'target','usage_mib':float(match[1])*units[match[2]],'limit_mib':float(match[3])*units[match[4]]})
    if {m['service'] for m in memory}!={'station','target'} or len(memory)!=2:raise ValueError('Expected two service memory records')
    return memory

def build_summary(out):
    out=Path(out);results=json.loads((out/'results.json').read_text());alerts=json.loads((out/'alerts.json').read_text())
    phases={}
    for mode in ['vulnerable','hardened']:
        with (out/f'{mode}-http.tsv').open() as f:rows=list(csv.DictReader(f,delimiter='\t'))
        origin=float(rows[0]['frame.time_epoch']) if rows else 0
        timeline=[{'frame':int(r['frame.number']),'seconds':round(float(r['frame.time_epoch'])-origin,3),'method':r['http.request.method'],'uri':r['http.request.uri']} for r in rows]
        scan=ET.parse(out/f'{mode}-nmap.xml').getroot()
        ports=[{'port':int(p.attrib['portid']),'state':p.find('state').attrib['state'],'service':p.find('service').attrib.get('name','unknown') if p.find('service') is not None else 'unknown'} for p in scan.findall('./host/ports/port')]
        phases[mode]={'pcap':pcap_metrics(out/f'{mode}.pcap'),'http_requests':len(rows),'timeline':timeline,'scan_ports':ports,'alerts':sum(a['mode']==mode for a in alerts),'login_statuses':results[mode]['failed_login_statuses']+[results[mode]['correct_login_after_attempts'][0]]}
    memory=parse_memory_snapshot((out/'resources.txt').read_text()) if (out/'resources.txt').exists() else []
    result={'schema_version':1,'run':out.name,'checks_passed':sum(results['checks'].values()),'checks_total':len(results['checks']),'alert_count':len(alerts),'phases':phases,'memory_snapshot':memory,'memory_snapshot_total_mib':round(sum(x['usage_mib'] for x in memory),2),'resource_note':'Snapshot captured at the end of the scenario; not an idle benchmark.'}
    (out/'evidence-summary.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    return result
if __name__=='__main__':
    import sys
    print(json.dumps(build_summary(sys.argv[1]),indent=2))
