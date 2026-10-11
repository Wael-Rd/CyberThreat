import json, os, socket, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if (ROOT/'.docker-host').exists(): os.environ['DOCKER_HOST']=(ROOT/'.docker-host').read_text().strip()
def run(args): return subprocess.check_output(args,cwd=ROOT,text=True,timeout=20)
ids=run(['docker','compose','ps','-q']).split()
assert len(ids)==2
configs=json.loads(run(['docker','inspect',*ids]))
summary=[]
for c in configs:
    h=c['HostConfig']; service=c['Config']['Labels']['com.docker.compose.service']
    assert h['Memory']==(128 if service=='target' else 384)*1024*1024
    assert not h['Privileged'] and h['ReadonlyRootfs'] and h['CapDrop']==['ALL']
    assert not h.get('PortBindings') and h['NetworkMode']!='host'
    assert not any('docker.sock' in m['Source'] for m in c['Mounts'])
    summary.append({'service':service,'memory_bytes':h['Memory'],'cpu_nanocpus':h['NanoCpus'],'read_only':True,'published_ports':False,'cap_add':h.get('CapAdd')})
def connect():
    try:
        with socket.create_connection(('1.1.1.1',443),timeout=3): return True
    except OSError: return False
host=connect()
probe="import socket,json\ntry:\n s=socket.create_connection(('1.1.1.1',443),timeout=3); s.close(); ok=True\nexcept OSError: ok=False\nprint(json.dumps({'connected':ok}))"
station=json.loads(run(['docker','compose','exec','-T','station','python3','-c',probe]))['connected']
assert not station, 'Unexpected outbound connectivity from station'
probes={}
probe_code=(ROOT/'scripts/container_probe.py').read_text()
for service in ('target','station'):
    probe=json.loads(run(['docker','compose','exec','-T',service,'python3','-c',probe_code]))
    for name in ('no_new_privs','seccomp_filter','rootfs_write_denied','mount_namespace_denied','samples_write_denied','docker_socket_absent','ipv6_disabled'):
        assert probe[name], f'{service}: {name} failed'
    assert int(probe['cap_effective'],16)==(0 if service=='target' else 1<<13)
    probes[service]=probe
worker=json.loads(run(['docker','compose','exec','-T','--user','65534:65534','station','python3','-c',probe_code]))
assert worker['uid']==65534 and int(worker['cap_effective'],16)==0
write_probe="from pathlib import Path\ntry:\n Path("+repr('/evidence/'+Path(sys.argv[1]).parent.name+'/static-write-probe')+").write_text('probe'); print('WRITABLE')\nexcept PermissionError: print('DENIED')"
assert run(['docker','compose','exec','-T','--user','65534:65534','station','python3','-c',write_probe]).strip()=='DENIED'
worker['evidence_write_denied']=True
probes['static_worker']=worker
network=json.loads(run(['docker','network','inspect','malware-analysis-lab_lab']))[0]
gateway=network['IPAM']['Config'][0]['Gateway']
with socket.socket() as listener:
    listener.bind((gateway,0)); listener.listen(2); port=listener.getsockname()[1]
    with socket.create_connection((gateway,port),timeout=3): pass
    peer,_=listener.accept(); peer.close()
    for service in ('target','station'):
        guard_probe="import socket,json\ntry:\n s=socket.create_connection(("+repr(gateway)+","+str(port)+"),timeout=2); s.close(); ok=True\nexcept OSError: ok=False\nprint(json.dumps({'connected':ok}))"
        connected=json.loads(run(['docker','compose','exec','-T',service,'python3','-c',guard_probe]))['connected']
        assert not connected, 'Host sentinel reachable from '+service
result={'container_probes':probes,'host_sentinel_denied':True,'containers':summary,'host_external_connection':host,'station_external_connection':station,'egress_test':'denied with reachable host baseline' if host else 'denied; host baseline unavailable, configuration separately verified'}
Path(sys.argv[1]).write_text(json.dumps(result,indent=2))
print('PASS runtime: memory limits, no published ports, read-only rootfs, outbound connection denied')
