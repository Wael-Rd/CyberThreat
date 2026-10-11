import json,os,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
if (root/'.docker-host').exists(): os.environ['DOCKER_HOST']=(root/'.docker-host').read_text().strip()
def cmd(args): return subprocess.check_output(args,cwd=root,text=True,timeout=30)
ids=cmd(['docker','compose','ps','-q']).split(); details=json.loads(cmd(['docker','inspect',*ids]))
checks=[]
for c in details:
    h=c['HostConfig']; service=c['Config']['Labels']['com.docker.compose.service']
    assert h['PidMode']!='host' and h['IpcMode']!='host'
    assert not h.get('Devices') and not h.get('DeviceRequests')
    assert h['PidsLimit']==(64 if service=='target' else 128)
    assert h['NanoCpus']==(500000000 if service=='target' else 750000000)
    assert len(h.get('MaskedPaths',[]))>0 and len(h.get('ReadonlyPaths',[]))>0
    mounts={m['Destination']:m for m in c['Mounts'] if m['Type']=='bind'}
    assert set(mounts)==({'/evidence'} if service=='target' else {'/evidence','/samples'})
    if service=='station': assert not mounts['/samples']['RW']
    checks.append({'service':service,'host_namespaces_absent':True,'host_devices_absent':True,'pids_limit':h['PidsLimit'],'cpu_limit':h['NanoCpus']/1e9,'mounts_allowlisted':True,'masked_kernel_paths':len(h['MaskedPaths'])})
result={'checks':checks,'kernel':cmd(['uname','-r']).strip(),'runc':cmd(['runc','--version']).splitlines()[0],'docker':cmd(['docker','version','--format','{{.Server.Version}}']).strip()}
Path(sys.argv[1]).write_text(json.dumps(result,indent=2)); print('PASS: namespaces, devices, CPU/PID limits, scoped mounts and masked kernel paths')
