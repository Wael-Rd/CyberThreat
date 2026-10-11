"""Project-scoped host firewall guard; no global flush or default-policy change."""
import json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if (ROOT/'.docker-host').exists(): os.environ['DOCKER_HOST']=(ROOT/'.docker-host').read_text().strip()
CHAIN='MALAB_HOST_GUARD'
def command(args,check=True): return subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=15,check=check)
def ip(*args,check=True): return command(['sudo','-n','iptables','-w','5',*args],check)
if sys.argv[1]=='apply':
    n=json.loads(command(['docker','network','inspect','malware-analysis-lab_lab']).stdout)[0]
    assert n['Internal'] and n['Labels'].get('com.docker.compose.project')=='malware-analysis-lab'
    bridge='br-'+n['Id'][:12]
    ip('-N',CHAIN,check=False)
    # This private chain is owned solely by this project.
    ip('-F',CHAIN)
    ip('-A',CHAIN,'-i',bridge,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
    ip('-A',CHAIN,'-i',bridge,'-j','DROP')
    ip('-A',CHAIN,'-j','RETURN')
    if ip('-C','INPUT','-j',CHAIN,check=False).returncode:
        ip('-I','INPUT','1','-j',CHAIN)
    print(json.dumps({'host_guard':True,'bridge':bridge,'chain':CHAIN}))
elif sys.argv[1]=='check':
    n=json.loads(command(['docker','network','inspect','malware-analysis-lab_lab']).stdout)[0]
    bridge='br-'+n['Id'][:12]
    assert n['Internal']
    ip('-C','INPUT','-j',CHAIN)
    ip('-C',CHAIN,'-i',bridge,'-j','DROP')
    print('Host guard active')
elif sys.argv[1]=='remove':
    ip('-D','INPUT','-j',CHAIN,check=False)
    ip('-F',CHAIN,check=False); ip('-X',CHAIN,check=False)
else: raise ValueError('Expected apply or remove')
