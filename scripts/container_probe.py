"""Benign negative probes; no kernel exploit, no submitted sample execution."""
import ctypes, errno, json, os
from pathlib import Path
status=Path('/proc/self/status').read_text()
fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines() if ':' in line}
root_ro=False
try:
    Path('/app/security-write-probe').write_text('test')
except OSError as e: root_ro=e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)
libc=ctypes.CDLL(None,use_errno=True)
ret=libc.unshare(0x00020000) # CLONE_NEWNS, benign isolated child namespace request
mount_namespace_denied=ret==-1 and ctypes.get_errno()==errno.EPERM
sample_ro=True
if Path('/samples').exists():
    try: Path('/samples/security-write-probe').write_text('test'); sample_ro=False
    except OSError as e: sample_ro=e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)
result={'uid':os.getuid(),'no_new_privs':fields.get('NoNewPrivs')=='1','seccomp_filter':fields.get('Seccomp')=='2','cap_effective':fields.get('CapEff'),'rootfs_write_denied':root_ro,'mount_namespace_denied':mount_namespace_denied,'samples_write_denied':sample_ro,'docker_socket_absent':not Path('/var/run/docker.sock').exists(),'ipv6_disabled':Path('/proc/sys/net/ipv6/conf/all/disable_ipv6').read_text().strip()=='1'}
print(json.dumps(result))
