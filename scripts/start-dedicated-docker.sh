#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Optional standalone engine; no changes to the main engine's data root.
if timeout 5 docker -H unix:///tmp/malware-lab-docker.sock info >/dev/null 2>&1; then
  printf 'unix:///tmp/malware-lab-docker.sock\n' > .docker-host
  exit 0
fi
sudo -n sh -c 'nohup dockerd --host unix:///tmp/malware-lab-docker.sock --data-root "$1/.docker-data" --exec-root /tmp/malware-lab-exec --pidfile /tmp/malware-lab-docker.pid --bridge none --default-address-pool base=172.31.0.0/16,size=24 > /tmp/malware-lab-dockerd.log 2>&1 &' sh "$PWD"
printf 'unix:///tmp/malware-lab-docker.sock\n' > .docker-host
for attempt in {1..30}; do
  if timeout 3 docker -H unix:///tmp/malware-lab-docker.sock info >/dev/null 2>&1; then exit 0; fi
  sleep 1
done
echo 'Docker not ready: inspect /tmp/malware-lab-dockerd.log' >&2
exit 1
