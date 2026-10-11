#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .docker-host ]]; then export DOCKER_HOST="$(cat .docker-host)"; fi
case "${1:-help}" in
  doctor) docker version; docker compose version; docker compose config --quiet ;;
  build)
    if ! docker image inspect malware-analysis-lab-tools-base > /dev/null 2>&1; then
      docker build --network host -f station/Dockerfile.tools -t malware-analysis-lab-tools-base station
    fi
    docker compose build
    ;;
  up) mkdir -p evidence; docker compose up -d --wait; python3 scripts/host_guard.py apply ;;
  run)
    docker compose up -d --wait
    python3 scripts/host_guard.py apply
    run="run-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir "evidence/$run"
    chmod 775 "evidence/$run"
    sudo -n chgrp 0 "evidence/$run"
    docker compose config > "evidence/$run/compose-resolved.yaml"
    docker network inspect malware-analysis-lab_lab > "evidence/$run/network.json"
    docker compose exec -T -e LAB_RUN="$run" station python3 /app/run.py
    for phase in vulnerable hardened; do
      docker compose exec -T --user 1000:1000 station tcpdump -nn -r "/evidence/$run/$phase.pcap" > "evidence/$run/$phase-tcpdump.txt" 2>&1
    done
    docker compose exec -T --user 65534:65534 station python3 /app/triage.py /samples/harmless-training.txt > "evidence/$run/triage.json"
    docker compose exec -T -e LAB_RUN="$run" station python3 /app/analyze.py
    docker compose ps > "evidence/$run/containers.txt"
    docker stats --no-stream $(docker compose ps -q) > "evidence/$run/resources.txt"
    python3 scripts/runtime_checks.py "evidence/$run/runtime-checks.json"
    python3 scripts/verify.py "evidence/$run"
    (cd "evidence/$run"; sha256sum *.pcap *.json *.jsonl *.txt *.tsv *.xml *.html *.md > SHA256SUMS)
    echo "Preuves : $PWD/evidence/$run"
    ;;
  down) docker compose down; python3 scripts/host_guard.py remove ;;
  *) echo "Usage: $0 {doctor|build|up|run|down}" ;;
esac
