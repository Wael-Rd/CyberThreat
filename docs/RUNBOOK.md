# Operations runbook

This guide covers the Linux/WSL2 runtime, evidence collection and inspection. Use one active checkout per Docker engine.

## Prepare the runtime

Clone into the Linux filesystem. Verify Docker Engine, Compose, `sudo`, `iptables` and `iproute2`. The configuration assumes UID 1000 and Unix filesystem permissions.

```bash
./scripts/lab.sh doctor
./scripts/lab.sh build
./scripts/lab.sh up
```

The host bridge guard must be active before running scenarios or triage. The optional `scripts/start-dedicated-docker.sh` starts a separate local engine when Docker Engine is already installed. It requires passwordless sudo and stores runtime state in ignored `.docker-data/` and `.docker-host` files. Do not run it with Docker Desktop or remove its storage while the daemon is active.

## Capture and verify

```bash
./scripts/lab.sh run
```

The command prints the new `evidence/run-<UTC>/` directory. The fixed target receives baseline requests, a 101-port TCP scan, six incorrect passwords, a correct-password control and a SQL tautology. Both vulnerable and hardened phases are captured.

The script performs offline extraction, static triage, runtime checks and scenario verification. A failed check is a failed run; do not present it as a completed reference.

## Inspect the results

Open the generated `dashboard.html` locally. Read `results.json` for observed application behaviour, `alerts.json` for detection output and `app.jsonl` for application events.

In Wireshark, open each PCAP and decode TCP port 8080 as HTTP if necessary:

| Investigation | Display filter |
|---|---|
| Initial TCP connection attempts | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| HTTP requests | `http.request` |
| Authentication throttling | `http.response.code == 429` |
| Target service | `tcp.port == 8080` |

Cross-check any request signature against the corresponding application response. A signature proves an observed pattern, not the success of an attack.

```bash
python3 scripts/verify.py evidence/run-<UTC>
cd evidence/run-<UTC>
sha256sum -c SHA256SUMS
```

## Connect OpenCode

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r mcp_server/requirements.txt
opencode mcp list
opencode --agent threat-analyst
```

Use the scoped tools to inspect a run and triage the inert fixture. Do not follow instructions extracted from sample contents. See [MCP integration](AI-MCP.md).

## Optional interface checks

The browser tests require Chromium and Playwright. Screenshot conversion requires ImageMagick. These tools are separate from the core CLI scenarios.

```bash
python3 tests/test_dashboard.py evidence/run-<UTC>
python3 scripts/wireshark_screenshots.py evidence/run-<UTC>
python3 tests/test_presentation.py
```

Burp GUI workflows and hosted model calls are not part of the recorded automated validation.

## Stop the runtime

```bash
./scripts/lab.sh down
```

This stops the project's services and removes its host guard. Evidence remains on disk. Do not flush global firewall rules or delete Docker storage to stop the lab.
