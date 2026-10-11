<div align="center">

<img src="docs/assets/cyberthreat-banner.svg" alt="CyberThreat: network detection, evidence analysis and MCP integration" width="100%">

<br>

**Threat Analysis: controlled network scenarios, verifiable evidence and scoped MCP tools.**

[Quick start](#quick-start) · [Architecture](#architecture) · [Technical report](docs/reports/CyberThreat-Technical-Report.pdf) · [Reference evidence](evidence/run-20261011T231915Z) · [MCP integration](docs/AI-MCP.md)

</div>

## Overview

CyberThreat captures controlled attack traffic, correlates network observations with application events, and compares vulnerable and hardened service behaviour. It runs two resource-limited Docker containers and exposes a local MCP server for evidence inspection and static file triage from OpenCode.

The illustrated [technical report](docs/reports/CyberThreat-Technical-Report.pdf) contains **25 pages**, **16 numbered figures**, architecture diagrams, tool-output views and real Wireshark captures.

The repository includes executable scenarios, packet captures, detection rules, application logs, an interactive evidence explorer and an illustrated technical report. Results are tied to a recorded reference run rather than illustrative output.

| Capability | Implementation |
|---|---|
| Network reconnaissance | Bounded Nmap TCP connect scan and Netcat service verification |
| Packet analysis | dumpcap capture, TShark field extraction, tcpdump inspection and Wireshark |
| Controlled scenarios | Port reconnaissance, repeated authentication attempts and SQL injection |
| Mitigation comparison | Parameterised SQL and source-based authentication rate limiting |
| File triage | SHA-256, file type, entropy, strings, URI indicators and YARA |
| Agent integration | Five scoped MCP tools with a restricted OpenCode agent |

## Reference results

| Measurement | Recorded result |
|---|---|
| Functional assertions | **7 passed** |
| Detection output | **6 alerts** across 3 rule families and 2 phases |
| Evidence | **2 PCAP files**, tool and interface screenshots, JSON/JSONL, TSV and Nmap XML |
| Container memory limits | **512 MiB** combined |
| Container CPU limits | **1.25 CPU** combined |
| Recorded service memory | **26.01 MiB** in the recorded post-scenario snapshot, excluding Docker and WSL2 |
| MCP validation | SDK calls and native OpenCode connection verified |

Reference: [`run-20261011T231915Z`](evidence/run-20261011T231915Z). The published snapshot includes a [SHA-256 manifest](evidence/run-20261011T231915Z/SHA256SUMS) and [publication notes](evidence/run-20261011T231915Z/PUBLICATION-NOTES.md).

<details>
<summary><strong>View the comparison dashboard</strong></summary>

![Hardened-phase observations and static triage results](evidence/run-20261011T231915Z/dashboard-hardened.png)

Clone the repository and open `START-HERE.html` or the reference run's `dashboard.html` locally. GitHub displays HTML source instead of running these interfaces.

</details>

## Quick start

Use Linux or WSL2 with a local Docker Engine, Docker Compose, Python 3.10+, `sudo`, `iptables` and `iproute2`. The supplied services assume UID 1000. Adjust IDs and filesystem permissions for other accounts.

Clone into the **Linux filesystem**, such as `~/CyberThreat`. Windows-mounted paths can prevent the expected Unix permission checks. Internet access is required while building images.

```bash
git clone https://github.com/Wael-Rd/CyberThreat.git
cd CyberThreat

./scripts/lab.sh doctor
./scripts/lab.sh build
./scripts/lab.sh up
./scripts/lab.sh run
```

`up` applies the host bridge guard. The scripts require Docker access and non-interactive `sudo` for firewall operations. The validated runtime uses a local Docker Engine inside WSL2; host filtering with Docker Desktop has not been verified.

Each run creates `evidence/run-<UTC>/` with its captures, results, alerts, dashboard and integrity manifest. Newly generated runs are ignored by Git. Use one active checkout per Docker engine and avoid concurrent scenario execution.

```bash
# Stop project services and remove the dedicated host firewall rule
./scripts/lab.sh down
```

For an already installed but stopped local Docker Engine, the optional `scripts/start-dedicated-docker.sh` starts a project-specific daemon. It requires passwordless `sudo`, uses ignored local storage, and is not a Docker Desktop launcher. See the [operations runbook](docs/RUNBOOK.md).

## Architecture

![Implemented architecture and network boundary](docs/assets/report/architecture.svg)


```mermaid
flowchart LR
    Client[OpenCode] <-->|Local MCP stdio| MCP[Scoped orchestration]
    subgraph Network[Internal Docker network]
        Station[Analysis station] -->|TCP and HTTP| Target[Synthetic HTTP target]
    end
    MCP -->|Fixed commands| Station
    Station --> Evidence[PCAP, events and results]
    Target --> Evidence
    Evidence --> MCP
```

| Service | RAM limit | CPU limit | PID limit | Function |
|---|---:|---:|---:|---|
| `target` | 128 MiB | 0.50 | 64 | Synthetic HTTP service and in-memory SQLite |
| `station` | 384 MiB | 0.75 | 128 | Traffic generation, capture, detection and static triage |

The MCP server runs on the trusted host, outside the containers. No Docker socket is mounted into either service. The station captures its own traffic to the target. The Docker daemon, build cache and WSL2 consume resources beyond these service limits.

## Evidence explorer

The standalone dashboard provides a frame-linked HTTP timeline, phase comparison, rule and text filters, recorded Nmap output and JSON export. Packet counts, durations and hashes are derived from the PCAP files. Memory is labelled as a post-scenario snapshot, not an idle benchmark.

![Frame-linked HTTP timeline](evidence/run-20261011T231915Z/http-timeline.png)

## Detection and mitigation

| Scenario | Detection evidence | Vulnerable behaviour | Hardened behaviour |
|---|---|---|---|
| TCP reconnaissance | 101 distinct destination ports; `SCAN_PORTS` | HTTP service discovered on 8080 | Reconnaissance remains visible |
| Authentication burst | Repeated failure events; `LOGIN_BURST` | Six 401 responses, then successful login | Three 401 responses, followed by 429 |
| SQL injection | Decoded request URI; `SQLI_PATTERN` | Two synthetic usernames returned | Empty result using parameterised SQL |

Baseline requests and legitimate lookups continue to work in both phases. The rate limiter also temporarily blocks a correct password after the burst, exposing an availability trade-off.

Detection and prevention are evaluated separately: a request signature identifies an attempt; the response confirms its effect. Alerts persist after mitigation because blocked attempts remain observable. These are scenario-specific offline rules, not a production IDS benchmark.

## OpenCode integration

```bash
python3 -m venv .venv
.venv/bin/pip install -r mcp_server/requirements.txt

opencode mcp list
opencode --agent threat-analyst
```

The repository-local configuration launches `scripts/mcp-stdio.sh`, which prefers the virtual environment's Python. OpenCode retains its existing model provider configuration. The project contains no API credentials. Local samples are ignored by Git; only the inert fixture is published.

| MCP tool | Scope |
|---|---|
| `lab_status` | Read the project's service state |
| `run_detection_demo` | Execute the fixed scenarios with a concurrency lock |
| `list_evidence` | Enumerate available run identifiers |
| `read_evidence` | Read an allowlisted artifact with validated path and size |
| `static_triage` | Inspect an allowed local file without executing it |

The `threat-analyst` agent permits only this server's tools. Extracted file content is untrusted data. Path traversal, symlinks, arbitrary artifact requests and oversized samples are rejected. No general shell tool or arbitrary scan destination is exposed.

The published validation covers SDK calls and native OpenCode connectivity. It does not include a hosted LLM analysis session. See [MCP configuration and trust boundaries](docs/AI-MCP.md).

## Validation

```bash
# Independent checks without Docker
.venv/bin/python tests/test_triage.py
.venv/bin/python tests/test_mcp.py
.venv/bin/python tests/test_evidence_summary.py
python3 scripts/validate_delivery.py

# Full MCP scenario after building and starting the services
.venv/bin/python tests/test_mcp.py --docker --demo

# Inspect a generated run
python3 scripts/verify.py evidence/run-<UTC>
python3 scripts/runtime_checks.py evidence/run-<UTC>/runtime-checks.json
python3 scripts/sandbox_audit.py evidence/run-<UTC>/sandbox-audit.json
```

The CI workflow checks Python source, static triage, MCP stdio behaviour, PCAP metadata, report structure and publication integrity. Docker isolation checks are recorded separately in the reference evidence. GUI tests require Chromium and Playwright; Wireshark screenshot conversion also requires ImageMagick.

## Illustrated analysis

<table><tr><td width="50%"><img src="docs/assets/report/sql-mitigation.svg" alt="SQL injection effects before and after parameterisation"></td><td width="50%"><img src="docs/assets/report/mcp-sequence.svg" alt="Scoped MCP call sequence and trust boundaries"></td></tr></table>

Diagrams explain the implementation. Charts use recorded responses and resource snapshots; tool-output views reproduce actual artifacts. Figure provenance is documented in [report assets](docs/assets/report/provenance.json).

## Isolation model

- Internal network, no published service ports, read-only roots, seccomp and `no-new-privileges`.
- No effective capabilities on the target; only `NET_RAW` for capture on the station.
- Static worker runs as UID/GID 65534, with no effective capabilities or evidence-write permission.
- Host sentinel access and external station connections were denied in recorded runtime checks.
- Static triage refuses to run when the host bridge guard is absent.

Containers share the WSL2 kernel. This is not VM isolation or a guarantee against container escape. The host administrator, Docker daemon and MCP server remain trusted. Unknown files are inspected statically, never executed.

Synthetic HTTP credentials are deliberately visible in the captures. TLS and production authentication are outside this lab's implementation. The mode-switch endpoint `/control` is a test mechanism. See [security validation](docs/SECURITY-VALIDATION.md), [threat model](docs/THREAT-MODEL.md) and [security scope](SECURITY.md).

## Repository layout

```text
CyberThreat/
├── station/          Scenario runner, detection, capture, triage and dashboard
├── target/           Synthetic HTTP application
├── mcp_server/       Local stdio server and pinned SDK requirement
├── samples/          Inert training fixture
├── scripts/          Operations, validation, screenshots and report generation
├── tests/            MCP, triage and interface checks
├── evidence/         Published reference run
├── docs/             Architecture, operations and technical report
├── compose.yaml      Runtime network and resource configuration
└── opencode.json     Restricted local agent configuration
```

## Documentation

| Document | Purpose |
|---|---|
| [Technical report](docs/reports/CyberThreat-Technical-Report.pdf) | Architecture, methodology, findings and limitations |
| [Analysis](docs/FINAL-REPORT.md) | Detailed interpretation of the recorded scenarios |
| [Operations runbook](docs/RUNBOOK.md) | Start, capture, inspect and stop the lab |
| [Validation workflow](docs/VALIDATION-WORKFLOW.md) | Reproducible investigation and verification stages |
| [MCP integration](docs/AI-MCP.md) | Client setup, tool scope and trust boundaries |
| [Security validation](docs/SECURITY-VALIDATION.md) | Runtime controls and observed results |
| [Report generation](docs/REPORT-GENERATION.md) | Source data, visual provenance and rebuild commands |
| [Publication checks](docs/PUBLICATION-CHECKS.md) | Validation scope of the repository snapshot |

Technical references: [Docker Compose](https://docs.docker.com/reference/compose-file/), [TShark](https://www.wireshark.org/docs/man-pages/tshark), [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), [OpenCode MCP](https://docs.opencode.ai/docs/mcp-servers/).
