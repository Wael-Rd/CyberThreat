# Investigation and validation workflow

The workflow separates generated traffic, observed indicators and verified effects.

| Stage | Action | Output | Acceptance criterion |
|---|---|---|---|
| 1. Scope | Define fixed target, resource limits and network boundary | Compose and threat model | Two services, internal network, no published ports |
| 2. Baseline | Check health and legitimate lookup | Application response records | Service and normal lookup work in both phases |
| 3. Reconnaissance | Scan the bounded TCP port set and verify HTTP | Nmap XML/TXT and Netcat output | Port observations preserved |
| 4. Collection | Capture controlled traffic and application events | PCAP and JSONL | Both phases have nonempty captures |
| 5. Correlation | Extract SYN/HTTP fields and evaluate rules | TSV, alerts and results | Three rule families per phase; seven assertions pass |
| 6. Review | Validate runtime controls and package evidence | Runtime checks, screenshots, report and hashes | Checks pass; limits and provenance are explicit |

## Detection interpretation

- A port scan can be legitimate inventory activity. It does not establish compromise.
- Failed authentication attempts identify a burst. Success is checked separately.
- An injection signature identifies the request pattern. The response demonstrates the resulting data exposure or prevention.
- Mitigation does not remove the attempted behaviour from the capture.

## Reference snapshot

The published run is `run-20261011T224758Z`. Runtime network checks, evidence integrity and MCP SDK tests are distinct validations. The publication checkout also verifies portable OpenCode connectivity.

The CI checks static triage, MCP stdio and reference checksums. It does not validate WSL2 host isolation, hosted model reasoning or Burp GUI behaviour.

See [operations](RUNBOOK.md), [security validation](SECURITY-VALIDATION.md) and [publication checks](PUBLICATION-CHECKS.md).
