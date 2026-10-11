# Publication validation

Validated locally on 12 October 2026. The reference is selected by `evidence/reference.json`.

## Runtime and transport

- Full controlled scenario through the real MCP SDK: passed after rebranding.
- Seven application assertions and six alerts: passed.
- Native OpenCode connection: `cyberthreat` connected.
- Docker state and static triage through MCP: passed.
- Traversal, shell metacharacters, symlinks, oversized samples and arbitrary artifacts: rejected.
- Host guard missing: triage refused; guard restored and call succeeded.
- Kernel/runtime controls: recorded in `runtime-checks.json` and `sandbox-audit.json`.

## Interface and evidence

- Browser phase switch, rule filter, text search and JSON export: passed.
- HTTP timeline linked to the recorded packet frames: verified.
- Embedded HTML control: inert; no injected image or script marker.
- A failed host-sentinel flag is displayed as unvalidated rather than successful.
- PCAP hashes and metadata match the recorded files; truncated inputs are rejected.
- Memory is reported as a post-scenario snapshot, not an idle benchmark.

## Report and packaging

- 25 A4 pages with 16 numbered figures and embedded diagrams.
- No content overlaps the page footers.
- Tagged PDF with linked contents, at least ten raster images and correct reference values.
- No private workstation links or long dash character in extracted PDF text.
- README links, vector assets and file manifests verified offline.

The Docker scenarios and host-isolation checks were performed in the Linux working checkout, not the Windows-mounted publication folder. CI checks static triage, MCP stdio, capture metadata, report structure and publication integrity. Hosted LLM reasoning and Burp GUI traffic are outside the validation scope.

A targeted publication scan excludes provider-token markers, private keys, databases, Docker storage and workstation home paths. It is not an exhaustive secret-detection guarantee.
