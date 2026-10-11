# Publication validation

Validated locally on 12 October 2026 from the publication checkout.

- Static triage test: passed (known SHA-256, inert indicators, no execution, empty file).
- Real MCP SDK stdio: passed; five tools and rejected traversal, shell metacharacters, symlink, oversized file and arbitrary artefact requests.
- Native OpenCode MCP: malware-analysis-lab connected using the portable wrapper.
- Published reference scenario: seven functional checks and six alerts verified.
- Reference evidence SHA-256 manifest: all files match.
- README local links: all resolve.
- Publication scan: no recognised provider-token/private-key markers, local engine storage or workstation home paths included. This is a targeted scan, not an exhaustive secret-detection guarantee.
- Report: 13 A4 pages, authors WAEL RDIFI and RIM MENZLI, class SSIR-5-F; no long dash character in extracted PDF text; no footer overlap.

The Docker scenarios and host-isolation tests were recorded in the Linux working checkout. They were not rerun from the Windows-mounted publication folder. The CI workflow validates source and SDK behaviour only; its hosted result must be checked after publication. No hosted LLM call was performed.
