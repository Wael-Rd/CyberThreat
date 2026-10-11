# Security scope

This repository is a local educational lab with synthetic attack scenarios and static file triage. It is not intended for executing unknown malware or exposing the MCP server remotely.

Docker shares the host kernel. The host, Docker daemon and MCP code are trusted. See [security validation](docs/SECURITY-VALIDATION.md) for tested controls and their limits.

Do not add API keys, private samples, real credentials or runtime Docker data to the repository. Published PCAP credentials belong only to the synthetic fixture.

Report suspected defects through the repository security contact available on GitHub, without including secrets or private sample data.
