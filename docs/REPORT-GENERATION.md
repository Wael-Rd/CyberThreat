# Report generation

The technical report is generated from the reference descriptor `evidence/reference.json`. It embeds its images and diagrams and remains readable offline.

## Dependencies

Install Chromium separately, then install the report-specific Python dependencies:

```bash
python3 -m venv .report-venv
.report-venv/bin/pip install -r scripts/report-requirements.txt
```

These dependencies are separate from the minimal MCP environment. The scripts use `/usr/bin/chromium`; adjust that explicit executable path for a different installation.

## Rebuild

```bash
.report-venv/bin/python scripts/report_visuals.py evidence/run-<UTC>
.report-venv/bin/python scripts/create_pdf_report.py evidence/run-<UTC>
.report-venv/bin/python tests/test_report.py
python3 scripts/validate_delivery.py
```

For a new published reference, update `evidence/reference.json`, the tracked-run exception in `.gitignore`, source-derived README values and the reference file manifests. A normal new lab run is not automatically a new publication.

## Visual provenance

- Wireshark figures are real GUI screenshots in the reference run.
- Dashboard figures are browser captures of the recorded evidence.
- Nmap, Netcat, TShark and MCP views render recorded text artifacts; they do not simulate a live terminal.
- Architecture, workflow, permissions and sequence diagrams explain the implemented configuration.
- HTTP response and memory plots use `results.json` and `evidence-summary.json`.

The PDF build checks content boundaries against every footer. Its tests verify page count, embedded images, tagged structure, linked contents, reference values and absence of private workstation links. Generated previews are in `docs/assets/report/`.
