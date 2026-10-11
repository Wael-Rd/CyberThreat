"""Validate the published report against the reference and PDF structure."""
import json,sys
from pathlib import Path
from pypdf import PdfReader
ROOT=Path(__file__).resolve().parents[1]
meta=json.loads((ROOT/'docs/reports/report-validation.json').read_text())
reference=json.loads((ROOT/'evidence/reference.json').read_text())['run']
summary=json.loads((ROOT/'evidence'/reference/'evidence-summary.json').read_text())
reader=PdfReader(ROOT/'docs/reports/CyberThreat-Technical-Report.pdf')
assert len(reader.pages)==meta['pages']==25
text='\n'.join(p.extract_text() or '' for p in reader.pages)
assert chr(8212) not in text
assert 'Malware Analysis Lab' not in text
assert 'WAEL RDIFI' in text and 'RIM MENZLI' in text and 'SSIR-5-F' in text
assert reference in text
assert f"{summary['memory_snapshot_total_mib']:g}" in text
assert f"{sum(p['pcap']['packets'] for p in summary['phases'].values())}" in text
assert len(reader.pages[1].get('/Annots',[]))>=20
assert reader.trailer['/Root']['/MarkInfo']['/Marked']
image_count=sum(len(p.images) for p in reader.pages)
assert image_count>=10,image_count
for p in reader.pages:
    for a in p.get('/Annots',[]):
        a=a.get_object();action=a.get('/A',{})
        assert not str(action.get('/URI','')).startswith('file:'),'Private workstation path in PDF link'
assert not meta['footer_overlaps']
print(f'PASS report: 25 pages, {image_count} embedded images, tagged structure, linked contents, reference values and no private file links')
