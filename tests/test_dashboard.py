import hashlib,json,sys
from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; run=Path(sys.argv[1]).resolve()
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-gpu'])
    page=browser.new_page(viewport={'width':1440,'height':1600})
    errors=[]; page.on('pageerror',lambda e: errors.append(str(e)))
    page.goto((run/'dashboard.html').as_uri())
    assert page.locator('#checks').inner_text()=='7'
    assert page.locator('#alerts').inner_text()=='6'
    assert 'analyst' in page.locator('#observations').inner_text()
    page.screenshot(path=str(run/'dashboard-vulnerable.png'),full_page=True)
    page.locator('#hardened').click()
    assert '429' in page.locator('#observations').inner_text()
    assert '{"users":[]}' in page.locator('#observations').inner_text()
    page.locator('summary').first.click()
    assert '</script><img' in page.locator('#strings').inner_text()
    assert page.locator('img').count()==0 and page.evaluate('window.labInjected === undefined')
    page.screenshot(path=str(run/'dashboard-hardened.png'),full_page=True)
    page.locator('#rule-filter').select_option('SQLI_PATTERN')
    assert page.locator('#detections .alertitem').count()==1
    page.locator('#alert-search').fill('no-such-evidence')
    assert page.locator('#detections .alertitem').count()==0
    page.locator('#alert-search').fill('')
    page.locator('#rule-filter').select_option('all')
    assert page.locator('#detections .alertitem').count()==3
    assert page.locator('#timeline tr').count()==11
    assert page.locator('#packets').inner_text().isdigit()
    with page.expect_download() as event:
        page.locator('#export-summary').click()
    download=event.value
    exported=json.loads(Path(download.path()).read_text())
    assert exported['phase']=='hardened'
    assert exported['results']['sql_injection'][1]['users']==[]
    assert exported['evidence']['pcap']['packets']>0
    assert len(exported['alerts'])==3
    page.locator('div.row').screenshot(path=str(run/'investigation-hardened.png'))
    page.locator('#requests').screenshot(path=str(run/'http-timeline.png'))
    page.locator('#tools').screenshot(path=str(run/'tool-nmap-dashboard.png'))
    page.locator('#vulnerable').click()
    page.locator('div.row').screenshot(path=str(run/'investigation-vulnerable.png'))
    page.evaluate('data.security.host_sentinel_denied=false;renderSecurity()')
    assert 'NON VALIDÉ' in page.locator('#security-status').inner_text()
    page.evaluate('data.security.host_sentinel_denied=true;renderSecurity()')
    assert not errors, errors
    browser.close()
(run/'dashboard-tests.json').write_text(json.dumps({'checks':7,'alerts':6,'phase_switch':True,'untrusted_html_not_executed':True,'alert_filtering':True,'summary_export':True,'http_timeline':True,'javascript_errors':errors},indent=2))
print('PASS dashboard: real results, phase switch, embedded HTML injection inert, screenshots saved')
