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
    assert not errors, errors
    browser.close()
(run/'dashboard-tests.json').write_text(json.dumps({'checks':7,'alerts':6,'phase_switch':True,'untrusted_html_not_executed':True,'javascript_errors':errors},indent=2))
print('PASS dashboard: real results, phase switch, embedded HTML injection inert, screenshots saved')
