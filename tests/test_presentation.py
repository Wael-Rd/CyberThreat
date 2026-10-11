from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-gpu'])
 page=browser.new_page(); errors=[]
 page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto((root/'START-HERE.html').as_uri())
 for href in page.locator('a').evaluate_all('(els)=>els.map(e=>e.getAttribute("href"))'):
  assert (root/href).is_file(),href
 page.goto((root/'presentation.html').as_uri())
 assert page.locator('section').count()==10
 page.keyboard.press('ArrowRight'); assert page.locator('#count').inner_text()=='2 / 10'
 page.keyboard.press('ArrowLeft'); assert page.locator('#count').inner_text()=='1 / 10'
 assert not errors,errors
 browser.close()
print('PASS presentation: links exist, ten slides, keyboard navigation, no JavaScript errors')
