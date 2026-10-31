"""Python Playwright + playwright-stealth (the Python port of the puppeteer-extra evasions).

    python rt_playwright_stealth.py <headless|headed> <url> <chrome-path>
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

mode, url, chrome = sys.argv[1:4]
with Stealth().use_sync(sync_playwright()) as p:
    browser = p.chromium.launch(executable_path=chrome, headless=(mode == 'headless'), args=['--no-sandbox'] + (['--user-agent=' + os.environ['REDTEAM_UA']] if mode == 'headless' and os.environ.get('REDTEAM_UA') else []))
    context = browser.new_context(locale='en-US', **({} if mode == 'headless' else {'no_viewport': True}))
    page = context.new_page()
    page.goto(url, wait_until='load')
    print(json.dumps({'version': browser.version, 'driver': 'playwright-stealth (python)'}), flush=True)
    sys.stdin.read()
    browser.close()
