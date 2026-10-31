"""undetected-chromedriver: patched chromedriver, the installed Chromium.

    python rt_uc.py <headless|headed> <url> <chrome-path> <chromedriver-path>

Prints one JSON line, then keeps the browser until stdin closes.
"""
import json
import os
import sys

import undetected_chromedriver as uc

mode, url, chrome, driver_path = sys.argv[1:5]
options = uc.ChromeOptions()
options.binary_location = chrome
options.add_argument('--no-sandbox')
options.add_argument('--lang=en-US')
if mode == 'headless':
    options.add_argument('--headless=new')
    if os.environ.get('REDTEAM_UA'):
        options.add_argument('--user-agent=' + os.environ['REDTEAM_UA'])
driver = uc.Chrome(options=options, driver_executable_path=driver_path, browser_executable_path=chrome, use_subprocess=True)
driver.get(url)
print(json.dumps({'version': driver.capabilities.get('browserVersion', 'unknown'), 'driver': 'undetected-chromedriver ' + getattr(uc, '__version__', '3.5.5') + ' / chromedriver ' + driver.capabilities.get('chrome', {}).get('chromedriverVersion', '?').split(' ')[0]}), flush=True)
sys.stdin.read()
driver.quit()
