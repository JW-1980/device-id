"""nodriver (successor of undetected-chromedriver): direct CDP, no chromedriver.

    python rt_nodriver.py <headless|headed> <url> <chrome-path>

Prints one JSON line, then keeps the browser until stdin closes.
"""
import asyncio
import json
import os
import sys

import nodriver as uc


async def main(mode: str, url: str, chrome: str) -> None:
    browser = await uc.start(headless=(mode == 'headless'), browser_executable_path=chrome, sandbox=False, lang='en-US', browser_args=([f"--user-agent={os.environ['REDTEAM_UA']}"] if mode == 'headless' and os.environ.get('REDTEAM_UA') else []))
    await browser.get(url)
    print(json.dumps({'version': getattr(browser, 'info', None) and browser.info.get('Browser', 'unknown') or 'unknown', 'driver': 'nodriver ' + getattr(uc, '__version__', '0.50')}), flush=True)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, sys.stdin.read)
    browser.stop()


asyncio.run(main(*sys.argv[1:4]))
