"""Camoufox (Firefox-based anti-detect browser) through its Python package.

    python rt_camoufox.py <headless|headed> <url>

Needs the browser downloaded once with `python -m camoufox fetch`. Prints one JSON line, then
keeps the browser until stdin closes.
"""
import json
import sys

from camoufox.sync_api import Camoufox

mode, url = sys.argv[1:3]
with Camoufox(headless=(mode == 'headless'), os='linux', locale='en-US') as browser:
    page = browser.new_page()
    page.goto(url, wait_until='load')
    print(json.dumps({'version': browser.version, 'driver': 'camoufox (python package)'}), flush=True)
    sys.stdin.read()
