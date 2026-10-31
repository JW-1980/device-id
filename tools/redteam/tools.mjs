/**
 * The red-team tool registry: every free stealth / anti-detect tool the harness drives.
 * `launch(dir, mode, url)` is the command that starts one run; the driver prints one JSON line
 * {"version","driver"} on stdout and keeps the browser open until its stdin closes.
 */
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const drivers = join(HERE, 'drivers');

export function chromePath() {
    if (process.env.REDTEAM_CHROME) return process.env.REDTEAM_CHROME;
    const root = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';
    if (!existsSync(root)) return null;
    const found = readdirSync(root).filter((d) => d.startsWith('chromium-')).sort().pop();
    if (!found) return null;
    const folder = readdirSync(join(root, found)).find((d) => d.startsWith('chrome-linux'));
    return folder ? join(root, found, folder, 'chrome') : null;
}

/** A chromedriver that matches the Chromium (`<dir>/chromedriver/chromedriver`, see install.sh), else the one on PATH. */
export function chromedriverPath(dir) {
    if (process.env.REDTEAM_CHROMEDRIVER) return process.env.REDTEAM_CHROMEDRIVER;
    if (existsSync(join(dir, 'chromedriver', 'chromedriver'))) return join(dir, 'chromedriver', 'chromedriver');
    for (const d of (process.env.PATH || '').split(':')) if (existsSync(join(d, 'chromedriver'))) return join(d, 'chromedriver');
    return '';
}

const node = (tool) => (dir, mode, url) => ({ cmd: process.execPath, args: [join(drivers, 'node-driver.mjs'), tool, mode, url, dir] });
const py = (dir) => join(dir, 'venv', 'bin', 'python');
const hasNodePackage = (name) => (dir) => existsSync(join(dir, 'node', 'node_modules', name));
const hasPythonPackage = (name) => (dir) => {
    const lib = join(dir, 'venv', 'lib');
    return existsSync(lib) && readdirSync(lib).some((v) => existsSync(join(lib, v, 'site-packages', name)));
};

export const TOOLS = {
    /** Not an attack: the same Chromium, plainly driven. The matcher comparison needs an honest browser of the same machine. */
    baseline: { baseline: true, engine: 'chromium', requires: () => true, launch: node('baseline') },
    'puppeteer-extra-stealth': { engine: 'chromium', requires: hasNodePackage('puppeteer-extra-plugin-stealth'), launch: node('puppeteer-extra-stealth') },
    'rebrowser-puppeteer': { engine: 'chromium', requires: hasNodePackage('rebrowser-puppeteer-core'), launch: node('rebrowser-puppeteer') },
    patchright: { engine: 'chromium', requires: hasNodePackage('patchright-core'), launch: node('patchright') },
    'playwright-stealth-script': { engine: 'chromium', requires: () => true, launch: node('playwright-stealth-script') },
    'playwright-stealth-py': {
        engine: 'chromium',
        requires: hasPythonPackage('playwright_stealth'),
        launch: (dir, mode, url) => ({ cmd: py(dir), args: [join(drivers, 'rt_playwright_stealth.py'), mode, url, chromePath()] }),
    },
    nodriver: {
        engine: 'chromium',
        requires: hasPythonPackage('nodriver'),
        launch: (dir, mode, url) => ({ cmd: py(dir), args: [join(drivers, 'rt_nodriver.py'), mode, url, chromePath()] }),
    },
    'undetected-chromedriver': {
        engine: 'chromium',
        requires: hasPythonPackage('undetected_chromedriver'),
        launch: (dir, mode, url) => ({ cmd: py(dir), args: [join(drivers, 'rt_uc.py'), mode, url, chromePath(), chromedriverPath(dir)] }),
    },
    camoufox: {
        engine: 'gecko',
        requires: () => existsSync(join(process.env.HOME || '', '.cache', 'camoufox', 'version.json')),
        launch: (dir, mode, url) => ({ cmd: py(dir), args: [join(drivers, 'rt_camoufox.py'), mode, url] }),
    },
};
