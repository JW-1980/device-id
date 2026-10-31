/**
 * Node-side attacker drivers. One process = one tool = one run:
 *
 *   node node-driver.mjs <tool> <headless|headed> <url> <redteam-dir>
 *
 * Prints one JSON line {"version","driver"} once the page is loading, keeps the browser open until
 * its stdin closes (the orchestrator closes it when the harness has both envelopes), then exits.
 * Each tool is configured the way its own README tells an attacker to use it, with the stealth
 * features ON. Tools live in <redteam-dir>/node (a scratch directory, never a repo dependency).
 */
import { createRequire } from 'node:module';
import { readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const [tool, mode, url, dir] = process.argv.slice(2);
const require = createRequire(join(dir, 'node', 'package.json'));
const headless = mode === 'headless';
const repoRequire = createRequire(join(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..'), 'package.json'));

function chromiumPath() {
    const root = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';
    const found = readdirSync(root).filter((d) => d.startsWith('chromium-')).sort().pop();
    const folder = readdirSync(join(root, found)).find((d) => d.startsWith('chrome-linux'));
    return join(root, found, folder, 'chrome');
}
const executablePath = process.env.REDTEAM_CHROME || chromiumPath();
const ARGS = ['--no-sandbox', '--disable-blink-features=AutomationControlled', ...(headless && process.env.REDTEAM_UA ? [`--user-agent=${process.env.REDTEAM_UA}`] : [])];

/** The init script every "playwright stealth" gist ships, in its common form. */
const COMMON_STEALTH = `
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
window.chrome = window.chrome || { runtime: {} };
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => parameters.name === 'notifications'
    ? Promise.resolve({ state: Notification.permission }) : originalQuery(parameters);
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function (p) {
    if (p === 37445) return 'Intel Inc.';
    if (p === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.call(this, p);
};
`;

async function viaPuppeteer(lib, extra) {
    const puppeteer = extra ? extra(require(lib)) : require(lib);
    const browser = await puppeteer.launch({ executablePath, headless, args: ARGS, defaultViewport: headless ? undefined : null });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'load' });
    return { browser, version: await browser.version() };
}

async function viaPlaywright(lib, init, req = require) {
    const { chromium } = req(lib);
    const browser = await chromium.launch({ executablePath, headless, args: ARGS });
    const context = await browser.newContext({ locale: 'en-US', ...(headless ? {} : { viewport: null }) });
    if (init) await context.addInitScript(init);
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'load' });
    return { browser, version: browser.version() };
}

const tools = {
    baseline: async () => {
        const r = await viaPlaywright('playwright', null, repoRequire);
        return { ...r, driver: 'playwright (pinned), honest baseline' };
    },
    'puppeteer-extra-stealth': async () => {
        const { addExtra } = require('puppeteer-extra');
        const Stealth = require('puppeteer-extra-plugin-stealth');
        const r = await viaPuppeteer('puppeteer-core', (core) => addExtra(core).use(Stealth()));
        return { ...r, driver: `puppeteer-extra ${require('puppeteer-extra/package.json').version} + stealth ${require('puppeteer-extra-plugin-stealth/package.json').version}` };
    },
    'rebrowser-puppeteer': async () => {
        const r = await viaPuppeteer('rebrowser-puppeteer-core');
        return { ...r, driver: `rebrowser-puppeteer-core ${require('rebrowser-puppeteer-core/package.json').version}` };
    },
    patchright: async () => {
        const r = await viaPlaywright('patchright-core');
        return { ...r, driver: `patchright-core ${require('patchright-core/package.json').version}` };
    },
    'playwright-stealth-script': async () => {
        const r = await viaPlaywright('playwright', COMMON_STEALTH, repoRequire);
        return { ...r, driver: 'playwright (pinned) + common stealth init script' };
    },
};

const run = tools[tool];
if (!run) {
    console.error(`unknown node tool ${tool}`);
    process.exit(2);
}
const { browser, version, driver } = await run();
console.log(JSON.stringify({ version, driver }));
process.stdin.resume();
process.stdin.on('end', async () => {
    await browser.close().catch(() => undefined);
    process.exit(0);
});
