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
import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { existsSync, readdirSync } from 'node:fs';
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

/**
 * Lightpanda (https://github.com/lightpanda-io/browser): not Chromium. The binary lives in
 * <redteam-dir>/lightpanda/lightpanda (or LIGHTPANDA_BIN); it serves CDP and puppeteer-core connects to it.
 * Its own User-Agent and Sec-CH-UA cannot be set to a Mozilla/Chrome string (the CLI and
 * Emulation.setUserAgentOverride refuse any value containing "Mozilla"), so the spoofed variant does what
 * an attacker does: an init script that rewrites navigator.* and navigator.userAgentData, and a local HTTP
 * proxy that rewrites the User-Agent and Sec-CH-UA request headers.
 */
const CHROME_UA = process.env.REDTEAM_UA || 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36';
const SPOOF_NAVIGATOR = `
(() => {
    const ua = ${JSON.stringify(CHROME_UA)};
    const major = /Chrome\\/(\\d+)/.exec(ua)[1];
    const def = (o, k, v) => Object.defineProperty(o, k, { get: () => v, configurable: true });
    def(Navigator.prototype, 'userAgent', ua);
    def(Navigator.prototype, 'appVersion', ua.replace('Mozilla/', ''));
    def(Navigator.prototype, 'vendor', 'Google Inc.');
    const brands = [{ brand: 'Chromium', version: major }, { brand: 'Google Chrome', version: major }, { brand: 'Not.A/Brand', version: '99' }];
    const data = { brands, mobile: false, platform: 'Linux', toJSON() { return { brands, mobile: false, platform: 'Linux' }; },
        getHighEntropyValues: async () => ({ brands, mobile: false, platform: 'Linux', architecture: 'x86', bitness: '64', model: '', platformVersion: '6.8.0', uaFullVersion: major + '.0.0.0', fullVersionList: brands }) };
    def(Navigator.prototype, 'userAgentData', data);
    window.chrome = { runtime: {}, loadTimes() {}, csi() {}, app: {} };
})();
`;

async function startRewritingProxy() {
    const proxy = createServer((req, res) => {
        const target = new URL(req.url);
        const headers = { ...req.headers, 'user-agent': CHROME_UA, host: target.host };
        const major = /Chrome\/(\d+)/.exec(CHROME_UA)[1];
        headers['sec-ch-ua'] = `"Chromium";v="${major}", "Google Chrome";v="${major}", "Not.A/Brand";v="99"`;
        delete headers['sec-ch-ua-full-version-list'];
        const upstream = httpRequest({ host: target.hostname, port: target.port, path: target.pathname + target.search, method: req.method, headers }, (r) => {
            res.writeHead(r.statusCode ?? 502, r.headers);
            r.pipe(res);
        });
        upstream.on('error', () => res.writeHead(502).end());
        req.pipe(upstream);
    });
    await new Promise((ok) => proxy.listen(0, '127.0.0.1', ok));
    return proxy;
}

async function viaLightpanda(spoof) {
    const binary = process.env.LIGHTPANDA_BIN || join(dir, 'lightpanda', 'lightpanda');
    if (!existsSync(binary)) throw new Error(`lightpanda binary not found at ${binary}`);
    const port = 9300 + Math.floor(Math.random() * 500);
    const proxy = spoof ? await startRewritingProxy() : null;
    const child = spawn(binary, ['serve', '--host', '127.0.0.1', '--port', String(port), ...(proxy ? ['--http-proxy', `http://127.0.0.1:${proxy.address().port}`] : [])], {
        // libcurl honours NO_PROXY even with --http-proxy, and the capture server is on loopback.
        stdio: 'ignore', env: { ...process.env, LIGHTPANDA_DISABLE_TELEMETRY: 'true', NO_PROXY: '', no_proxy: '' },
    });
    let browser = null;
    for (let n = 0; n < 40 && !browser; n++) {
        await new Promise((ok) => setTimeout(ok, 250));
        browser = await require('puppeteer-core').connect({ browserWSEndpoint: `ws://127.0.0.1:${port}` }).catch(() => null);
    }
    if (!browser) {
        child.kill('SIGKILL');
        throw new Error('lightpanda CDP server did not start');
    }
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    if (spoof) {
        await page.setUserAgent(CHROME_UA).catch(() => undefined);
        await page.evaluateOnNewDocument(SPOOF_NAVIGATOR);
    }
    page.goto(url, { waitUntil: 'load' }).catch(() => undefined);
    const version = (await browser.version().catch(() => 'Lightpanda')) || 'Lightpanda';
    const handle = { close: async () => { await browser.disconnect().catch(() => undefined); child.kill('SIGKILL'); proxy?.close(); } };
    return { browser: handle, version };
}

const tools = {
    lightpanda: async () => ({ ...(await viaLightpanda(false)), driver: 'lightpanda via puppeteer-core CDP, default user agent' }),
    'lightpanda-spoofed': async () => ({ ...(await viaLightpanda(true)), driver: 'lightpanda via puppeteer-core CDP, Chrome UA spoofed (init script + rewriting proxy)' }),
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
