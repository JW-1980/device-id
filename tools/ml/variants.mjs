#!/usr/bin/env node
/**
 * Generates labelled training runs with the REAL collector: honest context variants and
 * stealth/spoof variants, in the same raw run format as tools/capture/capture.mjs, so
 * `tools/ml/make-dataset.php` turns them into dataset records.
 *
 *   npm run ml:variants -- --out=tools/ml/out/variants [--only=recipe,recipe] [--machine=name]
 *
 * ## Labels
 *
 *   honest  Chromium headed, automation switches suppressed, with an ordinary browser context
 *           option (locale + timezone, viewport, scale factor, colour scheme, reduced motion).
 *           Still driven by Playwright (declared in `basis`): the harness has no human.
 *   spoof   a recipe that makes the browser claim something it is not, written as plain init
 *           scripts or context options. They are the COMMON evasions (what puppeteer-extra-stealth
 *           and Camoufox-style tools do), re-implemented in a few lines each; no stealth library
 *           is installed, so the recipes are a lower bound on a real tool, not a copy of one.
 *   headless / automation  the stock modes, so the model sees the baseline next to the evasions.
 *
 * Firefox and WebKit driven by Playwright report an automated browser and the engine has no tell
 * for it, so their runs are labelled `automation` (as tools/capture does), never `honest`.
 */
import { build } from 'vite';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { arch, cpus, hostname, release, tmpdir, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startCaptureServer } from '../capture/server.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const args = Object.fromEntries(process.argv.slice(2).map((a) => { const [k, ...r] = a.replace(/^--/, '').split('='); return [k, r.length ? r.join('=') : 'true']; }));
const only = args.only ? new Set(String(args.only).split(',')) : null;
const timeoutMs = Number(args.timeout ?? 45000);

if (platform() === 'linux' && !process.env.DISPLAY && !process.env.CAPTURE_XVFB && spawnSync('xvfb-run', ['--help'], { stdio: 'ignore' }).status === 0) {
    const again = spawnSync('xvfb-run', ['-a', '-s', '-screen 0 1920x1080x24', process.execPath, ...process.argv.slice(1)], { stdio: 'inherit', env: { ...process.env, CAPTURE_XVFB: '1' } });
    process.exit(again.status ?? 1);
}
const displayKind = platform() !== 'linux' ? 'native' : process.env.CAPTURE_XVFB ? 'xvfb' : 'x11';
const machineId = String(args.machine ?? createHash('sha256').update([hostname(), platform(), arch(), cpus()[0]?.model ?? ''].join('|')).digest('hex').slice(0, 12));
const machine = { id: machineId, os: { linux: 'linux', win32: 'windows', darwin: 'macos' }[platform()] ?? platform(), os_release: release(), arch: arch(), cpu_count: cpus().length, node: process.version, display: displayKind };
const outDir = resolve(args.out ?? join(HERE, 'out', 'variants'));
mkdirSync(join(outDir, 'runs'), { recursive: true });

// ---------------------------------------------------------------- init scripts (the evasions)
const defineGetter = `const __g = (o, k, v) => { try { Object.defineProperty(o, k, { get: () => v, configurable: true }); } catch (e) {} };`;
const SCRIPTS = {
    // Delete the webdriver flag: the classic first evasion.
    webdriverDeleted: `try { delete Navigator.prototype.webdriver; } catch (e) {}`,
    // Redefine it on the instance (what most stealth plugins do).
    webdriverFalse: `${defineGetter} __g(navigator, 'webdriver', false);`,
    platformWin32: `${defineGetter} __g(navigator, 'platform', 'Win32');`,
    platformMac: `${defineGetter} __g(navigator, 'platform', 'MacIntel');`,
    languagesPatched: `${defineGetter} __g(navigator, 'languages', ['de-DE', 'de']); __g(navigator, 'language', 'de-DE');`,
    cores8Memory8: `${defineGetter} __g(navigator, 'hardwareConcurrency', 8); __g(navigator, 'deviceMemory', 8);`,
    fakePlugins: `${defineGetter} __g(navigator, 'plugins', [{ name: 'Chrome PDF Plugin' }, { name: 'Chrome PDF Viewer' }, { name: 'Native Client' }]);`,
    chromeRuntime: `window.chrome = window.chrome || {}; window.chrome.runtime = window.chrome.runtime || {};`,
    permissionsPatched: `const q = navigator.permissions && navigator.permissions.query; if (q) navigator.permissions.query = (p) => p && p.name === 'notifications' ? Promise.resolve({ state: Notification.permission === 'default' ? 'prompt' : Notification.permission }) : q.call(navigator.permissions, p);`,
    webglVendor: `const patch = (proto) => { const get = proto.getParameter; proto.getParameter = function (p) { if (p === 37445) return 'Intel Inc.'; if (p === 37446) return 'Intel Iris OpenGL Engine'; return get.call(this, p); }; };
        if (window.WebGLRenderingContext) patch(WebGLRenderingContext.prototype); if (window.WebGL2RenderingContext) patch(WebGL2RenderingContext.prototype);`,
    screen1080: `${defineGetter} __g(screen, 'width', 1920); __g(screen, 'height', 1080); __g(screen, 'availWidth', 1920); __g(screen, 'availHeight', 1040);`,
    timezoneIntlOnly: `const orig = Intl.DateTimeFormat.prototype.resolvedOptions; Intl.DateTimeFormat.prototype.resolvedOptions = function () { const o = orig.call(this); o.timeZone = 'America/New_York'; return o; };`,
    canvasNoise: `const t = HTMLCanvasElement.prototype.toDataURL; HTMLCanvasElement.prototype.toDataURL = function (...a) { const c = this.getContext('2d'); if (c) { c.fillStyle = 'rgba(' + (Math.random() * 3 | 0) + ',0,0,0.01)'; c.fillRect(0, 0, 1, 1); } return t.apply(this, a); };`,
};
const stealthBundle = ['webdriverFalse', 'fakePlugins', 'chromeRuntime', 'permissionsPatched', 'webglVendor', 'cores8Memory8'].map((k) => SCRIPTS[k]).join('\n');

const UA = {
    winChrome: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36',
    macChrome: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36',
    winFirefox: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0',
    iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    macSafari: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
};

/**
 * @typedef {{ id: string, engine: 'chromium'|'firefox'|'webkit', klass: string, basis: string, headless?: boolean, quiet?: boolean, context?: object, script?: string, firefoxPrefs?: object, device?: string }} Recipe
 * @type {Recipe[]}
 */
const RECIPES = [
    // ---- honest context variants: Chromium headed, switches suppressed, ordinary context options
    ...[
        ['ctx-nl', { locale: 'nl-NL', timezoneId: 'Europe/Amsterdam' }],
        ['ctx-de', { locale: 'de-DE', timezoneId: 'Europe/Berlin' }],
        ['ctx-gb', { locale: 'en-GB', timezoneId: 'Europe/London' }],
        ['ctx-fr', { locale: 'fr-FR', timezoneId: 'Europe/Paris' }],
        ['ctx-us', { locale: 'en-US', timezoneId: 'America/New_York' }],
        ['ctx-dsf2', { deviceScaleFactor: 2, viewport: { width: 1440, height: 900 } }],
        ['ctx-dark', { colorScheme: 'dark' }],
        ['ctx-reduced-motion', { reducedMotion: 'reduce' }],
        ['ctx-viewport-1366', { viewport: { width: 1366, height: 768 } }],
        ['ctx-viewport-2560', { viewport: { width: 2560, height: 1440 } }],
    ].map(([id, context]) => ({ id, engine: 'chromium', klass: 'honest', quiet: true, context, basis: `harness-declared: headed, switches suppressed, context option ${id}; driven by Playwright` })),
    // ---- stock headless, to set the baseline
    { id: 'stock-headless', engine: 'chromium', klass: 'headless', headless: true, basis: 'harness-declared: headless launch' },
    { id: 'stock-headless', engine: 'firefox', klass: 'headless', headless: true, basis: 'harness-declared: headless launch' },
    { id: 'stock-headless', engine: 'webkit', klass: 'headless', headless: true, basis: 'harness-declared: headless launch' },
    // ---- spoof: user-agent only (context option, headers and navigator.userAgent change together)
    { id: 'ua-windows-chrome', engine: 'chromium', klass: 'spoof', quiet: true, context: { userAgent: UA.winChrome }, basis: 'harness-declared: user agent overridden to Windows Chrome' },
    { id: 'ua-macos-chrome', engine: 'chromium', klass: 'spoof', quiet: true, context: { userAgent: UA.macChrome }, basis: 'harness-declared: user agent overridden to macOS Chrome' },
    { id: 'ua-iphone-safari', engine: 'chromium', klass: 'spoof', quiet: true, context: { userAgent: UA.iphone }, basis: 'harness-declared: user agent overridden to iPhone Safari' },
    { id: 'ua-firefox', engine: 'chromium', klass: 'spoof', quiet: true, context: { userAgent: UA.winFirefox }, basis: 'harness-declared: Chromium claiming to be Firefox' },
    { id: 'ua-chrome-on-firefox', engine: 'firefox', klass: 'spoof', context: { userAgent: UA.winChrome }, basis: 'harness-declared: Firefox claiming to be Chrome' },
    { id: 'ua-chrome-on-webkit', engine: 'webkit', klass: 'spoof', context: { userAgent: UA.winChrome }, basis: 'harness-declared: WebKit claiming to be Chrome' },
    { id: 'ua-safari-on-chromium', engine: 'chromium', klass: 'spoof', quiet: true, context: { userAgent: UA.macSafari }, basis: 'harness-declared: Chromium claiming to be Safari' },
    // ---- spoof: navigator patches written as init scripts
    { id: 'ua-and-platform-win', engine: 'chromium', klass: 'spoof', quiet: true, context: { userAgent: UA.winChrome }, script: SCRIPTS.platformWin32, basis: 'harness-declared: UA and navigator.platform patched to Windows' },
    { id: 'platform-only', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.platformMac, basis: 'harness-declared: navigator.platform patched to MacIntel' },
    { id: 'languages-patched', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.languagesPatched, basis: 'harness-declared: navigator.languages patched (Accept-Language unchanged)' },
    { id: 'cores-memory-patched', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.cores8Memory8, basis: 'harness-declared: hardwareConcurrency and deviceMemory patched' },
    { id: 'webgl-vendor-patched', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.webglVendor, basis: 'harness-declared: WebGL vendor and renderer patched to Intel' },
    { id: 'screen-1080-patched', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.screen1080, basis: 'harness-declared: screen size patched to 1920x1080' },
    { id: 'timezone-intl-only', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.timezoneIntlOnly, basis: 'harness-declared: Intl time zone patched, Date untouched' },
    { id: 'timezone-emulated', engine: 'chromium', klass: 'spoof', quiet: true, context: { timezoneId: 'Asia/Tokyo', locale: 'ja-JP' }, basis: 'harness-declared: time zone and locale emulated through the driver' },
    { id: 'canvas-noise', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.canvasNoise, basis: 'harness-declared: canvas read-back noised by an injected script' },
    { id: 'webdriver-deleted', engine: 'chromium', klass: 'spoof', quiet: true, script: SCRIPTS.webdriverDeleted, basis: 'harness-declared: navigator.webdriver deleted from the prototype' },
    { id: 'webdriver-deleted-headless', engine: 'chromium', klass: 'spoof', headless: true, script: SCRIPTS.webdriverDeleted, basis: 'harness-declared: headless with navigator.webdriver deleted' },
    // ---- spoof: stealth bundles (what puppeteer-extra-stealth-class tools combine)
    { id: 'stealth-bundle-headed', engine: 'chromium', klass: 'spoof', quiet: true, script: stealthBundle, basis: 'harness-declared: stealth bundle (webdriver, plugins, chrome.runtime, permissions, WebGL vendor, cores) on headed' },
    { id: 'stealth-bundle-headless', engine: 'chromium', klass: 'spoof', headless: true, script: stealthBundle, basis: 'harness-declared: stealth bundle on headless' },
    { id: 'stealth-bundle-headless-ua', engine: 'chromium', klass: 'spoof', headless: true, context: { userAgent: UA.winChrome }, script: `${stealthBundle}\n${SCRIPTS.platformWin32}`, basis: 'harness-declared: stealth bundle on headless with the HeadlessChrome token removed and Windows platform' },
    // ---- spoof: device emulation
    { id: 'emulate-pixel', engine: 'chromium', klass: 'spoof', quiet: true, device: 'Pixel 7', basis: 'harness-declared: Playwright device emulation (Pixel 7) on desktop Chromium' },
    { id: 'emulate-iphone', engine: 'webkit', klass: 'spoof', device: 'iPhone 14', basis: 'harness-declared: Playwright device emulation (iPhone 14) on desktop WebKit' },
    // ---- privacy mode (driven, so labelled automation)
    { id: 'firefox-rfp', engine: 'firefox', klass: 'automation', firefoxPrefs: { 'privacy.resistFingerprinting': true }, basis: 'harness-declared: Firefox resistFingerprinting on, driven by Playwright (marionette sets webdriver)' },
    { id: 'stock-headed', engine: 'firefox', klass: 'automation', basis: 'harness-declared: headed, driven by Playwright' },
    { id: 'stock-headed', engine: 'webkit', klass: 'automation', basis: 'harness-declared: headed, driven by Playwright' },
    { id: 'stock-headed-switches', engine: 'chromium', klass: 'automation', basis: 'harness-declared: headed, driver default automation switches' },
];

// ---------------------------------------------------------------- build the capture page once
const distDir = mkdtempSync(join(tmpdir(), 'device-id-variants-'));
await build({ root: join(ROOT, 'tools', 'capture', 'page'), configFile: false, logLevel: 'warn', base: '/', build: { outDir: distDir, emptyOutDir: true, minify: true, target: 'es2022' } });
const policy = JSON.parse(spawnSync('php', [join(ROOT, 'tools', 'capture', 'policy.php')], { encoding: 'utf8' }).stdout || 'null');
if (!policy) { console.error('php tools/capture/policy.php failed'); process.exit(2); }
const server = await startCaptureServer({ distDir, disabledProbes: policy.disabled_probes });
const playwright = await import('playwright');
const playwrightVersion = JSON.parse(readFileSync(join(ROOT, 'node_modules', 'playwright', 'package.json'), 'utf8')).version;
const quietArgs = { ignoreDefaultArgs: ['--enable-automation'], args: ['--disable-blink-features=AutomationControlled'] };

let failures = 0;
for (const recipe of RECIPES) {
    if (only && !only.has(recipe.id)) continue;
    const mode = recipe.headless ? 'headless' : 'headed';
    const id = [machineId, machine.os, recipe.engine, mode, recipe.id].join('.');
    const started = Date.now();
    try {
        const launch = { headless: Boolean(recipe.headless), ...(recipe.quiet && recipe.engine === 'chromium' ? quietArgs : {}), ...(recipe.firefoxPrefs ? { firefoxUserPrefs: recipe.firefoxPrefs } : {}) };
        const browser = await playwright[recipe.engine].launch(launch);
        try {
            const device = recipe.device ? playwright.devices[recipe.device] : {};
            const context = await browser.newContext({ locale: 'en-US', ...(recipe.headless ? {} : { viewport: null }), ...device, ...(recipe.context ?? {}) });
            if (recipe.script) await context.addInitScript(recipe.script);
            const page = await context.newPage();
            const version = browser.version();
            server.beginRun();
            await page.goto(`${server.origin}/`, { waitUntil: 'load' });
            const run = await server.waitForRun(timeoutMs);
            const slots = run.claimRequests.map((c) => c.slot);
            const complete = slots.includes('tier1') && slots.includes('tier2');
            const record = {
                schema: 'device-id.capture-run', schema_version: 1, id, captured_at: new Date().toISOString(), machine,
                browser: { name: recipe.engine, channel: null, engine: { chromium: 'chromium', firefox: 'gecko', webkit: 'webkit' }[recipe.engine], version, driver: `playwright ${playwrightVersion}`, mode: recipe.headless ? 'headless' : 'headed-xvfb', variant: recipe.id, locale: 'en-US' },
                labels: { class: recipe.klass, basis: recipe.basis },
                collector: { envelope_version: run.claimRequests[0]?.envelope?.v ?? null, probe_set: run.claimRequests[0]?.envelope?.probes ?? null, disabled_probes: policy.disabled_probes },
                complete, outcome: run.outcome, navigation: run.navigation, claim_requests: run.claimRequests, elapsed_ms: Date.now() - started,
            };
            writeFileSync(join(outDir, 'runs', `${id}.json`), `${JSON.stringify(record, null, 1)}\n`);
            console.log(`${complete ? 'OK  ' : 'WARN'} ${recipe.engine} ${mode} ${recipe.id} (${recipe.klass})`);
            if (!complete) failures++;
        } finally {
            await browser.close().catch(() => undefined);
        }
    } catch (error) {
        failures++;
        console.log(`FAIL ${recipe.engine} ${mode} ${recipe.id}: ${String(error instanceof Error ? error.message : error).split('\n')[0]}`);
    }
}
await server.close();
rmSync(distDir, { recursive: true, force: true });
console.log(`\nRuns written to ${join(outDir, 'runs')}; ${failures} failed or incomplete.`);
process.exit(failures > 0 ? 1 : 0);
