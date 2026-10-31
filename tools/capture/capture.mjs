#!/usr/bin/env node
/**
 * Browser capture harness: runs the REAL collector (resources/js/collector) in real browsers
 * against a local server that implements the challenge and claims endpoints, and writes one
 * raw run file per browser/mode. `engine-report.php` then runs the engine over every run.
 *
 *   npm run capture                       every browser this machine has, headed and headless
 *   npm run capture -- --browsers=chrome,firefox --mode=headed
 *   npm run capture -- --out=capture-out --machine=my-laptop
 *
 * Options
 *   --browsers=a,b   chromium, chrome, msedge, firefox, webkit, safari (default: all of them;
 *                    one that is not installed is reported "not installed" and skipped)
 *   --mode=...       headless | headed | both (default both). Headed needs a display; on Linux
 *                    without DISPLAY the harness re-runs itself under `xvfb-run` when that
 *                    exists, otherwise it falls back to headless and records that.
 *   --variants=...   honest,automation: for headed Chromium runs, `automation` keeps the
 *                    driver's default automation switches, `honest` suppresses them. Firefox and
 *                    WebKit have no suppressible switches: one headed run, labelled automation
 *                    (default both)
 *   --out=dir        output directory (default tools/capture/out/<timestamp>)
 *   --machine=name   a label for this machine (default: a hash of hostname + hardware; the
 *                    hostname itself is never written)
 *   --timeout=ms     per-run wait for both envelopes (default 45000)
 *   --no-report      skip the engine step
 *
 * Playwright browsers: `npx playwright install chromium firefox webkit` (the pinned version).
 * Real Chrome and Edge are used through Playwright's `chrome` and `msedge` channels when they
 * are installed. Real Safari goes through `safaridriver` (macOS: `sudo safaridriver --enable`,
 * then Safari > Develop > Allow Remote Automation).
 */
import { build } from 'vite';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { arch, cpus, hostname, release, tmpdir, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startCaptureServer } from './server.mjs';
import { safaridriverAvailable, startSafari } from './webdriver.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');

const args = Object.fromEntries(
    process.argv.slice(2).map((arg) => {
        const [key, ...rest] = arg.replace(/^--/, '').split('=');
        return [key, rest.length > 0 ? rest.join('=') : 'true'];
    }),
);
const list = (value, fallback) => (value ? String(value).split(',').map((s) => s.trim()).filter(Boolean) : fallback);
const wantedBrowsers = list(args.browsers, ['chromium', 'chrome', 'msedge', 'firefox', 'webkit', 'safari']);
const mode = args.mode ?? 'both';
const variants = list(args.variants, ['honest', 'automation']);
const timeoutMs = Number(args.timeout ?? 45000);
if (!['headless', 'headed', 'both'].includes(mode)) {
    console.error(`--mode must be headless, headed or both (got ${mode})`);
    process.exit(2);
}

// ------------------------------------------------------------------ display
const hasDisplay = platform() !== 'linux' || Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
const wantsHeaded = mode !== 'headless';
if (wantsHeaded && !hasDisplay && !process.env.CAPTURE_XVFB && spawnSync('xvfb-run', ['--help'], { stdio: 'ignore' }).status === 0) {
    console.log('No display: re-running under xvfb-run so headed browsers can start.');
    const again = spawnSync('xvfb-run', ['-a', '-s', '-screen 0 1920x1080x24', process.execPath, ...process.argv.slice(1)], {
        stdio: 'inherit',
        env: { ...process.env, CAPTURE_XVFB: '1' },
    });
    process.exit(again.status ?? 1);
}
const displayKind = platform() !== 'linux' ? 'native' : process.env.CAPTURE_XVFB ? 'xvfb' : hasDisplay ? 'x11' : 'none';
const canRunHeaded = displayKind !== 'none';

// ------------------------------------------------------------------ machine
const osName = { linux: 'linux', win32: 'windows', darwin: 'macos' }[platform()] ?? platform();
const machineId = String(
    args.machine ??
        createHash('sha256')
            .update([hostname(), platform(), arch(), cpus()[0]?.model ?? ''].join('|'))
            .digest('hex')
            .slice(0, 12),
);
const machine = { id: machineId, os: osName, os_release: release(), arch: arch(), cpu_count: cpus().length, node: process.version, display: displayKind };

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const outDir = resolve(args.out ?? join(HERE, 'out', stamp));
mkdirSync(join(outDir, 'runs'), { recursive: true });

// ------------------------------------------------------------------ build the page
const distDir = mkdtempSync(join(tmpdir(), 'device-id-capture-'));
await build({
    root: join(HERE, 'page'),
    configFile: false,
    logLevel: 'warn',
    base: '/',
    build: { outDir: distDir, emptyOutDir: true, minify: true, target: 'es2022' },
});

const policy = JSON.parse(spawnSync('php', [join(HERE, 'policy.php')], { encoding: 'utf8' }).stdout || 'null');
if (!policy) {
    console.error('php tools/capture/policy.php failed: PHP is required for the challenge policy');
    process.exit(2);
}
const server = await startCaptureServer({ distDir, disabledProbes: policy.disabled_probes });

// ------------------------------------------------------------------ plan
const playwright = await import('playwright');
const playwrightVersion = JSON.parse(readFileSync(join(ROOT, 'node_modules', 'playwright', 'package.json'), 'utf8')).version;
/**
 * Playwright's headless Chromium sends no Accept-Language unless a locale is set; every real
 * browser sends one, so the harness sets the system locale (a harness artefact, not a finding).
 */
const locale = Intl.DateTimeFormat().resolvedOptions().locale || 'en-US';
const CHROMIUM_QUIET = { ignoreDefaultArgs: ['--enable-automation'], args: ['--disable-blink-features=AutomationControlled'] };

/** @returns {Array<object>} */
function plan() {
    const out = [];
    const modes = [];
    if (mode !== 'headed') modes.push('headless');
    if (mode !== 'headless') modes.push('headed');
    for (const name of wantedBrowsers) {
        for (const m of modes) {
            if (name === 'safari') {
                if (m === 'headless') continue; // Safari has no headless mode
                out.push({ name, mode: 'headed', variant: 'default' });
            } else if (m === 'headless') {
                out.push({ name, mode: 'headless', variant: 'default' });
            } else {
                // Only Chromium has switches that can be suppressed; Firefox and WebKit driven by
                // Playwright always report an automated browser, so they have one headed variant.
                const set = PW[name]?.type === 'chromium' ? variants : variants.includes('automation') ? ['automation'] : [];
                for (const variant of set) out.push({ name, mode: 'headed', variant });
            }
        }
    }
    return out;
}

const PW = {
    chromium: { type: 'chromium', engine: 'chromium', channel: undefined },
    chrome: { type: 'chromium', engine: 'chromium', channel: 'chrome' },
    msedge: { type: 'chromium', engine: 'chromium', channel: 'msedge' },
    firefox: { type: 'firefox', engine: 'gecko', channel: undefined },
    webkit: { type: 'webkit', engine: 'webkit', channel: undefined },
};

/** Labels the dataset carries. `basis` says how the label was established. */
function labelsFor(item) {
    if (item.mode === 'headless') return { class: 'headless', basis: 'harness-declared: headless launch' };
    if (item.name === 'safari') return { class: 'automation', basis: 'harness-declared: driven by safaridriver (navigator.webdriver cannot be hidden)' };
    if (item.variant === 'automation') return { class: 'automation', basis: 'harness-declared: headed, driver default automation switches' };
    return { class: 'honest', basis: 'harness-declared: headed, automation switches suppressed where the driver allows; still driven by Playwright' };
}

async function runPlaywright(item) {
    const spec = PW[item.name];
    const launch = { channel: spec.channel, headless: item.mode === 'headless' };
    if (item.mode === 'headed' && item.variant === 'honest' && spec.type === 'chromium') Object.assign(launch, CHROMIUM_QUIET);
    const browser = await playwright[spec.type].launch(launch);
    try {
        const context = await browser.newContext({ locale, ...(item.mode === 'headed' ? { viewport: null } : {}) });
        const page = await context.newPage();
        const version = browser.version();
        server.beginRun();
        await page.goto(`${server.origin}/`, { waitUntil: 'load' });
        const run = await server.waitForRun(timeoutMs);
        return { version, driver: `playwright ${playwrightVersion}`, run };
    } finally {
        await browser.close().catch(() => undefined);
    }
}

async function runSafari() {
    const safari = await startSafari();
    try {
        server.beginRun();
        await safari.navigate(`${server.origin}/`);
        const run = await server.waitForRun(timeoutMs);
        return { version: safari.version, driver: 'safaridriver', run };
    } finally {
        await safari.quit().catch(() => undefined);
    }
}

const NOT_INSTALLED = /Executable doesn't exist|is not found at|distribution .* is not found|ENOENT|browserType\.launch: Failed to launch.*not found/i;

// ------------------------------------------------------------------ run
const summary = [];
let hardFailures = 0;
for (const item of plan()) {
    const id = [machineId, osName, item.name, item.mode, item.variant].join('.');
    const tag = `${item.name} ${item.mode}${item.variant === 'default' ? '' : ` (${item.variant})`}`;
    if (item.mode === 'headed' && !canRunHeaded) {
        summary.push({ id, status: 'skipped', reason: 'no display and no xvfb-run' });
        console.log(`SKIP  ${tag}: no display and no xvfb-run`);
        continue;
    }
    if (item.name === 'safari' && !safaridriverAvailable()) {
        summary.push({ id, status: 'not installed', reason: 'safaridriver exists only on macOS' });
        console.log(`SKIP  ${tag}: safaridriver not available`);
        continue;
    }
    const started = Date.now();
    try {
        const result = item.name === 'safari' ? await runSafari() : await runPlaywright(item);
        const run = result.run;
        const slots = run.claimRequests.map((c) => c.slot);
        const complete = slots.includes('tier1') && slots.includes('tier2');
        const record = {
            schema: 'device-id.capture-run',
            schema_version: 1,
            id,
            captured_at: new Date().toISOString(),
            machine,
            browser: {
                name: item.name,
                channel: PW[item.name]?.channel ?? null,
                engine: PW[item.name]?.engine ?? 'webkit',
                version: result.version,
                driver: result.driver,
                mode: item.mode === 'headless' ? 'headless' : displayKind === 'xvfb' ? 'headed-xvfb' : 'headed',
                variant: item.variant,
                locale: item.name === 'safari' ? null : locale,
            },
            labels: labelsFor(item),
            collector: { envelope_version: run.claimRequests[0]?.envelope?.v ?? null, probe_set: run.claimRequests[0]?.envelope?.probes ?? null, disabled_probes: policy.disabled_probes },
            complete,
            outcome: run.outcome,
            navigation: run.navigation,
            claim_requests: run.claimRequests,
            elapsed_ms: Date.now() - started,
        };
        writeFileSync(join(outDir, 'runs', `${id}.json`), `${JSON.stringify(record, null, 1)}\n`);
        summary.push({ id, status: complete ? 'captured' : 'incomplete', version: result.version, slots });
        console.log(`${complete ? 'OK   ' : 'WARN '} ${tag}: ${result.version}, envelopes: ${slots.join(',') || 'none'}`);
        if (!complete) hardFailures++;
    } catch (error) {
        const message = error instanceof Error ? error.message.split('\n')[0] : String(error);
        if (NOT_INSTALLED.test(message)) {
            summary.push({ id, status: 'not installed', reason: message });
            console.log(`SKIP  ${tag}: not installed`);
        } else {
            summary.push({ id, status: 'failed', reason: message });
            console.log(`FAIL  ${tag}: ${message}`);
            hardFailures++;
        }
    }
}

await server.close();
rmSync(distDir, { recursive: true, force: true });
writeFileSync(join(outDir, 'harness.json'), `${JSON.stringify({ machine, mode, wantedBrowsers, variants, summary }, null, 1)}\n`);
console.log(`\nRaw runs written to ${outDir}`);

let reportStatus = 0;
if (args['no-report'] === undefined) {
    reportStatus = spawnSync('php', [join(HERE, 'engine-report.php'), outDir], { stdio: 'inherit' }).status ?? 1;
}

// One file the owner can send back: reports, dataset and raw runs. `tar` ships with Windows 10+,
// macOS and Linux; without it the folder itself is the thing to send.
const bundle = `${outDir}.tar.gz`;
const packed = spawnSync('tar', ['-czf', bundle, '-C', dirname(outDir), outDir.split(/[\\/]/).pop()], { stdio: 'ignore' });
console.log(packed.status === 0 ? `\nSend back: ${bundle}` : `\nSend back the folder: ${outDir}`);

if (hardFailures > 0) {
    console.error(`${hardFailures} run(s) failed or were incomplete.`);
}
process.exit(hardFailures > 0 || reportStatus !== 0 ? 1 : 0);
