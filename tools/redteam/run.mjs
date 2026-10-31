#!/usr/bin/env node
/**
 * Red-team harness: drives free stealth / anti-detect tools against the capture harness (the real
 * collector, the real challenge/claims endpoints) and has the engine judge them.
 *
 *   npm run redteam -- --dir=/path/to/scratch     tools installed by `npm run redteam:install -- <dir>`
 *   npm run redteam -- --tools=nodriver,patchright --mode=headless --repeat=2
 *
 * Options
 *   --dir=path     scratch directory holding the tools (default $REDTEAM_DIR or ./.redteam; never a repo dependency)
 *   --tools=a,b    default: every tool in tools.mjs; one whose files are absent is reported "not installed"
 *   --mode=...     headless | headed | both (default both; headed re-runs under xvfb-run when there is no display)
 *   --repeat=n     runs per tool and mode (default 2: the second shows whether the identity is fresh per run)
 *   --out=dir      output directory (default tools/redteam/out/<timestamp>)
 *   --save-fixtures=dir   also write the first run of each tool as a dataset record (tests/Fixtures/fingerprint/redteam)
 *   --timeout=ms   per-run wait (default 45000)
 *
 * Every run is labelled class `spoof` with `labels.name = "spoof:<tool>"`, so the ML dataset gains
 * realistic adversarial rows.
 */
import { build } from 'vite';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { arch, cpus, hostname, release, tmpdir, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startCaptureServer } from '../capture/server.mjs';
import { TOOLS, chromePath } from './tools.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const args = Object.fromEntries(process.argv.slice(2).map((a) => {
    const [k, ...r] = a.replace(/^--/, '').split('=');
    return [k, r.length ? r.join('=') : 'true'];
}));
const list = (v, d) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : d);
const dir = resolve(args.dir ?? process.env.REDTEAM_DIR ?? join(ROOT, '.redteam'));
const mode = args.mode ?? 'both';
const repeat = Number(args.repeat ?? 2);
const timeoutMs = Number(args.timeout ?? 45000);
const wanted = list(args.tools, Object.keys(TOOLS));
if (!wanted.includes('baseline')) wanted.unshift('baseline');
if (!['headless', 'headed', 'both'].includes(mode)) {
    console.error('--mode must be headless, headed or both');
    process.exit(2);
}

const hasDisplay = platform() !== 'linux' || Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
if (mode !== 'headless' && !hasDisplay && !process.env.CAPTURE_XVFB && spawnSync('xvfb-run', ['--help'], { stdio: 'ignore' }).status === 0) {
    const again = spawnSync('xvfb-run', ['-a', '-s', '-screen 0 1920x1080x24', process.execPath, ...process.argv.slice(1)], { stdio: 'inherit', env: { ...process.env, CAPTURE_XVFB: '1' } });
    process.exit(again.status ?? 1);
}
const displayKind = platform() !== 'linux' ? 'native' : process.env.CAPTURE_XVFB ? 'xvfb' : hasDisplay ? 'x11' : 'none';

const osName = { linux: 'linux', win32: 'windows', darwin: 'macos' }[platform()] ?? platform();
const machineId = String(args.machine ?? createHash('sha256').update([hostname(), platform(), arch(), cpus()[0]?.model ?? ''].join('|')).digest('hex').slice(0, 12));
const machine = { id: machineId, os: osName, os_release: release(), arch: arch(), cpu_count: cpus().length, node: process.version, display: displayKind };
const outDir = resolve(args.out ?? join(HERE, 'out', new Date().toISOString().replace(/[:.]/g, '-')));
mkdirSync(join(outDir, 'runs'), { recursive: true });

const distDir = mkdtempSync(join(tmpdir(), 'device-id-redteam-'));
await build({ root: join(ROOT, 'tools', 'capture', 'page'), configFile: false, logLevel: 'warn', base: '/', build: { outDir: distDir, emptyOutDir: true, minify: true, target: 'es2022' } });
const policy = JSON.parse(spawnSync('php', [join(ROOT, 'tools', 'capture', 'policy.php')], { encoding: 'utf8' }).stdout || 'null');
if (!policy) {
    console.error('php tools/capture/policy.php failed: PHP is required for the challenge policy');
    process.exit(2);
}
/**
 * Every anti-detect tutorial starts by removing "HeadlessChrome" from the user agent, so the attacker
 * runs the tools with a normal Chrome UA (the same version, as a real Chrome reports it).
 */
const chromeVersion = chromePath() ? /(\d+)\./.exec(spawnSync(chromePath(), ['--version'], { encoding: 'utf8' }).stdout ?? '')?.[1] : null;
if (chromeVersion) process.env.REDTEAM_UA = `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
const server = await startCaptureServer({ distDir, disabledProbes: policy.disabled_probes });

/** Runs one tool once; resolves {info, run}. Rejects with the last stderr line when the tool cannot start. */
async function drive(tool, runMode) {
    const spec = TOOLS[tool];
    server.beginRun();
    const { cmd, args: cmdArgs } = spec.launch(dir, runMode, `${server.origin}/`);
    const child = spawn(cmd, cmdArgs, { stdio: ['pipe', 'pipe', 'pipe'], env: spec.baseline ? { ...process.env, REDTEAM_UA: '' } : process.env, detached: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const exited = new Promise((ok) => child.on('exit', ok));
    try {
        const run = await Promise.race([
            server.waitForRun(timeoutMs),
            exited.then((code) => {
                if (code !== 0) throw new Error((stderr.trim().split('\n').filter(Boolean).pop() ?? `exit ${code}`).slice(0, 300));
                return server.waitForRun(1000);
            }),
        ]);
        let info = { version: 'unknown', driver: tool };
        try { info = JSON.parse(stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop() ?? '{}'); } catch { /* keep the default */ }
        return { info, run };
    } finally {
        child.stdin.end();
        await Promise.race([exited, new Promise((ok) => setTimeout(ok, 5000))]);
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ }
    }
}

const summary = [];
let failures = 0;
const modes = mode === 'both' ? ['headless', 'headed'] : [mode];
for (const tool of wanted) {
    const spec = TOOLS[tool];
    if (!spec) { summary.push({ id: tool, status: 'unknown tool' }); continue; }
    if (!spec.requires(dir) || (spec.engine === 'chromium' && !chromePath())) {
        summary.push({ id: tool, status: 'not installed', reason: `not found under ${dir}` });
        console.log(`SKIP  ${tool}: not installed under ${dir}`);
        continue;
    }
    for (const runMode of modes) {
        if (runMode === 'headed' && displayKind === 'none') {
            summary.push({ id: `${tool}.${runMode}`, status: 'skipped', reason: 'no display and no xvfb-run' });
            continue;
        }
        for (let n = 1; n <= (spec.baseline ? 1 : repeat); n++) {
            const id = [machineId, osName, tool, runMode, spec.baseline ? 'honest-baseline' : `spoof-${tool}`, ...(n > 1 ? [`r${n}`] : [])].join('.');
            const started = Date.now();
            try {
                const { info, run } = await drive(tool, runMode);
                const slots = run.claimRequests.map((c) => c.slot);
                const complete = slots.includes('tier1') && slots.includes('tier2');
                const record = {
                    schema: 'device-id.capture-run', schema_version: 1, id, captured_at: new Date().toISOString(), machine,
                    browser: { name: tool, channel: null, engine: spec.engine, version: info.version, driver: info.driver, mode: runMode === 'headless' ? 'headless' : displayKind === 'xvfb' ? 'headed-xvfb' : 'headed', variant: spec.baseline ? 'honest-baseline' : `spoof:${tool}`, locale: 'en-US' },
                    labels: spec.baseline
                        ? { class: runMode === 'headless' ? 'headless' : 'honest', name: 'honest:baseline', tool, repeat: n, basis: 'harness-declared: plainly driven Chromium of the same machine, the matcher baseline' }
                        : { class: 'spoof', name: `spoof:${tool}`, tool, repeat: n, basis: `redteam-declared: ${tool} with its stealth features on, ${runMode}` },
                    collector: { envelope_version: run.claimRequests[0]?.envelope?.v ?? null, probe_set: run.claimRequests[0]?.envelope?.probes ?? null, disabled_probes: policy.disabled_probes },
                    complete, outcome: run.outcome, navigation: run.navigation, claim_requests: run.claimRequests, elapsed_ms: Date.now() - started,
                };
                writeFileSync(join(outDir, 'runs', `${id}.json`), `${JSON.stringify(record, null, 1)}\n`);
                summary.push({ id, status: complete ? 'captured' : 'incomplete', version: info.version, driver: info.driver, slots });
                console.log(`${complete ? 'OK   ' : 'WARN '} ${tool} ${runMode} #${n}: ${info.driver}, ${info.version}, envelopes: ${slots.join(',') || 'none'}`);
                if (!complete) failures++;
            } catch (error) {
                const message = error instanceof Error ? error.message.split('\n')[0] : String(error);
                summary.push({ id, status: 'failed', reason: message });
                console.log(`FAIL  ${tool} ${runMode} #${n}: ${message}`);
                failures++;
            }
        }
    }
}
await server.close();
rmSync(distDir, { recursive: true, force: true });
writeFileSync(join(outDir, 'harness.json'), `${JSON.stringify({ machine, mode, wanted, repeat, summary }, null, 1)}\n`);
console.log(`\nRaw runs written to ${outDir}`);
const report = spawnSync('php', [join(HERE, 'report.php'), outDir, ...(args['save-fixtures'] ? [`--save-fixtures=${args['save-fixtures']}`] : [])], { stdio: 'inherit' });
process.exit(failures > 0 || report.status !== 0 ? 1 : 0);
