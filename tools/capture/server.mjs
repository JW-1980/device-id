/**
 * The capture server: serves the built capture page and implements the two endpoints the
 * collector expects (`POST /challenge`, `POST /claims`) the way a host with default settings
 * would, and records what it receives.
 *
 * What it records per run (`beginRun` / `finishRun`):
 *  - `navigation`: the request headers of the page load, in wire order and original case;
 *  - `claimRequests`: for each claims POST, the slot, the request headers (wire order) and the
 *    body, exactly as received. The transport witnesses the engine reads come from the FIRST
 *    claims request, as in an application: `Accept-CH` hints only reach requests made after the
 *    first response, and the collector's claims POST is such a request;
 *  - `outcome`: what the page said the collector did.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';

/** The README's "Device-hint request headers" value, verbatim. */
export const ACCEPT_CH = [
    'Sec-CH-UA-Full-Version-List', 'Sec-CH-UA-Platform-Version', 'Sec-CH-UA-Arch', 'Sec-CH-UA-Bitness',
    'Sec-CH-UA-Model', 'Sec-CH-Device-Memory', 'Sec-CH-DPR', 'Sec-CH-Viewport-Width',
].join(', ');

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.map': 'application/json' };

const pairs = (rawHeaders) => {
    const out = [];
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) out.push([rawHeaders[i], rawHeaders[i + 1]]);
    return out;
};

/**
 * @param {{ distDir: string, disabledProbes: string[] }} options
 */
export async function startCaptureServer({ distDir, disabledProbes }) {
    let run = null;

    const server = createServer((req, res) => {
        const url = new URL(req.url ?? '/', 'http://localhost');

        if (req.method === 'POST') {
            const chunks = [];
            req.on('data', (chunk) => chunks.push(chunk));
            req.on('end', () => handlePost(url.pathname, req, res, Buffer.concat(chunks).toString('utf8')));
            return;
        }

        const isPage = url.pathname === '/' || url.pathname === '/index.html';
        if (isPage && run) {
            run.navigation = { method: req.method, url: req.url, headers: pairs(req.rawHeaders), httpVersion: req.httpVersion };
        }
        const file = normalize(join(distDir, isPage ? 'index.html' : url.pathname));
        if (!file.startsWith(distDir) || !existsSync(file) || !statSync(file).isFile()) {
            res.writeHead(404).end();
            return;
        }
        const headers = { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' };
        if (isPage) headers['accept-ch'] = ACCEPT_CH;
        res.writeHead(200, headers).end(readFileSync(file));
    });

    function handlePost(pathname, req, res, body) {
        const json = (status, value) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
        if (!run) return json(409, { error: 'no run in progress' });

        if (pathname === '/challenge') {
            const token = randomBytes(32).toString('base64url');
            run.tokens.set(token, new Set());
            return json(200, { token, purpose: 'capture', expires_at: Math.floor(Date.now() / 1000) + 600, disabled_probes: disabledProbes });
        }
        if (pathname === '/claims') {
            let parsed;
            try {
                parsed = JSON.parse(body);
            } catch {
                return json(400, { error: 'malformed_json' });
            }
            const slots = run.tokens.get(parsed?.nonce);
            // The single-use-per-slot rule of the real challenge store.
            if (!slots || slots.has(parsed.slot)) return json(422, { error: 'bad_or_spent_token' });
            slots.add(parsed.slot);
            run.claimRequests.push({ slot: parsed.slot, bytes: Buffer.byteLength(body), headers: pairs(req.rawHeaders), envelope: parsed });
            return json(200, { ok: true });
        }
        if (pathname === '/done') {
            try {
                run.outcome = JSON.parse(body);
            } catch {
                run.outcome = { status: 'unparseable' };
            }
            run.done = true;
            return json(200, { ok: true });
        }
        return json(404, {});
    }

    await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
    const origin = `http://localhost:${server.address().port}`;

    return {
        origin,
        beginRun() {
            run = { navigation: null, claimRequests: [], outcome: null, done: false, tokens: new Map() };
        },
        /** Resolves when both slots arrived and the page reported, or when the timeout passes. */
        async waitForRun(timeoutMs) {
            const deadline = Date.now() + timeoutMs;
            while (Date.now() < deadline) {
                const slots = new Set(run.claimRequests.map((c) => c.slot));
                if (slots.has('tier1') && slots.has('tier2') && run.done) break;
                await new Promise((ok) => setTimeout(ok, 150));
            }
            return run;
        },
        finishRun() {
            const finished = run;
            run = null;
            return finished;
        },
        close: () => new Promise((ok) => server.close(ok)),
    };
}
