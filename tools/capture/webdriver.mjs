/**
 * A minimal W3C WebDriver client over plain `fetch`, for real Safari through `safaridriver`
 * (macOS only; run `sudo safaridriver --enable` once, and in Safari enable
 * Develop > Allow Remote Automation). Only what the capture needs: start a session, navigate,
 * read the browser version, quit.
 */
import { spawn, spawnSync } from 'node:child_process';

const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

export function safaridriverAvailable() {
    if (process.platform !== 'darwin') return false;
    return spawnSync('safaridriver', ['--version'], { stdio: 'ignore' }).status === 0;
}

export async function startSafari() {
    const port = 4400 + Math.floor(Math.random() * 400);
    const child = spawn('safaridriver', ['-p', String(port)], { stdio: 'ignore' });
    const base = `http://127.0.0.1:${port}`;
    let up = false;
    for (let i = 0; i < 40 && !up; i++) {
        try {
            up = (await fetch(`${base}/status`)).ok;
        } catch {
            await sleep(250);
        }
    }
    if (!up) {
        child.kill();
        throw new Error('safaridriver did not answer /status (is remote automation enabled?)');
    }

    const call = async (method, path, body) => {
        const response = await fetch(`${base}${path}`, {
            method,
            headers: { 'content-type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        const parsed = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(`WebDriver ${method} ${path}: ${response.status} ${JSON.stringify(parsed.value ?? parsed)}`);
        return parsed.value;
    };

    const session = await call('POST', '/session', { capabilities: { alwaysMatch: { browserName: 'safari' } } });
    const sessionId = session.sessionId;

    return {
        version: session.capabilities?.browserVersion ?? 'unknown',
        navigate: (url) => call('POST', `/session/${sessionId}/url`, { url }),
        async quit() {
            try {
                await call('DELETE', `/session/${sessionId}`);
            } finally {
                child.kill();
            }
        },
    };
}
