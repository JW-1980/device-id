/**
 * The capture page: runs the REAL collector (`collectAndSendDetailed`) against the capture
 * server's challenge and claims endpoints, waits for the tier-2 pass, and reports what the
 * collector said happened. No probe is reimplemented here.
 */
import { collectAndSendDetailed } from '../../../resources/js/collector';

const report = (body: Record<string, unknown>): Promise<unknown> =>
    fetch('/done', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).catch(() => null);

async function main(): Promise<void> {
    const outcome = await collectAndSendDetailed('capture', '/challenge', '/claims');
    let tier1Delivered: boolean | null = null;
    let tier2Sent: boolean | null = null;
    let tier2Delivered: boolean | null = null;
    if (outcome.status === 'sent') {
        tier1Delivered = await outcome.send.delivered;
        const second = await outcome.tier2;
        tier2Sent = second.send?.sent ?? false;
        tier2Delivered = second.send ? await second.send.delivered : false;
    }
    await report({ status: outcome.status, tier1Delivered, tier2Sent, tier2Delivered });
}

main().catch((error: unknown) => report({ status: 'page-error', error: String(error) }));
