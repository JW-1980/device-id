import { collectAndSend, reportDeclined } from './index';
import type { CollectionPurpose } from './protocol';

/**
 * Report once per tab per purpose, on pages where a real decision is being made.
 *
 * The collector does not run on catalogue pages: it is not telemetry, and a price page
 * does not need a device decision. Register, sign in, password reset and account actions
 * are the surfaces where the verdict is used.
 */
export async function initFingerprint(): Promise<void> {
    const purpose = document.body.dataset.fingerprintPurpose as CollectionPurpose | undefined;
    if (!purpose) return;

    const marker = `wzl:fp:${purpose}`;
    try {
        if (sessionStorage.getItem(marker)) return;
        sessionStorage.setItem(marker, '1');
    } catch {
        // Private modes that disable storage still get the protection; they just report
        // once per navigation instead of once per tab.
    }

    try {
        const result = await collectAndSend(purpose);
        if (result === null) {
            reportDeclined('/security/fingerprint/claims', 'unavailable');
        }
    } catch {
        reportDeclined('/security/fingerprint/claims', 'unsupported');
    }
}
