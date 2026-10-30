/**
 * The WebRTC media-stack probe: capability lines of a local offer, nothing about the network.
 *
 * jsdom has no RTCPeerConnection, so a fake one stands in. The fake records what the probe
 * calls, which is the point: the probe must never set a local description (that starts ICE
 * gathering) and must close the peer on every path.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { parseWebRtcSdp, webrtc, WEBRTC_TIMEOUT_MS } from '@device-id/collector/value-probes';

const SDP_LINES = [
    'v=0',
    'o=- 4611731400430051336 2 IN IP4 192.168.1.23',
    's=-',
    't=0 0',
    'a=ice-ufrag:UFRAG0001',
    'a=ice-pwd:PASSWORD0000000000000000',
    'a=fingerprint:sha-256 AA:BB:CC',
    'a=candidate:1 1 udp 2113937151 192.168.1.23 54321 typ host',
    'm=audio 9 UDP/TLS/RTP/SAVPF 111 63',
    'a=rtpmap:111 opus/48000/2',
    'a=fmtp:111 minptime=10;useinbandfec=1',
    'a=rtcp-fb:111 transport-cc',
    'a=rtpmap:63 red/48000/2',
    'a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level',
    'm=video 9 UDP/TLS/RTP/SAVPF 96',
    'a=rtpmap:96 VP8/90000',
    'a=rtcp-fb:96 nack',
    'a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
];

const sdpOf = (lines: readonly string[]): string => lines.join('\r\n') + '\r\n';

interface FakePeerLog {
    setLocalDescription: number;
    createDataChannel: number;
    closed: number;
    constructedWith: unknown[];
}

function installPeerConnection(behaviour: { sdp?: string; reject?: Error; never?: boolean; constructorThrows?: boolean }): { log: FakePeerLog; undo: () => void } {
    const log: FakePeerLog = { setLocalDescription: 0, createDataChannel: 0, closed: 0, constructedWith: [] };
    const original = (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection;

    class FakePeer {
        localDescription: { sdp: string } | null = null;

        constructor(config: unknown) {
            if (behaviour.constructorThrows) {
                throw Object.assign(new Error('webrtc disabled by policy'), { name: 'NotAllowedError' });
            }
            log.constructedWith.push(config);
        }

        createDataChannel(): void {
            log.createDataChannel += 1;
        }

        createOffer(): Promise<{ sdp: string }> {
            if (behaviour.never) return new Promise(() => undefined);
            if (behaviour.reject) return Promise.reject(behaviour.reject);

            return Promise.resolve({ sdp: behaviour.sdp ?? sdpOf(SDP_LINES) });
        }

        setLocalDescription(): Promise<void> {
            log.setLocalDescription += 1;
            // What a real peer would now do: gather candidates into the description.
            this.localDescription = { sdp: sdpOf([...SDP_LINES, 'a=candidate:2 1 udp 1 203.0.113.9 9 typ srflx']) };

            return Promise.resolve();
        }

        close(): void {
            log.closed += 1;
        }
    }

    (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection = FakePeer;

    return {
        log,
        undo: () => {
            (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection = original;
        },
    };
}

async function valueOf(): Promise<Record<string, any>> {
    const result = await webrtc();
    if (result.state !== 'ok') {
        throw new Error(`expected ok, got ${JSON.stringify(result)}`);
    }

    return result.value;
}

describe('parseWebRtcSdp', () => {
    it('counts the audio and video codecs and the header extensions', () => {
        const parsed = parseWebRtcSdp(sdpOf(SDP_LINES)) as Record<string, any>;

        expect(parsed.audio.count).toBe(2);
        expect(parsed.video.count).toBe(1);
        expect(parsed.extensions.count).toBe(2);
    });

    it('does not read the network: ICE credentials, candidates, addresses and the DTLS fingerprint change nothing', () => {
        const withOtherNetwork = SDP_LINES.map((line) =>
            line
                .replace('192.168.1.23', '10.99.99.99')
                .replace('UFRAG0001', 'OTHERUFRAG')
                .replace('AA:BB:CC', 'DD:EE:FF')
                .replace('54321', '11111'),
        );

        expect(parseWebRtcSdp(sdpOf(withOtherNetwork))).toEqual(parseWebRtcSdp(sdpOf(SDP_LINES)));
    });

    it('changes every affected hash when a codec, a feedback line or an extension changes', () => {
        const base = parseWebRtcSdp(sdpOf(SDP_LINES)) as Record<string, any>;

        const noRed = parseWebRtcSdp(sdpOf(SDP_LINES.filter((line) => !line.startsWith('a=rtpmap:63 ')))) as Record<string, any>;
        expect(noRed.audio.count).toBe(1);
        expect(noRed.audio.hash).not.toBe(base.audio.hash);
        expect(noRed.sdpHash).not.toBe(base.sdpHash);

        const otherFeedback = parseWebRtcSdp(sdpOf(SDP_LINES.map((line) => (line === 'a=rtcp-fb:96 nack' ? 'a=rtcp-fb:96 nack pli' : line)))) as Record<string, any>;
        expect(otherFeedback.video.hash).not.toBe(base.video.hash);

        const noExtension = parseWebRtcSdp(sdpOf(SDP_LINES.filter((line) => !line.includes('abs-send-time')))) as Record<string, any>;
        expect(noExtension.extensions.count).toBe(1);
        expect(noExtension.extensions.hash).not.toBe(base.extensions.hash);
    });

    it('is independent of line order inside a section and of the visitor\'s locale collation', () => {
        const reversedExtmaps = [...SDP_LINES.filter((line) => !line.startsWith('a=extmap:')), ...SDP_LINES.filter((line) => line.startsWith('a=extmap:')).reverse()];
        const base = parseWebRtcSdp(sdpOf(SDP_LINES));
        expect(parseWebRtcSdp(sdpOf(reversedExtmaps))).toEqual(base);

        const spy = vi.spyOn(String.prototype, 'localeCompare').mockImplementation(() => {
            throw new Error('the probe must not depend on locale collation');
        });
        try {
            expect(parseWebRtcSdp(sdpOf(SDP_LINES))).toEqual(base);
        } finally {
            spy.mockRestore();
        }
    });
});

describe('webrtc', () => {
    let undo: (() => void) | undefined;
    afterEach(() => {
        undo?.();
        undo = undefined;
        vi.useRealTimers();
    });

    it('is unavailable("no-webrtc") where the engine has no RTCPeerConnection', async () => {
        const original = (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection;
        delete (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection;
        try {
            expect(await webrtc()).toEqual({ state: 'unavailable', reason: 'no-webrtc' });
        } finally {
            (window as unknown as { RTCPeerConnection?: unknown }).RTCPeerConnection = original;
        }
    });

    it('reports the capability summary from an offer, with no ICE servers', async () => {
        const peer = installPeerConnection({});
        undo = peer.undo;

        const value = await valueOf();
        expect(value.audio.count).toBe(2);
        expect(value.video.count).toBe(1);
        expect(peer.log.constructedWith).toEqual([{ iceServers: [] }]);
        expect(peer.log.createDataChannel).toBe(1);
    });

    it('never sets a local description, so no ICE gathering starts and no address can reach the claim', async () => {
        const peer = installPeerConnection({});
        undo = peer.undo;

        const value = await valueOf();
        expect(peer.log.setLocalDescription).toBe(0);
        expect(JSON.stringify(value)).not.toMatch(/192\.168|203\.0\.113|candidate|ufrag|typ host/);
    });

    it('closes the peer on success, on a rejected offer and on a timeout', async () => {
        const success = installPeerConnection({});
        await webrtc();
        expect(success.log.closed).toBe(1);
        success.undo();

        const rejected = installPeerConnection({ reject: new TypeError('offer refused') });
        undo = rejected.undo;
        expect(await webrtc()).toEqual({ state: 'error', name: 'TypeError' });
        expect(rejected.log.closed).toBe(1);
        rejected.undo();

        vi.useFakeTimers();
        const hung = installPeerConnection({ never: true });
        undo = hung.undo;
        const pending = webrtc();
        await vi.advanceTimersByTimeAsync(WEBRTC_TIMEOUT_MS + 1);
        expect(await pending).toEqual({ state: 'error', name: 'Error' });
        expect(hung.log.closed).toBe(1);
    });

    it('is a tagged error, not a throw, when a policy blocks the constructor', async () => {
        const blocked = installPeerConnection({ constructorThrows: true });
        undo = blocked.undo;

        expect(await webrtc()).toEqual({ state: 'error', name: 'NotAllowedError' });
    });

    it('is unavailable("no-sdp") when the offer carries no SDP', async () => {
        const peer = installPeerConnection({ sdp: '' });
        undo = peer.undo;

        expect(await webrtc()).toEqual({ state: 'unavailable', reason: 'no-sdp' });
        expect(peer.log.closed).toBe(1);
    });
});
