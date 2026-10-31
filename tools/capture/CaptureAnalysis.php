<?php

declare(strict_types=1);

namespace DeviceId\Capture;

use NutriCompare\Fingerprint\Envelope\ClientClaimsEnvelope;
use NutriCompare\Fingerprint\Keys\DeviceKeyDeriver;
use NutriCompare\Fingerprint\Keys\DeviceKeys;
use NutriCompare\Fingerprint\Matching\DeviceCandidateSource;
use NutriCompare\Fingerprint\Matching\DeviceMatcher;
use NutriCompare\Fingerprint\Matching\MatchCandidate;
use NutriCompare\Fingerprint\Matching\MatcherSettings;
use NutriCompare\Fingerprint\ProbeRegistry;
use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Rules\IntegrityFindings;
use NutriCompare\Fingerprint\Scoring\ConfidenceScorer;
use NutriCompare\Fingerprint\Scoring\VerdictScorer;
use NutriCompare\Fingerprint\Support\Config;
use NutriCompare\Fingerprint\Support\TransportIntegrityResult;
use NutriCompare\Fingerprint\Support\TransportRequestFacts;
use NutriCompare\Fingerprint\Transport\TransportIntegrity;

/**
 * The engine's reading of one capture, and of pairs of captures from one machine.
 *
 * Used by `engine-report.php` (the harness' report) and by the PHPUnit regression suite over
 * `tests/Fixtures/fingerprint/captures/`, so both judge a capture the same way.
 *
 * A capture is a DATASET RECORD (see {@see toDataset()}): labels, machine, browser, the
 * claims of both envelopes and the request headers of the claims POST. Nothing in it is
 * derived by the engine, so a fixture never goes stale when the engine changes.
 */
final class CaptureAnalysis
{
    public const DATASET_SCHEMA = 'device-id.capture-dataset';

    public const DATASET_VERSION = 1;

    /** A fixed TEST secret: keys are HMACs, and pairs of one harness run must share one. */
    public const KEY_SECRET = 'capture-harness-fixed-test-secret-0123456789abcdef';

    /** The matcher weights NutriCompare ships (`config/security.php` `matcher`). */
    private const MATCHER_WEIGHTS = [
        'fonts' => 3, 'gpu' => 3, 'panel' => 1, 'emoji' => 1, 'scripts' => 1, 'voices' => 2, 'decoders' => 1, 'memory' => 1,
        'osVersion' => 1, 'gpuMath' => 2, 'browser_key' => 4, 'hardware_key' => 2, 'cores' => 1, 'aspect' => 1, 'display' => 1, 'audio' => 1,
    ];

    public static function configure(): void
    {
        Config::reset();
        Config::use([
            'fingerprint' => [
                'score_divisor' => 40,
                'bands' => ['elevated' => 40, 'challenge' => 60, 'block' => 80],
                'constraint_weights' => [],
                'enabled' => true,
                'device_key_secret' => self::KEY_SECRET,
                'matcher' => ['weights' => self::MATCHER_WEIGHTS],
            ],
            'transport_integrity' => ['ja4_profiles' => []],
        ]);
    }

    /**
     * A raw run file (`capture.mjs`) as a dataset record: the envelopes parsed by the engine's
     * own parser, the claims reduced to what the server scores, and the labels kept.
     *
     * @param  array<string, mixed>  $run
     * @return array<string, mixed>
     */
    public static function toDataset(array $run): array
    {
        $tier = [];
        $headers = null;
        foreach ($run['claim_requests'] ?? [] as $request) {
            $parsed = ClientClaimsEnvelope::parse((string) json_encode($request['envelope'], JSON_THROW_ON_ERROR));
            if ($parsed->envelope === null) {
                throw new \RuntimeException('envelope rejected by the engine parser: '.$parsed->reason);
            }
            $tier[$parsed->envelope->slot] = $parsed->envelope->signalClaims();
            $headers ??= $request['headers'];
        }

        return [
            'schema' => self::DATASET_SCHEMA,
            'schema_version' => self::DATASET_VERSION,
            'id' => $run['id'],
            'captured_at' => $run['captured_at'],
            'machine' => $run['machine'],
            'browser' => $run['browser'],
            'labels' => $run['labels'],
            'collector' => $run['collector'],
            'transport' => [
                'claims_request_headers' => $headers ?? [],
                'navigation_headers' => $run['navigation']['headers'] ?? [],
            ],
            'claims' => ['tier1' => $tier['tier1'] ?? null, 'tier2' => $tier['tier2'] ?? null],
        ];
    }

    /**
     * The identify-path form: tier 1 with tier 2 laid over it, integrity findings
     * concatenated and integrity data merged with the deferred keys winning (index.ts
     * `mergeIntegrity`).
     *
     * @param  array<string, mixed>  $record
     * @return array<string, mixed>
     */
    public static function mergedClaims(array $record): array
    {
        $one = $record['claims']['tier1'] ?? [];
        $two = $record['claims']['tier2'] ?? null;
        if (! is_array($two)) {
            return $one;
        }
        $merged = $one;
        $merged['tier2'] = $two['tier2'] ?? [];
        $merged['integrity'] = [
            'findings' => [...($one['integrity']['findings'] ?? []), ...($two['integrity']['findings'] ?? [])],
            'data' => array_replace($one['integrity']['data'] ?? [], $two['integrity']['data'] ?? []),
            'elapsedMs' => ($one['integrity']['elapsedMs'] ?? 0) + ($two['integrity']['elapsedMs'] ?? 0),
        ];

        return $merged;
    }

    /**
     * What the host's transport analysis sees: the headers of the FIRST claims request, which is
     * made after the page response named the hints in `Accept-CH` (README), as a fetch POST.
     *
     * @param  array<string, mixed>  $record
     */
    public static function transport(array $record): TransportIntegrityResult
    {
        $pairs = array_map(static fn (array $pair): array => [(string) $pair[0], (string) $pair[1]], $record['transport']['claims_request_headers'] ?? []);

        return (new TransportIntegrity)->analyse($pairs, new TransportRequestFacts(
            clientSpokeHttp2: false,
            method: 'POST',
            isDocumentRequest: false,
            headerOrderAvailable: true,
        ));
    }

    /**
     * The engine's answer for one capture. Call {@see configure()} first.
     *
     * @param  array<string, mixed>  $record
     * @return array<string, mixed>
     */
    public static function analyse(array $record): array
    {
        $transport = self::transport($record);
        $merged = self::mergedClaims($record);

        return [
            'merged' => self::answer($merged, $transport),
            'tier1' => self::answer($record['claims']['tier1'] ?? [], $transport),
            'keys' => self::keys($merged, $transport),
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    private static function answer(array $claims, TransportIntegrityResult $transport): array
    {
        $confidence = (new ConfidenceScorer)->score($claims, $transport, ProbeRegistry::disabled());
        $verdict = (new VerdictScorer(new EnvironmentConsistency))->score($claims, $transport, confidence: $confidence);

        $codes = [];
        foreach ($verdict->disagreements as $disagreement) {
            $codes[$disagreement['code']] = ['weight' => $disagreement['weight'], 'detail' => $disagreement['detail']];
        }

        return [
            'band' => $verdict->band,
            'score' => $verdict->score,
            'total_weight' => $verdict->totalWeight(),
            'codes' => $codes,
            'integrity_codes' => IntegrityFindings::effective($claims),
            'confidence' => ['score' => $confidence->score, 'earned' => $confidence->earned, 'expected' => $confidence->expected, 'missing' => $confidence->missing, 'penalties' => $confidence->penalties],
        ];
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>|null
     */
    private static function keys(array $claims, TransportIntegrityResult $transport): ?array
    {
        $keys = (new DeviceKeyDeriver)->keys($claims, $transport);

        return $keys === null ? null : [
            'browser_key' => $keys->browserKey,
            'hardware_key' => $keys->hardwareKey,
            'coverage' => $keys->coverage,
            'protected' => $keys->protected,
            'untrusted' => $keys->untrusted,
            'components' => $keys->components,
        ];
    }

    /**
     * @param  array<string, mixed>  $record
     */
    public static function deviceKeys(array $record): ?DeviceKeys
    {
        return (new DeviceKeyDeriver)->keys(self::mergedClaims($record), self::transport($record));
    }

    /**
     * What `DeviceMatcher` says when the capture `$stored` is a known device and `$seen` reports.
     *
     * @return array<string, mixed>|null null when either capture cannot be keyed
     */
    public static function match(array $stored, array $seen): ?array
    {
        $storedKeys = self::deviceKeys($stored);
        $seenKeys = self::deviceKeys($seen);
        if ($storedKeys === null || $seenKeys === null) {
            return null;
        }

        $candidate = new class($storedKeys) implements MatchCandidate
        {
            public function __construct(private readonly DeviceKeys $keys) {}

            public function matchId(): int
            {
                return 1;
            }

            public function matchClusterId(): int
            {
                return 1;
            }

            public function matchComponents(): array
            {
                return $this->keys->components;
            }

            public function matchBrowserKey(): ?string
            {
                return $this->keys->browserKey;
            }

            public function matchNetwork(): ?string
            {
                return 'loopback';
            }

            public function matchHardwareKey(): ?string
            {
                return $this->keys->hardwareKey;
            }
        };

        $source = new class($candidate) implements DeviceCandidateSource
        {
            public function __construct(private readonly MatchCandidate $stored) {}

            public function exact(string $browserKey, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, ?string $ipPrefix = null): ?MatchCandidate
            {
                return $this->stored->matchBrowserKey() === $browserKey ? $this->stored : null;
            }

            public function candidates(?string $hardwareKey, ?string $blockTuple, int $saltVersion, ?int $organizationId, ?int $excludeDeviceId, int $windowDays, int $maxCandidates): array
            {
                return $hardwareKey !== null && $hardwareKey === $this->stored->matchHardwareKey() ? [$this->stored] : [];
            }

            public function addBrowserKey(int $deviceId, string $browserKey, int $saltVersion): void {}
        };

        $matcher = new DeviceMatcher($source);
        $result = $matcher->match($seenKeys, null, null, 'loopback');

        return [
            'stored' => $stored['id'],
            'seen' => $seen['id'],
            'method' => $result->method,
            'linked' => $result->isLink(),
            'posterior' => round($result->posterior, 4),
            'veto' => $result->linkVeto,
            'candidates' => $result->candidatesConsidered,
            'score' => $result->candidatesConsidered > 0 ? $matcher->score($seenKeys, $candidate, MatcherSettings::current()['weights']) : null,
            'hardware_key_equal' => $storedKeys->hardwareKey !== null && $storedKeys->hardwareKey === $seenKeys->hardwareKey,
            'hard_components' => ['stored' => self::hard($storedKeys), 'seen' => self::hard($seenKeys)],
        ];
    }

    /**
     * @return array<string, scalar|null>
     */
    private static function hard(DeviceKeys $keys): array
    {
        return array_intersect_key($keys->components, ['os' => 1, 'arch' => 1, 'touch' => 1]);
    }

    /**
     * Pairs of captures from one machine and one mode, across different browsers.
     * Each pair is matched both ways.
     *
     * @param  list<array<string, mixed>>  $records
     * @return list<array<string, mixed>>
     */
    public static function pairs(array $records): array
    {
        $out = [];
        $count = count($records);
        for ($i = 0; $i < $count; $i++) {
            for ($j = $i + 1; $j < $count; $j++) {
                [$a, $b] = [$records[$i], $records[$j]];
                if ($a['machine']['id'] !== $b['machine']['id']
                    || $a['browser']['mode'] !== $b['browser']['mode']
                    || $a['browser']['name'] === $b['browser']['name']) {
                    continue;
                }
                $out[] = [
                    'a' => $a['id'],
                    'b' => $b['id'],
                    'browsers' => [$a['browser']['name'], $b['browser']['name']],
                    'forward' => self::match($a, $b),
                    'backward' => self::match($b, $a),
                ];
            }
        }

        return $out;
    }

    /**
     * A flat map of the claims' scalar leaves, `path` => value, for a model to train on.
     * A list becomes `path.__len` (its length) and, when it holds only scalars, `path.__hash`
     * (a hash of its canonical content) so a set's identity is a feature without its length
     * of text. Strings longer than 256 bytes are replaced by their length (`path.__len`) and hash.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, scalar|null>
     */
    public static function features(array $claims): array
    {
        $out = [];
        $walk = static function (mixed $node, string $path) use (&$walk, &$out): void {
            if (is_array($node)) {
                if (array_is_list($node)) {
                    $out[$path.'.__len'] = count($node);
                    if (count($node) > 0 && count(array_filter($node, 'is_scalar')) === count($node)) {
                        $out[$path.'.__hash'] = substr(hash('sha256', (string) json_encode($node)), 0, 16);
                    } else {
                        foreach ($node as $index => $child) {
                            if ($index < 16) {
                                $walk($child, $path.'.'.$index);
                            }
                        }
                    }

                    return;
                }
                foreach ($node as $key => $child) {
                    $walk($child, $path === '' ? (string) $key : $path.'.'.$key);
                }

                return;
            }
            if (is_string($node) && strlen($node) > 256) {
                $out[$path.'.__len'] = strlen($node);
                $out[$path.'.__hash'] = substr(hash('sha256', $node), 0, 16);

                return;
            }
            $out[$path] = $node;
        };
        $walk($claims, '');
        ksort($out);

        return $out;
    }
}
