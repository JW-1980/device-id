<?php

declare(strict_types=1);

/**
 * The demo's labelled claim sets, shared by `demo/standalone-demo.php` (which prints what the
 * engine makes of them) and `tools/golden-check.php` (which asserts fixed answers for them).
 *
 * Fixtures, not measurements. Each is a claim set of the shape a browser's collector
 * produces; the engine cannot tell the difference and does not need to.
 *
 * One file rather than a copy in each script, so the golden values are always about the
 * claim sets the demo shows.
 *
 * @return array<string, array<string, mixed>>
 */
return [
    'honest chromium on windows' => [
        'v' => 2,
        'purpose' => 'signin',
        'integrity' => ['findings' => [], 'data' => [], 'elapsedMs' => 0.6],
        'tier1' => [
            'environment' => ['state' => 'ok', 'value' => [
                'screen' => '1920x1080',
                'identity' => [
                    'userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
                    'platform' => 'Win32',
                    'maxTouchPoints' => 0,
                    'hardwareConcurrency' => 8,
                    'deviceMemory' => 8,
                ],
            ]],
            'esFeatures' => ['state' => 'ok', 'value' => ['count' => 61, 'present' => 'arrayAt,errorCause']],
            'uaClientHints' => ['state' => 'ok', 'value' => [
                'brands' => [
                    ['brand' => 'Not_A Brand', 'version' => '8'],
                    ['brand' => 'Chromium', 'version' => '141'],
                    ['brand' => 'Google Chrome', 'version' => '141'],
                ],
                'mobile' => false,
                'platform' => 'Windows',
                'high' => ['uaFullVersion' => '141.0.7390.54'],
            ]],
            'languages' => ['state' => 'ok', 'value' => ['nl-NL', 'nl', 'en-US', 'en']],
            'timezone' => ['state' => 'ok', 'value' => 'Europe/Amsterdam'],
        ],
        'timing' => ['elapsedMs' => 6.1, 'budgetMs' => 30, 'tier2Skipped' => false],
    ],

    'a browser that contradicts itself' => [
        'v' => 2,
        'purpose' => 'signin',
        'integrity' => ['findings' => [], 'data' => [], 'elapsedMs' => 0.9],
        'tier1' => [
            'environment' => ['state' => 'ok', 'value' => [
                'screen' => '1920x1080',
                'identity' => [
                    'userAgent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
                    'platform' => 'Win32',
                    'maxTouchPoints' => 5,
                    'hardwareConcurrency' => 64,
                    'deviceMemory' => 0.5,
                ],
            ]],
            'esFeatures' => ['state' => 'ok', 'value' => ['count' => 3, 'present' => 'at']],
            'uaClientHints' => ['state' => 'ok', 'value' => [
                'brands' => [['brand' => 'Chromium', 'version' => '141']],
                'mobile' => false,
                'platform' => 'macOS',
                'high' => ['uaFullVersion' => '141.0.0.1'],
            ]],
        ],
        'timing' => ['elapsedMs' => 7.0, 'budgetMs' => 30, 'tier2Skipped' => false],
    ],

    'a tampered page (integrity probe fired)' => [
        'v' => 2,
        'purpose' => 'signin',
        'integrity' => [
            'findings' => [['code' => 'descriptor_patched', 'detail' => 'navigator.userAgent has no getter']],
            'data' => [],
            'elapsedMs' => 1.1,
        ],
        'tier1' => [
            'environment' => ['state' => 'ok', 'value' => [
                'identity' => ['userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0.0.0 Safari/537.36'],
            ]],
        ],
        'timing' => ['elapsedMs' => 4.0, 'budgetMs' => 30, 'tier2Skipped' => false],
    ],

    'nothing collected (a browser that declined)' => [],
];
