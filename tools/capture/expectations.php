<?php

declare(strict_types=1);

/**
 * What the capture harness expects the engine to say about each class of capture.
 *
 * Classes (`labels.class`): `honest` (headed, automation switches suppressed where the driver
 * allows), `automation` (headed, driver defaults, or Safari under safaridriver), `headless`.
 *
 * - `max_band`: the highest band a class may reach. An honest headed browser must not reach
 *   `challenge`.
 * - `allowed`: codes a class may fire. Anything else is a reported failure with its detail.
 * - `environment_artefacts`: codes that fire only because of how THIS harness environment
 *   builds the browser, scoped by OS, browser and class, each with the reason. They are not a
 *   statement about real browsers.
 * - `must_fire` / `must_penalise`: detection that must keep working (a rule that stops
 *   catching headless Chromium is a regression, not a quiet improvement).
 *
 * `variant` narrows an assertion to one harness variant (`default`, `honest`, `automation`,
 * `instrumented`). `instrumented` is a headless run whose driver exposes a binding to the page.
 *
 * WebKit's headless mode is still indistinguishable from headed (no `must_fire` entry): that is the
 * engine's measured limit, reported as "no headless signal", never turned into an assertion nobody
 * can satisfy. Headless Chromium and Firefox are caught (see `must_fire`).
 */
$chromiumFamily = ['chromium', 'chrome', 'msedge'];

return [
    'version' => 1,

    'max_band' => [
        'honest' => 'elevated',
        // A driven headed browser is automation and now says so (`webdriver_true`, 20). `challenge`
        // leaves room for the documented environment artefacts below to add to it, and still
        // forbids `block` for a browser that merely has a driver attached and nothing else wrong.
        'automation' => 'challenge',
    ],

    'allowed' => [
        'honest' => [],
        // A headed browser under a driver's default switches reports navigator.webdriver = true.
        'automation' => ['webdriver_true'],
        // What a headless browser legitimately gives away.
        'headless' => [
            'ua_headless_token',
            'automation_global_present',
            'headless_shell_geometry',
            'headless_gecko_screen',
            'notification_permission_vs_query',
            'webdriver_true',
            'webdriver_missing',
        ],
    ],

    'environment_artefacts' => [
        [
            'code' => 'lied_os',
            'os' => ['linux'],
            'browser' => ['webkit'],
            'reason' => 'Playwright\'s WebKit build for Linux (WPE/GTK) reports a Macintosh User-Agent and navigator.platform "Linux x86_64". '
                .'It is not Safari; real Safari on a Mac reports MacIntel. Scoped to webkit on Linux.',
        ],
    ],

    'must_fire' => [
        [
            'class' => ['headless'],
            'browser' => $chromiumFamily,
            'any_of' => ['ua_headless_token'],
            'reason' => 'headless Chromium announces itself as HeadlessChrome in the User-Agent',
        ],
        [
            'class' => ['headless'],
            'browser' => $chromiumFamily,
            'variant' => ['default', 'instrumented'],
            'any_of' => ['headless_shell_geometry'],
            'reason' => 'a driven headless Chromium has outer = inner and a history of two (its tab starts on about:blank); measured on Chromium 153',
        ],
        [
            'class' => ['headless'],
            'browser' => ['firefox'],
            'any_of' => ['headless_gecko_screen'],
            'reason' => 'headless Firefox reports the fixed 1366x768 panel-less screen of its headless widget; measured on Firefox 155',
        ],
        [
            'class' => ['headless'],
            'browser' => ['chromium', 'chrome', 'msedge', 'firefox', 'webkit'],
            'variant' => ['instrumented'],
            'any_of' => ['automation_global_present'],
            'reason' => 'Playwright defines __playwright__binding__ on window once the driver exposes a binding (page.exposeBinding)',
        ],
        [
            'class' => ['automation', 'headless'],
            'browser' => ['chromium', 'chrome', 'msedge', 'firefox', 'webkit', 'safari'],
            'any_of' => ['webdriver_true'],
            'reason' => 'every driven browser keeps navigator.webdriver = true unless the driver hides it',
        ],
    ],

    'must_penalise' => [
        [
            'class' => ['automation', 'headless'],
            'browser' => $chromiumFamily,
            'penalty' => 'webdriver',
            'reason' => 'navigator.webdriver is true under a driver that keeps its default switches',
        ],
    ],

    'must_not_penalise' => [
        [
            'class' => ['honest'],
            'browser' => $chromiumFamily,
            'penalty' => 'webdriver',
            'reason' => 'the honest variant suppresses --enable-automation, so navigator.webdriver is false',
        ],
    ],

    /*
     * Why a same-machine pair that does not link is not an engine fault. Reported next to the
     * match result; a pair that matches none of these and does not link is reported bare.
     * `mode` is the capture mode ('headless', 'headed', 'headed-xvfb'), `veto` the matcher's
     * veto, `browser` a browser that must be in the pair, `hardware_key_equal` the hard key.
     */
    'pair_notes' => [
        [
            'mode' => ['headless'],
            'veto' => 'high_entropy_disagreement',
            'reason' => 'Headless drivers emulate the screen (Playwright: Chromium 1280 wide, Firefox 1366), so the panel component, '
                .'a veto component, differs between engines. Headed runs on one display agree on the panel and link.',
        ],
        [
            'browser' => 'webkit',
            'hardware_key_equal' => false,
            'reason' => 'Playwright\'s Linux WebKit reports a Macintosh User-Agent on a Linux machine, so its OS family differs from the other browsers on this machine. '
                .'Not Safari; the Safari-on-Mac pair is what the harness checks on a Mac.',
        ],
    ],
];
