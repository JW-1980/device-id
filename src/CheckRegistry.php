<?php

declare(strict_types=1);

namespace DeviceId;

/**
 * Every check the engine can perform, with its default weight and a plain description.
 *
 * ## Why a registry rather than a hard-coded weight table
 *
 * Three reasons, in increasing order of how much they cost to get wrong.
 *
 * 1. **An operator has to be able to switch checks off individually.** A rule that is wrong
 *    for one deployment — a browser shipped a change the rule has not caught up with, a
 *    proxy injects a header the rule reads — must be silenceable without a deploy. That is
 *    the single most-requested operational control and it needs a list of what exists.
 *
 * 2. **A weight of 0 must silence a rule, not downweight it.** Half-weighting a rule that
 *    fires on everyone is worse than switching it off, because the score still moves and the
 *    operator has to work out why. `weightFor()` returns 0 and the scorer skips zero, so the
 *    two are the same control.
 *
 * 3. **A check nobody can see is a check nobody can trust.** Every code here carries a
 *    description, and `descriptions()` is what an admin panel renders. A rule added without a
 *    description is invisible in the UI, which means it can never be diagnosed when it fires
 *    on an honest user.
 *
 * ## The weights are argued on the scoring scale, and they are not free parameters
 *
 * They come from the application's own scoring scale, where 80 is the block band and 60 the
 * challenge band, and are argued per rule in `EnvironmentConsistency` (notes/12 §2; one of
 * them is measured). The heaviest single contradiction is 45 (score 68, `challenge`; an
 * operator may raise a weight to 60, score 78), which is deliberately below the block
 * threshold: **no one check can block a device on its own.** A device has to contradict
 * itself in two independent ways. Learning the weights from the population is
 * notes/23 (not implemented).
 *
 * ## What the JS-to-header checks are worth more than
 *
 * `ua_vs_ch_brand`, `ua_vs_ch_major`, `brands_vs_ch_header` and `ua_vs_ua_header` are all
 * 20-25 because they compare a claim against the `sec-ch-ua` / `user-agent` request header,
 * which a JavaScript-only spoofer cannot rewrite. The purely claim-against-claim rules sit
 * lower, because a spoofer can satisfy those by writing a self-consistent set of lies —
 * `notes/07` section 2 measured that eleven header lines defeat all of them.
 */
final class CheckRegistry
{
    /**
     * code => [weight, family, description]
     *
     * @var array<string, array{int, string, string}>
     */
    private const CHECKS = [
        // --- Integrity: the page's own environment betrays a tamper script --------
        'wrong_receiver_did_not_throw' => [40, 'integrity', 'A getter that brand-checks its receiver did not throw, so the page is not being inspected.'],
        'math_pf_mismatch' => [40, 'integrity', 'Math functions report exact IEEE-754 identity on real hardware and imprecise identity on a patch layer.'],
        'descriptor_patched' => [30, 'integrity', 'A property descriptor is missing the shape a native one has.'],
        'descriptor_unstable' => [25, 'integrity', 'A property descriptor changes between two reads in the same tick.'],
        'descriptor_missing' => [30, 'integrity', 'A property a shipping engine has is absent.'],
        'descriptor_shadowed' => [30, 'integrity', 'An own property on the navigator instance shadows a native attribute getter.'],
        'canvas_dual_diverged' => [35, 'integrity', 'Two canvas contexts on the same engine produced different pixels.'],
        'canvas_winding_false' => [25, 'integrity', 'A winding rule reports false for a path that must be non-zero on real hardware.'],
        'descriptor_has_setter' => [25, 'integrity', 'A read-only navigator attribute has a setter, which no engine gives a WebIDL attribute.'],
        'dom_blocker_present' => [30, 'integrity', 'A global that only an automation driver injects (Selenium, WebDriver, Nightmare) is present.'],
        'dom_blocker_threw' => [6, 'integrity', 'Reading an ordinary global threw, which suggests a blocker or extension intercepts property access.'],
        'webdriver_missing' => [25, 'integrity', 'navigator.webdriver is absent; every shipping engine defines it, and deleting it is the classic stealth evasion.'],
        'canvas_pattern_perturbed' => [4, 'integrity', 'A two-colour canvas pattern read back with pixels that differ from what was drawn: canvas noise that leaves a uniform fill exact (Firefox Private/Strict, Safari advanced protection). An honest privacy tool; the canvas-measured components are not matched.'],
        'automation_global_present' => [30, 'integrity', 'A global that only a driver or automation framework defines (ChromeDriver, Playwright, Selenium, PhantomJS, the Chrome automation controller) exists on window or document.'],
        'headless_shell_geometry' => [8, 'integrity', 'A desktop browser window without chrome around its viewport (outer size equals inner size) and a history of at most two entries (a driven tab starts on about:blank): the geometry of a headless shell. Not WebKit, where the protection sets it.'],
        'webdriver_true' => [20, 'integrity', 'navigator.webdriver is true: the browser reports an attached automation protocol (WebDriver, Marionette, CDP). Honest visitors essentially never carry it; managed enterprise test browsers are the edge case.'],
        'headless_gecko_screen' => [10, 'integrity', 'A Firefox on Linux or macOS reports exactly the fixed 1366x768 panel-less screen of its headless widget (available area equal to the screen at the origin), the one tell headless Gecko has.'],
        'canvas_readback_perturbed' => [4, 'integrity', 'A solid canvas fill read back with pixels that differ from the fill colour, so canvas values are noised (farbling or a noise extension) and cannot identify the device.'],
        'lie_battery_failed' => [35, 'integrity', 'A native function failed a conformance invariant (constructible, extra own properties, survives a cyclic prototype), so it is a Proxy or a closure standing in for the real one.'],
        'realm_tostring_mismatch' => [35, 'integrity', 'A pristine Function.prototype.toString from a fresh same-origin realm describes a page function differently from the page\'s own toString, so the page\'s toString is patched.'],
        'lie_battery_privacy_tool' => [15, 'integrity', 'Navigator, Screen or time-zone getters are wrapped in the page realm only, with no other conformance tell: the footprint of a privacy or User-Agent-switcher extension rather than a fraud tool.'],
        'lie_battery_noise_tool' => [6, 'integrity', 'A native function on a read-back surface (canvas, WebGL, audio buffers, element rectangles) is wrapped: the footprint of a noise extension, an honest visitor whose noised components are then not matched.'],
        'realm_tostring_noise_tool' => [6, 'integrity', 'A pristine realm describes a read-back-surface function differently from the page\'s toString: a noise extension masking itself; scored softly like the other read-back codes.'],
        'domrect_inconsistent' => [25, 'integrity', 'Element rectangles fail their own arithmetic (right minus left is not width, identical elements differ), which only a noise extension produces.'],
        'svg_text_inconsistent' => [20, 'integrity', 'SVG text measured twice, or two ways, gave different lengths, which only a noise extension produces.'],

        // --- Transport: evidence a JavaScript spoofer cannot rewrite -----------------
        'ua_vs_ua_header' => [20, 'transport', 'The User-Agent the page reported differs from the one the browser sent.'],
        'brands_vs_ch_header' => [20, 'transport', 'The brands the page reported differ from the Sec-CH-UA header the browser sent.'],
        'ua_vs_ch_brand' => [20, 'transport', 'The User-Agent claims a non-Chromium engine while the reported brands say Chromium.'],
        'ua_vs_ch_major' => [25, 'transport', 'The User-Agent major version disagrees with the browser\'s own un-redacted version list.'],
        'ja4_vs_ua' => [20, 'transport', 'The TLS ClientHello matches a measured profile whose engine contradicts the claimed User-Agent.'],
        'lang_vs_accept_language' => [5, 'transport', 'The page language list disagrees with the Accept-Language header.'],
        'touch_vs_ch_mobile' => [15, 'transport', 'Sec-CH-UA-Mobile reports a touch device while maxTouchPoints is zero.'],
        'transport_temporal_ja4_changed_without_ua_change' => [25, 'transport', 'The ClientHello changed between observations while the reported browser did not.'],
        'transport_sec_ch_full_version_mismatch' => [45, 'transport', 'The full version list contradicts the reported User-Agent.'],
        'transport_temporal_hard_component_changed' => [25, 'transport', 'The device\'s hard components (OS family, CPU architecture, touch) changed between two observations linked by cookie or browser key, which one physical device cannot do.'],
        'transport_fetch_none_with_referer' => [8, 'transport', 'Sec-Fetch-Site is none (a user-started navigation) while a web Referer is present; a driver or an embedder added the header.'],
        'transport_referer_implausible' => [8, 'transport', 'Sec-Fetch-Site is same-origin while the Referer names another site (Chromium and Firefox only; Safari legitimately keeps the old referrer on reload).'],
        'transport_agent_self_identified' => [0, 'transport', 'The request carries HTTP message-signature headers (Signature-Agent, or Signature with Signature-Input): the client announces itself as an automated agent. Weight 0, logged only.'],
        'transport_default' => [45, 'transport', 'A hard transport finding with no more specific rule.'],
        'transport_crawler_impersonation' => [45, 'transport', 'The User-Agent claims a search crawler (Googlebot, Bingbot, ...) and reverse DNS or the vendor\'s published IP list contradicts it.'],
        'transport_soft_default' => [6, 'transport', 'A soft transport finding with no more specific rule.'],
        'engine_vs_ch_header' => [30, 'transport', 'The browser sent a Sec-CH-UA header (only Chromium does) while the JavaScript engine is not V8.'],

        // --- Environment: the page contradicts itself ---------------------------------
        'lied_browser' => [20, 'environment', 'A browser-specific API is present in a browser that never shipped it.'],
        'lied_os' => [20, 'environment', 'The platform and the Client-Hints platform disagree.'],
        'lied_languages' => [15, 'environment', 'The language list is a shape no browser produces.'],
        'lied_resolution' => [8, 'environment', 'The screen geometry is not one any display produces.'],
        'screen_zoom_implausible' => [6, 'environment', 'The screen size implies a device pixel ratio no real display has.'],
        'plugins_vs_ua' => [12, 'environment', 'The plugin list contradicts the claimed browser.'],
        'plugins_vs_pdfviewer' => [20, 'environment', 'The PDF plugin set is reported while the PDF viewer is disabled.'],
        'cores_vs_memory' => [8, 'environment', 'The core count and the reported device memory are not a pair any device ships.'],
        'arch_vs_ch_arch' => [15, 'transport', 'The CPU architecture from the NaN-sign probe differs from the Sec-CH-UA-Arch header.'],
        'device_memory_vs_ch' => [15, 'transport', 'navigator.deviceMemory differs from the Sec-CH-Device-Memory header the browser sent (needs the host\'s Accept-CH).'],
        'ch_bitness_vs_js' => [15, 'transport', 'getHighEntropyValues bitness differs from the Sec-CH-UA-Bitness header (needs the host\'s Accept-CH).'],
        'ch_model_vs_js' => [15, 'transport', 'getHighEntropyValues model differs from the Sec-CH-UA-Model header (needs the host\'s Accept-CH).'],
        'dpr_vs_ch' => [8, 'transport', 'window.devicePixelRatio differs from the Sec-CH-DPR header (needs the host\'s Accept-CH).'],
        'viewport_vs_ch' => [6, 'transport', 'window.innerWidth differs from the Sec-CH-Viewport-Width header beyond a scrollbar and resize tolerance (needs the host\'s Accept-CH; silent on touch devices).'],
        'gpu_webgpu_vs_webgl' => [10, 'environment', 'The WebGPU adapter vendor and the WebGL renderer name belong to different GPU vendor families.'],
        'touch_vs_pointer_media' => [6, 'environment', 'A touch screen is reported while no media query matches a coarse pointer.'],
        'tz_vs_lang_region' => [4, 'environment', 'The timezone is not one of the regions the language list implies.'],

        // --- WebGL: the renderer and its limits against the claimed platform ----------
        'renderer_vs_limits' => [12, 'environment', 'A WebGL limit is below the published WebGL 1.0/2.0 specification minimum, which no hardware implementation reports.'],
        'ch_platform_vs_gpu' => [10, 'environment', 'The WebGL renderer names a GPU family that cannot exist on the claimed operating system (for example an Apple GPU on Windows or Direct3D on macOS).'],
        'ua_vs_engine' => [30, 'environment', 'The User-Agent names one browser engine while the JavaScript engine identifies itself as another (V8, SpiderMonkey or JavaScriptCore, read from error-object shape).'],
        'ua_vs_feature_version' => [25, 'environment', 'The User-Agent version disagrees with the ECMAScript and web features the engine actually exposes, by three or more releases.'],
        'worker_vs_window_navigator' => [30, 'environment', 'A dedicated worker reports a different user agent, platform, core count, memory, Client-Hints platform/mobile/brands, engine or ICU build than the page, so the page values are patched.'],
        'worker_vs_window_timezone' => [20, 'environment', 'A dedicated worker resolves a different time zone, UTC offset or Intl locale than the page.'],
        'worker_vs_window_gpu' => [15, 'environment', 'A dedicated worker sees a different WebGL renderer than the page.'],
        'notification_permission_vs_query' => [15, 'environment', 'permissions.query says notifications are at prompt while Notification.permission says denied, the headless-browser pattern.'],
        'notification_permission_nonstandard' => [25, 'environment', 'Notification.permission or the permissions.query notifications state is a value outside the enumeration of its own API (for example the DOM word default returned by permissions.query), which no engine produces.'],
        'fonts_single_family_desktop' => [10, 'environment', 'The User-Agent names Windows or macOS, but at most one of that operating system\'s base font families is installed (a minimal container or agent browser; not WebKit, not a privacy mode that restricts fonts).'],
        'tz_utc_vs_language_region' => [6, 'environment', 'The resolved time zone is UTC while the language tag names a country; servers and kiosks are the honest collision, so it never scores alone.'],
        'ua_reduced_shape_violation' => [15, 'environment', 'A plain-Chrome User-Agent from release 110 on carries an OS version or device model that Chromium freezes (Windows NT 10.0, Mac OS X 10_15_7, Android 10 with model K) while Sec-CH-UA is present.'],
        'webview_ua_shape' => [8, 'environment', 'An Android WebView User-Agent (; wv) without the device model and Build token every WebView ships; OEM overrides are the honest collision.'],
        'audio_readback_perturbed' => [4, 'environment', 'A constant audio source rendered offline read back with values other than the constant, so audio values are noised and cannot identify the device.'],
        'ua_headless_token' => [30, 'environment', 'The User-Agent, as reported by the page or sent by the browser, carries a headless-browser product token (HeadlessChrome, PhantomJS, SlimerJS).'],
        'screen_vs_css_media' => [20, 'environment', 'screen.width and screen.height both differ from the device size the CSS media-query path reports, which a JavaScript override of screen cannot change.'],
        'tz_intl_vs_date' => [20, 'environment', 'The Intl time zone\'s historic (1113) offset differs from the offset the engine computes itself, the signature of an Intl-only time zone spoof.'],
        'fonts_vs_ua_os' => [15, 'environment', 'None of the fonts the User-Agent\'s operating system ships is installed while another operating system\'s set is.'],
        'gpu_webgl_params_mismatch' => [20, 'environment', 'WebGL1 and WebGL2 report different values for parameters that describe the same GPU; one context\'s getParameter is patched.'],
        'cores_vs_measured_parallelism' => [10, 'environment', 'The measured parallel capacity (timed workers) is well above the reported core count; a low measurement is load, not evidence.'],
        'resistance_vs_engine' => [30, 'environment', 'The client reports a privacy mode (Firefox resistFingerprinting, Tor, Brave) that the engine marks, the User-Agent or the headers contradict; faking it would otherwise reduce what the matcher sees.'],
        'canvas_realm_mismatch' => [4, 'environment', 'The page and its worker rasterised the same geometry differently, so the page\'s canvas read-back is noised by something the worker realm does not see.'],
        'gpu_realm_mismatch' => [4, 'environment', 'The page and its dedicated worker rendered the same shader to different pixels at the same precision, so the page\'s WebGL read-back is hooked (a page-only readPixels or getParameter patch).'],
    ];

    /**
     * @return list<string>
     */
    public static function codes(): array
    {
        return array_keys(self::CHECKS);
    }

    /**
     * @return list<string>
     */
    public static function families(): array
    {
        $families = [];
        foreach (self::CHECKS as [$weight, $family, $description]) {
            unset($weight, $description);
            $families[$family] = true;
        }

        return array_keys($families);
    }

    /**
     * The overrides map: code => weight.
     *
     * ## Why this is read as a nested array and not a dotted key
     *
     * The first version asked `Settings` for `'check_weights.'.$code`. `Settings::has()`
     * is an `array_key_exists` on a flat array, so a host that supplied
     * `['check_weights' => ['ua_vs_ua_header' => 0]]` — the natural shape, and the one the
     * admin screen writes — was silently not found. Every override appeared to be ignored
     * and the registry returned the shipped weight, so a silenced check kept scoring. The
     * tests caught it because they assert the *effect on the engine* rather than on
     * storage.
     *
     * Both spellings are accepted: the nested array, and a flat `check_weights.code` key for
     * a host that has only a string-keyed store. The nested one is checked first, so the
     * more natural shape wins where both are present.
     *
     * @return array<string, mixed>
     */
    private static function overrides(Settings $settings): array
    {
        $nested = $settings->get('check_weights');
        if (is_array($nested)) {
            // Re-keyed rather than returned as-is. A host that reads its overrides from a
            // store which integer-keys a JSON object would hand back `['0' => 0]`, and
            // `array_key_exists($code, …)` on that would miss every code.
            $keyed = [];
            foreach ($nested as $code => $weight) {
                $keyed[(string) $code] = $weight;
            }

            return $keyed;
        }

        // Flat fallback: every key that begins `check_weights.`.
        $flat = [];
        foreach ($settings->all() as $key => $value) {
            if (is_string($key) && str_starts_with($key, 'check_weights.')) {
                $flat[substr($key, strlen('check_weights.'))] = $value;
            }
        }

        return $flat;
    }

    /**
     * The effective weight for a code: 0 when the host has switched it off.
     */
    public static function weightFor(string $code, Settings $settings): int
    {
        $overrides = self::overrides($settings);

        if (array_key_exists($code, $overrides)) {
            // A host override is authoritative, including 0, and a wrong-typed value falls
            // back to the shipped default rather than coercing to 0 — coercing would mean a
            // mistyped weight silently disabled a check.
            $default = self::CHECKS[$code][0] ?? 0;

            return is_numeric($overrides[$code]) ? (int) $overrides[$code] : $default;
        }

        if ($settings->has('checks_enabled') && ! $settings->bool('checks_enabled', true)) {
            return 0;
        }

        if (array_key_exists($code, self::CHECKS)) {
            return self::CHECKS[$code][0];
        }

        // An unknown code is scored at 0, never at a catch-all default. A check the
        // deployment has not heard of cannot be assumed to be rare; the Laravel package
        // enforces the same rule with a test.
        return 0;
    }

    public static function isKnown(string $code): bool
    {
        return array_key_exists($code, self::CHECKS);
    }

    public static function familyOf(string $code): ?string
    {
        return self::CHECKS[$code][1] ?? null;
    }

    public static function descriptionOf(string $code): ?string
    {
        return self::CHECKS[$code][2] ?? null;
    }

    /**
     * The whole registry, for a settings UI.
     *
     * `default_weight` is alongside `weight` deliberately, and not derivable: `weight` is
     * the value in force, `default_weight` is the shipped one. A settings screen needs both
     * to show "changed from 40" and to offer a reset, and a screen that has to reconstruct
     * the default from a second lookup is a screen where the two can disagree.
     *
     * @return array<string, array{weight: int, default_weight: int, family: string, description: string}>
     */
    public static function describe(Settings $settings = new Settings): array
    {
        $out = [];
        foreach (self::CHECKS as $code => [$weight, $family, $description]) {
            $out[$code] = [
                'weight' => self::weightFor($code, $settings),
                'default_weight' => $weight,
                'family' => $family,
                'description' => $description,
            ];
        }

        return $out;
    }
}
