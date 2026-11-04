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
 * them is measured). The heaviest single contradiction is 45 (score 68, `challenge`), and
 * `EnvironmentConsistency::MAX_WEIGHT` (45) is also the ceiling an operator override is
 * clamped to. Learning the weights from the population is notes/23 (not implemented).
 *
 * ## Evidence groups: one root cause counts once
 *
 * A ceiling per RULE is not enough, because several rules can read one underlying fact. A
 * User-Agent switcher makes the UA disagree with Sec-CH-UA-Full-Version-List
 * (`transport_sec_ch_full_version_mismatch`, 45), with the JavaScript version list
 * (`ua_vs_ch_major`, 25) and with the engine's feature set (`ua_vs_feature_version`, 25): one
 * fact, three rules, 95 summed, `block` on a real Chromium whose only change was its UA
 * (skeptical review H2). `EVIDENCE_GROUPS` declares which rules share their evidence, and
 * {@see effectiveWeight()} counts each group once, at its heaviest member. A code in no group
 * is its own group. Every rule is still listed in the verdict at its own weight; only the sum
 * the score is computed from changes.
 *
 * The invariant, enforced by `SingleRootCauseInvariantTest` on facts rather than rules: one
 * root cause is one group, one group weighs at most 45, and 45 scores 68, so **no single root
 * cause can block a device**; a device has to contradict itself in two independent ways.
 * Grouping is deliberately coarse where an honest tool touches several facts at once (a UA
 * switcher rewrites the UA, the userAgentData values and the page-realm getters together; a
 * noise extension noises canvas, audio, rectangles and text together).
 *
 * A group is NOT a family. Families (`integrity`, `transport`, `environment`) describe the
 * kind of source; a group spans families when one cause shows up in several of them.
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
        'viewport_fills_screen' => [20, 'environment', 'On a desktop Chromium the viewport is exactly as large as the screen although the window has a title bar and toolbar around it: the device-metrics override Playwright and Puppeteer apply by default.'],
        'headless_default_screen' => [15, 'environment', 'A desktop Chromium reports exactly the 800x600 screen with no taskbar that headless Chromium defaults to.'],
        'window_exceeds_screen' => [12, 'environment', 'A desktop Chromium window is larger than the screen in both dimensions by more than any border (undetected-chromedriver headless: 1920x1080 on 800x600).'],
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
        'transport_temporal_engine_changed' => [20, 'transport', 'The browser engine the page measured (JavaScript engine marks, or the Lightpanda brand) changed between two observations of the same first-party cookie: the cookie was exported into another browser, as when a session is moved into a headless one. A one-time browser migration that imports cookies is the honest collision.'],
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
        'ua_headless_token' => [30, 'environment', 'The User-Agent, as reported by the page or sent by the browser, carries a headless-browser product token (HeadlessChrome, PhantomJS, SlimerJS, Lightpanda), or Sec-CH-UA or userAgentData.brands names Lightpanda.'],
        'media_hover_unanswered' => [15, 'environment', 'matchMedia matches neither (hover: hover) nor (hover: none), which every browser with a media-query engine does; a headless engine without one (Lightpanda) answers false to both.'],
        'render_surfaces_stubbed' => [30, 'environment', 'Text width does not depend on the font (no layout engine behind the page) and there is no WebGL or the canvas fill rules are stubs: an engine that neither lays out nor draws (Lightpanda, DOM-only scrapers).'],
        'screen_vs_css_media' => [20, 'environment', 'screen.width and screen.height both differ from the device size the CSS media-query path reports, which a JavaScript override of screen cannot change.'],
        'tz_intl_vs_date' => [20, 'environment', 'The Intl time zone\'s historic (1113) offset differs from the offset the engine computes itself, the signature of an Intl-only time zone spoof.'],
        'fonts_vs_ua_os' => [15, 'environment', 'None of the fonts the User-Agent\'s operating system ships is installed while another operating system\'s set is.'],
        'gpu_webgl_params_mismatch' => [20, 'environment', 'WebGL1 and WebGL2 report different values for parameters that describe the same GPU; one context\'s getParameter is patched.'],
        'cores_vs_measured_parallelism' => [10, 'environment', 'The measured parallel capacity (timed workers) is well above the reported core count; a low measurement is load, not evidence.'],
        'resistance_vs_engine' => [30, 'environment', 'The client reports a privacy mode (Firefox resistFingerprinting, Tor, Brave) that the engine marks, the User-Agent or the headers contradict; faking it would otherwise reduce what the matcher sees.'],
        'canvas_realm_mismatch' => [4, 'environment', 'The page and its worker rasterised the same geometry differently, so the page\'s canvas read-back is noised by something the worker realm does not see.'],
        'gpu_realm_mismatch' => [4, 'environment', 'The page and its dedicated worker rendered the same shader to different pixels at the same precision, so the page\'s WebGL read-back is hooked (a page-only readPixels or getParameter patch).'],

        // --- Smart signals: network, virtual machine, emulator, private browsing (all soft) -----------
        'ip_country_vs_locale' => [5, 'environment', 'The IP address geolocates to a country that neither the time zone nor the language list names; both settings must disagree, so an expat or a traveller who changed one of them is silent. Needs the host\'s local IP data.'],
        'network_vpn' => [4, 'environment', 'The IP address belongs to an autonomous system whose registered name says VPN. A commercial VPN is an honest choice; the signal is soft. Needs the host\'s local IP data.'],
        'network_hosting' => [5, 'environment', 'The IP address belongs to a hosting, cloud or colocation network (an ASN name or list, or a published cloud range). Corporate gateways and VPN egress are the honest cases. Needs the host\'s local IP data.'],
        'vm_gpu_renderer' => [5, 'environment', 'The WebGL renderer names a hypervisor\'s virtual GPU (VMware, VirtualBox, Parallels, QEMU/virtio, Hyper-V) on a non-headless desktop browser. Corporate VDI users are honest and fire this.'],
        'vm_software_gpu_screen' => [4, 'environment', 'A software-rendered WebGL context together with a default virtual-machine screen size (800x600, 1024x768, 1152x864). A software renderer alone, as on many Linux desktops, is silent.'],
        'emulator_android' => [8, 'environment', 'An Android browser that identifies as an emulator (emulator token in the user agent or device model) or runs on a software GPU.'],
        'private_mode_with_other_signals' => [3, 'environment', 'The tab looks like private browsing (storage profile) AND a network, virtual-machine, emulator or locale signal is present. Private browsing alone is never scored.'],
    ];

    /**
     * group => codes that read one underlying fact (one root cause). Codes in no group are their
     * own group. Each group is argued in a comment; `SingleRootCauseInvariantTest` checks that
     * every member is a registered check and that perturbing one cause of an honest capture adds
     * at most one group's weight.
     *
     * @var array<string, list<string>>
     */
    private const EVIDENCE_GROUPS = [
        // The browser identity the client claims (User-Agent header, navigator.userAgent /
        // appVersion / platform, userAgentData) against what the engine, the headers and the
        // TLS stack prove. A UA switcher, an enterprise UA override or a spoofer's UA lie is ONE
        // cause however many of these comparisons it trips: header vs page, version vs CH list,
        // version vs features, family vs engine, OS vs platform/fonts/GPU, the page-realm getter
        // wrap a switcher leaves (`lie_battery_privacy_tool`), and the page/worker split a
        // page-only override leaves (`worker_vs_window_navigator`).
        'claimed_identity' => [
            'ua_vs_ua_header', 'brands_vs_ch_header', 'ua_vs_ch_brand', 'ua_vs_ch_major',
            'transport_sec_ch_full_version_mismatch', 'ja4_vs_ua', 'ch_bitness_vs_js', 'ch_model_vs_js',
            'lied_os', 'lied_browser', 'plugins_vs_ua', 'ua_vs_engine', 'ua_vs_feature_version',
            'worker_vs_window_navigator', 'fonts_single_family_desktop', 'fonts_vs_ua_os',
            'ua_reduced_shape_violation', 'webview_ua_shape', 'ch_platform_vs_gpu',
            'lie_battery_privacy_tool', 'emulator_android',
        ],
        // The visitor's locale settings against each other and the network: an expat, a
        // traveller or a server on UTC is one cause.
        'locale' => ['tz_vs_lang_region', 'tz_utc_vs_language_region', 'ip_country_vs_locale', 'lang_vs_accept_language'],
        // Browser zoom moves devicePixelRatio, innerWidth and the screen/DPR relation together.
        'display_metrics' => ['dpr_vs_ch', 'viewport_vs_ch', 'screen_zoom_implausible'],
        // One noise extension or privacy mode (Brave farbling, Firefox RFP/FPP, Safari advanced
        // protection) noises every read-back surface at once.
        'readback_noise' => [
            'canvas_readback_perturbed', 'canvas_pattern_perturbed', 'audio_readback_perturbed', 'lie_battery_noise_tool',
            'realm_tostring_noise_tool', 'canvas_realm_mismatch', 'gpu_realm_mismatch', 'domrect_inconsistent', 'svg_text_inconsistent',
        ],
        // A VPN exit is commonly also a hosting network.
        'network' => ['network_vpn', 'network_hosting'],
        // An engine that neither lays out nor draws (Lightpanda, DOM-only scrapers): font-independent
        // text with no WebGL, and a canvas whose fill rules are stubs, are one cause. The unanswered
        // `hover` query and the self-announced token are separate measurements and stay outside.
        'non_rendering_engine' => ['render_surfaces_stubbed', 'canvas_winding_false'],
        // A virtual machine shows as a virtual GPU and as a VM default screen.
        'virtual_machine' => ['vm_gpu_renderer', 'vm_software_gpu_screen'],
    ];

    /**
     * @return array<string, list<string>>
     */
    public static function evidenceGroups(): array
    {
        return self::EVIDENCE_GROUPS;
    }

    /**
     * The evidence group of a code: its declared group, or the code itself.
     */
    public static function evidenceGroupOf(string $code): string
    {
        static $index = null;
        if ($index === null) {
            $index = [];
            foreach (self::EVIDENCE_GROUPS as $group => $codes) {
                foreach ($codes as $member) {
                    $index[$member] = $group;
                }
            }
        }

        return $index[$code] ?? $code;
    }

    /**
     * The weight a score is computed from: per evidence group, the heaviest member's weight,
     * summed over groups. A code outside every group (including `model_adjustment`, which may be
     * negative) counts as its own group. Two disagreements with one code count once.
     *
     * @param  iterable<array-key, mixed>  $disagreements  `{code, weight}` entries
     */
    public static function effectiveWeight(iterable $disagreements): int
    {
        $byGroup = [];
        foreach ($disagreements as $disagreement) {
            if (! is_array($disagreement) || ! is_string($disagreement['code'] ?? null) || ! is_int($disagreement['weight'] ?? null)) {
                continue;
            }
            $group = self::evidenceGroupOf($disagreement['code']);
            $byGroup[$group] = isset($byGroup[$group]) ? max($byGroup[$group], $disagreement['weight']) : $disagreement['weight'];
        }

        return array_sum($byGroup);
    }

    /**
     * Distinct evidence groups among disagreements with a positive weight.
     *
     * @param  iterable<array-key, mixed>  $disagreements
     * @return list<string>
     */
    public static function groupsOf(iterable $disagreements): array
    {
        $groups = [];
        foreach ($disagreements as $disagreement) {
            if (is_array($disagreement) && is_string($disagreement['code'] ?? null) && ($disagreement['weight'] ?? 0) > 0) {
                $groups[self::evidenceGroupOf($disagreement['code'])] = true;
            }
        }
        $out = array_keys($groups);
        sort($out);

        return $out;
    }

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
