<?php

declare(strict_types=1);

namespace DeviceId\Rules;

use DeviceId\Network\NetworkFacts;
use DeviceId\Scoring\ShadowWeights;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Signals\SmartSignals;
use DeviceId\Support\Config;
use DeviceId\Support\FeatureShipVersions;
use DeviceId\Support\ProbeEnvelope;
use DeviceId\Support\TransportIntegrityResult;
use DeviceId\Transport\StructuredFieldList;

/**
 * The disagreement engine: compares what the page claimed against what the transport
 * proved, and returns named contradictions.
 *
 * A pure function of its two arguments (no container, clock or I/O), so every rule is
 * tested both ways: it fires on a violating input and stays silent on a real captured
 * claim set. It never asks "is this value suspicious?", only "do two independently
 * obtained facts disagree?" — a missing value therefore silences a rule, never trips it.
 *
 * Wire shape: `{ integrity: {findings, data}, tier1: {...}, tier2: {...} }`. A probe is
 * its raw value when it succeeded and `{ state: 'unavailable'|'error', ... }` otherwise;
 * older fixtures wrap values as `{ state: 'ok', value }`. `read()` unwraps both.
 *
 * Disagreement `detail` strings name the fields that disagree and never embed a claim
 * value or a header value: they are stored per observation and shown to operators.
 */
final class EnvironmentConsistency
{
    /**
     * IANA zone to ISO 3166 region, for the zones this application will see.
     *
     * ## Deliberately incomplete
     *
     * The design warned against hard-coding a timezone table, because such a table
     * goes stale silently and starts flagging real users. This one is scoped to be
     * incomplete on purpose: `tz_vs_lang_region` looks a zone up here, and **a zone
     * that is absent produces no finding at all**.
     *
     * So the failure mode is under-detection, which is the acceptable direction for a
     * weight-4 check, rather than false positives on every visitor in a region nobody
     * thought to list. Adding zones is a one-line change and needs no code review of
     * the rule.
     *
     * @var array<string, string>
     */
    private const TIMEZONE_REGIONS = [
        // Western Europe
        'europe/amsterdam' => 'NL', 'europe/brussels' => 'BE', 'europe/berlin' => 'DE',
        'europe/vienna' => 'AT', 'europe/zurich' => 'CH', 'europe/paris' => 'FR',
        'europe/madrid' => 'ES', 'europe/lisbon' => 'PT', 'europe/rome' => 'IT',
        'europe/copenhagen' => 'DK', 'europe/oslo' => 'NO', 'europe/stockholm' => 'SE',
        'europe/helsinki' => 'FI', 'europe/warsaw' => 'PL', 'europe/prague' => 'CZ',
        'europe/budapest' => 'HU', 'europe/dublin' => 'IE', 'europe/london' => 'GB',
        // North America
        'america/new_york' => 'US', 'america/chicago' => 'US', 'america/denver' => 'US',
        'america/los_angeles' => 'US', 'america/phoenix' => 'US', 'america/toronto' => 'CA',
        'america/vancouver' => 'CA', 'america/mexico_city' => 'MX',
        // Asia
        'asia/tokyo' => 'JP', 'asia/seoul' => 'KR', 'asia/shanghai' => 'CN',
        'asia/hong_kong' => 'HK', 'asia/singapore' => 'SG', 'asia/kolkata' => 'IN',
        'asia/calcutta' => 'IN', 'asia/dubai' => 'AE', 'asia/bangkok' => 'TH',
        'asia/jakarta' => 'ID', 'asia/manila' => 'PH', 'asia/jerusalem' => 'IL',
        // Oceania
        'australia/sydney' => 'AU', 'australia/melbourne' => 'AU',
        // Was the bare key `auckland`, which no IANA identifier ever matches, so New
        // Zealand silently never took part in `tz_vs_lang_region` (notes/21 §4).
        'australia/perth' => 'AU', 'pacific/auckland' => 'NZ',
        // Americas, south
        'america/sao_paulo' => 'BR', 'america/argentina/buenos_aires' => 'AR',
        'america/santiago' => 'CL', 'america/bogota' => 'CO', 'america/lima' => 'PE',
        // Africa
        'africa/johannesburg' => 'ZA', 'africa/lagos' => 'NG', 'africa/cairo' => 'EG',
        'africa/nairobi' => 'KE',
    ];

    /**
     * Weights are not entropy and not confidence. They express *how much a
     * contradiction of this kind is worth*, on the reasoning that a conformance
     * failure (weight 25-40) means the environment is not a browser, while a
     * cross-source inconsistency (weight 4-20) means two sources disagree and the
     * cheaper explanation is usually an exotic configuration.
     *
     * Every entry has a rule (`EnvironmentConsistencyTest::every_weighted_code_has_a_rule`
     * asserts both directions). `UNIMPLEMENTED_SPEC_RULES` records the spec rules that
     * are deliberately absent.
     *
     * @var array<string, int>
     */
    /**
     * The largest weight any rule, and therefore any evidence group, may carry, shipped or
     * overridden: 100 × (1 − e^(−45/40)) is 68, 12 points below the shipped `block` band of 80,
     * so no single root cause can block (CheckRegistry, "Evidence groups").
     *
     * It was 60 (score 78), which left a 2-point margin: a host that lowered the divisor to 37
     * let one overridden rule block. 45 is the heaviest shipped weight, so the shipped
     * behaviour is unchanged; only overrides above 45 are now clamped. The model's bounded
     * adjustment is capped by this value too, and never moves a verdict into `block`.
     */
    public const MAX_WEIGHT = 45;

    /**
     * Releases of tolerance either side of the claimed version before a feature counts
     * as contradicting it, and how many features must do so. See `ua_vs_feature_version`.
     */
    private const FEATURE_VERSION_TOLERANCE = 3;

    private const FEATURE_VERSION_MIN_WITNESSES = 2;

    private const FEATURE_VERSION_MIN_PRESENT = 10;

    /** CSS px `viewport_vs_ch` allows between `innerWidth` and `Sec-CH-Viewport-Width` (scrollbar, resize). */
    private const VIEWPORT_HEADER_TOLERANCE = 24;

    /** Families of ANOTHER operating system that must be present for `fonts_vs_ua_os`. */
    private const FONTS_OTHER_OS_MIN = 4;

    /**
     * `esFeatures` keys that are ECMAScript builtins: present in every build of the
     * engine version that shipped them, independent of secure context, enterprise policy
     * or platform. Only these may count as "absent" evidence in `ua_vs_feature_version`.
     *
     * @var list<string>
     */
    private const ALWAYS_ON_ES_FEATURES = [
        'weakRef', 'finalizationRegistry', 'arrayAt', 'errorCause', 'errorErrors', 'regExpHasIndices',
        'arrayToSorted', 'arrayToReversed', 'arrayToSpliced', 'arrayWith', 'arrayFindLast', 'arrayFindLastIndex',
        'objectGroupBy', 'promiseWithResolvers', 'arrayBufferResize', 'arrayBufferTransfer', 'regexpVFlag',
        'stringIsWellFormed', 'stringToWellFormed', 'iteratorHelpers', 'setUnion', 'regexpEscape', 'promiseTry',
        'float16Array', 'uint8FromBase64', 'uint8ToBase64', 'uint8SetFromBase64', 'uint8ToHex', 'errorIsError',
        'mathSumPrecise', 'arrayFromAsync', 'mapGetOrInsert',
    ];

    /**
     * The last claim set's effective integrity findings; see `effectiveFindings()`.
     *
     * @var array{claims: array<array-key, mixed>, effective: array<string, string>}|null
     */
    private ?array $effectiveMemo = null;

    private const WEIGHTS = [
        // Tier A — conformance. A real browser cannot produce these. Measured 30/30
        // against a stealth spoofer for 0.125 ms total.
        'wrong_receiver_did_not_throw' => 40,
        'math_pf_mismatch' => 40,
        'descriptor_patched' => 30,
        'descriptor_unstable' => 25,
        'descriptor_missing' => 30,
        // An own property on the `navigator` instance shadowing a WebIDL attribute getter:
        // the one-line spoof `navigator.userAgent = '…'`. Client code v3.
        'descriptor_shadowed' => 30,
        'canvas_dual_diverged' => 35,
        'canvas_winding_false' => 25,
        // The three codes below were EMITTED by the client since v3 and weighted by
        // nothing (notes/19 C8): they cost 5 coverage points each and never reached the
        // risk score. A setter on a read-only WebIDL attribute is the same class of
        // evidence as a patched descriptor and is weighted just under it. An
        // automation-injected global (`__webdriver_evaluate`, `__selenium_evaluate`,
        // `__nightmare`) is a driver's own footprint, not a spoofer's mistake, so it
        // sits with the conformance tier. A global whose READ throws is merely odd
        // (a blocker extension), so it is soft.
        'descriptor_has_setter' => 25,
        'dom_blocker_present' => 30,
        'dom_blocker_threw' => 6,
        // `navigator.webdriver` deleted. Every shipping engine defines the attribute
        // (it is a required member of Navigator in the WebDriver specification), and
        // `delete Navigator.prototype.webdriver` is the oldest stealth evasion there is.
        // CreepJS's `webDriverIsOn` makes the same inference (notes/21 §2 item 4).
        'webdriver_missing' => 25,
        // A solid-colour canvas fill that reads back as something other than the fill
        // colour. This is NOT tampering by an attacker — it is Brave's farbling, Firefox's
        // fingerprinting protection or a noise extension, i.e. an honest visitor with a
        // privacy tool — so it carries 4: enough to be visible to an operator and to be
        // the input the per-component trust projection (notes/21 §2 item 7) needs, and
        // far too little to move a band on its own.
        'canvas_readback_perturbed' => 4,
        // The same fact over a two-colour pattern with edges: noise that leaves a uniform fill
        // exact (Firefox Private/Strict, Safari advanced protection). An honest privacy tool.
        'canvas_pattern_perturbed' => 4,
        // A driver global (the ChromeDriver `cdc_` property, Playwright binding, Selenium, PhantomJS) that
        // no site defines: as certain as `dom_blocker_present`, which it extends, and weighted
        // the same.
        'automation_global_present' => 30,
        // Outer size equals inner size and a one-entry history on a desktop browser that is not
        // WebKit: a headless shell. Weak on its own (kiosk modes exist), so it stays small.
        'headless_shell_geometry' => 8,
        // `navigator.webdriver === true`: the browser itself says an automation protocol is attached
        // (WebDriver, Marionette, CDP with `--enable-automation`). The WebDriver specification
        // defines it as exactly that. Honest visitors essentially never carry it; the edge cases
        // are managed enterprise test browsers and a developer with Safari's Remote Automation on.
        // 20 alone scores 39 (pass, visible to an operator), and with the self-announced headless
        // token it reaches challenge, never block on its own. It is the explicit rule for what
        // the confidence score already penalised (`ConfidenceScorer`, reason `webdriver`).
        'webdriver_true' => 20,
        // Firefox's headless widget has a fixed 1366x768 screen with no panel (available area equal
        // to the screen at the origin), so every headless Gecko (geckodriver, Marionette, Playwright's
        // Firefox) reports exactly that on a Linux or macOS UA. Measured on Firefox 155, raw
        // `-headless` and under Playwright 1.63. 10: a 1366x768 panel-less Linux desktop is the
        // honest collision (Windows is excluded: an auto-hidden taskbar gives the same numbers).
        'headless_gecko_screen' => 10,
        // Red-team measurements (tools/redteam, Chromium 153 driven by Puppeteer, Playwright, Patchright,
        // rebrowser, nodriver and undetected-chromedriver with their stealth features on):
        // `Emulation.setDeviceMetricsOverride`, which Playwright and Puppeteer apply by default (1280x720
        // and 800x600), makes the page's `screen` equal its viewport while the window still has a title
        // bar and toolbar around it. A real window cannot fill the whole screen with its viewport and
        // still have chrome. 20: unambiguous on desktop Chromium, never block alone.
        'viewport_fills_screen' => 20,
        // Headless Chromium's own default screen is exactly 800x600 with no taskbar (`--window-size`
        // default), which nodriver, undetected-chromedriver and Puppeteer keep. No desktop has had an
        // 800x600 display for twenty years, but kiosks and legacy VMs exist, so 15.
        'headless_default_screen' => 15,
        // The window is larger than the screen in BOTH dimensions by more than any border or shadow
        // (Windows adds 16 px to a maximised window): undetected-chromedriver's headless window is
        // 1920x1080 on an 800x600 screen. A window spanning monitors exceeds the screen in one axis only.
        'window_exceeds_screen' => 12,
        // Contract 2 integrity codes. The lie battery and the cross-realm toString are the
        // CreepJS `lies` module re-done without tables: a native function that is
        // constructible, owns a property other than length/name, or survives a cyclic
        // prototype is a Proxy or a closure — conformance tier, just under
        // `wrong_receiver_did_not_throw` because the battery has more surface for an
        // engine quirk. DOMRect and SVG arithmetic are what a noise extension breaks and
        // nothing else does; 25 and 20 because sub-pixel layout has more honest variance
        // than a getter does.
        'lie_battery_failed' => 35,
        'realm_tostring_mismatch' => 35,
        // The same two findings when every lied API is a read-back surface: a noise
        // extension, i.e. the honest visitor the read-back codes weight at 4. 6, soft.
        'lie_battery_noise_tool' => 6,
        // The lie battery alone, on identity getters only (Navigator, Screen, Date/Intl time zone),
        // in the page realm only (the worker disagrees) and with no other conformance tell: a
        // User-Agent switcher or JShelter-class extension. It is still a lie, so it keeps a
        // weight (15), but it is not scored as the fraud-tool footprint (35) and stacked with
        // `worker_vs_window_*` into `block`.
        'lie_battery_privacy_tool' => 15,
        'realm_tostring_noise_tool' => 6,
        'domrect_inconsistent' => 25,
        'svg_text_inconsistent' => 20,

        // Tier B — cross-source. Two independently obtained facts disagreeing.
        'plugins_vs_pdfviewer' => 20,
        'ua_vs_ch_major' => 25,
        'ua_vs_ch_brand' => 20,
        // The same family of finding as `ua_vs_ch_brand`, and the same weight: one
        // contradiction between what the page said and what the browser sent. It is a
        // separate code rather than a stronger version of the same one so that an
        // operator can tell "the UA string was patched" from "the hints were patched" —
        // different attacker effort and worth knowing which is being attempted.
        'brands_vs_ch_header' => 20,
        // Rewriting `navigator.userAgent` is the single most common thing a spoofer does,
        // and this is the first rule in the system that can see it. Same weight as its
        // sibling above: one contradiction, not two, however it is reached.
        'ua_vs_ua_header' => 20,
        // The only rule in this table whose evidence is below the header layer. See the
        // rule for why 20 and not higher: a deployment with no TLS terminator configured
        // has less evidence, not a worse client, and this must never become a way to
        // punish that.
        'ja4_vs_ua' => 20,
        // The only CROSS-OBSERVATION rule. Every other weight in this table scores a
        // within-request disagreement; this one scores observation N against observation
        // N-1, which is the only place in the system where an attacker has to be
        // consistent OVER TIME rather than within a single request.
        //
        // 25, not 40, and the gap matters twice over. It is above `ja4_vs_ua` because a
        // TLS stack that changed while the reported browser did not is a stronger signal
        // than one ClientHello disagreeing with a User-Agent. And it is below 40 so the
        // `block` band stays unreachable on this alone - the same property every other
        // weight in this table is chosen to preserve, and the reason a single
        // cross-visit rule cannot be turned into a one-signal ban.
        'transport_temporal_ja4_changed_without_ua_change' => 25,
        // The hard components (`os`, `arch`, `touch`: what one physical device cannot change) differ
        // between two observations the host linked by something other than those components (the same
        // first-party cookie, the same browser key). Stored as the existing unkeyed `block_tuple`
        // hash, so no claim value is kept. 25: a cookie jar shared across devices is the honest
        // collision, so it is never the 45 of a protocol violation.
        'transport_temporal_hard_component_changed' => 25,
        // The Referer against Sec-Fetch-Site (see TransportIntegrity). Both are improbable rather
        // than impossible (an embedder or a privacy tool can add a header), hence soft and 8.
        'transport_fetch_none_with_referer' => 8,
        'transport_referer_implausible' => 8,
        // A self-identified AI agent: weight 0, logged for policy and the operator's panel only.
        'transport_agent_self_identified' => 0,
        'plugins_vs_ua' => 12,
        'touch_vs_ch_mobile' => 15,
        // The NaN-sign architecture probe against the Sec-CH-UA-Arch header.
        'arch_vs_ch_arch' => 15,
        // The device-hint request headers against what the page claims (README, "Per-application
        // configuration", lists the `Accept-CH` a host must send). Both-present only, so
        // Firefox and Safari, which send none of them, are never judged.
        'device_memory_vs_ch' => 15,
        'ch_bitness_vs_js' => 15,
        'ch_model_vs_js' => 15,
        'dpr_vs_ch' => 8,
        'viewport_vs_ch' => 6,
        'cores_vs_memory' => 8,
        // Two GPU identities from one page (WebGPU adapter vs WebGL renderer) naming
        // different vendors.
        'gpu_webgpu_vs_webgl' => 10,
        // A touch screen whose media queries report no coarse pointer at all.
        'touch_vs_pointer_media' => 6,
        'screen_zoom_implausible' => 6,
        'lang_vs_accept_language' => 5,
        'tz_vs_lang_region' => 4,

        // The engine the JavaScript runtime IS, against the engine the User-Agent names.
        // A JavaScript spoofer rewrites `navigator.userAgent` in one line; making V8
        // produce SpiderMonkey's error-object shape means replacing `Error` itself,
        // which the descriptor probes see. 30, the conformance tier: a browser whose UA
        // and engine disagree is not misconfigured, it is lying.
        'ua_vs_engine' => 30,
        // The same fact against a HEADER: only Chromium sends `Sec-CH-UA`, so a request
        // carrying it from a non-V8 engine cannot be a real browser. The JS half cannot
        // rewrite the header; the header half cannot rewrite the engine.
        'engine_vs_ch_header' => 30,
        // The User-Agent version against the feature set the engine exposes, per MDN
        // browser-compat-data (`FeatureShipVersions`, regenerated per release). Three or
        // more releases apart, on two or more features, in either direction. 25 rather
        // than 30: the table is third-party data with its own lag, so one notch of
        // humility is built into the weight.
        'ua_vs_feature_version' => 25,
        // The page against its own dedicated worker. The worker is a separate realm that
        // page-level spoofers — extensions, puppeteer-extra evasions — never reach, so a
        // disagreement means the page values were patched. Navigator identity is
        // conformance-tier; the time zone and GPU are lower because engine-level
        // overrides exist that legitimately reach one realm first (not measured;
        // the lower weights are the hedge).
        'worker_vs_window_navigator' => 30,
        'worker_vs_window_timezone' => 20,
        'worker_vs_window_gpu' => 15,
        // `permissions.query({name:'notifications'})` at `prompt` while
        // `Notification.permission` is `denied`: the headless-Chrome inconsistency (CreepJS
        // `hasPermissionsBug`), measured still present in headless Chromium 153 (anti-fraud
        // review). 15: a headful browser with notifications refused at OS level is
        // UNVERIFIED, so it stays below the conformance tier.
        'notification_permission_vs_query' => 15,
        // A value outside the enumeration of its own API: `Notification.permission` is a WebIDL enum
        // (`default|granted|denied`) and `permissions.query` resolves `prompt|granted|denied`, so
        // no engine returns anything else (puppeteer-extra-style overrides answer `default` to the
        // query, the DOM word). A lie rather than a setting, but the pair is cheap to forge both
        // ways, so 25 and not the conformance tier.
        'notification_permission_nonstandard' => 25,
        // A consumer-desktop UA (Windows or macOS) on a browser that loads at most one of the
        // OS-indicative font families: ChatGPT Agent's single-font list, Manus's empty one (agent-fingerprinting survey, item
        // #18). A real Windows or macOS has most of the ten probed. Minimal containers claiming
        // Windows are the honest collision, hence 10.
        'fonts_single_family_desktop' => 10,
        // The Intl zone is UTC while the language tag names a country: servers, kiosks and Linux
        // developers are honest UTC users, so 6 and never alone (survey #18, Manus).
        'tz_utc_vs_language_region' => 6,
        // A Chromium UA from release 110 on carries a frozen OS version (UA reduction): Windows NT
        // 10.0, Mac OS X 10_15_7, Android 10 with the model K. Plain-Chrome shape only, with
        // Sec-CH-UA present so the client really is Chromium; pasted pre-reduction UAs break it.
        'ua_reduced_shape_violation' => 15,
        // An Android WebView UA (`; wv`) carries the device model and a Build token (arXiv 2208.01968);
        // a fabricated one usually has neither. OEM overrides are the honest collision: 8, never alone.
        'webview_ua_shape' => 8,
        // A rendered constant that does not read back as the constant: audio read-back is
        // noised. Same reasoning and weight as `canvas_readback_perturbed`.
        'audio_readback_perturbed' => 4,
        // The User-Agent — claimed or on the wire — carries a headless/automation product
        // token (`HeadlessChrome/`, `PhantomJS`, `SlimerJS`, `Lightpanda`). Nothing in this system
        // looked for it: `headless_automation` reads WebGL strings only. PayPal's
        // challenge script gates its token on exactly this regex (notes/21 §6), and
        // CreepJS's `hasHeadlessUA` is the same test. 30: a browser announcing itself as
        // headless is not a liar, but it is not a visitor either. Lightpanda (a headless
        // browser in Zig on V8 with no rendering engine, github.com/lightpanda-io/browser)
        // sends `Lightpanda/1.0` on the wire and in `navigator.userAgent` by default; its
        // `--user_agent_suffix` appends to that string, so the token survives it.
        'ua_headless_token' => 30,
        // Contract 2 claim rules.
        // `screen.width/height` against the CSS `device-width/height` media path read in
        // the phantom realm: a JavaScript hook on `screen` does not reach a stylesheet.
        // Both dimensions must disagree, because page zoom and Gecko's fractional sizes
        // can honestly move one.
        'screen_vs_css_media' => 20,
        // The engine's own 1113 local-mean-time offset against the Intl zone's: an
        // Intl-only time zone spoof (the common extension technique) disagrees.
        'tz_intl_vs_date' => 20,
        // Fonts that only one OS ships, present on a device whose UA names another OS.
        'fonts_vs_ua_os' => 15,
        // WebGL1 and WebGL2 describe one GPU; a spoofer that patches one context's
        // getParameter and not the other's produces two.
        'gpu_webgl_params_mismatch' => 20,
        // Measured parallel capacity against the reported core count. 10: load on the
        // machine and the scheduler make the measurement soft; it is a hint that a
        // hardwareConcurrency override is in place, not a proof.
        'cores_vs_measured_parallelism' => 10,
        // The same geometry rasterised in the page and in the worker reads back
        // differently (notes/22 M2): page-realm-only read-back noise, which the known-value
        // and dual-construction checks both miss for free-form scenes. 4, like the other
        // read-back codes: noise is a privacy tool first and a spoofer second.
        'canvas_realm_mismatch' => 4,
        // The same comparison for the WebGL shader render (`gpuMath`): the page's read-back
        // against the worker's own context. A page-only `readPixels`/`getParameter` hook that
        // passes the lie battery is the one thing that splits them. Weight 4 for the same
        // reason as the canvas: GPU-versus-CPU raster differences between a window and a worker
        // are unverified on hardware.
        'gpu_realm_mismatch' => 4,
        // A privacy-mode flag that the engine evidence contradicts: `rfp`/`tor` are
        // Gecko-only, `brave` is Chromium-only, and the engine marks, the User-Agent and
        // the Sec-CH-UA header each say which family this is. Faking the flag is the one
        // move that would otherwise REDUCE what the matcher sees (security review, HIGH),
        // so it is conformance-tier: an honest browser cannot produce it.
        'resistance_vs_engine' => 30,
        // Removed: `audio_unavailable_but_reported` (fired on an absent probe; weight 0
        // since notes/07).

        // WebGL limits below the PUBLISHED specification minima: no hardware implementation
        // reports them, and the minima are the spec's, not a vendor table, so the rule cannot go
        // stale with a new GPU model. It fires only on a context that lies about its own limits,
        // which is rare and unambiguous: 12, between `gpu_webgpu_vs_webgl` (10) and
        // `gpu_webgl_params_mismatch` (20). Read from `tier2.gpu.webgl.limits`.
        'renderer_vs_limits' => 12,
        // A renderer family that cannot exist on the claimed OS (Direct3D on macOS, an Apple GPU
        // on Windows). The one rule here that can be wrong for a real visitor (Windows 11 ARM in
        // a VM, an exotic Mesa build), so it sits at 10, below `lied_os` (20), and the pairs it
        // fires on are an explicit table (see `contradictingGpuFamilies`). Weights of this rule
        // and the one above are reasoned from the failure cases, not measured on traffic.
        'ch_platform_vs_gpu' => 10,
        // Smart signals (network, virtual machine, emulator, private browsing). All soft: each is
        // an honest configuration for some real visitors (a VPN, a corporate VDI, a developer's
        // emulator, a private tab), so none reaches the elevated band alone (5 scores 12).
        'ip_country_vs_locale' => 5,
        'network_hosting' => 5,
        'network_vpn' => 4,
        'vm_gpu_renderer' => 5,
        'vm_software_gpu_screen' => 4,
        'emulator_android' => 8,
        'private_mode_with_other_signals' => 3,
        // Removed: `storage_quota_round` (no collector sends `storageEstimate`, and a round quota
        // is a plausible real answer, so the rule had no input and weak evidence) and
        // `stack_depth_anomalous` (the stackDepth probe is gone: a constant in V8).

        // Prior art, ported from fingerprintjs2's hasLied* family.
        'lied_languages' => 15,
        'lied_resolution' => 8,
        'lied_os' => 20,
        'lied_browser' => 20,

        // Transport findings, so an operator can retune them alongside everything
        // else rather than editing a method.
        //
        // A hard finding is a protocol violation — the strongest evidence in the
        // system, and weighted above every claim-side rule for that reason. A soft one
        // is merely improbable and gets 6: several soft findings together are
        // informative, which is what the curve's diminishing returns are for.
        //
        // These were hard-coded in VerdictScorer, which meant `weightOf()` returned the
        // generic default for them and an operator could not see or change them. The
        // test `a_soft_transport_finding_is_scored_too_but_far_lower` caught that.
        'transport_sec_ch_full_version_mismatch' => 45,
        'transport_default' => 45,
        // A User-Agent claiming a search crawler that DNS or the vendor's published list contradicts.
        // 45 like every heaviest single check: challenge (68), never block on its own.
        'transport_crawler_impersonation' => 45,
        'transport_soft_default' => 6,
    ];

    /**
     * Specification rules that are not implemented, and the reason for each.
     *
     * Every one needs a claim the client does not currently collect. Writing the rule
     * before the probe would produce a rule that can never fire, which is the same as
     * no rule while reading as coverage.
     *
     * @var array<string, string>
     */
    public const UNIMPLEMENTED_SPEC_RULES = [
        'ip_country_vs_lang_tz' => 'Needs IP geolocation, which this application does not have and should not acquire for a fingerprint. The design also says never to block on it alone, so its absence costs nothing today.',
        'voices_empty_after_event' => 'Needs an async wait for the voiceschanged event, which does not fit the synchronous collection window. It wants its own deferred phase.',
        'getter_cost_anomalous' => 'Needs a per-client baseline recorded on first run and compared later. That is a stateful cross-session rule and belongs with the fraud surface, not with this stateless contradiction list.',
    ];

    /**
     * The ISO region of an IANA time zone from the deliberately partial table, or null when the
     * zone is not listed (an unlisted zone produces no finding anywhere that uses this).
     */
    public static function regionOfTimeZone(string $zone): ?string
    {
        return self::TIMEZONE_REGIONS[strtolower($zone)] ?? null;
    }

    /**
     * Weights as data: the shipped table under the operator's overrides (the `settings`
     * table first, `config()` second — `config()` alone is frozen by `config:cache`).
     *
     * @return array<string, int>
     */
    public static function weights(): array
    {
        $weights = self::WEIGHTS;

        $configured = Config::array('fingerprint.constraint_weights');

        foreach ($configured as $code => $weight) {
            if (is_string($code) && is_numeric($weight)) {
                $weights[$code] = max(0, min(self::MAX_WEIGHT, (int) $weight));
            }
        }

        return $weights;
    }

    /**
     * The codes `rules()` can emit, for the weights/rules agreement test.
     *
     * @return list<string>
     */
    public function ruleCodes(): array
    {
        return array_values(array_map(static fn (array $rule): string => $rule['code'], $this->rules()));
    }

    /**
     * The shadow weights an operator is TESTING (`fingerprint.constraint_weights_shadow`, code =>
     * weight, same bounds as the live ones). They never score: {@see ShadowWeights}
     * evaluates them next to the live weights, like minFraud's `test` disposition.
     *
     * @return array<string, int>
     */
    public static function shadowWeights(): array
    {
        $out = [];
        foreach (Config::array('fingerprint.constraint_weights_shadow') as $code => $weight) {
            if (is_string($code) && is_numeric($weight)) {
                $out[$code] = max(0, min(self::MAX_WEIGHT, (int) $weight));
            }
        }

        return $out;
    }

    public function weightOf(string $code): int
    {
        return self::weights()[$code] ?? 10;
    }

    /**
     * Every contradiction between the claims and the transport.
     *
     * @param  array<array-key, mixed>  $claims  a decoded claim set
     * @return list<array{code: string, detail: string, weight: int}>
     */
    public function contradictions(array $claims, TransportIntegrityResult $transport, ?NetworkFacts $network = null): array
    {
        // Resolved once per claim set, not once per rule: each resolution reads the
        // settings store, and there are dozens of rules.
        return $this->contradictionsWith(self::weights(), $claims, $transport, $network);
    }

    /**
     * The same contradictions under an explicit weight table (a rule weighted 0 is silenced).
     * {@see contradictions()} passes the live table; the shadow comparison passes the live table
     * under the weights being tested.
     *
     * @param  array<string, int>  $weights  code => weight; a code missing from it weighs 10 as in {@see weightOf()}
     * @param  array<array-key, mixed>  $claims  a decoded claim set
     * @return list<array{code: string, detail: string, weight: int}>
     */
    public function contradictionsWith(array $weights, array $claims, TransportIntegrityResult $transport, ?NetworkFacts $network = null): array
    {
        $found = [];

        try {
            foreach ($this->rules() as $rule) {
                $weight = $weights[$rule['code']] ?? 10;

                // A rule weighted 0 is SILENCED here rather than being emitted with no
                // weight.
                //
                // This matters because a weight of 0 is the documented response to a rule
                // that started firing on honest traffic after a browser release. If the
                // engine still emitted it, the admin's "why was this flagged" panel would
                // list a contradiction that contributes nothing to the score — which reads
                // as a bug in the scoring and trains the operator to ignore the panel.
                // Dropping it here means the override means what the config comment says
                // it means.
                if ($weight <= 0) {
                    continue;
                }

                $hit = ($rule['rule'])($claims, $transport, $network);

                if ($hit === null) {
                    continue;
                }

                $found[] = [
                    'code' => $rule['code'],
                    'detail' => $hit,
                    'weight' => $weight,
                ];
            }
        } finally {
            // Not kept past the call: an instance the container shares across requests
            // would otherwise hold the last visitor's claim set in memory.
            $this->effectiveMemo = null;
        }

        return $found;
    }

    /**
     * The rule table, as data.
     *
     * @return list<array{code: string, rule: \Closure(mixed, TransportIntegrityResult, ?NetworkFacts=): ?string}>
     */
    private function rules(): array
    {
        return [
            // ---------------------------------------------------------------
            // Tier A — conformance. No real browser produces these.
            // ---------------------------------------------------------------

            // The integrity probes already did the work; this lifts their findings
            // into the same list as everything else so there is one scoring path. A
            // client that reports `wrong_receiver_did_not_throw` is telling us the
            // environment is patched, and that is the highest-yield signal in the
            // system (REPORT.md §7.21, 6/6 measured). Every code below is the client's
            // finding UNITED with the server's own derivation from `integrity.data`
            // (`IntegrityFindings`, notes/24 F10): an empty `findings` array next to the
            // tell-tale data no longer hides anything.
            [
                'code' => 'wrong_receiver_did_not_throw',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'wrong_receiver_did_not_throw'),
            ],
            [
                'code' => 'math_pf_mismatch',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'math_pf_mismatch'),
            ],
            [
                'code' => 'descriptor_patched',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'descriptor_patched'),
            ],
            [
                'code' => 'descriptor_unstable',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'descriptor_unstable'),
            ],
            [
                'code' => 'descriptor_missing',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'descriptor_missing'),
            ],
            [
                'code' => 'descriptor_shadowed',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'descriptor_shadowed'),
            ],
            [
                'code' => 'canvas_dual_diverged',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'canvas_dual_diverged'),
            ],
            [
                'code' => 'canvas_winding_false',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'canvas_winding_false'),
            ],
            // Emitted by the client since v3, weighted by nothing until notes/21.
            [
                'code' => 'descriptor_has_setter',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'descriptor_has_setter'),
            ],
            [
                'code' => 'dom_blocker_present',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'dom_blocker_present'),
            ],
            [
                'code' => 'dom_blocker_threw',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'dom_blocker_threw'),
            ],
            [
                'code' => 'webdriver_missing',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'webdriver_missing'),
            ],
            [
                'code' => 'canvas_readback_perturbed',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'canvas_readback_perturbed'),
            ],
            [
                'code' => 'canvas_pattern_perturbed',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'canvas_pattern_perturbed'),
            ],
            [
                'code' => 'automation_global_present',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'automation_global_present'),
            ],
            // Gated beyond the client's own test, because the client cannot know the claimed
            // operating system and an engine whose protection sets outer = inner (WebKit; Firefox
            // resistFingerprinting, which reports the outer size as the inner size and was
            // measured firing this on a HEADED window, skeptical review L5) is no headless shell.
            // The Gecko protection counts only under its engine evidence (`protectedGecko()`).
            [
                'code' => 'headless_shell_geometry',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    if ($this->fromIntegrity($c, 'headless_shell_geometry') === null || self::protectedGecko($c, $t)) {
                        return null;
                    }

                    $marks = $this->value($c, 'tier1', 'engineIdentity');
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $engine = is_array($marks) ? self::engineFromMarks($marks) : null;
                    $family = is_string($ua) ? self::uaOsFamily($ua) : null;

                    if ($engine === 'webkit' || ! in_array($family, ['windows', 'macos', 'linux'], true)) {
                        return null;
                    }

                    return 'The browser window has no chrome around its viewport and a history of at most two entries, the geometry of a headless shell.';
                },
            ],
            // The browser's own statement that an automation protocol is attached. Gecko's
            // Marionette and WebKit's remote automation set it as well as Chromium's switches.
            [
                'code' => 'webdriver_true',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    return $this->value($c, 'tier1', 'environment', 'identity', 'webdriver') === true
                        ? 'navigator.webdriver is true: the browser reports an attached automation protocol.'
                        : null;
                },
            ],
            // Headless Gecko has no tell in a header or a global (Playwright's Firefox, geckodriver and
            // a bare `firefox -headless` are the same widget), but its fixed virtual screen is one.
            [
                'code' => 'headless_gecko_screen',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    if (! self::engineEvidence($c, $t)['gecko'] || self::claimsGeckoProtection($c)) {
                        return null;
                    }

                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    if (! is_string($ua) || ! in_array(self::uaOsFamily($ua), ['linux', 'macos'], true)) {
                        return null;
                    }

                    $expected = ['width' => 1366, 'height' => 768, 'availWidth' => 1366, 'availHeight' => 768, 'availLeft' => 0, 'availTop' => 0];
                    foreach ($expected as $field => $value) {
                        if ($this->value($c, 'tier1', 'environment', 'screen', $field) !== $value) {
                            return null;
                        }
                    }

                    return 'The screen is the fixed 1366x768 panel-less screen of Firefox\'s headless widget.';
                },
            ],
            // Geometry a driven Chromium leaves behind (tools/redteam). Three rules over the same
            // measurements, each silent unless a desktop Chromium reports whole, positive numbers.
            [
                'code' => 'viewport_fills_screen',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $g = $this->desktopChromiumGeometry($c, $t);
                    if ($g === null || $g['outerHeight'] - $g['innerHeight'] < 40 || $g['outerWidth'] < $g['innerWidth']) {
                        return null;
                    }

                    return $g['innerWidth'] === $g['screenWidth'] && $g['innerHeight'] === $g['screenHeight']
                        ? 'The viewport is exactly as large as the screen although the window has a title bar and toolbar around it: an emulated device metrics override.'
                        : null;
                },
            ],
            [
                'code' => 'headless_default_screen',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $g = $this->desktopChromiumGeometry($c, $t);
                    if ($g === null) {
                        return null;
                    }

                    return $g['screenWidth'] === 800 && $g['screenHeight'] === 600 && $g['availWidth'] === 800 && $g['availHeight'] === 600
                        ? 'The screen is exactly 800x600 with no taskbar, the default screen of a headless Chromium.'
                        : null;
                },
            ],
            [
                'code' => 'window_exceeds_screen',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $g = $this->desktopChromiumGeometry($c, $t);
                    if ($g === null) {
                        return null;
                    }

                    return $g['outerWidth'] - $g['screenWidth'] > 32 && $g['outerHeight'] - $g['screenHeight'] > 32
                        ? 'The browser window is larger than the screen in both dimensions.'
                        : null;
                },
            ],
            // Contract 2 (notes/21 §2 items 5, 6, 11): the lie battery, the cross-realm
            // toString, and the layout-arithmetic invariants.
            // The two lie codes are split by WHAT lied (sceptical and anti-fraud reviews).
            // A patched Navigator/Screen/Date/Intl/Permissions getter, Math or
            // Function.toString is an identity lie and keeps the conformance weight. A patch
            // on the canvas, WebGL, AudioBuffer or getBoundingClientRect surface is what a
            // canvas-noise or client-rects extension installs — the same honest visitor the
            // read-back codes weight at 4 — and is scored as a noise tool at 6 while the
            // trust projection stops matching the components it noised. Without the split,
            // one CanvasBlocker-class extension scored 35 + 35 + 4 = block.
            [
                'code' => 'lie_battery_failed',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->liedApiClass($c, 'lie_battery_failed', ['integrity', 'data', 'lieBattery', 'lied']) === 'identity'
                    ? 'A native function on an identity surface (navigator, screen, Date, Intl, permissions, toString or Math) failed its conformance invariants.'
                    : null,
            ],
            [
                'code' => 'lie_battery_privacy_tool',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->liedApiClass($c, 'lie_battery_failed', ['integrity', 'data', 'lieBattery', 'lied']) === 'privacy'
                    ? 'Navigator, Screen or time-zone getters are wrapped in the page only (the worker disagrees) and nothing else about the environment is patched: the footprint of a privacy or User-Agent-switcher extension.'
                    : null,
            ],
            [
                'code' => 'lie_battery_noise_tool',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->liedApiClass($c, 'lie_battery_failed', ['integrity', 'data', 'lieBattery', 'lied']) === 'noise'
                    ? 'A native function on a read-back surface (canvas, WebGL, audio buffers or element rectangles) is wrapped, the footprint of a noise extension.'
                    : null,
            ],
            [
                'code' => 'realm_tostring_mismatch',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->liedApiClass($c, 'realm_tostring_mismatch', ['integrity', 'data', 'phantomRealm', 'nativeToString', 'mismatched']) === 'identity'
                    ? 'A pristine realm describes an identity-surface function differently from the page\'s own toString, so the page\'s toString is patched.'
                    : null,
            ],
            [
                'code' => 'realm_tostring_noise_tool',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->liedApiClass($c, 'realm_tostring_mismatch', ['integrity', 'data', 'phantomRealm', 'nativeToString', 'mismatched']) === 'noise'
                    ? 'A pristine realm describes a read-back-surface function differently from the page\'s own toString, the footprint of a noise extension masking itself.'
                    : null,
            ],
            [
                'code' => 'domrect_inconsistent',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'domrect_inconsistent'),
            ],
            [
                'code' => 'svg_text_inconsistent',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => $this->fromIntegrity($c, 'svg_text_inconsistent'),
            ],

            // ---------------------------------------------------------------
            // Tier B — cross-source consistency.
            // ---------------------------------------------------------------

            // No Chrome produces the PDF plugin set *and* pdfViewerEnabled false. The
            // benchmark saw this fire: a spoofer injected the plugin list and left
            // pdfViewerEnabled at its default.
            [
                'code' => 'plugins_vs_pdfviewer',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $plugins = $this->value($c, 'tier1', 'environment', 'plugins');
                    $pdf = $this->value($c, 'tier1', 'environment', 'identity', 'pdfViewerEnabled');

                    if (! is_array($plugins) || ! is_bool($pdf)) {
                        return null;
                    }

                    // Narrowed rather than cast: `$plugins` came from a decoded body, so
                    // every field is attacker-influenced.
                    $rawNames = is_array($plugins['names'] ?? null) ? $plugins['names'] : [];
                    $names = array_values(array_map(
                        static fn (mixed $name): string => strtolower(is_scalar($name) ? (string) $name : ''),
                        $rawNames,
                    ));
                    $hasPdf = (bool) array_filter($names, static fn (string $n): bool => str_contains($n, 'pdf'));

                    // Only the *specific* inconsistent pair, not "plugins present".
                    return $hasPdf && ($plugins['length'] ?? 0) === 5 && $pdf === false
                        ? 'The PDF plugin set is reported while pdfViewerEnabled is false; no engine produces that pair.'
                        : null;
                },
            ],

            // UA major vs the browser's own un-redacted Client-Hints version list. The
            // industry deliberately reduces UA-*; this header is not reduced, so a
            // copied User-Agent cannot pass it. Measured as the highest-value single
            // server-side check in REPORT.md §3.6.
            [
                'code' => 'ua_vs_ch_major',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    if ($t->has('sec_ch_full_version_mismatch')) {
                        return 'The User-Agent major version disagrees with Sec-CH-UA-Full-Version-List.';
                    }

                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $high = $this->value($c, 'tier1', 'uaClientHints', 'high', 'uaFullVersion');
                    $list = $this->value($c, 'tier1', 'uaClientHints', 'high', 'fullVersionList');

                    if (! is_string($ua)) {
                        return null;
                    }

                    // Opera, Samsung Internet, Yandex and the rest report their OWN version as
                    // `uaFullVersion` and carry the Chromium version in the `Chrome/` token, so
                    // the two honestly differ. The `Chromium` entry of the version list is the
                    // engine version in every Chromium browser: the same comparison the header
                    // rule (`checkFullVersionList`) makes. Without that entry the rule falls
                    // back to `uaFullVersion` for a plain Chrome UA only.
                    $chromiumMajor = self::chromiumMajorFromVersionList($list);
                    if ($chromiumMajor !== null) {
                        $tokenMajor = preg_match('/Chrome\/(\d+)/', $ua, $m) === 1 ? (int) $m[1] : null;

                        return ($tokenMajor !== null && $tokenMajor !== $chromiumMajor)
                            ? 'The Chrome version in navigator.userAgent disagrees with the Chromium entry of getHighEntropyValues fullVersionList.'
                            : null;
                    }

                    if (! is_string($high) || preg_match('/(?:OPR|SamsungBrowser|YaBrowser|Vivaldi|UCBrowser|Edg\w*)\//', $ua) === 1) {
                        return null;
                    }

                    $uaMajor = $this->majorFromUserAgent($ua);
                    $hintMajor = (int) explode('.', $high)[0];

                    return ($uaMajor !== null && $uaMajor !== $hintMajor)
                        ? 'The User-Agent major version disagrees with uaFullVersion from getHighEntropyValues.'
                        : null;
                },
            ],

            // UA says Firefox or Safari, but the Client-Hints brands say Chromium.
            [
                'code' => 'ua_vs_ch_brand',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $brands = $this->value($c, 'tier1', 'uaClientHints', 'brands');

                    if (! is_string($ua) || ! is_array($brands)) {
                        return null;
                    }

                    $saysChromium = str_contains($ua, 'Chrome/') || str_contains($ua, 'CriOS/');
                    $saysOther = str_contains($ua, 'Firefox/') || str_contains($ua, 'FxiOS/')
                        || (str_contains($ua, 'Safari/') && ! $saysChromium);

                    $hintsChromium = false;
                    foreach ($brands as $brand) {
                        // A brand is either `{brand, version}` or a bare string depending
                        // on what the client reported, and a hostile body can send
                        // anything — so both branches narrow before use rather than
                        // casting mixed.
                        $name = is_array($brand)
                            ? strtolower(is_scalar($brand['brand'] ?? null) ? (string) $brand['brand'] : '')
                            : (is_scalar($brand) ? strtolower((string) $brand) : '');
                        if (str_contains($name, 'chromium') || str_contains($name, 'google chrome') || str_contains($name, 'edge')) {
                            $hintsChromium = true;
                        }
                    }

                    return ($saysOther && $hintsChromium)
                        ? 'The engine family of navigator.userAgent disagrees with the engine family of userAgentData.brands.'
                        : null;
                },
            ],

            // Chrome's plugin list has been frozen at exactly five entries since 2015,
            // so a Chrome claiming zero is inconsistent.
            [
                'code' => 'plugins_vs_ua',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $length = $this->value($c, 'tier1', 'environment', 'plugins', 'length');

                    if (! is_string($ua) || ! is_int($length)) {
                        return null;
                    }

                    // An embedded WebView has no plugin list, and says so in its own
                    // User-Agent. Android WebView appends `; wv` and the token
                    // `Version/4.0`; the in-app browsers on iOS append their own
                    // vendor token. All of them report zero plugins and none of them
                    // are lying, so the rule is skipped rather than satisfied — an
                    // in-app browser is a real user on a real device, and this is the
                    // check that put it in band `challenge`.
                    if (str_contains($ua, '; wv') || str_contains($ua, 'Version/4.0')) {
                        return null;
                    }

                    // Android Chrome and iOS Chrome have no PDF plugin set at all, and a desktop
                    // Chrome whose built-in PDF viewer is switched off (policy, or "download PDFs")
                    // reports `pdfViewerEnabled === false` with an empty list. Both are honest.
                    // What is left is a desktop Chrome that claims a PDF viewer (or never says)
                    // and lists nothing.
                    if (str_contains($ua, 'Mobile') || str_contains($ua, 'Android')
                        || $this->value($c, 'tier1', 'environment', 'identity', 'pdfViewerEnabled') === false) {
                        return null;
                    }

                    return (str_contains($ua, 'Chrome/') && $length === 0)
                        ? 'navigator.plugins is empty for an engine whose plugin list is fixed at five entries.'
                        : null;
                },
            ],

            // The Client-Hints brands the PAGE reported, against the `sec-ch-ua` header the
            // BROWSER actually sent. The first JS-to-transport cross-check in the system
            // that does not depend on any edge being deployed.
            //
            // WHY THIS IS NOT THE SAME AS `ua_vs_ch_brand`
            //
            // That rule compares `identity.userAgent` with `uaClientHints.brands` — two
            // JAVASCRIPT values. Overwriting `navigator.userAgentData` defeats it in one
            // line, and no spoofer is going to leave it alone. `ua_vs_ch_major` has the
            // same shape via `getHighEntropyValues()`. Both are worth keeping: they catch
            // a *partial* patch, where the UA string was changed and the hints were not.
            //
            // This one compares a claim against a HEADER, and patching a JS property does
            // not change what the browser put on the wire. Measured across the three
            // engines (research/fingerprinting/candidates/probe-client-hints.mjs):
            //
            //     chromium  header  "HeadlessChrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"
            //               page    ["HeadlessChrome/153","Not_A Brand/8","Chromium/153"]
            //               -> identical, brand for brand
            //     firefox   header absent, no navigator.userAgentData
            //     webkit    header absent, no navigator.userAgentData
            //
            // So the agreement is exact, which is what makes the tolerance zero. The
            // asymmetry is also measured: only the Chromium family sends the header at
            // all, so a spoofer claiming Firefox while the header says Chromium is
            // detectable in a way no JS-only spoofer can prevent.
            //
            // WHY IT FIRES ONLY WHEN BOTH SIDES ARE PRESENT
            //
            // The tempting extra cases are "the page claims Chromium brands but no header
            // was sent" and the reverse. Both are deliberately SILENT, and the reason is
            // that both have honest explanations this code cannot see: a reverse proxy
            // that strips or rewrites headers, a non-secure context where the low-entropy
            // hints are not sent at all, an enterprise client, or a browser version that
            // sends the hints on navigation requests but not on this one. Firing on
            // absence is precisely the "missing data is never evidence" mistake the rest
            // of this file is built to avoid, and it would fire on honest users.
            //
            // So the strong, zero-false-positive case is the only one: two sources that
            // both exist, disagreeing about which browser this is.
            [
                'code' => 'brands_vs_ch_header',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = $this->value($c, 'tier1', 'uaClientHints', 'brands');
                    $header = $t->witnessString('sec_ch_ua');

                    if (! is_array($claimed) || $claimed === [] || $header === null || $header === '') {
                        return null;
                    }

                    // Header side. A structured field: "Brand";v="1", "Brand2";v="2",
                    // read by the ONE RFC 8941 list parser (round-3 R3-S6, G-D4i/STD-22): a
                    // malformed field — an inner list, an invalid escape, a stray
                    // character — is no evidence at all, never members parsed from the
                    // wrong place. GREASE brands are excluded on both sides — they are
                    // deliberately fake, and which one appears is not a fact about the
                    // engine.
                    $fromHeader = [];
                    foreach (StructuredFieldList::brandList($header) as [$name, $_version]) {
                        // The empty result is filtered HERE as well as on the claim
                        // side. Appending it unconditionally leaves a `''` in the
                        // header list that `array_unique()` keeps, so the two sides
                        // disagree on the one real brand and the rule fires on every
                        // honest Chromium request — the exact failure this rule's
                        // design exists to avoid, reached by a one-word omission.
                        $normalised = $this->normaliseBrand($name);
                        if ($normalised !== '') {
                            $fromHeader[] = $normalised;
                        }
                    }

                    if ($fromHeader === []) {
                        return null;
                    }

                    // Page side. A brand is `{brand, version}` or a bare string depending
                    // on what the client sent, and a hostile body can send anything, so
                    // both shapes narrow before use rather than being cast.
                    $fromClaim = [];
                    foreach ($claimed as $brand) {
                        $name = is_array($brand)
                            ? (is_scalar($brand['brand'] ?? null) ? (string) $brand['brand'] : '')
                            : (is_scalar($brand) ? (string) $brand : '');
                        $normalised = $this->normaliseBrand($name);
                        if ($normalised !== '') {
                            $fromClaim[] = $normalised;
                        }
                    }

                    if ($fromClaim === []) {
                        return null;
                    }

                    // Set comparison, not a positional one: the order of the brand list is
                    // not contract, and comparing position would fire on a browser that
                    // merely shuffled it.
                    sort($fromHeader);
                    sort($fromClaim);
                    $header = array_values(array_unique($fromHeader));
                    $claim = array_values(array_unique($fromClaim));

                    if ($header === $claim) {
                        return null;
                    }

                    return 'The brands the page reported (userAgentData.brands) differ from the Sec-CH-UA header the browser sent.';
                },
            ],

            // The User-Agent string the PAGE reported, against the `user-agent` header the
            // BROWSER actually sent.
            //
            // This is the most-spoofed value in the system, and until this rule existed
            // nothing compared it to anything the client could not simply rewrite.
            // `lied_os` and `ua_vs_ch_brand` both compare the UA string against other
            // CLAIMED values, so a spoofer that rewrote `navigator.userAgent` and left the
            // rest of the claim set consistent passed all of them.
            //
            // Measured exact (probe-client-hints.mjs, and the `user-agent` witness beside
            // `navigator.userAgent` in every real engine), so the tolerance is zero: no
            // trimming, no case folding, no version tolerance. A difference of any kind is
            // the finding.
            //
            // Both-present only, for the same reason as `brands_vs_ch_header`, and the
            // exposure is slightly higher here: a reverse proxy that REWRITES the
            // User-Agent is not unusual the way one that strips a header is, and such a
            // deployment would fire this on every request. That is a deployment to fix
            // rather than a reason to be vague, because a rewritten UA means the UA the
            // risk rules have been reading all along was not the browser's.
            [
                'code' => 'ua_vs_ua_header',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $header = $t->witnessString('user_agent');

                    if (! is_string($claimed) || $claimed === '' || $header === null || $header === '') {
                        return null;
                    }

                    return ($claimed === $header)
                        ? null
                        : 'navigator.userAgent differs from the User-Agent header the browser sent.';
                },
            ],

            // Sec-CH-UA-Mobile ?1 with no touch points. No shipping browser does this.
            [
                'code' => 'touch_vs_ch_mobile',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $touch = $this->value($c, 'tier1', 'environment', 'identity', 'maxTouchPoints');
                    $mobile = $t->witnessString('sec_ch_ua_mobile');

                    if (! is_int($touch) || $mobile === null) {
                        return null;
                    }

                    return ($mobile === '?1' && $touch === 0)
                        ? 'Sec-CH-UA-Mobile reports ?1 while maxTouchPoints is 0.'
                        : null;
                },
            ],

            // deviceMemory is bucketed to at most 8 by the specification, so a core
            // count that no plausible device pairs with the claimed memory is a
            // contradiction. Deliberately weak (weight 8): a 16-core desktop reporting
            // 0.25 GB is odd but a spoofer that guessed 0.25 for everything is the
            // likelier explanation, and this should not carry a decision alone.
            [
                'code' => 'cores_vs_memory',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $cores = $this->value($c, 'tier1', 'environment', 'identity', 'hardwareConcurrency');
                    $memory = $this->value($c, 'tier1', 'environment', 'identity', 'deviceMemory');

                    if (! is_int($cores) || (! is_int($memory) && ! is_float($memory))) {
                        return null;
                    }

                    // deviceMemory is fractional BY SPECIFICATION — the permitted values
                    // are 0.25, 0.5, 1, 2, 4 and 8 — so requiring an int here silently
                    // disabled the rule for the exact value it exists to catch.
                    return ($cores >= 16 && (float) $memory <= 0.25)
                        ? 'hardwareConcurrency and deviceMemory are not a pairing any shipping browser produces.'
                        : null;
                },
            ],

            // The NaN sign byte (Float32 Infinity − Infinity) is `x86` or `arm` by CPU,
            // and the browser sends its own Sec-CH-UA-Arch. Both present and both
            // definite only; `unknown` on either side is silence.
            [
                'code' => 'arch_vs_ch_arch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = self::read($c, 'tier1', 'architecture', 'nanSign');
                    $hint = $t->witnessString('sec_ch_ua_arch');

                    if (! is_string($claimed) || ! in_array($claimed, ['x86', 'arm'], true) || $hint === null) {
                        return null;
                    }

                    $hinted = strtolower(trim($hint, "\" \t"));
                    if (! in_array($hinted, ['x86', 'arm'], true)) {
                        return null;
                    }

                    return $claimed === $hinted
                        ? null
                        : 'The CPU architecture from the NaN-sign probe differs from the Sec-CH-UA-Arch header.';
                },
            ],

            // Device-hint headers against the page's claims. A browser sends these only when the
            // host's `Accept-CH` asked for them, and Firefox and Safari never do, so absence is
            // silence. The header is what the browser put on the wire; a JavaScript spoof of the
            // claim does not change it. Every detail names the field, never a value.
            [
                'code' => 'device_memory_vs_ch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = $this->value($c, 'tier1', 'environment', 'identity', 'deviceMemory');
                    $header = self::numericHeader($t->witnessString('sec_ch_device_memory'));

                    if ((! is_int($claimed) && ! is_float($claimed)) || $header === null) {
                        return null;
                    }

                    return abs((float) $claimed - $header) < 0.001
                        ? null
                        : 'navigator.deviceMemory differs from the Sec-CH-Device-Memory header the browser sent.';
                },
            ],
            [
                'code' => 'ch_bitness_vs_js',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => self::hintStringsDiffer($this->value($c, 'tier1', 'uaClientHints', 'high', 'bitness'), $t->witnessString('sec_ch_ua_bitness'))
                    ? 'getHighEntropyValues bitness differs from the Sec-CH-UA-Bitness header the browser sent.'
                    : null,
            ],
            [
                'code' => 'ch_model_vs_js',
                'rule' => fn (mixed $c, TransportIntegrityResult $t): ?string => self::hintStringsDiffer($this->value($c, 'tier1', 'uaClientHints', 'high', 'model'), $t->witnessString('sec_ch_ua_model'))
                    ? 'getHighEntropyValues model differs from the Sec-CH-UA-Model header the browser sent.'
                    : null,
            ],
            // Page zoom is part of both values (same document, same moment), so a difference
            // beyond rounding is a patched `devicePixelRatio`.
            [
                'code' => 'dpr_vs_ch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = $this->value($c, 'tier1', 'environment', 'viewport', 'devicePixelRatio');
                    $header = self::numericHeader($t->witnessString('sec_ch_dpr'));

                    if ((! is_int($claimed) && ! is_float($claimed)) || $header === null) {
                        return null;
                    }

                    return abs((float) $claimed - $header) <= 0.01
                        ? null
                        : 'window.devicePixelRatio differs from the Sec-CH-DPR header the browser sent.';
                },
            ],
            // The header is the layout viewport; `innerWidth` includes a classic scrollbar (up to
            // 17 px) and a window can be resized between navigation and collection, so the
            // tolerance is generous. Silent on touch devices, where pinch-zoom moves `innerWidth`
            // and not the layout viewport.
            [
                'code' => 'viewport_vs_ch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = $this->value($c, 'tier1', 'environment', 'viewport', 'innerWidth');
                    $header = self::numericHeader($t->witnessString('sec_ch_viewport_width'));
                    $touch = $this->value($c, 'tier1', 'environment', 'identity', 'maxTouchPoints');
                    $mobile = $t->witnessString('sec_ch_ua_mobile');

                    if ((! is_int($claimed) && ! is_float($claimed)) || $header === null
                        || (is_int($touch) && $touch > 0) || ($mobile !== null && trim($mobile) === '?1')) {
                        return null;
                    }

                    return abs((float) $claimed - $header) <= self::VIEWPORT_HEADER_TOLERANCE
                        ? null
                        : 'window.innerWidth differs from the Sec-CH-Viewport-Width header the browser sent.';
                },
            ],

            // A page that exposes both a WebGPU adapter and a WebGL renderer describes one
            // GPU twice. Both resolving to a known vendor family and disagreeing is the
            // finding; an unrecognised string on either side is silence.
            [
                'code' => 'gpu_webgpu_vs_webgl',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $vendor = self::read($c, 'tier2', 'gpu', 'webgpu', 'vendor');
                    $model = self::read($c, 'tier2', 'gpu', 'webgl', 'model');
                    if (! is_string($model) || $model === '') {
                        $model = self::read($c, 'tier2', 'gpu', 'webgl', 'renderer');
                    }

                    if (! is_string($vendor) || ! is_string($model)) {
                        return null;
                    }

                    $fromWebgpu = self::gpuFamily($vendor);
                    $fromWebgl = self::gpuFamily($model);

                    if ($fromWebgpu === null || $fromWebgl === null || $fromWebgpu === $fromWebgl) {
                        return null;
                    }

                    // Hybrid graphics: a laptop with an integrated and a discrete GPU exposes both,
                    // and `requestAdapter()` with no preference may pick a different one from
                    // WebGL's default context. Intel, AMD and NVIDIA are the vendors that ship in
                    // such pairs (Intel+NVIDIA, AMD+NVIDIA, Intel+AMD, AMD+AMD), so a disagreement
                    // among them is a laptop, not a lie. What stays impossible on one machine is
                    // everything else: Apple, Qualcomm, Arm or PowerVR next to a PC GPU vendor.
                    $hybrid = ['intel', 'amd', 'nvidia'];
                    if (in_array($fromWebgpu, $hybrid, true) && in_array($fromWebgl, $hybrid, true)) {
                        return null;
                    }

                    return 'The WebGPU adapter vendor and the WebGL renderer name belong to different GPU vendor families.';
                },
            ],

            // A touch screen (maxTouchPoints > 0) whose `(any-pointer: coarse)` and
            // `(pointer: coarse)` both report false. Weight 6: hybrid laptops and
            // desktops with a touch monitor can legitimately report a fine primary
            // pointer, but any-pointer should still be coarse.
            [
                'code' => 'touch_vs_pointer_media',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $touch = self::read($c, 'tier1', 'environment', 'identity', 'maxTouchPoints');
                    $coarse = self::coarsePointer(self::read($c, 'tier1', 'cssMedia'));

                    if (! is_int($touch) || $coarse === null) {
                        return null;
                    }

                    return ($touch > 0 && ! $coarse)
                        ? 'maxTouchPoints reports a touch screen while neither (any-pointer: coarse) nor (pointer: coarse) matches.'
                        : null;
                },
            ],

            // A 3x-or-higher device pixel ratio on a screen narrower than 360 CSS
            // pixels does not correspond to a shipping device. Weight 6, because
            // zoom and OS scaling settings make this softer than it looks.
            [
                'code' => 'screen_zoom_implausible',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ratio = $this->value($c, 'tier1', 'environment', 'viewport', 'devicePixelRatio');
                    $width = $this->value($c, 'tier1', 'environment', 'screen', 'width');

                    if (! is_float($ratio) && ! is_int($ratio)) {
                        return null;
                    }
                    if (! is_int($width)) {
                        return null;
                    }

                    return ($ratio >= 3.0 && $width < 360)
                        ? 'devicePixelRatio against screen.width is not a shipping configuration.'
                        : null;
                },
            ],

            // The primary language subtag must appear in the Accept-Language header the
            // transport observed. Weight 5: a mismatch is usually a legitimate
            // configuration (a Dutch UI in a German browser) rather than a forgery.
            [
                'code' => 'lang_vs_accept_language',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $language = $this->value($c, 'tier1', 'environment', 'identity', 'language');
                    $header = $t->witnessString('accept_language');

                    if (! is_string($language) || $header === null) {
                        return null;
                    }

                    $primary = strtolower(explode('-', $language)[0]);

                    return (! str_contains(strtolower($header), $primary))
                        ? 'The primary subtag of navigator.language does not appear in the Accept-Language header.'
                        : null;
                },
            ],

            // The timezone against the UI language's likely region.
            //
            // The first version compared the timezone's PREFIX to a region code, which
            // can never agree: IANA identifiers are "Europe/Amsterdam", not "NL".
            // The rule as written fired on every browser, which the honest-fixture test
            // caught. Getting this right needs a mapping from IANA area to region, so
            // that is what it uses — but a DELIBERATELY PARTIAL one, covering the zones
            // this application will actually see.
            //
            // A zone that is not listed produces no finding at all. That fallthrough is
            // the point: the design warned against hard-coding a timezone table because
            // such a table goes stale silently and starts flagging real users, so this
            // one is scoped to be incomplete rather than exhaustive. It can under-detect
            // and it cannot false-positive on an unlisted zone.
            //
            // Weight 4, and never block on it: a traveller and a VPN both produce a
            // legitimate mismatch.
            [
                'code' => 'tz_vs_lang_region',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $timezone = $this->value($c, 'tier2', 'intl', 'resolved', 'timeZone');
                    $language = $this->value($c, 'tier1', 'environment', 'identity', 'language');

                    if (! is_string($timezone) || ! is_string($language)) {
                        return null;
                    }

                    $timezoneRegion = self::TIMEZONE_REGIONS[strtolower($timezone)] ?? null;
                    $languageRegion = $this->likelyRegionFor($language);

                    if ($timezoneRegion === null || $languageRegion === null) {
                        return null;
                    }

                    return ($timezoneRegion !== $languageRegion)
                        ? 'The region implied by the resolved timeZone differs from the region implied by navigator.language.'
                        : null;
                },
            ],

            // ---------------------------------------------------------------
            // Prior art: fingerprintjs2's hasLied* family, ported with attribution.
            //
            // BotD independently reimplements two of the same predicates, which is the
            // evidence that they are worth having: three projects arrived at the same
            // handful of checks. They were dropped from FingerprintJS v5, not because
            // they stopped working but because v5 stopped counting contradictions as
            // risk. This system counts them, so they are worth having here.
            // ---------------------------------------------------------------

            // hasLiedLanguages: navigator.languages must be a non-empty array whose
            // first element is navigator.language, and every entry must be a plausible
            // tag. A patch that overrides `language` but not `languages` is immediate.
            [
                'code' => 'lied_languages',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $language = $this->value($c, 'tier1', 'environment', 'identity', 'language');
                    $languages = $this->value($c, 'tier1', 'environment', 'identity', 'languages');

                    if (! is_string($language) || ! is_array($languages) || $languages === []) {
                        return null;
                    }

                    // Both sides lowercased: BCP 47 tags are case-insensitive, so
                    // "nl-NL" and "nl-nl" are the same tag. Comparing a lowercased entry
                    // against the raw `language` string made every browser look like a
                    // liar, which the honest-fixture test caught.
                    $firstEntry = $languages[0] ?? null;
                    $first = is_scalar($firstEntry) ? strtolower((string) $firstEntry) : '';
                    $languageLower = strtolower($language);
                    $implied = explode('-', $languageLower)[0];
                    $allValid = true;
                    foreach ($languages as $entry) {
                        if (! is_string($entry) || preg_match('/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/', $entry) !== 1) {
                            $allValid = false;
                        }
                    }

                    if ($first !== $languageLower && $first !== $implied) {
                        return 'navigator.languages does not start with navigator.language.';
                    }

                    return $allValid
                        ? null
                        : 'navigator.languages contains a tag that is not a well-formed BCP 47 language tag.';
                },
            ],

            // hasLiedResolution: screen geometry that a real window cannot produce.
            // innerWidth must be positive and not exceed outerWidth, and the avail area
            // must be inside the screen.
            [
                'code' => 'lied_resolution',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $inner = $this->value($c, 'tier1', 'environment', 'viewport', 'innerWidth');
                    $outer = $this->value($c, 'tier1', 'environment', 'viewport', 'outerWidth');
                    $screenWidth = $this->value($c, 'tier1', 'environment', 'screen', 'width');
                    $availWidth = $this->value($c, 'tier1', 'environment', 'screen', 'availWidth');

                    // Narrowed one at a time rather than in a loop.
                    //
                    // A `foreach` over `[$inner, $outer, ...]` asserting `is_int` is
                    // correct, but PHPStan does not carry that narrowing back to the
                    // individual variables afterwards — so `sprintf('%d', $inner)` stays
                    // `mixed` and level max rejects it. Four explicit checks are less
                    // clever and type-safe.
                    if (! is_int($inner) || ! is_int($outer)) {
                        return null;
                    }

                    if (! is_int($screenWidth) || ! is_int($availWidth)) {
                        return null;
                    }

                    // `outerWidth === 0` means "not measurable", not "impossible".
                    //
                    // In-app browsers (Facebook, Instagram, Gmail, WhatsApp), installed
                    // PWAs running in standalone mode, and some headless containers all
                    // report an outer size of zero while reporting a perfectly ordinary
                    // inner size. The original rule compared them and produced
                    // `innerWidth 412, outerWidth 0 -> lied_resolution`, weight 8, on
                    // every one of them — a contradiction inferred from a value that was
                    // never a claim about anything.
                    //
                    // This is the same error the class docblock says it never makes:
                    // treating an absent measurement as evidence. Here the measurement
                    // is present but uninformative, and the honest reading of zero is
                    // "unknown".
                    if ($outer <= 0) {
                        return null;
                    }

                    if ($inner <= 0 || $outer < $inner) {
                        return 'innerWidth exceeds outerWidth; a real window has an inner size no larger than its outer size.';
                    }

                    return ($availWidth > $screenWidth)
                        ? 'screen.availWidth exceeds screen.width.'
                        : null;
                },
            ],

            // hasLiedOs: the three-way UA <-> platform <-> touch check. The engines
            // disagree in known ways — desktop Chrome on Windows reports "Win32" while
            // the Client-Hints platform is "Windows" — so this compares the *family*,
            // not the exact string, and a family-level contradiction is the only
            // finding. A UA claiming Windows with a platform of "Linux" is not that.
            [
                'code' => 'lied_os',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $platform = $this->value($c, 'tier1', 'environment', 'identity', 'platform');
                    $hintPlatform = $t->witnessString('sec_ch_ua_platform');

                    // NOT silenced for resistFingerprinting / Tor Browser (security review
                    // round 4). Those browsers spoof the UA operating system AND
                    // `navigator.platform` from one per-platform table, so the two stay in the
                    // same family (Firefox `nsRFPService.h` SPOOFED_UA_OS next to
                    // `Navigator::GetPlatform()`; measured 2026-10-06 in Firefox 155 with
                    // privacy.resistFingerprinting on Linux: "X11; Linux x86_64" and
                    // "Linux x86_64"). A UA/platform contradiction is therefore not something
                    // the protection explains, and silencing it let a forged `rfp` flag buy
                    // the removal of a 20-point finding.
                    if (! is_string($ua) || ! is_string($platform)) {
                        return null;
                    }

                    $uaFamily = self::uaOsFamily($ua);
                    $hintFamily = $hintPlatform === null ? null : $this->platformOsFamily(trim($hintPlatform, '"'));

                    // An ARM suffix (`Linux armv8l`, `Linux aarch64`) is Android only when the
                    // browser says so elsewhere; a Raspberry Pi or an Asahi laptop reports the
                    // same suffix and is an honest Linux.
                    $platformFamily = $this->platformOsFamily($platform, $uaFamily === 'android' || $hintFamily === 'android');

                    if ($uaFamily === null || $platformFamily === null) {
                        return null;
                    }

                    // ChromeOS reports a Linux `navigator.platform` by design (and a Chrome OS
                    // Sec-CH-UA-Platform), so the two are one family for this comparison.
                    $uaFamily = $uaFamily === 'chromeos' ? 'linux' : $uaFamily;
                    $platformFamily = $platformFamily === 'chromeos' ? 'linux' : $platformFamily;
                    $hintFamily = $hintFamily === 'chromeos' ? 'linux' : $hintFamily;

                    // Android Chrome's "desktop site" mode swaps the User-Agent for a Linux desktop one
                    // and leaves the client hints (`Android`, `?1`) and the touch screen as they were;
                    // `navigator.platform` is either the device's (`Linux armv8l`) or the desktop's
                    // (`Linux x86_64`). That is a setting, not a lie: a Linux UA is silent when the
                    // browser's own hint says Android, a touch screen is present and the platform is
                    // Linux-family. A Windows or macOS UA over an Android hint still fires, because
                    // desktop mode never claims those.
                    if ($uaFamily === 'linux' && $hintFamily === 'android' && in_array($platformFamily, ['android', 'linux'], true)) {
                        $touchPoints = $this->value($c, 'tier1', 'environment', 'identity', 'maxTouchPoints');
                        if (is_int($touchPoints) && $touchPoints > 0) {
                            return null;
                        }
                    }

                    // Client-Hints is authoritative where it exists, because it is what
                    // the browser reported about itself rather than a string it chose.
                    if ($hintFamily !== null && $hintFamily !== $platformFamily) {
                        return 'The OS family of navigator.platform differs from the Sec-CH-UA-Platform header.';
                    }

                    return ($platformFamily !== $uaFamily)
                        ? 'The OS family implied by navigator.userAgent differs from navigator.platform.'
                        : null;
                },
            ],

            // ja4_vs_ua: the ClientHello disagrees with the User-Agent.
            //
            // This is the one cross-check in the system where the second half of the
            // comparison CANNOT be written by the client. Every other rule compares two
            // things the page reported — and notes/07 section 2 measured that a competent
            // spoofer wins those by writing consistent lies. A JA4 comes from the TLS
            // terminator, below the header layer, and reproducing one requires a real
            // browser and a real network stack. `fingerprintd` calls this "a bot signal the
            // client never controls", and it is the reason JA4 was worth building.
            //
            // It fires ONLY on an exact match against a measured profile whose family
            // contradicts the claimed UA. Everything else is silent:
            //
            //   - an unknown correlator produces nothing. The profile table holds three
            //     SPECIFIC BUILDS measured on one machine, so most honest traffic will
            //     not be in it, and that is the safe direction.
            //   - a known correlator whose family AGREES with the UA produces nothing.
            //   - a request with no JA4 at all produces nothing, because absent evidence
            //     is not evidence of absence. A deployment that has not configured a
            //     terminator is not full of liars.
            //
            // The three-way family comparison is deliberately coarse. A Linux UA can be
            // Chrome, Firefox or Safari, so a single family cannot be inferred from the
            // platform; the rule asks whether the UA's engine token is consistent with
            // the measured family, and stays silent when it cannot tell.
            [
                'code' => 'ja4_vs_ua',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $profiles = Config::raw('transport_integrity.ja4_profiles', []);
                    if (! is_array($profiles) || $profiles === []) {
                        return null;
                    }

                    $correlator = $t->witnessString('ja4');
                    if ($correlator === null || ! isset($profiles[$correlator])) {
                        return null;
                    }

                    $family = $profiles[$correlator];
                    if (! is_string($family)) {
                        return null;
                    }

                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    if (! is_string($ua)) {
                        return null;
                    }

                    $claimed = self::uaEngineFamily($ua);
                    if ($claimed === null) {
                        return null;
                    }

                    // Engine tokens, not platform. "Mozilla/5.0 … Chrome/141 … Safari/537"
                    // contains "Safari" and is a Chromium browser; matching on platform or
                    // on any single token would fire on every honest Chrome.
                    foreach (['Firefox/' => 'gecko', 'Edg/' => 'chromium', 'OPR/' => 'chromium', 'Chrome/' => 'chromium'] as $token => $engine) {
                        if (str_contains($ua, $token) && $engine === $family) {
                            return null;
                        }
                    }

                    if ($family === 'gecko' && str_contains($ua, 'Firefox/')) {
                        return null;
                    }

                    if ($family === 'webkit' && str_contains($ua, 'Version/') && str_contains($ua, 'Safari/') && ! str_contains($ua, 'Chrome/')) {
                        return null;
                    }

                    return 'The TLS ClientHello matches a measured profile whose engine family contradicts the User-Agent.';
                },
            ],
            // hasLiedBrowser: productSub must be "20030107" or "20100101" for every
            // shipping engine, and the two are a legacy pair — an engine reports one or
            // the other, never a third value, and never an empty string. A spoofer that
            // sets productSub to a date it invented is caught here.
            [
                'code' => 'lied_browser',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $productSub = $this->value($c, 'tier1', 'environment', 'identity', 'productSub');
                    $appCodeName = $this->value($c, 'tier1', 'environment', 'identity', 'appCodeName');

                    if (! is_string($productSub)) {
                        return null;
                    }

                    $known = ['20030107', '20100101', ''];

                    if (! in_array($productSub, $known, true)) {
                        return 'navigator.productSub is not a value any shipping engine reports.';
                    }

                    if ($appCodeName !== null && ! is_string($appCodeName)) {
                        return null;
                    }

                    return ($appCodeName !== null && $appCodeName !== '' && $appCodeName !== 'Mozilla')
                        ? 'navigator.appCodeName is not the value every engine reports.'
                        : null;
                },
            ],

            // ---------------------------------------------------------------
            // notes/21: the engine, the worker realm, the feature set, and two
            // read-back invariants. CreepJS does the first three in some form
            // (`getEngine`, `workerScope`, `features`); the engine marks and the
            // read-back invariants here are table-free re-designs of those ideas.
            // ---------------------------------------------------------------

            // ua_vs_engine: the engine the User-Agent names against the engine the
            // runtime IS. The client sends raw marks (own-property names of a fresh
            // Error, the stack-line format, whether `InternalError` exists); the engine
            // family is derived HERE from those marks and the client's own `engine`
            // label is ignored, because a label is one more string a spoofer can set
            // while the marks are facts about the object model.
            //
            // CreepJS's `getEngine()` sums the length of one error message with the
            // length of `Array`'s source text (80 / 58 / 77). A message rewording in any
            // engine release changes the sum and silences the check; the own-property
            // SHAPE of an Error has been stable in each engine for over a decade and
            // does not depend on English text.
            //
            // Chrome on iOS (`CriOS/`) is WebKit and `uaEngineFamily()` already says so,
            // so a real iPhone Chrome agrees with its JavaScriptCore marks. A UA that
            // names no engine, or marks that identify none, are silence.
            [
                'code' => 'ua_vs_engine',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $marks = $this->value($c, 'tier1', 'engineIdentity');

                    if (! is_string($ua) || ! is_array($marks)) {
                        return null;
                    }

                    $claimed = self::uaEngineFamily($ua);
                    $actual = self::engineFromMarks($marks);

                    if ($claimed === null || $actual === null) {
                        return null;
                    }

                    return $claimed === $actual
                        ? null
                        : 'The engine family named by navigator.userAgent differs from the JavaScript engine identified by its error-object shape.';
                },
            ],

            // engine_vs_ch_header: the same marks against a HEADER. Only the Chromium
            // family implements UA Client Hints, so `Sec-CH-UA` on the wire means a
            // Chromium browser sent the request; marks that say SpiderMonkey or
            // JavaScriptCore then cannot be real. The JavaScript half cannot remove the
            // header and the header half cannot change the object model, which is the
            // property every rule in this file would like to have and few do.
            // Both-present only: a stripped header is a deployment, not a liar.
            [
                'code' => 'engine_vs_ch_header',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $header = $t->witnessString('sec_ch_ua');
                    $marks = $this->value($c, 'tier1', 'engineIdentity');

                    if ($header === null || trim($header) === '' || ! is_array($marks)) {
                        return null;
                    }

                    $actual = self::engineFromMarks($marks);
                    if ($actual === null) {
                        return null;
                    }

                    // Worded without the header's brand token: a detail must never carry a
                    // header value, and "Chromium" is one.
                    return $actual === 'chromium'
                        ? null
                        : 'The browser sent a Sec-CH-UA header, which only Blink-based browsers do, while the JavaScript engine is not V8.';
                },
            ],

            // ua_vs_feature_version: the User-Agent's engine version against the features
            // the engine exposes, per MDN browser-compat-data (`FeatureShipVersions`,
            // generated by scripts/fingerprint/generate-feature-versions.mjs and
            // regenerated per release — CreepJS's equivalent maps were last updated for
            // Chrome 115 and Firefox 112, which is the failure mode a generator avoids).
            //
            // Two directions, one code, the detail says which:
            //
            //  - the claim is TOO LOW: features are present that shipped three or more
            //    releases AFTER the claimed version. Two of them, not one, so a single
            //    mis-dated table row cannot fire on honest traffic, and three releases
            //    rather than one because Beta and Canary legitimately carry next
            //    release's features.
            //  - the claim is TOO HIGH: features are absent that shipped three or more
            //    releases BEFORE the claimed version. Only the ECMAScript builtins in
            //    `ALWAYS_ON_ES_FEATURES` count here, because a Web API can be absent for
            //    an honest reason (enterprise policy, a non-secure context, a platform
            //    build) while a language builtin that V8 shipped is in every V8 of that
            //    version. Two of them, same reason.
            //
            // A null in the table is "no evidence" (never shipped, behind a flag,
            // platform-partial, or unknown), never "absent". A tiny `present` list is a
            // probe that did not run properly, so the too-high direction needs at least
            // ten present features before it says anything.
            [
                'code' => 'ua_vs_feature_version',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $present = $this->value($c, 'tier1', 'esFeatures', 'present');

                    if (! is_string($ua) || ! is_string($present)) {
                        return null;
                    }

                    $engine = self::engineVersionFromUserAgent($ua);
                    if ($engine === null) {
                        return null;
                    }

                    [$column, $claimed] = $engine;
                    $presentKeys = array_fill_keys(array_filter(array_map('trim', explode(',', $present)), static fn (string $name): bool => $name !== ''), true);

                    $tooNew = 0;
                    $tooOld = 0;
                    foreach (FeatureShipVersions::SHIPPED as $key => $versions) {
                        $shipped = $versions[$column];
                        if (! is_int($shipped)) {
                            continue;
                        }

                        if (isset($presentKeys[$key])) {
                            if ($shipped >= $claimed + self::FEATURE_VERSION_TOLERANCE) {
                                $tooNew++;
                            }

                            continue;
                        }

                        if (in_array($key, self::ALWAYS_ON_ES_FEATURES, true) && $shipped + self::FEATURE_VERSION_TOLERANCE <= $claimed) {
                            $tooOld++;
                        }
                    }

                    if ($tooNew >= self::FEATURE_VERSION_MIN_WITNESSES) {
                        return 'navigator.userAgent claims an engine version older than the feature set the engine exposes.';
                    }

                    if (count($presentKeys) >= self::FEATURE_VERSION_MIN_PRESENT && $tooOld >= self::FEATURE_VERSION_MIN_WITNESSES) {
                        return 'navigator.userAgent claims an engine version newer than the feature set the engine exposes.';
                    }

                    return null;
                },
            ],

            // worker_vs_window_*: the page against its own dedicated worker, which is a
            // separate realm that a page-level patch never reaches. The client takes
            // both snapshots with identical keys in the same probe; these rules compare
            // field by field and name the fields that differ, never their values.
            //
            // `language`/`languages` are deliberately NOT compared. CreepJS skips the
            // worker's language because of a Chromium discrepancy it observed; that has
            // not been reproduced here, and a comparison that might fire on honest
            // Chrome is worse than one fewer field.
            [
                'code' => 'worker_vs_window_navigator',
                'rule' => $this->workerRule([
                    'userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory',
                    'uaPlatform', 'uaMobile', 'uaBrands', 'engine', 'currencyCount',
                ]),
            ],
            [
                'code' => 'worker_vs_window_timezone',
                'rule' => $this->workerRule(['timeZone', 'tzOffset', 'locale']),
            ],
            [
                'code' => 'worker_vs_window_gpu',
                'rule' => $this->workerRule(['webglVendor', 'webglRenderer']),
            ],

            // canvas_realm_mismatch (notes/22 M2): the window and the worker drew the same
            // geometry-only scene and hashed two agreeing reads each; the hashes differ.
            // Measured identical in every stock configuration (0 of 40 960 bytes differ,
            // Chromium/Firefox/WebKit, GPU and CPU raster), so a difference is page-realm
            // read-back noise that the worker realm does not see. Silent when a protection
            // that noises every realm is reported AND the engine evidence agrees (RFP/Tor
            // through `protectedGecko()`, Brave through the Chromium evidence: the same
            // gate the host's `DeviceComponents::untrusted()` applies, security review round 4), or
            // when the known-value fill already failed: those are the same honest visitor,
            // already scored once. An un-gated flag no longer silences it.
            [
                'code' => 'canvas_realm_mismatch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $window = $this->value($c, 'tier2', 'workerScope', 'window', 'canvasHash');
                    $worker = $this->value($c, 'tier2', 'workerScope', 'worker', 'canvasHash');

                    if (! is_string($window) || ! is_string($worker) || $window === '' || $worker === '' || $window === $worker) {
                        return null;
                    }

                    if (self::protectedGecko($c, $t) || self::protectedBrave($c, $t)) {
                        return null;
                    }

                    if ($this->value($c, 'integrity', 'data', 'canvasFill', 'exact') === false
                        || $this->value($c, 'integrity', 'data', 'canvasPattern', 'exact') === false) {
                        return null;
                    }

                    return 'The page and its worker rasterised the same geometry differently, so the page\'s canvas read-back is noised.';
                },
            ],

            // gpu_realm_mismatch: see the weight table. Silent under the same protections and
            // read-back findings as `canvas_realm_mismatch`: the same honest visitor, scored once.
            [
                'code' => 'gpu_realm_mismatch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    if (! self::gpuRealmsDisagree($c)) {
                        return null;
                    }

                    if (self::protectedGecko($c, $t) || self::protectedBrave($c, $t)) {
                        return null;
                    }

                    if ($this->value($c, 'integrity', 'data', 'canvasFill', 'exact') === false
                        || $this->value($c, 'integrity', 'data', 'canvasPattern', 'exact') === false) {
                        return null;
                    }

                    return 'The page and its worker rendered the same shader to different pixels, so the page\'s WebGL read-back is hooked.';
                },
            ],

            // resistance_vs_engine: see the weight table. The flags are honoured by
            // the host's DeviceComponents::untrusted() only under the same evidence, so an honest Firefox
            // with RFP is untrusted-and-silent and a Chrome claiming RFP is trusted-and-scored.
            [
                'code' => 'resistance_vs_engine',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $rfp = $this->value($c, 'integrity', 'data', 'resistance', 'rfp') === true;
                    $tor = $this->value($c, 'integrity', 'data', 'resistance', 'tor') === true;
                    $brave = $this->value($c, 'integrity', 'data', 'resistance', 'brave') === true;

                    if (! $rfp && ! $tor && ! $brave) {
                        return null;
                    }

                    $marks = $this->value($c, 'tier1', 'engineIdentity');
                    $engine = is_array($marks) ? self::engineFromMarks($marks) : null;
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $uaFamily = is_string($ua) ? self::uaEngineFamily($ua) : null;
                    $header = $t->witnessString('sec_ch_ua');
                    $hasClientHints = is_string($header) && trim($header) !== '';

                    if (($rfp || $tor) && (($engine !== null && $engine !== 'gecko') || ($uaFamily !== null && $uaFamily !== 'gecko') || $hasClientHints)) {
                        return 'The client reports a privacy mode that exists in only one browser engine while the engine marks, the User-Agent or the request headers name another engine.';
                    }

                    if ($brave && (($engine !== null && $engine !== 'chromium') || ($uaFamily !== null && $uaFamily !== 'chromium'))) {
                        return 'The client reports a browser-specific shield while the engine marks or the User-Agent name another engine.';
                    }

                    return null;
                },
            ],

            // A WebGL context that reports less than the specification's minimum limits is
            // not a hardware implementation. This is not a renderer-family table: it uses
            // only the published WebGL minima, so it cannot go stale with a new GPU model.
            // Read from `tier2.gpu.webgl` (renderer, limits, webgl2), the shape the collector
            // sends; the software rasterisers are skipped because their limits are chosen by
            // the software, not by hardware.
            [
                'code' => 'renderer_vs_limits',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $webgl = $this->value($c, 'tier2', 'gpu', 'webgl');

                    if (! is_array($webgl) || self::isSoftwareRenderer($webgl['renderer'] ?? null)) {
                        return null;
                    }

                    $limits = $webgl['limits'] ?? null;
                    if (! is_array($limits)) {
                        return null;
                    }

                    // The minima are the published WebGL 1.0 (OpenGL ES 2.0) and WebGL 2.0
                    // (OpenGL ES 3.0) floors, not a measured vendor table. A real
                    // implementation cannot report below them. The WebGL2 floors are higher for
                    // every checked limit, not just vertex attribs; using the WebGL1 floor under
                    // a WebGL2 context would let a spoofed context under-report the other
                    // limits without firing.
                    $minimums = [
                        'MAX_VERTEX_ATTRIBS' => 8,
                        'MAX_VERTEX_UNIFORM_VECTORS' => 128,
                        'MAX_FRAGMENT_UNIFORM_VECTORS' => 16,
                        'MAX_VARYING_VECTORS' => 8,
                        'MAX_COMBINED_TEXTURE_IMAGE_UNITS' => 8,
                        'MAX_TEXTURE_IMAGE_UNITS' => 8,
                    ];

                    if (($webgl['webgl2'] ?? false) === true) {
                        $minimums = [
                            'MAX_VERTEX_ATTRIBS' => 16,
                            'MAX_VERTEX_UNIFORM_VECTORS' => 256,
                            'MAX_FRAGMENT_UNIFORM_VECTORS' => 224,
                            'MAX_VARYING_VECTORS' => 15,
                            'MAX_COMBINED_TEXTURE_IMAGE_UNITS' => 32,
                            'MAX_TEXTURE_IMAGE_UNITS' => 16,
                        ];
                    }

                    foreach ($minimums as $name => $minimum) {
                        $value = $limits[$name] ?? null;

                        // The collector writes -1 for a limit that did not read as a number;
                        // that is "unknown", never "below the minimum".
                        if ((is_int($value) || is_float($value)) && $value >= 0 && $value < $minimum) {
                            return sprintf(
                                'The WebGL %s limit is %s, below the specification minimum of %d.',
                                $name,
                                (string) $value,
                                $minimum,
                            );
                        }
                    }

                    return null;
                },
            ],

            // A renderer family that cannot exist on the claimed OS. The pairs are an explicit
            // table (`contradictingGpuFamilies`), limited to unambiguous ones; the real-world
            // combinations that look odd (Windows-on-ARM Adreno, Linux boards with Mali, Apple
            // GPUs under Asahi Linux, Chromebooks with Mali/Adreno, Mesa under Android-x86, the
            // Direct3D-backed Mesa of WSL) are deliberately silent. Read from
            // `tier2.gpu.webgl.renderer`, the unmasked renderer where the browser exposes it.
            [
                'code' => 'ch_platform_vs_gpu',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $rendererValue = $this->value($c, 'tier2', 'gpu', 'webgl', 'renderer');

                    if (! is_string($rendererValue) || $rendererValue === '' || self::isSoftwareRenderer($rendererValue)) {
                        return null;
                    }

                    $hint = $this->value($c, 'tier1', 'uaClientHints', 'platform');
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $family = is_string($hint) ? $this->platformOsFamily($hint) : null;

                    if ($family === null && is_string($ua)) {
                        $family = $this->uaOsFamily($ua);
                    }

                    if ($family === null) {
                        return null;
                    }

                    $gpuFamily = $this->gpuPlatformFamily(strtolower($rendererValue));
                    if ($gpuFamily === null || ! in_array($family, self::contradictingGpuFamilies($gpuFamily, $rendererValue), true)) {
                        return null;
                    }

                    return sprintf(
                        'The WebGL renderer describes a %s GPU while the platform reports %s.',
                        $gpuFamily,
                        $family,
                    );
                },
            ],

            // notification_permission_vs_query: `permissions.query({name:'notifications'})`
            // answers `prompt` while `Notification.permission` is `denied`. A real browser
            // keeps the two in step; headless Chrome (the classic build) did not, and
            // several automation stacks still carry that pair. Both values come from the
            // same tier-2 probe, so "both present" means the probe ran.
            [
                'code' => 'notification_permission_vs_query',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $states = $this->value($c, 'tier2', 'permissions', 'states');
                    $permission = $this->value($c, 'tier2', 'permissions', 'notificationPermission');

                    if (! is_string($states) || ! is_string($permission)) {
                        return null;
                    }

                    $queried = null;
                    foreach (explode(',', $states) as $pair) {
                        if (str_starts_with($pair, 'notifications=')) {
                            $queried = substr($pair, strlen('notifications='));
                        }
                    }

                    // Worded without either state's name: both are claim values.
                    return ($queried === 'prompt' && $permission === 'denied')
                        ? 'permissions.query reports the notifications permission as not yet decided while Notification.permission reports it refused.'
                        : null;
                },
            ],

            // notification_permission_nonstandard: see the weight. Two halves: the DOM side (the
            // collector reports the fixed marker `invalid` for any value outside the enum) and the
            // Permissions-API side (the `notifications` entry of the state vector, which is
            // `prompt|granted|denied` or the NAME of the error the engine rejected with).
            [
                'code' => 'notification_permission_nonstandard',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $permission = $this->value($c, 'tier2', 'permissions', 'notificationPermission');
                    if (is_string($permission) && ! in_array($permission, ['default', 'granted', 'denied'], true)) {
                        return 'Notification.permission is outside the values its specification defines.';
                    }

                    $states = $this->value($c, 'tier2', 'permissions', 'states');
                    if (! is_string($states)) {
                        return null;
                    }

                    foreach (explode(',', $states) as $pair) {
                        if (! str_starts_with($pair, 'notifications=')) {
                            continue;
                        }
                        $queried = substr($pair, strlen('notifications='));
                        // A rejected query reports the error's name (`TypeError`, `NotSupportedError`) or the
                        // sentinel `unsupported`; those are an engine's answer, not a state.
                        $isEngineAnswer = in_array($queried, ['prompt', 'granted', 'denied', 'unsupported'], true)
                            || preg_match('/^[A-Z][A-Za-z]{0,40}(?:Error|Exception)$/', $queried) === 1;
                        if (! $isEngineAnswer) {
                            return 'permissions.query reports the notifications permission as a value the Permissions API does not define.';
                        }
                    }

                    return null;
                },
            ],

            // fonts_single_family_desktop: see the weight. Windows and macOS only (the fonts the probe
            // asks for are those OSes' base set); WebKit is skipped because Safari restricts what
            // `local()` reveals, and so is every privacy mode that restricts fonts on purpose.
            [
                'code' => 'fonts_single_family_desktop',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    if (! is_string($ua)) {
                        return null;
                    }

                    $column = match (self::uaOsFamily($ua)) {
                        'windows' => 'windows',
                        'macos' => 'mac',
                        default => null,
                    };
                    $marks = $this->value($c, 'tier1', 'engineIdentity');
                    $engine = is_array($marks) ? self::engineFromMarks($marks) : null;
                    if ($column === null || $engine === 'webkit' || self::uaEngineFamily($ua) === 'webkit') {
                        return null;
                    }

                    if (self::protectedGecko($c, $t) || self::protectedBrave($c, $t)) {
                        return null;
                    }

                    $total = $this->value($c, 'tier2', 'fontFaces', 'count');
                    $own = $this->value($c, 'tier2', 'fontFaces', $column);
                    if (! is_int($total) || ! is_int($own)) {
                        return null;
                    }

                    return ($total <= 1 && $own <= 1)
                        ? 'The User-Agent names Windows or macOS but at most one of the operating system\'s base font families is installed.'
                        : null;
                },
            ],

            // tz_utc_vs_language_region: see the weight. The region comes from the language tag's own
            // region subtag (no ICU needed), preferring the Accept-Language header the browser sent.
            // resistFingerprinting and Tor pin the zone to UTC and the language to en-US by design.
            [
                'code' => 'tz_utc_vs_language_region',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $timezone = $this->value($c, 'tier2', 'intl', 'resolved', 'timeZone');
                    if (! is_string($timezone) || ! in_array(strtolower($timezone), ['utc', 'etc/utc', 'etc/uct', 'etc/universal', 'etc/zulu'], true)) {
                        return null;
                    }

                    if (self::claimsGeckoProtection($c)) {
                        return null;
                    }

                    $header = $t->witnessString('accept_language');
                    $tag = $header !== null ? trim(explode(',', $header)[0]) : $this->value($c, 'tier1', 'environment', 'identity', 'language');
                    if (! is_string($tag)) {
                        return null;
                    }

                    return preg_match('/^[A-Za-z]{2,3}(?:-[A-Za-z]{4})?-([A-Za-z]{2})(?:[-;]|$)/', trim($tag)) === 1
                        ? 'The resolved time zone is UTC while the language tag names a country.'
                        : null;
                },
            ],

            // ua_reduced_shape_violation / webview_ua_shape: see the weights. Server-only, over the
            // claimed User-Agent, so a header-only client is judged by `ua_vs_ua_header` instead.
            [
                'code' => 'ua_reduced_shape_violation',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $hint = $t->witnessString('sec_ch_ua');
                    if (! is_string($ua) || $hint === null || trim($hint) === '') {
                        return null;
                    }

                    // The exact shape of Google Chrome's reduced UA. Anything with another product token
                    // (Edg/, OPR/, SamsungBrowser/, a WebView's Version/4.0 and `; wv`) is not matched, so
                    // forks that keep the model and the Android version stay silent.
                    if (preg_match('~^Mozilla/5\.0 \(([^)]*)\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/(\d+)\.0\.0\.0 (?:Mobile )?Safari/537\.36$~', $ua, $m) !== 1
                        || (int) $m[2] < 110 || str_contains($m[1], '; wv')) {
                        return null;
                    }

                    $platform = $m[1];
                    $violates = match (true) {
                        preg_match('/Windows NT ([\d.]+)/', $platform, $v) === 1 => $v[1] !== '10.0',
                        preg_match('/Mac OS X ([\d_.]+)/', $platform, $v) === 1 => $v[1] !== '10_15_7',
                        preg_match('/Android ([\d.]+); ([^;)]*)$/', $platform, $v) === 1 => $v[1] !== '10' || $v[2] !== 'K',
                        default => false,
                    };

                    return $violates
                        ? 'A Chromium 110 or newer User-Agent carries an operating-system version or device model that Chromium freezes.'
                        : null;
                },
            ],
            [
                'code' => 'webview_ua_shape',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    if (! is_string($ua) || preg_match('/\(([^)]*; wv)\)/', $ua, $m) !== 1 || ! str_contains($m[1], 'Android')) {
                        return null;
                    }

                    return (preg_match('/; ([^;]+) Build\/[^;)]+; wv$/', $m[1], $model) === 1 && trim($model[1]) !== '' && trim($model[1]) !== 'K')
                        ? null
                        : 'The Android WebView User-Agent carries no device model and Build token, which every WebView ships.';
                },
            ],

            // ua_headless_token: the one check that needs no cross-source at all, because
            // the source announces itself. Either the page's UA or the header the browser
            // sent; the header alone is enough (no JavaScript needed), the claim alone is
            // enough (a headless build that rewrote its header but not `navigator`).
            [
                'code' => 'ua_headless_token',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $claimed = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    $header = $t->witnessString('user_agent');

                    foreach ([$claimed, $header] as $userAgent) {
                        if (is_string($userAgent) && preg_match('/HeadlessChrome\/|PhantomJS|SlimerJS|Lightpanda\b/i', $userAgent) === 1) {
                            return 'The User-Agent carries a headless-browser product token.';
                        }
                    }

                    return null;
                },
            ],

            // audio_readback_perturbed: a ConstantSourceNode rendered offline must read
            // back as exactly its constant in every sample, and `copyFromChannel` must
            // agree with `getChannelData`. Specified behaviour, no reference table. A
            // false on either is additive or multiplicative noise on the read path —
            // Brave's audio farbling multiplies samples by a factor near 1, which a
            // zero-signal test (CreepJS `hasFakeAudio`, 0 Hz) cannot see because
            // 0 × anything is 0; a non-zero constant can.
            //
            // Contract 2 adds the three CreepJS checks as further invariants: a 0 Hz
            // oscillator renders exact zeros, an analyser on silence reports -Infinity in
            // every bin, and a trap value written into a buffer reads back unchanged. Each
            // is boolean|null; null (the client could not run that part) is not evidence.
            [
                'code' => 'audio_readback_perturbed',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $exact = $this->value($c, 'tier2', 'audioReadback', 'constantExact');
                    $agree = $this->value($c, 'tier2', 'audioReadback', 'methodsAgree');

                    if (! is_bool($exact) || ! is_bool($agree)) {
                        return null;
                    }

                    if (! $exact || ! $agree) {
                        return 'An offline-rendered constant did not read back as the constant, so audio read-back is noised.';
                    }

                    foreach (['silenceExact', 'analyserSilent', 'trapSurvives'] as $invariant) {
                        if ($this->value($c, 'tier2', 'audioReadback', $invariant) === false) {
                            return 'An audio read-back invariant (rendered silence, analyser silence or a written trap value) did not hold, so audio read-back is noised.';
                        }
                    }

                    return null;
                },
            ],

            // screen_vs_css_media: `screen.width/height` against the CSS media path. The
            // phantom realm injects `@media (device-width: Wpx)` into its own document and
            // reads the custom property it sets; a JavaScript override of `screen` does not
            // change what the style engine believes. Both dimensions false, because page
            // zoom and Gecko's fractional screen sizes can honestly miss one.
            [
                'code' => 'screen_vs_css_media',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $width = $this->value($c, 'integrity', 'data', 'phantomRealm', 'screenTruth', 'cssWidth');
                    $height = $this->value($c, 'integrity', 'data', 'phantomRealm', 'screenTruth', 'cssHeight');

                    if (! is_bool($width) || ! is_bool($height)) {
                        return null;
                    }

                    // Brave Balanced snaps `screen` to a few sizes and reports CSS device-width as
                    // the viewport plus a small random amount, so both honestly miss. Silent only
                    // when the engine evidence agrees with the client-reported Brave flag (the gate
                    // `canvas_realm_mismatch` uses), so a forged flag buys nothing on Gecko/WebKit.
                    if (self::protectedBrave($c, $t)) {
                        return null;
                    }

                    return (! $width && ! $height)
                        ? 'screen.width and screen.height both differ from the device size the CSS media path reports.'
                        : null;
                },
            ],

            // tz_intl_vs_date: before standard time, tzdb offsets are local mean time and
            // differ per city, so the engine's own offset for 1 July 1113 (via the Date
            // constructor, in the real zone) and the Intl zone's offset for the same instant
            // agree only when the Intl zone IS the real zone. An extension that rewrites
            // `resolvedOptions().timeZone` and leaves Date alone disagrees. CreepJS
            // `timezone.locationMeasured`; the client reduces it to one boolean.
            [
                'code' => 'tz_intl_vs_date',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $agree = $this->value($c, 'tier2', 'timezoneLmt', 'agree');

                    return $agree === false
                        ? 'The Intl time zone\'s historic offset differs from the offset the engine itself computes for the same instant.'
                        : null;
                },
            ],

            // fonts_vs_ua_os: `document.fonts.check` over families only one OS ships. The
            // UA names an OS whose own families are ALL absent while four or more of another
            // OS's are present. Four, not one: a Windows user can install Roboto, a Mac user
            // Segoe UI; a Mac without a single Apple family is not a Mac.
            [
                'code' => 'fonts_vs_ua_os',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
                    // Silenced under the protection gate, because there the font set itself
                    // is the protection's: resistFingerprinting restricts CSS font matching to
                    // the base system fonts (Firefox `RFPTargets.inc`
                    // FontVisibilityBaseSystem) and Tor Browser ships its own font set, so the
                    // counts describe the protection, not the operating system. The
                    // UA-against-platform contradiction (`lied_os`) is NOT silenced.
                    if (! is_string($ua) || self::protectedGecko($c, $t)) {
                        return null;
                    }

                    $family = self::uaOsFamily($ua);
                    $column = match ($family) {
                        'windows' => 'windows',
                        'macos', 'ios' => 'mac',
                        'linux', 'chromeos' => 'linux',
                        'android' => 'android',
                        default => null,
                    };
                    if ($column === null) {
                        return null;
                    }

                    $counts = [];
                    foreach (['windows', 'mac', 'linux', 'android'] as $name) {
                        $count = $this->value($c, 'tier2', 'fontFaces', $name);
                        if (! is_int($count)) {
                            return null;
                        }
                        $counts[$name] = $count;
                    }

                    if ($counts[$column] !== 0) {
                        return null;
                    }

                    foreach ($counts as $name => $count) {
                        if ($name !== $column && $count >= self::FONTS_OTHER_OS_MIN) {
                            return 'None of the fonts the User-Agent\'s operating system ships is installed, while another operating system\'s set is.';
                        }
                    }

                    return null;
                },
            ],

            // gpu_webgl_params_mismatch: WebGL1 and WebGL2 contexts on one page describe one
            // GPU; a spoofer that patches `getParameter` on one prototype and not the other
            // produces two (CreepJS "mirrored params").
            [
                'code' => 'gpu_webgl_params_mismatch',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $agree = $this->value($c, 'tier2', 'gpu', 'mirroredParamsAgree');

                    return $agree === false
                        ? 'The WebGL1 and WebGL2 contexts report different values for parameters that describe the same GPU.'
                        : null;
                },
            ],

            // cores_vs_measured_parallelism: a timed worker fan-out saturates near the real
            // core count; `hardwareConcurrency` is a property. A CDP override or Brave's
            // farbling changes the property and not the measurement. ONE direction only: a
            // measurement ABOVE the claim. Background load, a throttled tab and the rest of
            // the collection running alongside all push the measurement DOWN (a stock
            // four-core Firefox read '1-2' in the harness), so a low bucket is no evidence;
            // nothing makes two cores look like five.
            [
                'code' => 'cores_vs_measured_parallelism',
                'rule' => function (mixed $c, TransportIntegrityResult $t): ?string {
                    $cores = $this->value($c, 'tier1', 'environment', 'identity', 'hardwareConcurrency');
                    $bucket = $this->value($c, 'tier2', 'parallelism', 'bucket');

                    if (! is_int($cores) || ! is_string($bucket)) {
                        return null;
                    }

                    if ($cores <= 2 && in_array($bucket, ['5-8', '9+'], true)) {
                        return 'hardwareConcurrency reports one or two cores while the measured parallel capacity is that of five or more.';
                    }

                    return null;
                },
            ],

            // ---------------------------------------------------------------
            // Smart signals: network, virtual machines, emulators, private mode.
            // ---------------------------------------------------------------

            // ip_country_vs_locale: the IP's country against the clock's time zone AND the
            // language list. Fires only when BOTH independent settings disagree with the
            // country (see SmartSignals::localeAgainstCountry): an expat whose language is
            // foreign and whose clock is local, or a traveller who only changed the clock, is
            // silent. A VPN user who never touched either setting fires: that is the signal.
            // Silent for a protected Gecko (resistFingerprinting reports UTC and en-US).
            [
                'code' => 'ip_country_vs_locale',
                'rule' => function (mixed $c, TransportIntegrityResult $t, ?NetworkFacts $n = null): ?string {
                    if ($n === null || $n->country === null || self::protectedGecko($c, $t)) {
                        return null;
                    }
                    $locale = SmartSignals::localeAgainstCountry(is_array($c) ? $c : [], $n);

                    return $locale['timezone'] === true && $locale['language'] === true
                        ? 'The time zone and the language list both name regions other than the country the IP address is in.'
                        : null;
                },
            ],

            // network_vpn / network_hosting: the announcing ASN says VPN service, or hosting,
            // cloud or colocation (or the address is in a published cloud range). Exclusive, so
            // one address never pays twice. Silent for a protected Gecko (VPN users of Mullvad
            // Browser and Tor are the honest majority there). A corporate gateway in a cloud and
            // a person on a commercial VPN are the honest cohort; hence 4-5.
            [
                'code' => 'network_vpn',
                'rule' => function (mixed $c, TransportIntegrityResult $t, ?NetworkFacts $n = null): ?string {
                    return $n !== null && $n->isVpn() && ! self::protectedGecko($c, $t)
                        ? 'The IP address belongs to an autonomous system whose registered name says it is a VPN service.'
                        : null;
                },
            ],
            [
                'code' => 'network_hosting',
                'rule' => function (mixed $c, TransportIntegrityResult $t, ?NetworkFacts $n = null): ?string {
                    return $n !== null && $n->isHosting() && ! self::protectedGecko($c, $t)
                        ? 'The IP address belongs to a hosting, cloud or colocation network, not an access network.'
                        : null;
                },
            ],

            // vm_gpu_renderer: a hypervisor's virtual GPU on a non-headless desktop browser.
            // Corporate VDI (VMware Horizon, Parallels, Hyper-V desktops) is honest; weight 5.
            [
                'code' => 'vm_gpu_renderer',
                'rule' => function (mixed $c): ?string {
                    $vm = SmartSignals::virtualMachine(is_array($c) ? $c : []);

                    return $vm['hypervisor_gpu']
                        ? 'The WebGL renderer names a hypervisor\'s virtual GPU (VMware, VirtualBox, Parallels, QEMU/virtio or Hyper-V).'
                        : null;
                },
            ],

            // vm_software_gpu_screen: a software rasteriser alone is an honest Linux or driverless
            // Windows desktop; with a screen size only a hypervisor offers before its guest
            // tools are installed, it is a VM.
            [
                'code' => 'vm_software_gpu_screen',
                'rule' => function (mixed $c): ?string {
                    $vm = SmartSignals::virtualMachine(is_array($c) ? $c : []);

                    return $vm['software_gpu'] && $vm['vm_screen']
                        ? 'A software-rendered WebGL context and a default virtual-machine screen size occur together on a desktop browser.'
                        : null;
                },
            ],

            // emulator_android: an emulator token in the User-Agent or the device model, or an
            // Android browser on a software GPU. Developers and testers are the honest cohort.
            [
                'code' => 'emulator_android',
                'rule' => function (mixed $c): ?string {
                    return SmartSignals::androidEmulator(is_array($c) ? $c : [])
                        ? 'The Android device identifies as an emulator (an emulator token in the user agent or device model, or a software GPU).'
                        : null;
                },
            ],

            // private_mode_with_other_signals: private browsing is NOT fraud and never fires
            // alone. It adds 3 only when a network, VM or emulator signal is also present, because
            // privacy-minded visitors use VPNs and a private tab on a hosting network is the
            // combination a bot farm produces. The model sees private mode as its own feature.
            [
                'code' => 'private_mode_with_other_signals',
                'rule' => function (mixed $c, TransportIntegrityResult $t, ?NetworkFacts $n = null): ?string {
                    $claims = is_array($c) ? $c : [];
                    $private = SmartSignals::privateMode($claims, $t);
                    if ($private === null || ! $private['likely']) {
                        return null;
                    }
                    $vm = SmartSignals::virtualMachine($claims);
                    $locale = SmartSignals::localeAgainstCountry($claims, $n);
                    $other = ($n !== null && ($n->isHosting() || $n->isVpn()))
                        || $vm['hypervisor_gpu']
                        || SmartSignals::androidEmulator($claims)
                        || ($locale['timezone'] === true && $locale['language'] === true);

                    return $other
                        ? 'The tab looks like private browsing and a network, virtual-machine, emulator or locale signal is present as well.'
                        : null;
                },
            ],
        ];
    }

    /**
     * Which class of API lied, for a lie finding: `identity` when any lied API is an
     * identity surface, `noise` when every lied API is a read-back surface, null when the
     * finding is absent — reported by the client or derived from its data, see
     * `fromIntegrity()`. The API list comes from the integrity DATA (`lied` map keys or a
     * `mismatched` list); when the finding is present but the data is unreadable (an older
     * client, a hostile body) the finding alone counts as identity, so stripping the data
     * cannot lower the score.
     *
     * @param  list<string>  $path
     */
    private function liedApiClass(mixed $claims, string $finding, array $path): ?string
    {
        if ($this->fromIntegrity($claims, $finding) === null) {
            return null;
        }

        $data = $this->value($claims, ...$path);
        $apis = [];
        if (is_array($data)) {
            foreach ($data as $key => $entry) {
                $api = is_string($key) ? $key : (is_string($entry) ? $entry : null);
                if ($api !== null) {
                    $apis[] = $api;
                }
            }
        }

        if ($apis === []) {
            return 'identity';
        }

        $allNoise = true;
        $allPrivacy = true;
        foreach ($apis as $api) {
            if (! self::isNoiseSurface($api)) {
                $allNoise = false;
            }
            if (! self::isPrivacyToolSurface($api)) {
                $allPrivacy = false;
            }
        }

        if ($allNoise) {
            return 'noise';
        }

        // Only the lie battery itself (`lie_battery_failed`) can be a privacy-tool footprint; a
        // patched `toString` in a pristine realm is a spoofer hiding its work.
        return ($finding === 'lie_battery_failed' && $allPrivacy && $this->isPageOnlyPatch($claims)) ? 'privacy' : 'identity';
    }

    /**
     * The identity getters a privacy or User-Agent-switcher extension wraps. NOT
     * `Navigator.webdriver` (hiding it is an automation evasion), `Permissions.query`, `Math`,
     * `Function.toString` or any canvas/WebGL surface.
     */
    private static function isPrivacyToolSurface(string $api): bool
    {
        return (str_starts_with($api, 'Navigator.') && $api !== 'Navigator.webdriver')
            || str_starts_with($api, 'Screen.')
            || $api === 'Date.getTimezoneOffset'
            || $api === 'Intl.DateTimeFormat.resolvedOptions';
    }

    /**
     * Whether the patch is confined to the page realm and hides nothing: the dedicated worker
     * disagrees with the page about an identity field, and none of the other conformance
     * findings (closure getter, patched descriptor, shadowing, a patched `toString` seen from a
     * pristine realm, `Math` lookup tables) fired. A spoofer that covers its tracks trips at
     * least one of them; a plain extension trips none.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function isPageOnlyPatch(mixed $claims): bool
    {
        if ($this->workerDisagreements($claims, ['userAgent', 'platform', 'hardwareConcurrency', 'deviceMemory', 'language', 'languages', 'timeZone', 'tzOffset', 'uaPlatform', 'uaMobile', 'uaBrands']) === []) {
            return false;
        }

        foreach (['wrong_receiver_did_not_throw', 'descriptor_patched', 'descriptor_unstable', 'descriptor_has_setter', 'descriptor_shadowed', 'descriptor_missing', 'realm_tostring_mismatch', 'math_pf_mismatch'] as $code) {
            if ($this->fromIntegrity($claims, $code) !== null) {
                return false;
            }
        }

        return true;
    }

    /**
     * The read-back surfaces a canvas/WebGL/audio/rects noise extension wraps. Everything
     * else a lie can name (Navigator, Screen, Date, Intl, Permissions, Math, Function) is an
     * identity surface.
     */
    public static function isNoiseSurface(string $api): bool
    {
        foreach (['HTMLCanvasElement.', 'CanvasRenderingContext2D.', 'OffscreenCanvas', 'WebGLRenderingContext.', 'WebGL2RenderingContext.', 'AudioBuffer.', 'AnalyserNode.', 'Element.getBoundingClientRect', 'Element.getClientRects', 'Range.'] as $prefix) {
            if (str_starts_with($api, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The window and screen numbers of a desktop Chromium: null for any other engine, a phone or
     * tablet (touch points or a mobile OS), a window that reports no outer size, or a number that is
     * not a positive integer. The geometry rules read only this.
     *
     * @return array{innerWidth: int, innerHeight: int, outerWidth: int, outerHeight: int, screenWidth: int, screenHeight: int, availWidth: int, availHeight: int}|null
     */
    private function desktopChromiumGeometry(mixed $c, TransportIntegrityResult $t): ?array
    {
        if (! self::engineEvidence($c, $t)['chromium']) {
            return null;
        }

        $ua = $this->value($c, 'tier1', 'environment', 'identity', 'userAgent');
        if (! is_string($ua) || ! in_array(self::uaOsFamily($ua), ['windows', 'macos', 'linux'], true)
            || $this->value($c, 'tier1', 'environment', 'identity', 'maxTouchPoints') !== 0) {
            return null;
        }

        $g = [];
        foreach ([
            'innerWidth' => ['viewport', 'innerWidth'], 'innerHeight' => ['viewport', 'innerHeight'],
            'outerWidth' => ['viewport', 'outerWidth'], 'outerHeight' => ['viewport', 'outerHeight'],
            'screenWidth' => ['screen', 'width'], 'screenHeight' => ['screen', 'height'],
            'availWidth' => ['screen', 'availWidth'], 'availHeight' => ['screen', 'availHeight'],
        ] as $name => [$group, $field]) {
            $value = $this->value($c, 'tier1', 'environment', $group, $field);
            if (! is_int($value) || $value <= 0) {
                return null;
            }
            $g[$name] = $value;
        }

        return $g;
    }

    /**
     * Whether the engine evidence says this is a Gecko browser with no Client Hints (the only
     * browsers that can honestly report resistFingerprinting or Tor) or a Chromium browser
     * (the only one that can honestly report Brave). Shared with
     * the host's `DeviceComponents::untrusted()` so the two never disagree.
     *
     * ## What this evidence is, and what it is not (security review round 4)
     *
     * Most of it is CLIENT-REPORTED. The engine marks and the claimed User-Agent are values
     * the page wrote, so a non-browser HTTP client can send them; the server cannot prove a
     * client is a browser. What the server sees itself is only the request: the User-Agent
     * header, the Client-Hints headers and, where a TLS terminator supplies one, the JA4.
     * The gate is therefore built to make the forgery as expensive as the evidence allows
     * and to let every server-observed fact REFUTE it:
     *
     * - **Gecko needs the complete SpiderMonkey mark set**, not one of them: a global
     *   `InternalError`, own `fileName`/`lineNumber`/`columnNumber` on a fresh Error, and the
     *   `fn@url:line:col` stack format (`at-sign`). Every Firefox and Tor Browser build
     *   produces all of them (tests/Fixtures/fingerprint/engines/firefox*.json, measured
     *   Firefox 155 with and without resistFingerprinting). `engineFromMarks()` still names
     *   the engine from any one mark, which is right for a contradiction rule and wrong for a
     *   gate that buys unlinkability: `internalError: true` alone used to be enough.
     * - **The claimed User-Agent must name Gecko**, and so must the User-Agent HEADER when the
     *   request was analysed (a real Firefox sends the same string in both, measured).
     * - **No Client-Hints header** (`Sec-CH-UA`, `-Mobile`, `-Platform`): only Chromium sends
     *   them, and a Gecko browser never does.
     * - **A JA4 that matches a measured profile of another family refutes it.** A JA4 that
     *   is absent or not in `ja4_profiles` is neutral: that table holds three specific builds
     *   measured on one machine, so requiring a match would take the protection from almost
     *   every honest Firefox and re-create "block one, block all".
     *
     * Residual, stated rather than hidden: a client that replays a complete honest Firefox
     * capture with matching headers, from a network without a contradicting JA4, still
     * passes. Protected visits are therefore kept countable (`FingerprintIngest`: the same
     * cohort key from the same network prefix within the velocity window is logged and
     * stored on the observation), not invisible.
     *
     * @return array{gecko: bool, chromium: bool}
     */
    public static function engineEvidence(mixed $claims, TransportIntegrityResult $transport): array
    {
        $marks = self::read($claims, 'tier1', 'engineIdentity');
        $engine = is_array($marks) ? self::engineFromMarks($marks) : null;
        $userAgent = self::read($claims, 'tier1', 'environment', 'identity', 'userAgent');
        $uaFamily = is_string($userAgent) ? self::uaEngineFamily($userAgent) : null;
        $headerUserAgent = $transport->witnessString('user_agent');
        $headerFamily = $headerUserAgent === null ? null : self::uaEngineFamily($headerUserAgent);
        $ja4Family = self::ja4Family($transport);

        $hasClientHints = false;
        foreach (['sec_ch_ua', 'sec_ch_ua_mobile', 'sec_ch_ua_platform'] as $witness) {
            $header = $transport->witnessString($witness);
            if (is_string($header) && trim($header) !== '') {
                $hasClientHints = true;
            }
        }

        return [
            'gecko' => $engine === 'gecko'
                && is_array($marks) && self::hasCompleteSpiderMonkeyMarks($marks)
                && $uaFamily === 'gecko'
                && ($headerUserAgent === null || $headerFamily === 'gecko')
                && ! $hasClientHints
                && ($ja4Family === null || $ja4Family === 'gecko'),
            'chromium' => $engine === 'chromium' && $uaFamily === 'chromium'
                && ($ja4Family === null || $ja4Family === 'chromium'),
        ];
    }

    /**
     * Every SpiderMonkey engine mark at once: the global `InternalError`, the three own
     * properties a fresh Error carries only there, and the `fn@url:line:col` stack format.
     *
     * @param  array<array-key, mixed>  $marks
     */
    public static function hasCompleteSpiderMonkeyMarks(array $marks): bool
    {
        if (($marks['internalError'] ?? null) !== true || ($marks['stackShape'] ?? null) !== 'at-sign') {
            return false;
        }

        $own = is_string($marks['errorOwnProps'] ?? null) ? strtolower($marks['errorOwnProps']) : '';
        $props = array_map('trim', explode(',', $own));

        return in_array('filename', $props, true)
            && in_array('linenumber', $props, true)
            && in_array('columnnumber', $props, true);
    }

    /**
     * The engine family of the request's JA4 when it is a measured profile
     * (`security.transport_integrity.ja4_profiles`), else null: an unknown or absent JA4 is
     * no evidence either way.
     */
    private static function ja4Family(TransportIntegrityResult $transport): ?string
    {
        $correlator = $transport->witnessString('ja4');
        if ($correlator === null) {
            return null;
        }

        $profiles = Config::raw('transport_integrity.ja4_profiles', []);
        $family = is_array($profiles) ? ($profiles[$correlator] ?? null) : null;

        return is_string($family) ? $family : null;
    }

    /**
     * A Gecko browser under resistFingerprinting or Tor, by its own report AND the engine
     * evidence (`engineEvidence()`: complete SpiderMonkey marks, a Gecko User-Agent in the
     * claims and in the header, no Client-Hints header, no contradicting JA4 profile). The
     * ONE definition of the gate: such a browser's font set and screen are the protection's,
     * so the font-against-OS rule is silenced for it (anti-fraud review; `lied_os` is not,
     * see that rule), and `DeviceComponents` uses the same gate for the per-component trust
     * projection and for protected (unlinkable) key sets.
     */
    public static function protectedGecko(mixed $claims, TransportIntegrityResult $transport = new TransportIntegrityResult): bool
    {
        return self::claimsGeckoProtection($claims) && self::engineEvidence($claims, $transport)['gecko'];
    }

    /**
     * Brave with its shields, by the client's `brave` report AND engine evidence a flag alone
     * cannot supply: the Chromium engine marks and a Chromium User-Agent
     * (`engineEvidence()['chromium']`), and Brave's own brand in `userAgentData.brands` and, when
     * the request carries Client Hints, in the `Sec-CH-UA` header (Brave lists a `Brave` brand
     * in both; documented by Brave, not measured in this repository, which has no Brave build).
     *
     * It was the flag plus `engineEvidence()['chromium']`, which every Chrome satisfies, so one
     * client-reported bit nulled eleven components and silenced four rules (skeptical review
     * M1). A JavaScript spoofer cannot rewrite the header; a non-browser client that forges
     * both still gains only what not sending those probes would give it.
     */
    public static function protectedBrave(mixed $claims, TransportIntegrityResult $transport = new TransportIntegrityResult): bool
    {
        if (self::read($claims, 'integrity', 'data', 'resistance', 'brave') !== true || ! self::engineEvidence($claims, $transport)['chromium']) {
            return false;
        }

        $brands = self::read($claims, 'tier1', 'uaClientHints', 'brands');
        $namesBrave = false;
        foreach (is_array($brands) ? $brands : [] as $brand) {
            $name = is_array($brand) ? ($brand['brand'] ?? null) : $brand;
            if (is_string($name) && strtolower(trim($name)) === 'brave') {
                $namesBrave = true;
            }
        }
        if (! $namesBrave) {
            return false;
        }

        $header = $transport->witnessString('sec_ch_ua');
        if ($header === null || trim($header) === '') {
            // No Client Hints on this request (an http origin, a host without Accept-CH): the
            // brands are the only witness.
            return true;
        }

        return preg_match('/(^|,)\s*"Brave"\s*;\s*v=/i', $header) === 1;
    }

    /**
     * The client's own `rfp`/`tor` report, without the evidence check. Only meaningful
     * together with `engineEvidence()['gecko']`; see `protectedGecko()`.
     */
    public static function claimsGeckoProtection(mixed $claims): bool
    {
        return self::read($claims, 'integrity', 'data', 'resistance', 'rfp') === true
            || self::read($claims, 'integrity', 'data', 'resistance', 'tor') === true;
    }

    /**
     * A rule comparing the page's and the worker's snapshot on the given fields; the
     * detail names the differing fields and never their values.
     *
     * @param  list<string>  $fields
     * @return \Closure(mixed, TransportIntegrityResult): ?string
     */
    private function workerRule(array $fields): \Closure
    {
        return function (mixed $c, TransportIntegrityResult $t) use ($fields): ?string {
            $differing = $this->workerDisagreements($c, $fields);

            return $differing === []
                ? null
                : 'The worker realm disagrees with the page about: '.implode(', ', $differing).'.';
        };
    }

    /**
     * Snapshot fields on which the page and its dedicated worker disagree, by name.
     *
     * A field counts only when BOTH realms reported a non-null value: a worker that could
     * not create a WebGL context, or a page without `userAgentData`, is silence for that
     * field, not disagreement.
     *
     * @param  list<string>  $fields
     * @return list<string>
     */
    private function workerDisagreements(mixed $claims, array $fields): array
    {
        $window = $this->value($claims, 'tier2', 'workerScope', 'window');
        $worker = $this->value($claims, 'tier2', 'workerScope', 'worker');

        if (! is_array($window) || ! is_array($worker)) {
            return [];
        }

        $differing = [];
        foreach ($fields as $field) {
            $a = $window[$field] ?? null;
            $b = $worker[$field] ?? null;

            if ($a === null || $b === null) {
                continue;
            }

            // Scalars only: a snapshot field is a string, number or boolean by contract,
            // and a hostile body that nests an array here must not become a comparison.
            if (! is_scalar($a) || ! is_scalar($b)) {
                continue;
            }

            // The engine label `unknown` is "could not classify" (a page that set
            // `Error.stackTraceLimit = 0` loses its stack marks), not a value; comparing it
            // scored 30 against a non-answer (sceptical review).
            if ($field === 'engine' && ($a === 'unknown' || $b === 'unknown')) {
                continue;
            }

            if ($a !== $b) {
                $differing[] = $field;
            }
        }

        return $differing;
    }

    // -----------------------------------------------------------------------
    // Reading claims
    // -----------------------------------------------------------------------

    /**
     * A claim's value at a logical path, or null. The `{state, value}` probe envelope is
     * unwrapped at every step, and a non-`ok` envelope reads as null, so a rule cannot
     * tell "returned null" from "never ran" and cannot treat absence as evidence.
     *
     * @param  mixed  $claims  any node of the claim tree; the walk is defensive
     */
    public function value(mixed $claims, string ...$path): mixed
    {
        return self::read($claims, ...$path);
    }

    /**
     * The static form of {@see value()}, for readers outside the rule engine.
     */
    public static function read(mixed $claims, string ...$path): mixed
    {
        $cursor = $claims;

        foreach ($path as $segment) {
            $cursor = self::unwrapProbe($cursor);

            if (! is_array($cursor) || ! array_key_exists($segment, $cursor)) {
                return null;
            }

            $cursor = $cursor[$segment];
        }

        return self::unwrapProbe($cursor);
    }

    /**
     * Unwrap a probe envelope, or pass the value through (ProbeEnvelope: the one reader
     * of the wire format, shared with the key deriver and the confidence scorer).
     */
    private static function unwrapProbe(mixed $node): mixed
    {
        return ProbeEnvelope::unwrap($node);
    }

    /**
     * Lift one integrity finding into the contradiction list, by code only: the client's own
     * finding united with what the server derives from the client's integrity DATA
     * (`IntegrityFindings::effective()`, notes/24 F10), so a client that drops a finding
     * while sending its tell-tale data still produces it. The client's `detail` is
     * attacker-controlled free text that reaches an admin panel, so the server writes its own
     * sentence, which says where the finding came from.
     */
    private function fromIntegrity(mixed $claims, string $code): ?string
    {
        if (! is_array($claims)) {
            return null;
        }

        return match ($this->effectiveFindings($claims)[$code] ?? null) {
            IntegrityFindings::PROVENANCE_CLIENT => sprintf('The client reported "%s" in its own conformance probes.', $code),
            IntegrityFindings::PROVENANCE_BOTH => sprintf('The client reported "%s" in its own conformance probes, and its integrity data shows it too.', $code),
            IntegrityFindings::PROVENANCE_SERVER => sprintf('The client\'s own integrity data shows "%s", which the client did not report.', $code),
            default => null,
        };
    }

    /**
     * `IntegrityFindings::effective()` for this claim set, computed once per claim set rather
     * than once per rule: about twenty rules ask, and each computation costs roughly as much
     * as a few rules (measured 14-15 µs against a 154-188 µs `contradictions()` call on the
     * engine fixtures in round 4; an earlier 0.57-of-1.27 ms figure did not reproduce, and
     * both are machine-specific). Keyed on the claims
     * array itself (`===`; the rules receive the same array, which PHP compares by pointer
     * before contents), so a different claim set is never served a stale answer and the
     * engine stays a pure function of its arguments.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array<string, string>
     */
    private function effectiveFindings(array $claims): array
    {
        if ($this->effectiveMemo !== null && $this->effectiveMemo['claims'] === $claims) {
            return $this->effectiveMemo['effective'];
        }

        $effective = IntegrityFindings::effective($claims);
        $this->effectiveMemo = ['claims' => $claims, 'effective' => $effective];

        return $effective;
    }

    /**
     * Whether the page's and the worker's `gpuMath` render both exist, ran at the same shader
     * precision, and differ. Shared with `DeviceComponents::untrusted()`: a page whose
     * read-back disagrees with its worker's does not offer a trustworthy `gpuMath` hash.
     */
    public static function gpuRealmsDisagree(mixed $claims): bool
    {
        $page = self::read($claims, 'tier2', 'workerScope', 'window', 'gpuMathHash');
        $worker = self::read($claims, 'tier2', 'workerScope', 'worker', 'gpuMathHash');
        $pagePrecision = self::read($claims, 'tier2', 'workerScope', 'window', 'gpuMathPrecision');
        $workerPrecision = self::read($claims, 'tier2', 'workerScope', 'worker', 'gpuMathPrecision');

        return is_string($page) && is_string($worker) && $page !== '' && $worker !== '' && $page !== $worker
            && is_string($pagePrecision) && $pagePrecision !== '' && $pagePrecision === $workerPrecision;
    }

    /**
     * A numeric client-hint header value ("8", "1.5"; quotes tolerated), or null.
     */
    private static function numericHeader(?string $header): ?float
    {
        if ($header === null) {
            return null;
        }

        $value = trim($header, "\" \t");

        return is_numeric($value) ? (float) $value : null;
    }

    /**
     * Whether a JavaScript client-hint string and the header carrying the same hint are both
     * present and differ. The header is an RFC 8941 string (`"64"`), so quotes and blanks are
     * stripped from it; the claim is compared exactly.
     */
    private static function hintStringsDiffer(mixed $claimed, ?string $header): bool
    {
        if (! is_string($claimed) || $header === null) {
            return false;
        }

        return $claimed !== trim($header, "\" \t");
    }

    /**
     * The major version of the `Chromium` entry of a `fullVersionList`, or null when the list
     * has no such entry (not Chromium, or a hostile body).
     */
    private static function chromiumMajorFromVersionList(mixed $list): ?int
    {
        if (! is_array($list)) {
            return null;
        }

        foreach ($list as $entry) {
            if (is_array($entry) && ($entry['brand'] ?? null) === 'Chromium' && is_string($entry['version'] ?? null)
                && preg_match('/^(\d+)/', $entry['version'], $m) === 1) {
                return (int) $m[1];
            }
        }

        return null;
    }

    private function majorFromUserAgent(string $userAgent): ?int
    {
        // Ordered most-specific first: Chrome's token also appears in Edge's and
        // Opera's strings, so testing those first reads an Edge request as Edge rather
        // than as the Chrome underneath it.
        //
        // `Version/` is LAST, and it used to be fourth. That ordering put every Android
        // WebView in band `challenge`:
        //
        //     Mozilla/5.0 (Linux; Android 14; …; wv) AppleWebKit/537.36 (KHTML, like Gecko)
        //       Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36
        //                                  ^^^^^^^^^^ matched first, giving major 4
        //
        // `Version/4.0` is a legacy WebView placeholder, not a browser version. It is
        // present in every Android in-app browser — Facebook, Instagram, Gmail,
        // WhatsApp — so the rule (weight 25, i.e. score 44 and out of `pass` on its
        // own) fired on that entire population while the real Chromium major sat
        // further down the same string.
        //
        // Last is correct, not merely better: Safari's `Version/18.5 Safari/605.1.15`
        // carries no `Chrome/`, `CriOS/`, `FxiOS/`, `Firefox/` or `OPR/` token at all,
        // so it is still the only pattern that can match it. `Version/` is the
        // Safari-only token, and treating it as a general fallback is what broke the
        // WebViews.
        foreach ([
            '/Edg(?:e|A|iOS)?\/(\d+)/',
            '/OPR\/(\d+)/',
            '/Firefox\/(\d+)/',
            '/Chrome\/(\d+)/',
            '/CriOS\/(\d+)/',
            '/FxiOS\/(\d+)/',
            '/Version\/(\d+)/',
        ] as $pattern) {
            if (preg_match($pattern, $userAgent, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return null;
    }

    /**
     * A Client-Hints brand, reduced to a comparable form, or '' when it is not one.
     *
     * The GREASE brand is dropped, and the reason matters: the spec plants a deliberately
     * fake brand in the list, and *which* fake brand appears, and where in the order, is
     * not a fact about the engine. Comparing it would compare noise, and a noise
     * comparison that fires is a false positive.
     *
     * The pattern is deliberately loose about the separator because the measured spellings
     * differ between sources: the header carries `Not_A Brand` and the page carries
     * `Not A Brand`. If only the exact form were matched, the one browser family that
     * sends this header would fail to match its own header — a guaranteed false positive
     * on every honest Chromium request, which is the worst possible failure mode for a
     * rule like this one.
     */
    private function normaliseBrand(string $name): string
    {
        $name = strtolower(trim($name));
        if ($name === '') {
            return '';
        }

        // `Not_A Brand`, `Not A Brand`, `Not)A;Brand` — the GREASE brand under the
        // spellings Chromium has shipped.
        if (str_contains($name, 'not') && str_contains($name, 'brand')) {
            return '';
        }

        return preg_replace('/[^a-z0-9]+/', '', $name) ?? '';
    }

    /**
     * The engine family the JavaScript object model belongs to, from the raw marks the
     * `engineIdentity` probe sends, or null when they identify none.
     *
     * The marks are facts about a freshly constructed `Error`: SpiderMonkey gives it own
     * `fileName`/`lineNumber`/`columnNumber` properties (and is the only engine with a
     * global `InternalError`); JavaScriptCore gives it own `line`/`column`/`sourceURL`;
     * V8 gives it only `stack` and `message`, and formats stack frames as `    at …`.
     * Returned in `uaEngineFamily()`'s vocabulary so the two can be compared directly.
     *
     * @param  array<array-key, mixed>  $marks
     */
    public static function engineFromMarks(array $marks): ?string
    {
        $own = is_string($marks['errorOwnProps'] ?? null) ? strtolower($marks['errorOwnProps']) : '';
        $props = array_filter(array_map('trim', explode(',', $own)), static fn (string $p): bool => $p !== '');
        $stackShape = is_string($marks['stackShape'] ?? null) ? $marks['stackShape'] : '';
        $internalError = ($marks['internalError'] ?? null) === true;

        if ($internalError || in_array('linenumber', $props, true) || in_array('columnnumber', $props, true) || in_array('filename', $props, true)) {
            return 'gecko';
        }

        if (in_array('sourceurl', $props, true) || (in_array('line', $props, true) && in_array('column', $props, true))) {
            return 'webkit';
        }

        if ($stackShape === 'at' && in_array('stack', $props, true)) {
            return 'chromium';
        }

        return null;
    }

    /**
     * The ENGINE version a User-Agent claims, as `[column, major]` where the column is the
     * `FeatureShipVersions` browser key, or null when the string names none.
     *
     * Not `majorFromUserAgent()`: that returns the BROWSER's major (Edge 141, Opera 120),
     * which is the right thing to compare with a Client-Hints version list and the wrong
     * thing to compare with an engine feature table — Opera 120 runs Chromium 134, and
     * its `Chrome/134` token is the engine version. iOS browsers (`CriOS/`, `FxiOS/`,
     * `EdgiOS/`) are WebKit at the iOS version, which the UA does not carry as a Safari
     * major, so they are silence.
     *
     * @return array{0: 'chrome'|'firefox'|'safari', 1: int}|null
     */
    public static function engineVersionFromUserAgent(string $userAgent): ?array
    {
        if (str_contains($userAgent, 'CriOS/') || str_contains($userAgent, 'FxiOS/') || str_contains($userAgent, 'EdgiOS/')) {
            return null;
        }

        if (preg_match('/Firefox\/(\d+)/', $userAgent, $m) === 1) {
            return ['firefox', (int) $m[1]];
        }

        if (preg_match('/Chrome\/(\d+)/', $userAgent, $m) === 1) {
            return ['chrome', (int) $m[1]];
        }

        if (str_contains($userAgent, 'Safari/') && preg_match('/Version\/(\d+)/', $userAgent, $m) === 1) {
            return ['safari', (int) $m[1]];
        }

        return null;
    }

    /**
     * The engine a User-Agent claims, as a family name.
     *
     * Returned rather than a boolean because "this UA does not name a known engine" is a
     * different fact from "this UA names an engine that contradicts the fingerprint", and
     * only the second is a finding.
     */
    public static function uaEngineFamily(string $userAgent): ?string
    {
        // Ordered most specific first, because Edge and Opera both carry `Chrome/` and a
        // Chrome user also carries `Safari/`.
        foreach ([
            'Firefox/' => 'gecko',
            'Edg/' => 'chromium',
            'OPR/' => 'chromium',
            'Chrome/' => 'chromium',
            'CriOS/' => 'webkit',
            'Version/' => 'webkit',
        ] as $token => $family) {
            if (str_contains($userAgent, $token)) {
                return $family;
            }
        }

        return null;
    }

    /**
     * Bit positions in the client's `cssMedia` string (value-probes.ts `cssMedia()`):
     * `(any-pointer: coarse)` and `(pointer: coarse)`.
     */
    private const CSS_ANY_POINTER_COARSE = 6;

    private const CSS_POINTER_COARSE = 22;

    private const CSS_MIN_LENGTH = 23;

    /**
     * Whether `cssMedia` reports a coarse pointer (either query). Null when unknown.
     */
    public static function coarsePointer(mixed $cssMedia): ?bool
    {
        if (! is_string($cssMedia) || strlen($cssMedia) < self::CSS_MIN_LENGTH) {
            return null;
        }

        $any = $cssMedia[self::CSS_ANY_POINTER_COARSE];
        $primary = $cssMedia[self::CSS_POINTER_COARSE];

        if (! in_array($any, ['0', '1'], true) || ! in_array($primary, ['0', '1'], true)) {
            return null;
        }

        return $any === '1' || $primary === '1';
    }

    /**
     * A GPU vendor family from a WebGPU vendor string or a WebGL renderer/model string,
     * or null when the string names no known vendor.
     */
    public static function gpuFamily(string $value): ?string
    {
        $needle = strtolower($value);

        return match (true) {
            str_contains($needle, 'swiftshader'), str_contains($needle, 'llvmpipe'), str_contains($needle, 'softpipe') => 'software',
            str_contains($needle, 'nvidia'), str_contains($needle, 'geforce'), str_contains($needle, 'quadro'), str_contains($needle, 'rtx ') => 'nvidia',
            str_contains($needle, 'amd'), str_contains($needle, 'radeon'), str_contains($needle, 'ati ') => 'amd',
            str_contains($needle, 'intel'), str_contains($needle, 'iris'), str_contains($needle, 'uhd graphics') => 'intel',
            str_contains($needle, 'apple') => 'apple',
            str_contains($needle, 'qualcomm'), str_contains($needle, 'adreno') => 'qualcomm',
            str_contains($needle, 'mali'), str_contains($needle, 'arm ') => 'arm',
            str_contains($needle, 'powervr'), str_contains($needle, 'imagination') => 'imagination',
            default => null,
        };
    }

    /**
     * Whether a WebGL renderer string names a software rasteriser (SwiftShader, llvmpipe,
     * softpipe, lavapipe, WARP / Basic Render, Mesa's offscreen paths): the same list the
     * collector's `isSoftwareRenderer` uses, so the server never judges a software context by
     * hardware rules.
     */
    public static function isSoftwareRenderer(mixed $renderer): bool
    {
        return is_string($renderer)
            && preg_match('/swiftshader|llvmpipe|softpipe|lavapipe|\bwarp\b|basic render|software rasterizer|mesa offscreen/i', $renderer) === 1;
    }

    /**
     * The OS families a GPU family cannot coexist with (`gpuPlatformFamily`'s result against
     * `uaOsFamily`/`platformOsFamily`'s). An explicit table so every combination that is left
     * silent is a decision, not an accident:
     *
     * - `apple`: Windows, Android, ChromeOS. NOT Linux: Asahi Linux runs on Apple Silicon and
     *   reports the Apple GPU.
     * - `windows` (Direct3D): macOS, iOS, Android, ChromeOS, and Linux except the Direct3D-backed
     *   Mesa of WSL, whose renderer reads `D3D12 (…)`.
     * - `mobile` (Adreno, Mali, PowerVR): macOS, iOS. Windows-on-ARM, Linux boards, Android and
     *   Chromebooks all ship these.
     * - `linux` (Mesa, X.Org): Windows, macOS, iOS. Android-x86 and Waydroid use Mesa.
     *
     * @return list<string>
     */
    private static function contradictingGpuFamilies(string $gpuFamily, string $renderer): array
    {
        return match ($gpuFamily) {
            'apple' => ['windows', 'android', 'chromeos'],
            'windows' => preg_match('/^\s*d3d12 \(/i', $renderer) === 1
                ? ['macos', 'ios', 'android', 'chromeos']
                : ['macos', 'ios', 'android', 'chromeos', 'linux'],
            'mobile' => ['macos', 'ios'],
            'linux' => ['windows', 'macos', 'ios'],
            default => [],
        };
    }

    /**
     * The OS a WebGL renderer string names, using only unambiguous families.
     *
     * Deliberately not a renderer-model table. `ANGLE (NVIDIA ...)` is intentionally
     * absent because NVIDIA exists on Windows and Linux; the rule that uses this only
     * contradicts families that cannot coexist, such as an Apple GPU on Windows.
     */
    private function gpuPlatformFamily(string $renderer): ?string
    {
        if (preg_match('/apple m|apple gpu|metal renderer|angle metal/i', $renderer) === 1) {
            return 'apple';
        }
        if (preg_match('/direct3d|d3d1[12]/i', $renderer) === 1) {
            return 'windows';
        }
        if (preg_match('/adreno|mali|powervr/i', $renderer) === 1) {
            return 'mobile';
        }
        if (preg_match('/mesa|llvmpipe|lavapipe|x\.org/i', $renderer) === 1) {
            return 'linux';
        }

        return null;
    }

    public static function uaOsFamily(string $userAgent): ?string
    {
        return match (true) {
            str_contains($userAgent, 'Windows') => 'windows',
            str_contains($userAgent, 'Android') => 'android',
            // Checked before Linux, because Android's UA also contains "Linux".
            str_contains($userAgent, 'iPhone'), str_contains($userAgent, 'iPad') => 'ios',
            str_contains($userAgent, 'Mac OS X') => 'macos',
            str_contains($userAgent, 'CrOS') => 'chromeos',
            str_contains($userAgent, 'Linux'), str_contains($userAgent, 'X11') => 'linux',
            default => null,
        };
    }

    /**
     * `navigator.platform` reduced to an OS family. The ARM suffix is matched before the
     * generic `linux` arm because Chromium on Android reports `Linux armv8l` /
     * `Linux aarch64` while Sec-CH-UA-Platform says `Android`.
     */
    private function platformOsFamily(string $platform, bool $androidContext = true): ?string
    {
        $needle = strtolower($platform);

        // Android's deliberately-chosen platform strings, before the generic `linux`
        // arm can claim them. `Linux armv8l` is the one Chromium emits on Android;
        // `Linux aarch64` is what an Android WebView build reports. Read as Android only in
        // an Android context (the default keeps the other callers' behaviour).
        if ($androidContext && preg_match('/\barmv?\d*l?\b|aarch64\b/', $needle) === 1) {
            return 'android';
        }

        return match (true) {
            str_contains($needle, 'win') => 'windows',
            str_contains($needle, 'android') => 'android',
            // "iPhone"/"iPad"/"iPod" before "mac", because "MacIntel" is a real platform
            // string for a desktop Safari and must not be read as iOS.
            str_contains($needle, 'iphone'), str_contains($needle, 'ipad'), str_contains($needle, 'ipod') => 'ios',
            str_contains($needle, 'mac') => 'macos',
            // `navigator.platform` is `CrOS x86_64`; Sec-CH-UA-Platform is `Chrome OS` (with a space).
            str_contains($needle, 'cros'), str_contains($needle, 'chrome os') => 'chromeos',
            str_contains($needle, 'linux'), str_contains($needle, 'x11') => 'linux',
            default => null,
        };
    }

    /**
     * The region a BCP 47 tag implies, or null. Needs ext-intl (declared in composer.json);
     * without it the rule stays silent rather than failing.
     */
    private function likelyRegionFor(string $language): ?string
    {
        if (! class_exists(\Locale::class)) {
            return null;
        }

        $region = \Locale::getRegion($language);

        return ($region === null || $region === '') ? null : $region;
    }
}
