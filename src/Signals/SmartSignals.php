<?php

declare(strict_types=1);

namespace DeviceId\Signals;

use DeviceId\CheckRegistry;
use DeviceId\Model\FeatureCatalogue;
use DeviceId\Network\NetworkFacts;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Support\TransportIntegrityResult;

/**
 * The environment facts behind the "smart signals": locale against the network's country,
 * virtual machines and emulators, and private browsing. Pure functions over a decoded claim set
 * (and, for the first, {@see NetworkFacts}); no I/O, no clock, no state. Each returns FACTS, not
 * a verdict: the weights live in {@see CheckRegistry}, the rules in
 * {@see EnvironmentConsistency}, and the same facts become model features through
 * {@see features()}.
 *
 * ## The common rule: honest-silent, never "guilty by absence"
 *
 * Every function answers `null` or a "not checked" shape when its evidence is missing (no
 * network data, an unlisted time zone, a probe that did not run). A fact that holds is a soft
 * hint; a fact that cannot be checked says nothing.
 */
final class SmartSignals
{
    /** @var array<string, string> region subtags that name the same country as the ISO code */
    private const REGION_ALIASES = ['UK' => 'GB'];

    /**
     * A WebGL renderer or vendor naming a hypervisor's virtual GPU. Real GPUs never carry these
     * tokens; a VDI or developer VM does. "microsoft basic render" (WARP) is NOT here: it is the
     * software fallback of every Windows machine without a driver, honest far more often than not.
     */
    private const HYPERVISOR_GPU = '/vmware|svga3d|vmsvga|virtualbox|\bvbox|parallels|\bqemu|virtio|virgl|\bqxl\b|red hat|hyper-v|bochs|apple paravirtual|vmware/i';

    /** Screen sizes a hypervisor offers before its guest tools set a real one (VirtualBox, VMware, QEMU std VGA). */
    private const VM_SCREENS = ['800x600', '1024x768', '1152x864'];

    private const EMULATOR_UA = '/sdk_gphone|google_sdk|android sdk built for|\bemulator\b|generic_x86|ranchu|goldfish|genymotion|\bvbox86/i';

    private const EMULATOR_GPU = '/android emulator|goldfish|ranchu|genymotion|swiftshader/i';

    // ------------------------------------------------------------------ IP country against locale

    /**
     * How the IP country compares with two INDEPENDENT settings of the browser: the clock's time
     * zone and the language/locale list. Each group is `true` (disagrees), `false` (agrees) or
     * `null` (cannot be checked: no region on the zone or the languages, no network country).
     *
     * Languages are one group however many fields carry them (`language`, `languages`, the Intl
     * locale): an expat with `en-US` everywhere would otherwise "disagree" three times from a
     * single setting. A region anywhere in the list that equals the IP country is agreement, so
     * `['nl-NL', 'en-US']` in the Netherlands, or `['en-US']` in the Netherlands with a
     * Netherlands time zone, never fires.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array{timezone: bool|null, language: bool|null}
     */
    public static function localeAgainstCountry(array $claims, ?NetworkFacts $network): array
    {
        $country = $network?->country;
        if ($country === null) {
            return ['timezone' => null, 'language' => null];
        }

        $zone = EnvironmentConsistency::read($claims, 'tier2', 'intl', 'resolved', 'timeZone');
        $zoneRegion = is_string($zone) ? EnvironmentConsistency::regionOfTimeZone($zone) : null;

        $regions = [];
        $tags = [
            EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'language'),
            EnvironmentConsistency::read($claims, 'tier2', 'intl', 'resolved', 'locale'),
        ];
        $languages = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'languages');
        foreach (is_array($languages) ? array_slice($languages, 0, 8) : [] as $tag) {
            $tags[] = $tag;
        }
        foreach ($tags as $tag) {
            $region = is_string($tag) ? self::regionOfTag($tag) : null;
            if ($region !== null) {
                $regions[$region] = true;
            }
        }

        return [
            'timezone' => $zoneRegion === null ? null : $zoneRegion !== $country,
            'language' => $regions === [] ? null : ! isset($regions[$country]),
        ];
    }

    /**
     * The explicit region subtag of a BCP 47 tag (`nl-NL` gives `NL`), or null. A bare `nl` has
     * no region: guessing one would call a Belgian Dutch speaker a Dutchman.
     */
    public static function regionOfTag(string $tag): ?string
    {
        if (preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z]{4})?[-_]([A-Za-z]{2})(?:[-_@.].*)?$/', $tag, $m) !== 1) {
            return null;
        }
        $region = strtoupper($m[1]);

        return self::REGION_ALIASES[$region] ?? $region;
    }

    // ------------------------------------------------------------------ virtual machines and emulators

    /**
     * @param  array<array-key, mixed>  $claims
     * @return array{desktop: bool, hypervisor_gpu: bool, software_gpu: bool, vm_screen: bool}
     */
    public static function virtualMachine(array $claims): array
    {
        $none = ['desktop' => false, 'hypervisor_gpu' => false, 'software_gpu' => false, 'vm_screen' => false];

        $ua = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'userAgent');
        // A headless UA is judged by the headless rules; a touch device is not a desktop VM.
        if (! is_string($ua) || stripos($ua, 'headless') !== false
            || ! in_array(EnvironmentConsistency::uaOsFamily($ua), ['windows', 'macos', 'linux'], true)
            || EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'maxTouchPoints') !== 0) {
            return $none;
        }

        $renderer = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgl', 'renderer');
        $vendor = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgl', 'vendor');
        $gpuText = (is_string($renderer) ? $renderer : '').' '.(is_string($vendor) ? $vendor : '');

        $width = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'screen', 'width');
        $height = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'screen', 'height');

        return [
            'desktop' => true,
            'hypervisor_gpu' => preg_match(self::HYPERVISOR_GPU, $gpuText) === 1,
            'software_gpu' => EnvironmentConsistency::isSoftwareRenderer($renderer),
            'vm_screen' => is_int($width) && is_int($height) && in_array($width.'x'.$height, self::VM_SCREENS, true),
        ];
    }

    /**
     * An Android emulator: an emulator token in the User-Agent or the client-hint model, or an
     * Android user agent on a software or emulator GPU (no phone ships SwiftShader).
     *
     * @param  array<array-key, mixed>  $claims
     */
    public static function androidEmulator(array $claims): bool
    {
        $ua = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'userAgent');
        if (! is_string($ua) || EnvironmentConsistency::uaOsFamily($ua) !== 'android') {
            return false;
        }
        $model = EnvironmentConsistency::read($claims, 'tier1', 'uaClientHints', 'high', 'model');
        $renderer = EnvironmentConsistency::read($claims, 'tier2', 'gpu', 'webgl', 'renderer');

        return preg_match(self::EMULATOR_UA, $ua.' '.(is_string($model) ? $model : '')) === 1
            || (is_string($renderer) && preg_match(self::EMULATOR_GPU, $renderer) === 1);
    }

    // ------------------------------------------------------------------ private browsing

    /**
     * Whether the storage profile says this is a private-browsing (or storage-restricted) tab.
     *
     * - **Chromium**: the storage quota of an incognito profile is carved out of memory, the
     *   same pool the V8 heap limit scales with, so incognito quota is about the heap limit
     *   (measured on Chromium 153, 16 GB: incognito 3 GiB quota against a 3.5 GiB heap limit;
     *   a normal profile 10 GiB, a ratio of 2.3 to 2.9). Fires when quota is not above the heap
     *   limit (half-octave buckets, so "not above" is a ratio of about 1.0 give or take 41 %).
     *   False positive: a normal profile on a disk that is nearly full, whose quota falls to a
     *   fraction of free space. Confidence `low`; false negative: machines with much more RAM
     *   than the heap cap.
     * - **Gecko**: `navigator.storage.getDirectory()` is rejected with a SecurityError in private
     *   browsing (measured on Firefox 155 with `browser.privatebrowsing.autostart`; accepted in
     *   a normal profile). The same error appears when the visitor blocks all cookies and site
     *   data, which is a storage-restricted mode with the same meaning to a rule. Confidence
     *   `medium`. Not reported for a protected Gecko (resistFingerprinting, Tor), which is a
     *   known privacy mode and not "private browsing".
     * - **WebKit**: a non-persistent website data store rejects `getDirectory()` with an
     *   UnknownError (measured on WebKit 26.6, ephemeral against persistent context). Safari
     *   private tabs use that kind of store, but Safari itself could NOT be measured here, so the
     *   confidence is `low`.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array{likely: bool, engine: string, basis: string, confidence: string}|null null: not checkable
     */
    public static function privateMode(array $claims, TransportIntegrityResult $transport = new TransportIntegrityResult): ?array
    {
        $profile = EnvironmentConsistency::read($claims, 'tier2', 'storageProfile');
        $ua = EnvironmentConsistency::read($claims, 'tier1', 'environment', 'identity', 'userAgent');
        $marks = EnvironmentConsistency::read($claims, 'tier1', 'engineIdentity');
        if (! is_array($profile) || ! is_string($ua) || ! is_array($marks)) {
            return null;
        }

        $engine = EnvironmentConsistency::engineFromMarks($marks);
        $family = EnvironmentConsistency::uaEngineFamily($ua);
        if ($engine === null || $engine !== $family) {
            return null;
        }
        if ($engine === 'gecko' && (EnvironmentConsistency::protectedGecko($claims, $transport) || EnvironmentConsistency::claimsGeckoProtection($claims))) {
            return null;
        }

        $opfs = $profile['opfs'] ?? null;
        $quota = $profile['quotaStep'] ?? null;
        $heap = $profile['heapStep'] ?? null;

        return match ($engine) {
            'gecko' => $opfs === null || $opfs === 'absent' ? null
                : ['likely' => $opfs === 'security', 'engine' => 'gecko', 'basis' => 'opfs_denied', 'confidence' => 'medium'],
            'webkit' => $opfs === null || $opfs === 'absent' ? null
                : ['likely' => $opfs === 'error', 'engine' => 'webkit', 'basis' => 'opfs_denied', 'confidence' => 'low'],
            'chromium' => is_int($quota) && is_int($heap)
                ? ['likely' => $quota - $heap <= 0, 'engine' => 'chromium', 'basis' => 'quota_below_heap', 'confidence' => 'low']
                : null,
            default => null,
        };
    }

    // ------------------------------------------------------------------ model features

    /**
     * The soft model features of one visit ({@see FeatureCatalogue::SIGNALS}); only those that
     * hold. Pass the result, merged with {@see NetworkFacts::features()} and the reputation
     * features, as the `$reputation` argument of the model scorer.
     *
     * @param  array<array-key, mixed>  $claims
     * @return array<string, float>
     */
    public static function features(array $claims, ?NetworkFacts $network = null, TransportIntegrityResult $transport = new TransportIntegrityResult): array
    {
        $vm = self::virtualMachine($claims);
        $locale = self::localeAgainstCountry($claims, $network);
        $private = self::privateMode($claims, $transport);

        $features = [
            'sig_locale_disagreements' => (float) count(array_filter($locale)),
            'sig_vm_gpu' => $vm['hypervisor_gpu'] ? 1.0 : 0.0,
            'sig_vm_screen' => $vm['vm_screen'] ? 1.0 : 0.0,
            'sig_software_gpu' => $vm['software_gpu'] ? 1.0 : 0.0,
            'sig_emulator' => self::androidEmulator($claims) ? 1.0 : 0.0,
            'sig_private_mode' => $private === null || ! $private['likely'] ? 0.0 : ($private['confidence'] === 'medium' ? 1.0 : 0.5),
        ];

        return array_filter($features, static fn (float $v): bool => $v > 0.0);
    }
}
