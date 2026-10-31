<?php

declare(strict_types=1);

namespace DeviceId\Crawlers;

/**
 * The known crawlers and uptime monitors, in match order (the first definition whose token appears
 * in the User-Agent wins).
 *
 * ## Extending it
 *
 * `default()->with(new CrawlerDefinition(...))` adds or replaces one entry; `fromArray()` builds a
 * catalogue from host configuration (the same shape NutriCompare's `antiscraping.crawlers` has).
 * Nothing is added by inference: an entry exists because the vendor documents how to recognise it.
 *
 * ## Sources (retrieved 2026-10-31 unless noted; re-check before relying on a URL)
 *
 * Crawlers: developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests (Google's
 * three classes: common crawlers `crawl-*.googlebot.com` / `geo-crawl-*.geo.googlebot.com` with
 * common-crawlers.json; special-case crawlers `rate-limited-proxy-*.google.com` with
 * special-crawlers.json; user-triggered fetchers, see below), blogs.bing.com (Bingbot,
 * `search.msn.com`, bing.com/toolbox/bingbot.json), support.apple.com/119829 (Applebot,
 * `applebot.apple.com`), yandex.com/support/webmaster (`yandex.ru|net|com`), Baidu webmaster docs
 * (`baidu.com|baidu.jp`). DuckDuckGo documents an IP list on an HTML help page only, and no reverse
 * DNS, so DuckDuckBot is recognised but config-only. Range URLs must be the final URL: the hosts'
 * fetchers refuse redirects (Google moved its lists from /static/search/apis/ipranges/ to
 * /static/crawling/ipranges/, and Perplexity from perplexity.com to perplexity.ai; both old URLs
 * answer 3xx).
 *
 * ## Only crawlers are crawlers
 *
 * A verified crawler skips the host's captcha, fingerprint and throttles, so only traffic the vendor
 * itself originates and documents as a crawler may verify. USER-TRIGGERED fetchers are excluded,
 * both their User-Agent tokens and their IP lists: Google's `user-triggered-fetchers.json` is App
 * Engine egress (`*.gae.googleusercontent.com`) that any Google Cloud customer's site sends on behalf
 * of its users, `user-triggered-fetchers-google.json` resolves to `google-proxy-*.google.com`, and
 * ChatGPT-User, Claude-User and Perplexity-User fetch whatever a user asks. Such a request is
 * ordinary traffic. For that reason `google.com` is accepted only as the special-case crawler
 * pattern, never as a suffix.
 *
 * `googleusercontent.com` is deliberately NOT a suffix here: Compute Engine hands every customer VM a
 * PTR under `*.bc.googleusercontent.com` that forward-confirms, so it would verify any rented VM as
 * Google.
 *
 * Anthropic publishes one list (claude.com/crawling/bots.json) for its bots without saying which bot
 * uses which prefix; whether Claude-User shares it is UNKNOWN, so a ClaudeBot claim from a Claude-User
 * address may verify. The same holds for OpenAI's GPTBot vs OAI-SearchBot lists (both crawlers).
 *
 * Uptime monitors are provable ONLY by the provider's published IP list. A User-Agent alone is
 * spoofable and never sufficient. Official list URLs, as documented by each provider:
 *  - UptimeRobot: cdn.uptimerobot.com/api/IPv4andIPv6.txt (uptimerobot.com/help/locations/)
 *  - Pingdom: my.pingdom.com/probes/ipv4 and /ipv6 (SolarWinds Pingdom docs, "Probe servers IP addresses")
 *  - Better Stack: incidents.betterstack.com/ips.txt (betterstack.com/docs/uptime/frequently-asked-questions;
 *    the provider itself warns the IPs change without notice, hence the cache keeps the last good list)
 *  - StatusCake: app.statuscake.com/Workfloor/Locations.php?format=txt (statuscake.com/kb/?p=37)
 *  - Oh Dear: ohdear.app/used-ips (ohdear.app/docs/faq/what-ips-does-oh-dear-monitor-from)
 *  - Checkly: api.checklyhq.com/v1/static-ips.txt and static-ipv6s.txt (checklyhq.com/docs/monitoring/allowlisting)
 *  - Datadog Synthetics: ip-ranges.datadoghq.com, JSON `synthetics.prefixes_ipv4|ipv6` (US1 site;
 *    other Datadog sites have their own `ip-ranges.<site>` host, set it in configuration)
 *  - HetrixTools: hetrixtools.com/resources/uptime-monitor-only-ips.txt (docs.hetrixtools.com/uptime-monitoring-nodes)
 * Config-only (no official machine-readable list found): Site24x7 (its list is a download from an HTML
 * page with no stable direct URL; it also publishes a DNS name, `site24x7.enduserexp.com`, which this
 * package does not resolve), Freshping (nothing found). Operators enter their CIDRs in the allowlist.
 */
final class CrawlerCatalogue
{
    /** @var array<string, CrawlerDefinition> */
    private array $definitions = [];

    /**
     * @param  list<CrawlerDefinition>  $definitions
     */
    public function __construct(array $definitions = [])
    {
        foreach ($definitions as $definition) {
            $this->definitions[$definition->key] = $definition;
        }
    }

    /**
     * @param  array<array-key, mixed>  $config  key => definition array
     */
    public static function fromArray(array $config): self
    {
        $definitions = [];
        foreach ($config as $key => $data) {
            if (is_string($key) && $key !== '' && is_array($data)) {
                $definitions[] = CrawlerDefinition::fromArray($key, $data);
            }
        }

        return new self($definitions);
    }

    public static function default(): self
    {
        return new self([...self::defaultCrawlers(), ...self::defaultMonitors()]);
    }

    public function with(CrawlerDefinition $definition): self
    {
        $copy = clone $this;
        $copy->definitions[$definition->key] = $definition;

        return $copy;
    }

    public function get(string $key): ?CrawlerDefinition
    {
        return $this->definitions[$key] ?? null;
    }

    /**
     * @return array<string, CrawlerDefinition>
     */
    public function all(): array
    {
        return $this->definitions;
    }

    /**
     * @return list<string>
     */
    public function monitorKeys(): array
    {
        return array_keys(array_filter($this->definitions, static fn (CrawlerDefinition $d): bool => $d->isMonitor()));
    }

    /** The crawler key a User-Agent claims, or null. Monitors are not crawlers. */
    public function crawlerClaimFor(?string $userAgent): ?string
    {
        return $this->claimOfKind($userAgent, CrawlerDefinition::KIND_CRAWLER);
    }

    /** The monitor key a User-Agent claims, or null. Only a claim: never proof. */
    public function monitorClaimFor(?string $userAgent): ?string
    {
        return $this->claimOfKind($userAgent, CrawlerDefinition::KIND_MONITOR);
    }

    private function claimOfKind(?string $userAgent, string $kind): ?string
    {
        if ($userAgent === null || trim($userAgent) === '') {
            return null;
        }

        $haystack = strtolower($userAgent);
        foreach ($this->definitions as $definition) {
            if ($definition->kind === $kind && $definition->claimedBy($haystack)) {
                return $definition->key;
            }
        }

        return null;
    }

    /**
     * @return list<CrawlerDefinition>
     */
    public static function defaultCrawlers(): array
    {
        $google = 'https://developers.google.com/static/crawling/ipranges/';

        return [
            new CrawlerDefinition(
                'googlebot',
                'Google',
                CrawlerDefinition::KIND_CRAWLER,
                [
                    // Common crawlers, then special-case crawlers. No user-triggered fetcher tokens
                    // (Feedfetcher, Google-Read-Aloud, Google-Site-Verification, GoogleProducer).
                    'googlebot', 'googleother', 'storebot-google', 'google-inspectiontool', 'google-cloudvertexbot',
                    'google-extended', 'apis-google', 'adsbot-google', 'mediapartners-google', 'google-safety',
                ],
                ['crawl-*.googlebot.com', 'geo-crawl-*.geo.googlebot.com', 'rate-limited-proxy-*.google.com'],
                [$google.'common-crawlers.json', $google.'special-crawlers.json'],
            ),
            new CrawlerDefinition(
                'bingbot',
                'Bing',
                CrawlerDefinition::KIND_CRAWLER,
                ['bingbot', 'adidxbot', 'bingpreview', 'msnbot'],
                ['search.msn.com'],
                ['https://www.bing.com/toolbox/bingbot.json'],
            ),
            new CrawlerDefinition(
                'applebot',
                'Apple',
                CrawlerDefinition::KIND_CRAWLER,
                ['applebot'],
                ['applebot.apple.com'],
                ['https://search.developer.apple.com/applebot.json'],
            ),
            new CrawlerDefinition(
                'duckduckbot',
                'DuckDuckGo',
                CrawlerDefinition::KIND_CRAWLER,
                ['duckduckbot'],
            ),
            new CrawlerDefinition(
                'yandex',
                'Yandex',
                CrawlerDefinition::KIND_CRAWLER,
                ['yandexbot', 'yandexmobilebot', 'yandeximages', 'yandexvideo', 'yandexmedia', 'yandexwebmaster', 'yandexpagechecker', 'yandexturbo'],
                ['yandex.ru', 'yandex.net', 'yandex.com'],
            ),
            new CrawlerDefinition(
                'baiduspider',
                'Baidu',
                CrawlerDefinition::KIND_CRAWLER,
                ['baiduspider'],
                ['baidu.com', 'baidu.jp'],
            ),
            new CrawlerDefinition('openai', 'OpenAI', CrawlerDefinition::KIND_CRAWLER, ['gptbot', 'oai-searchbot'], [], [
                'https://openai.com/gptbot.json', 'https://openai.com/searchbot.json',
            ]),
            new CrawlerDefinition('anthropic', 'Anthropic', CrawlerDefinition::KIND_CRAWLER, ['claudebot', 'claude-searchbot'], [], ['https://claude.com/crawling/bots.json']),
            new CrawlerDefinition('perplexity', 'Perplexity', CrawlerDefinition::KIND_CRAWLER, ['perplexitybot'], [], ['https://www.perplexity.ai/perplexitybot.json']),
        ];
    }

    /**
     * @return list<CrawlerDefinition>
     */
    public static function defaultMonitors(): array
    {
        $monitor = static fn (string $key, string $label, array $tokens, array $urls = [], array $paths = []): CrawlerDefinition => new CrawlerDefinition(
            $key, $label, CrawlerDefinition::KIND_MONITOR, $tokens, [], $urls, $paths,
        );

        return [
            $monitor('uptimerobot', 'UptimeRobot', ['uptimerobot'], ['https://cdn.uptimerobot.com/api/IPv4andIPv6.txt']),
            $monitor('pingdom', 'Pingdom', ['pingdom'], ['https://my.pingdom.com/probes/ipv4', 'https://my.pingdom.com/probes/ipv6']),
            $monitor('betterstack', 'Better Stack (Better Uptime)', ['betteruptime', 'better stack', 'betterstack'], ['https://incidents.betterstack.com/ips.txt']),
            $monitor('statuscake', 'StatusCake', ['statuscake'], ['https://app.statuscake.com/Workfloor/Locations.php?format=txt']),
            $monitor('ohdear', 'Oh Dear', ['ohdear', 'oh dear'], ['https://ohdear.app/used-ips']),
            $monitor('site24x7', 'Site24x7', ['site24x7']),
            $monitor('freshping', 'Freshping', ['freshping']),
            $monitor('checkly', 'Checkly', ['checkly'], ['https://api.checklyhq.com/v1/static-ips.txt', 'https://api.checklyhq.com/v1/static-ipv6s.txt']),
            $monitor('datadog_synthetics', 'Datadog Synthetics', ['datadogsynthetics', 'datadog/synthetics'], ['https://ip-ranges.datadoghq.com/'], ['synthetics.prefixes_ipv4', 'synthetics.prefixes_ipv6']),
            $monitor('hetrixtools', 'HetrixTools', ['hetrixtools'], ['https://hetrixtools.com/resources/uptime-monitor-only-ips.txt']),
        ];
    }
}
