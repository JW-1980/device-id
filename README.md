# `jw-1980/device-id`

Device fingerprinting for PHP: the server-side engine that turns a browser collector's claims
into a **keyed device key**, a **risk verdict** (score + band + reasons) and a **confidence**
number (1–100: how much of the expected measurement surface answered). Framework-free: plain
PHP 8.2+, no Laravel, no Symfony, no PSR-7.

This repository is the **single place the engine is developed**. Applications install it with
Composer; they never copy it. Current consumers: NutriCompare and WelZoLekker.

The PHP namespace is `DeviceId\` (PSR-4 root `src/`).

## Installing it in an application (private, not on Packagist)

The package is **not** published on Packagist and this repository is private, so nobody outside
the account can download it. An application adds this repository as a Composer `vcs` source:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/JW-1980/device-id.git", "no-api": true }
    ],
    "require": {
        "jw-1980/device-id": "^1.0"
    }
}
```

```bash
composer update jw-1980/device-id
```

Composer then needs **read access to this repository**:

- **Developer machine:** a GitHub account with access (git credentials), or
  `composer config --global github-oauth.github.com <token>`.
- **CI / deployment:** a fine-grained personal access token limited to this one repository with
  only *Contents: read*, passed as
  `COMPOSER_AUTH='{"github-oauth":{"github.com":"<token>"}}'` (in GitHub Actions: a repository
  secret, e.g. `DEVICE_ID_READ_TOKEN`, see NutriCompare's `.github/workflows/ci.yml`).

### Releasing a new version

1. Change the engine here, with tests (`composer gates`: standalone proof, golden values, demo,
   PHPUnit). A rule change that changes a golden answer updates `tools/golden-check.php` in the
   same commit.
2. Merge, then tag a semantic version: `git tag v1.1.0 && git push origin v1.1.0`. A change that
   alters the public API or what a consumer must configure is a new MAJOR version.
3. In each application: `composer update jw-1980/device-id`, run its fingerprint tests, commit
   the `composer.lock` change.

## Per-application configuration

The engine reads everything through `Support\Config` (`Config::use()` with an array, or
`Config::resolveWith()` with a live resolver). Two settings are worth knowing:

| Key | Purpose |
|---|---|
| `fingerprint.constraint_weights` | Rule weights over the shipped table. A weight of 0 silences a rule. Every shipped rule is on by default, including `renderer_vs_limits` (WebGL limits below the published spec minima, 12) and `ch_platform_vs_gpu` (a GPU family impossible on the claimed OS, 10). |
| `fingerprint.confidence_probes` | An optional probe catalogue for the confidence number: `'tier:probe' => ['weight' => int, 'charge' => float]`. When set it **replaces** the shipped list. The shipped list is exactly the probe set of the one collector in this package (`tests/Unit/ProbeSetTest` keeps them equal), so a host needs no override; it exists for a host that ships a modified collector. |

### Device-hint request headers (the host sends `Accept-CH`)

Five rules compare what the page claims with a header the browser put on the wire, which a
JavaScript spoof cannot change: `device_memory_vs_ch` (15), `ch_bitness_vs_js` (15),
`ch_model_vs_js` (15), `dpr_vs_ch` (8) and `viewport_vs_ch` (6). The engine already reads the
witnesses; **the host has to ask the browser for them**, because a Chromium browser sends a
high-entropy hint only after a response named it in `Accept-CH`. Send this on the HTML document
responses of every page that runs the collector (HTTPS or localhost only):

```
Accept-CH: Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-Device-Memory, Sec-CH-DPR, Sec-CH-Viewport-Width
```

| Header | Read by | Without it |
|---|---|---|
| `Sec-CH-UA-Full-Version-List` | `sec_ch_full_version_mismatch` (45), `ua_vs_ch_major` | those two checks see nothing |
| `Sec-CH-UA-Platform-Version` | the `osVersion` matcher component | the component is absent |
| `Sec-CH-UA-Arch` | `arch_vs_ch_arch` (15), the `arch` hard component | the component falls back to the NaN-sign probe |
| `Sec-CH-UA-Bitness`, `Sec-CH-UA-Model` | `ch_bitness_vs_js`, `ch_model_vs_js` | rule silent |
| `Sec-CH-Device-Memory` | `device_memory_vs_ch` | rule silent |
| `Sec-CH-DPR` | `dpr_vs_ch` | rule silent |
| `Sec-CH-Viewport-Width` | `viewport_vs_ch` | rule silent |

Rules and limits worth knowing:

- Every rule is both-present only. Firefox and Safari send none of these headers and are never
  judged; a proxy or WAF that strips a header only silences the rule. A proxy that **rewrites** one
  would make the rule fire for everyone behind it, so keep these headers untouched at the edge.
- Do **not** add them to `Critical-CH`: that makes the browser repeat the first navigation to
  obtain them, which doubles the first page load. `Accept-CH` is enough, because the claims
  request is a later same-origin request.
- `Sec-CH-DPR`, `Sec-CH-Viewport-Width` and `Sec-CH-Device-Memory` are marked experimental; if a
  browser stops sending one, the matching rule goes silent rather than wrong.
- `sec_ch_partial_default_set` (`Sec-CH-UA` without `Sec-CH-UA-Mobile`) is a hard finding only when
  the headers PHP sees are the client's own frame (`headersAreClientFrame`); behind a proxy it is
  recorded as soft, because a proxy that drops one of the pair produces it for every visitor.

### Matcher components added with probe set 4

`keyboard` (Chromium keyboard layout, keyed), `gpuCaps` (WebGL/WebGPU capability class, keyed and
engine-conditioned) and `codecsHw` (hardware decode/encode bits) are stored soft components. The
engine ships **no weight** for any of them (matcher weights are the host's `fingerprint.matcher.weights`),
so they change no match until a host sets one. `keyboard` and `gpuCaps` are agree-only (a disagreement
never counts against a link); none of the three is part of `browser_key` or `hardware_key`
(`hardware_key` stays `os|arch|touch`), and none counts towards coverage. Give `gpuCaps` and
`codecsHw` a weight only after a three-engine capture on one real machine shows they agree.

## Verified crawlers, uptime monitors and the operator allowlist (`src/Crawlers/`)

Googlebot and the other search crawlers must never be challenged or blocked by fingerprinting or
bot defences, and neither must the operator's uptime monitors. `TrafficGate::classify($ip, $userAgent, $deviceKey)`
gives a host one answer, from caches only (no DNS, no HTTP on the request path):

| `decision` | Meaning |
|---|---|
| `ALLOW_LISTED` | the operator allowlist matched (IP/CIDR or device key) |
| `ALLOW_VERIFIED_CRAWLER` | the User-Agent claims a known crawler and reverse DNS + forward confirm (or the vendor's published list) proves it |
| `ALLOW_VERIFIED_MONITOR` | an uptime monitor the host enabled, and the address is in that provider's published list |
| `SCORE` | score it normally |

`$classification->applyTo($verdict, keepAnalysis: false)` returns the engine `Verdict` with `allowance` set and
band `pass` (so a host that reads only the band skips challenge and block); `Verdict::decision()` returns the
marker or `SCORE`. A crawler has no fingerprint: `fingerprintExpected()` is false for it.

**The host supplies three small interfaces**: `DnsResolver` (`NativeDnsResolver` is the pure-PHP default;
`gethostbyaddr`/`dns_get_record` use the system resolver with no timeout, so call from a worker or after the
response), `CrawlerCache` (`ArrayCache` for tests) and `RangeFetcher` (HTTPS, no redirects, size cap, SSRF
screening are the host's job). Pending claims are resolved in the background with
`CrawlerVerifier::verifyAndCache()`; `claimResolution()` makes one caller per address dispatch it.

**Fail closed.** No PTR, a DNS exception, an empty forward set, an unreadable list or a dead cache all yield
`unverifiable`/`pending`, never `verified`. `forged` means DNS or a list that was read contradicts the claim.
Suffix matching is on label boundaries (`evil-googlebot.com` and `googlebot.com.evil.net` do not match).
`googleusercontent.com` is deliberately not a Google suffix (every Compute Engine VM has a forward-confirming
PTR there); Google's user-triggered fetchers are covered by its published JSON ranges.

**Catalogue** (`CrawlerCatalogue::default()`, extend with `->with(new CrawlerDefinition(...))` or `fromArray()`):
Google (all families: Googlebot, Google-InspectionTool, GoogleOther, Storebot-Google, AdsBot-Google,
Mediapartners-Google, APIs-Google ...), Bingbot, Applebot, DuckDuckBot (recognised, no published method:
config-only), YandexBot, Baiduspider, OpenAI, Anthropic and Perplexity (published lists). Sources are in the
`CrawlerCatalogue` docblock.

**Uptime monitors** are provable ONLY by the provider's published IP list; a User-Agent never suffices. The
host enables monitors by key (default none): UptimeRobot, Pingdom, Better Stack, StatusCake, Oh Dear, Checkly,
Datadog Synthetics, HetrixTools have official lists; Site24x7 and Freshping are config-only (no official
machine-readable list found: enter their CIDRs in the allowlist). Lists are cached; a failed refresh keeps the
last good list for up to 30 days, and with no list the answer is "not listed". A monitor User-Agent from an
unlisted address is never an impersonation signal (monitors change addresses); it is returned in
`unlistedMonitorClaim` for logging. Refresh with `TrafficGate::refreshMonitorLists()` after the response or
from a scheduler.

**Operator allowlist**: `new OperatorAllowlist($ips, $deviceKeys)` (IPv4/IPv6 addresses and CIDRs). Invalid
entries never match and are listed in `invalidEntries()`; a `/0` is refused. Device keys are recognition handles,
not credentials: prefer IPs.

**Impersonation**: a User-Agent claiming a crawler that DNS or the vendor's list contradicts is the hard
transport finding `crawler_impersonation` (`TransportRequestFacts(crawler: $verification)`), weight
`transport_crawler_impersonation` = 45: score 68, `challenge`, never `block` on its own.

## Browser collector

One collector runs in the visitor's browser, shipped as TypeScript sources under
`resources/js/collector/`. The application's bundler compiles it, so nothing is published to npm.
It speaks envelope version 3 (`{ v, nonce, slot, digest, claims, probes }`, two slots per challenge:
`tier1` at once, `tier2` after tier 1 was answered 2xx). `resources/js/shared/xsrf.ts` reads the
Laravel `X-XSRF-TOKEN` value.

| Entry | Exports / use |
|---|---|
| `@device-id/collector` (`index.ts`) | `collectAndSend(purpose, challengeUrl?, claimsUrl?)`, `collectAndSendDetailed` (says what happened), `collectAndConfirm` (resolves once tier 1 was accepted: a guest vote), `collectForIdentity` (both tiers in one claim set, no challenge), `reportDeclined`, `FINGERPRINT_VERSION`, diagnostics (`measureProbes`, ...) |
| `@device-id/collector/boot` | `initFingerprint(options?)` for pages without a SPA. Reads `<body data-fingerprint-purpose="signin" data-fingerprint-challenge-url="..." data-fingerprint-claims-url="...">`; no purpose attribute, no collection; once per tab per purpose. |

The purpose is any string your challenge endpoint accepts; the URLs default to
`/security/fingerprint/challenge` and `/security/fingerprint/claims`. An operator can switch
non-core probes off (`ProbeRegistry`, `disabled_probes`); the challenge response carries the list.

The collector is the merge of two collectors that had drifted apart. What was kept, by probe:

| Part | Decision |
|---|---|
| Integrity probes, lie battery, phantom realm, worker/realm cross-checks, tier system, scheduler, canonicalisation, transport, protocol | NutriCompare's collector only: a strict superset of WelZoLekker's and the only one with tests |
| `voices`, `permissions` (incl. `Notification.permission`), `gpu`, `uaClientHints`, `environment`, ... | NutriCompare's: same measurement as WelZoLekker's plus the fixes that one lacked (empty list is `unavailable`, listener cleanup, error names, WebGPU, WebGL1/2 agreement) |
| `webrtc` (codec/extension hashes of a local offer) | ported from WelZoLekker's collector, changed: no `setLocalDescription` (no ICE gathering, no address can leak), locale-independent ordering; tier 2, no key |
| `behavior` (passive input aggregates) | ported from WelZoLekker's collector, changed: listener lifecycle (stopped after the tier-2 snapshot), handlers cannot raise page errors; tier 2, `late`, no key (session data); **off by default** (`ProbeRegistry::DEFAULT_DISABLED`, owner decision), switch it on through `disabled_probes` |
| `collectAndConfirm`, `boot.ts` | ported from WelZoLekker's collector; boot made host-configurable, retries after a transient failure |
| `stackDepth` | **not ported**: a constant in V8, call-site dependent elsewhere, removed from NutriCompare's collector on evidence |
| third "behaviour" envelope on page hide | **not ported**: the challenge store has two slots; behaviour rides in tier 2 |

A host maps `@device-id` to the installed package and imports the collector:

```js
// vite.config.js
import { fileURLToPath } from 'node:url';

export default defineConfig({
    resolve: {
        alias: {
            '@device-id': fileURLToPath(new URL('./vendor/jw-1980/device-id/resources/js', import.meta.url)),
        },
    },
});
```

```js
const { collectAndSend } = await import('@device-id/collector');
// or, on a Blade page:  import('@device-id/collector/boot').then(({ initFingerprint }) => initFingerprint());
```

TypeScript hosts add `"@device-id/*": ["./vendor/jw-1980/device-id/resources/js/*"]` to
`compilerOptions.paths`. Because the bundler reads `vendor/`, **`composer install` must run
before `npm run build`** (and before the host's type-check and Vitest).

Tests and type-check here: `npm ci && npm test && npm run typecheck`.

## Capturing real browsers

`npm run capture` runs the **real collector** (`collectAndSendDetailed`, nothing reimplemented) in real
browsers against a local server that answers the challenge and claims endpoints the way a host with
default settings does (envelope v3, two slots, a nonce, `disabled_probes` from `ProbeRegistry`, and the
`Accept-CH` header above), then runs the engine over what it received. It needs Node, PHP 8.2+ and
`npm ci`; nothing is installed or sent anywhere.

```bash
npm ci
npx playwright install chromium firefox webkit   # the pinned Playwright 1.63.0; skip browsers you do not need
npm run capture                                  # every browser it finds, headed and headless
npm run capture -- --browsers=chrome,msedge,safari --mode=headed --machine=my-laptop
npm run capture:report                           # redo the engine step for the newest capture
```

- **Browsers.** `chromium`, `firefox`, `webkit` (Playwright's own builds), `chrome` and `msedge` (the
  installed browsers, through Playwright's channels) and `safari` (real Safari through `safaridriver`
  over a plain-`fetch` WebDriver client; on a Mac run `sudo safaridriver --enable` once and tick
  Safari > Develop > Allow Remote Automation). A browser that is not installed is reported as
  "not installed" and skipped.
- **Headed or headless.** Both by default. Headed needs a display; on Linux without one the harness
  re-runs itself under `xvfb-run` when that exists and otherwise records "skipped". The mode of every
  run is written down (`headless`, `headed`, `headed-xvfb`).
- **Output.** `tools/capture/out/<timestamp>/` (git-ignored; change it with `--out=`) and a
  `.tar.gz` of it, which is what to send back from another machine: `runs/` (raw envelopes and request
  headers), `dataset/` (see below), `report.md`, `report.json`.
- **What the report means.** Per capture: the verdict (band, score, rule codes with weights), the
  confidence number with missing probes and penalties, and whether `tools/capture/expectations.php` is
  met. An honest headed browser must not reach `challenge` and may fire no code; a headless run is
  expected to give itself away (headless Chromium: `ua_headless_token`); any other code on an honest
  run is a reported failure with the engine's own detail sentence, and the command exits non-zero.
  `navigator.webdriver` is a confidence penalty (`webdriver`), not a rule code. The report also matches
  every pair of different browsers captured on the same machine and mode with `DeviceMatcher`, both
  ways. A link is reported, not required: signals legitimately differ between browsers.
- **Labels.** `honest` (headed, automation switches suppressed where the driver allows: Chromium family
  only), `automation` (headed with the driver's defaults; Firefox and WebKit under Playwright, and
  Safari under safaridriver, cannot hide it), `headless`. They are the harness's declaration, not a
  human judgement, and even `honest` is driven by a program: it is the closest approximation to a
  person's browser the harness can make, not a population sample.

The same captures feed the permanent regression suite: `tests/Fixtures/fingerprint/captures/` holds
captures (what the browser said, not what the engine answered) and `tests/Unit/CaptureFixturesTest`
runs the engine over each against the expectations. To add a machine's captures:
`php tools/capture/engine-report.php <capture-dir> --save-fixtures=tests/Fixtures/fingerprint/captures`.

### The dataset (`dataset/<id>.json`, schema `device-id.capture-dataset`, version 1)

One JSON per run, for a later model to train and evaluate on: `labels` (`class`, `basis`), `machine`
(`id` is a hash of hostname and hardware, or `--machine`; the hostname is never written; `os`,
`arch`), `browser` (`name`, `engine`, `version`, `mode`, `variant`, `driver`), `collector`
(envelope and probe-set versions, the method policy), `transport` (request headers in wire order),
`claims` (the engine-parsed claims of both envelopes), `features` (the merged claims flattened to
`dotted.path` scalars; a list becomes `path.__len` and `path.__hash`), and `engine` (the verdict,
confidence and keys under a fixed test secret). `index.jsonl` has one summary line per run. The schema
version changes with any change to these names; `engine` is derived and should be recomputed, not trained
on, when the engine changes.

## Usage without a framework

```php
require 'vendor/autoload.php';   // or src/autoload.php for a drop-in copy

use DeviceId\Settings;

$settings = Settings::fromArray([
    'enabled'           => true,
    'device_key_secret' => getenv('FP_SECRET'),   // 32+ chars, or keys are not derived
]);
```

## What "no framework" means, and how it is checked

`php tools/prove-standalone.php` autoloads every class in `src/` with a **bare SPL
autoloader** — not Composer's — and then asserts that no symbol from Laravel, Symfony or PSR
appears anywhere in the load graph, and that no file in `src/` calls `config()`, `Log::`,
`Cache::`, `Cookie::`, `DB::`, `app()`, `request()`, `view()` or `redirect()`.

That is a stronger claim than "there is no `use Illuminate` at the top of the file". A
transitive `require`, a framework type in a method signature, or a constant that only resolves
on Laravel would all pass a grep and all break a drop-in install.

The script is also a demonstration: `src/autoload.php` is a short `spl_autoload_register` file
(36 lines, mostly comment) and nothing else. Copy the directory and it works.

## Try it

```bash
php demo/standalone-demo.php     # the whole engine, no framework
php tools/prove-standalone.php   # framework-freedom, as a gate
php tools/golden-check.php       # fixed answers for fixed claim sets
vendor/bin/phpunit               # unit tests
composer gates                   # all of the above
```

The demo is not a preview. It runs the engine over labelled fixture claim sets
(`demo/fixtures.php`) and prints what came out, including its own load-graph check so the
framework-free claim is visible in the output rather than in a separate script.

## Status (2026-10-21: one engine)

**This package is the fingerprint engine.** Until 2026-10-21 the Laravel application kept its
own copy in `app/` and 20 classes here were generated from it; the copies drifted (see "Why the
generator and the parity gates are gone" below). Since the one-engine migration
(`research/fingerprinting/notes/26-one-engine-migration.md`) every engine class exists once, here,
and the application depends on it.

| Area | In this package | The host supplies |
|---|---|---|
| `Canonicaliser` — deterministic canonical serialisation | **yes** | — |
| `Settings`, `CheckRegistry`, `ProbeRegistry` | **yes** | — |
| `Support/Config` — the configuration bridge | **yes**: `use()` (snapshot) or `resolveWith()` (live resolver) | the values |
| `Rules/EnvironmentConsistency`, `Rules/IntegrityFindings` | **yes** | — |
| `Rules/TemporalConsistency` | **yes**, over a `Support/PreviousObservation` | the previous observation, via `Support/ObservationReader` (app: `EloquentObservationReader`) |
| `Scoring/VerdictScorer`, `ConfidenceScorer`, `ProbeOmission`, `ScoredClaims`, `OmissionGateSettings` | **yes** | the gate settings via `fingerprint.omission_gate` |
| `Keys/DeviceKeyDeriver`, `DeviceComponents`, `DeviceKeys` — keyed derivation | **yes** | `fingerprint.device_key_secret` (32+ chars, or no key is derived) |
| `Matching/DeviceMatcher`, `MatchResult`, `MatchCandidate`, `LinkState`, `MatcherSettings`, `MatchesAsCandidate` | **yes** | the candidate rows: a `Matching/DeviceCandidateSource` (required constructor argument; app: `FingerprintDeviceCandidates`, `VisitorDeviceCandidates`) |
| `Envelope/ClientClaimsEnvelope`, `EnvelopeParse`, `Slot` — the wire parser | **yes** | the raw body |
| `Transport/Ja4`, `Ja4Capture`, `RawHeaderCapture`, `RawHeaderOrder`, `TransportIntegrity`, `StructuredFieldList` | **yes** (`RawHeaderCapture` takes header and `$_SERVER` arrays, not a request object) | the request's headers |
| `Support/` value objects (Verdict, Confidence, DeviceKey, DeviceSignals, TransportFinding, …) | **yes** | — |
| Challenge / nonce store (`FingerprintChallenge`, token, record) | no — a cache concern | yes |
| Device cookie, `Ja4Reader` (cache + request), `ClientDecline` (logging), `LinkNetwork` | no | yes |
| Ingest orchestration (`FingerprintIngest`, `IngestOutcome`, `IngestContext`, `DeviceIdentityResolver`) | no — persistence and HTTP | yes |
| `BotRiskScorer` | no — anti-scraping, not this engine | — |
| Storage (device and observation rows), HTTP endpoints, admin screens | no | yes |
| Client collectors (browser TypeScript) | **yes**: `resources/js/collector/` (see "Browser collector") | the bundler alias and the HTTP endpoints |

## How NutriCompare (Laravel) depends on it

- Autoload: the application requires `jw-1980/device-id` (see "Installing it" above); Composer's
  PSR-4 map points `DeviceId\` at `vendor/jw-1980/device-id/src/`.
  `app/` imports the package classes directly; there are no aliases and no shim classes.
- `App\Providers\FingerprintServiceProvider` (registered in `bootstrap/providers.php`) calls
  `Config::resolveWith()` with a resolver that answers each key LIVE: `fingerprint.constraint_weights`,
  `fingerprint.bands`, `fingerprint.matcher`, `fingerprint.omission_gate` and
  `fingerprint.disabled_probes` from `FingerprintSettingsStore` (settings table first, config
  second); every other `fingerprint.*` / `transport_integrity.*` key from `config('security.<key>')`;
  `session.cookie` from `config()`. A snapshot taken at boot would be stale as soon as an
  operator edits a weight on the admin screen (tests, queue workers, Octane); the resolver makes
  one store read per engine read, so the read budget is unchanged
  (`tests/Feature/Performance/FingerprintSettingsReadBudgetTest.php`).
- The provider binds `Support\ObservationReader` → `App\Services\Security\EloquentObservationReader`
  and `Matching\DeviceCandidateSource` → `App\Services\Security\FingerprintDeviceCandidates`.
- The matcher and omission-gate normalisation (defaults, clamps, component-name filter, stored
  overrides) lives in `Matching\MatcherSettings` and `Scoring\OmissionGateSettings`; the
  application's `FingerprintSettingsStore` calls those same functions, so a plain-PHP host and the
  application agree on every default.

## Why the generator and the parity gates are gone

`research/fingerprinting/audit/port-engine.php` generated this package from the application's
copy, and `parity-canonicaliser.php`, `parity-engine.php`, `parity-transport.php`,
`parity-mutation-check.php` and `api-surface.php` compared the two copies. On 2026-10-21 the
port gate reported `PORT: FAIL`: the application had added `DeviceKey::REFERENCE_LENGTH` and
`DeviceKey::reference()` on 2026-10-12 and the package was never regenerated — and CI, where the
gate ran, was switched off, so nobody saw it. Differential gates prove that two copies agree, never
that either is right (`notes/17`). With one copy there is nothing to compare, so they were deleted
with the second copy. What replaced them asserts fixed values instead:

- `tools/prove-standalone.php` — bare SPL autoloader, no framework symbol in the load graph, no
  framework call in `src/`, every referenced class resolves;
- `demo/standalone-demo.php` — runs end to end with no framework;
- `tools/golden-check.php` — rule codes and weights, score, band, confidence, canonical digest,
  integrity codes and derived keys for the fixture claim sets (`tests/Fixtures/fingerprint/` and
  `demo/fixtures.php`) equal values recorded from a real run on 2026-10-21. A rule change must
  change that file in the same commit. It proves on every run that it can fail.

The intended behaviour of each rule is asserted by this package's PHPUnit suite (`tests/Unit`)
and by the consuming applications' suites (NutriCompare `tests/Unit/Security`,
`tests/Feature/Security`; WelZoLekker `tests/Unit/Security`, `tests/Feature`).

## How the port was done (history, 2026-10), and the three defects it caught

The engine was ported by script (`research/fingerprinting/audit/port-engine.php`), not by
hand. 202 KB across 16 classes, six framework call sites, and a namespace rewrite. Three
defects were found along the way, and none of them would have been caught by the obvious
checks:

**1. `fdiv`, not `/`.** `canonicaliseFloat` uses `fdiv(1.0, $value)` to detect `-0.0`.
Division by zero is a **fatal error** in PHP 8, so a hand-written `/` would have shipped a
crash — in the one branch no test in the application exercises. Found by reading the
original.

**2. A wrong `__DIR__` in this package's own autoloader.** `src/autoload.php` lives *inside*
`src/`, so `__DIR__` already is `src` and appending another segment resolved `src/src/…`.
`prove-standalone.php` never noticed, because it uses its own inline autoloader rather than
this file — the file had been written and never loaded. Found by the parity tool.

**3. Cross-directory imports, which `php -l` cannot see.** `VerdictScorer` and
`EnvironmentConsistency` shared a namespace in the application, so the scorer had no `use` for
it. In this package they live in different directories, so the unimported name resolved to
`Scoring\EnvironmentConsistency` — which does not exist — and the failure was a `TypeError`
the moment anything constructed the scorer. The port script's first version rewrote imports to
the *current file's* namespace; it now resolves each imported class to its own destination.

**And one that reached production of the first port:** `BotRiskScorer` came through with
`php -l` clean, no `App\` reference left, and `prove-standalone.php` green — while importing
`AntiScrapingConfig` and `BotRiskState`, which are **not in this package**. A dangling import
is valid PHP and introduces no framework symbol, so both gates passed it. The port script now
resolves every `DeviceId\…` import to a file and refuses to pass if one does
not exist.

**An inventory that was wrong.** Before starting, all eighteen candidate classes were reported
framework-free. Two were not: `IngestOutcome` and `TemporalConsistency` import Eloquent
models. The scan's pattern was the PowerShell string `'use App\\'`, a literal *double*
backslash, which never matched `use App\Models\…`. The port script caught it; the inventory
did not.

## Design notes

**A key is only derived when a secret is configured.** `Settings::deviceKeySecret()` returns
null below 32 characters, and callers treat null as "do not derive a key" and log it. An
unkeyed key would be a public function of the claims, which is the exact weakness a keyed key
exists to remove.

**The master switch defaults to false.** `enabled` is off unless a host turns it on, so an
absent configuration key can never mean "on" by accident.

**A wrong-typed setting falls back, it does not coerce.** `bool()` is strict: the string
`"false"` is not `false`, it is a wrong-typed value, and it falls back to the default.
Coercing would mean a configuration typo could silently enable a feature an operator meant
to disable, which is the failure mode the whole class exists to prevent.

**A weight of 0 silences a check rather than halving it.** `CheckRegistry::weightFor()`
returns 0 and the scorer skips zero, so "switch it off" and "halve it" are the same control.
Half-weighting a rule that fires on everyone is worse than switching it off, because the
score still moves and the operator has to work out why.

**An unknown check code is scored at 0, never at a catch-all default.** A check the
deployment has not heard of cannot be assumed to be rare. The Laravel package enforces the
same rule with a test, and the registry does it structurally.

**No one check can block a device alone.** The heaviest contradiction is 40 and the block
band is 80, so a device must contradict itself in two independent ways. That property lives
in the weights, so it is preserved by the port — and `CheckRegistry` documents it next to the
numbers rather than leaving it implicit.

## Relationship to the Laravel application

Since 2026-10-21 this is **the** implementation, not a separate one: the application keeps only
its Laravel adapters (controllers, Eloquent models and candidate sources, the cache-backed
challenge, cookies, logging, the settings table, the service provider) and runs the engine from
here — see "How the Laravel application depends on it" above.

`CheckRegistry` is also where the admin panel's per-check toggles come from: the application
renders them from `describe()` and writes them to the same `constraint_weights` the engine reads
through the resolver.
