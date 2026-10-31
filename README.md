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

### Hardware identity (one vote per hardware) and client-reported flags

`DeviceKeys::$hardwareIdentity` (`DeviceKeyDeriver::hardwareIdentity()`) is an HMAC over the measured
high-entropy components `DeviceComponents::HARDWARE_IDENTITY` (fonts, gpu, gpuMath, voices, emoji,
scripts), for a host's one-vote-per-hardware correlation. It is computed without the trust projection's
client-reported inputs (`canvasFill.exact`, `canvasPattern.exact`, wrapped read-back functions), so no
single client bit changes it. It is null when there is no secret, when no component was measured, and
under a protection the engine evidence proves (Firefox resistFingerprinting or Tor; Brave), whose values
are constants or per-session noise. A host must treat a null identity at least as strictly as a known one,
or declining becomes the evasion. **Limit:** a client that forges a measurement (one bit of
`tier2.scripts.bits`) derives a different identity; it is a correlation signal, never a sole dedupe key.

The Brave shields report is honoured (components untrusted, four rules silenced) only under
`EnvironmentConsistency::protectedBrave()`: the Chromium engine marks and UA, AND a `Brave` brand in
`userAgentData.brands` and, when Client Hints are sent, in `Sec-CH-UA`. It used to need only the Chromium
evidence every Chrome has, so one bit nulled eleven components. That Brave sends its own brand is Brave's
documented behaviour; it is not measured here (no Brave build in this environment).

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
PTR there). An entry with one `*` is a host pattern (`rate-limited-proxy-*.google.com`: one first label with
that prefix, then exactly that domain); Google is verified only by its crawler names (`crawl-*.googlebot.com`,
`geo-crawl-*.geo.googlebot.com`, `rate-limited-proxy-*.google.com`) and its crawler lists
(`common-crawlers.json`, `special-crawlers.json`).

**User-triggered fetchers are not crawlers.** Google's user-triggered fetchers (App Engine customer egress under
`*.gae.googleusercontent.com`, `google-proxy-*.google.com`), Feedfetcher, Google-Read-Aloud,
Google-Site-Verification, GoogleProducer, ChatGPT-User, Claude-User and Perplexity-User claim no crawler identity
and their lists are not read: they are scored as ordinary traffic. Anthropic publishes one list for all its
bots, so whether a ClaudeBot claim from a Claude-User address verifies is unknown. Range URLs must be final
URLs, because the host fetchers refuse redirects.

**Catalogue** (`CrawlerCatalogue::default()`, extend with `->with(new CrawlerDefinition(...))` or `fromArray()`):
Google (common and special-case crawlers: Googlebot, Google-InspectionTool, GoogleOther, Storebot-Google,
Google-CloudVertexBot, AdsBot-Google, Mediapartners-Google, APIs-Google, Google-Safety), Bingbot, Applebot,
DuckDuckBot (recognised, no published method: config-only), YandexBot, Baiduspider, OpenAI (GPTBot,
OAI-SearchBot), Anthropic (ClaudeBot, Claude-SearchBot) and PerplexityBot (published lists). Sources are in the
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
`transport_crawler_impersonation` = 45: score 68, `challenge`, never `block` on its own (no single root cause can block; see "No single root cause can block a device").

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

## Red-team testing (`npm run redteam`, `tools/redteam/`)

The capture harness above measures honest browsers. `npm run redteam` points the same harness (the real
collector, the real challenge and claims endpoints, the same engine step) at the free stealth and
anti-detect tools fraudsters use, with their stealth features on, headless and headed, and reports what
the engine says about each. The tools are never repository dependencies: they live in a scratch
directory you choose.

```bash
npm run redteam:install -- /path/to/scratch     # npm + a python venv in that directory; needs network
npm run redteam -- --dir=/path/to/scratch       # every tool, headless and headed, 2 runs each
npm run redteam -- --dir=... --tools=nodriver,patchright --mode=headless --repeat=3
npm run redteam -- --dir=... --save-fixtures=tests/Fixtures/fingerprint/redteam   # refresh the regression fixtures
```

- **Tools** (`tools/redteam/tools.mjs`): `puppeteer-extra-stealth` (puppeteer-extra + stealth plugin),
  `rebrowser-puppeteer`, `patchright`, `playwright-stealth-script` (Playwright plus the init script every
  "stealth" gist ships), `playwright-stealth-py`, `nodriver`, `undetected-chromedriver` and `camoufox`.
  The Chromium tools drive the Playwright Chromium (`PLAYWRIGHT_BROWSERS_PATH`, default `/opt/pw-browsers`,
  or `REDTEAM_CHROME`); `undetected-chromedriver` needs a chromedriver of the same version, which
  `install.sh` downloads from Chrome for Testing to `<dir>/chromedriver/chromedriver` (or set
  `REDTEAM_CHROMEDRIVER`). Camoufox's own Firefox build is a
  separate download from its GitHub releases; when it is absent the tool is reported "not installed".
  A `baseline` run (plain Playwright Chromium, same machine and mode) is added every time: it is the
  honest browser the matcher comparison uses.
- **Headless runs** pass a normal Chrome user agent (every tutorial starts by removing
  `HeadlessChrome`); headed runs use the tool's best-practice configuration (no viewport emulation).
- **Labels.** Every run is `labels.class = "spoof"` with `labels.name = "spoof:<tool>"`, so the ML
  dataset (`tools/ml`) gains adversarial rows. The evaluation reads
  `tests/Fixtures/fingerprint/redteam` as well as `tests/Fixtures/ml/dataset`.
- **Report** (`tools/redteam/out/<timestamp>/report.md` and `report.json`, plus `dataset/`): per tool and
  mode the band, score, confidence, codes, whether every repeat reached `challenge` ("flagged"), whether
  the browser key differs between repeats ("fresh identity per run"; it does not for any tool measured:
  the identity follows the machine, not the tool) and whether `DeviceMatcher` links the run to the
  baseline browser of the same machine.
- **Regression guard.** `tests/Unit/RedteamFixturesTest` runs the engine over the saved runs and
  asserts, per tool and mode, the expected outcome in `tests/Fixtures/fingerprint/redteam/expectations.json`:
  flagged with the named codes, or, for the combinations the engine does not catch, still unflagged with
  the reason written down. Detection that improves therefore fails the test until the expectation is
  promoted, and a rule that stops catching a tool fails it too.

What the measurements show, and what they cannot: engine-level stealth (Patchright, rebrowser, nodriver,
undetected-chromedriver driving a real Chrome headed) leaves no JavaScript-visible lie on a fresh profile;
only default configuration leaves geometry behind (`viewport_fills_screen`, `headless_default_screen`,
`window_exceeds_screen`). The measurements come from one Linux container with software GL, not from
Windows or macOS hardware.

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
php tools/probe-bypass-shapes.php  # every probe feeding several checks is classified (silence/trip/mixed)
vendor/bin/phpunit               # unit tests
composer gates                   # all of the above
```

`probe-bypass-shapes` is an audit, not a proof: it parses the collector source and fails when a probe
that feeds more than one rule has no recorded direction (what a one-property stub does to it), so a new
probe or rule cannot widen the single-point-bypass surface unnoticed.

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
  `demo/fixtures.php`) equal values recorded from a real run (first on 2026-10-21; every
  re-recording since is explained in the file). A rule change must change that file in the same
  commit. It proves on every run that it can fail.

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

**No single root cause can block a device.** Several rules can read one fact: a User-Agent
switcher trips `transport_sec_ch_full_version_mismatch` (45), `ua_vs_ch_major` (25) and
`ua_vs_feature_version` (25) at once, and summed that blocked a real Chromium whose only change
was its User-Agent (score 92). `CheckRegistry::EVIDENCE_GROUPS` declares which rules share their
evidence (`claimed_identity`, `locale`, `display_metrics`, `readback_noise`, `network`,
`virtual_machine`; every other code is its own group), and the score is computed from the
effective weight: each group counts once, at its heaviest member (`Verdict::totalWeight()`;
`rawWeight()` is the plain sum, for diagnostics). Every rule is still listed at its own weight.
The heaviest weight, and the ceiling an operator override is clamped to, is 45
(`EnvironmentConsistency::MAX_WEIGHT`, score 68, `challenge`), so one cause cannot block and a
device must contradict itself in two independent ways. The same real capture now scores 72
(`challenge`). `SingleRootCauseInvariantTest` enforces it on facts: every honest capture under
~36 single-cause perturbations (UA version, family and OS, in the header, the page and the
worker; language; Accept-Language; stripped Client-Hints or Sec-Fetch headers) stays below
`block`, no perturbation of any capture adds more than one group's weight, and the red-team
fixtures keep their bands. The honest fixtures are Chromium only (Firefox and WebKit honest
captures are not in the set). A host that lowers `score_divisor` or the `block` threshold can
break the invariant; `VerdictScorer::singleCauseCanBlock()` reports such a configuration, and a
settings screen should refuse it.

**One cause plus the model never blocks either.** In `bounded` mode the model escalates only when
the rules fired in at least two families AND two evidence groups, and its adjustment is reduced
until the band is not `block` (`ModelScorer`, bound 4). One cause is at most 45 (68), so the
combination stays below 80.

## Relationship to the Laravel application

Since 2026-10-21 this is **the** implementation, not a separate one: the application keeps only
its Laravel adapters (controllers, Eloquent models and candidate sources, the cache-backed
challenge, cookies, logging, the settings table, the service provider) and runs the engine from
here — see "How the Laravel application depends on it" above.

`CheckRegistry` is also where the admin panel's per-check toggles come from: the application
renders them from `describe()` and writes them to the same `constraint_weights` the engine reads
through the resolver.

## Smart signals (`src/Network/`, `src/Signals/`)

Soft, evidence-based signals that read a visitor's network, machine and storage. None blocks alone (the heaviest is 8; the engine's invariant is a maximum of 45 and no single check blocks), none makes a network call on the request path, and every one is **silent when its evidence is missing**: no data is never "clean" and never "listed".

| rule code | weight | fires when | honest cases that fire it (why the weight is low) | honest cases it ignores |
|---|---|---|---|---|
| `ip_country_vs_locale` | 5 | the IP's country (and the ASN's registration country, when the lookup has one) is named by **neither** the time zone **nor** any language/locale region (both independent settings must disagree). The country source is a registration and routing country, so a second country can only add ways to agree: its errors make the rule quieter, never noisier | a VPN user; a traveller who changed both | an expat (foreign language, local clock), a traveller who changed only one, a bare `nl` (no region), an unlisted time zone, a protected Firefox (UTC, en-US) |
| `network_hosting` | 5 | the ASN is a hosting/cloud/colocation network (name classifier, bad-asn-list) or the address is in a published cloud range (`IpReputation`) | corporate gateways, VPN egress, cloud-hosted browsers | residential and mobile networks, unknown data, protected Firefox |
| `network_vpn` | 4 | the ASN's registered name says VPN (exclusive with `network_hosting`) | everyone who bought a commercial VPN | as above |
| `vm_gpu_renderer` | 5 | the WebGL renderer names VMware, VirtualBox, Parallels, QEMU/virtio/virgl, Hyper-V (non-headless desktop UA, no touch) | corporate VDI users, developers | real GPUs, Windows "Basic Render" (WARP), Linux llvmpipe, headless (other rules) |
| `vm_software_gpu_screen` | 4 | a software rasteriser **and** a screen exactly 800x600, 1024x768 or 1152x864 | a VDI session on a small screen | a software renderer alone (many honest Linux desktops), a small screen alone |
| `emulator_android` | 8 | an Android UA/device model with an emulator token (`sdk_gphone`, `Android SDK built for`, `ranchu`, `goldfish`, Genymotion...) or a software GPU | developers and testers | real phones; a desktop on SwiftShader |
| `private_mode_with_other_signals` | 3 | private browsing is likely **and** a hosting/VPN network, a hypervisor GPU, an emulator or a locale mismatch is present | privacy-minded users on a VPN | a private tab alone: never scored |

The same facts are model features (`net_hosting`, `net_vpn`, `net_tor_exit`, `sig_locale_disagreements`, `sig_vm_gpu`, `sig_vm_screen`, `sig_software_gpu`, `sig_emulator`, `sig_private_mode`, `vel_burst`, `vel_impossible_travel`; `FeatureCatalogue::optional()`). Rules are in `CheckRegistry` (so an operator can switch each off with weight 0).

**What was deliberately skipped.** A WebRTC public-IP versus HTTP-IP mismatch needs ICE candidate gathering, which the collector does not do on purpose (it would expose the visitor's local and public addresses; the `webrtc` probe reads codecs from a local offer only). `hardwareConcurrency` against measured parallelism already exists as `cores_vs_measured_parallelism` (the `parallelism` probe is off by default because it costs CPU); a VM reports its configured vCPUs honestly, so no VM-specific cores rule was added. Corporate VDI is documented above as the honest cohort of the two VM rules.

### Network keys for limits (`Network\NetworkKey`)

The hosts compute their own network codes. For limits, use `NetworkKey` so IPv6 is aggregated where
one party controls it: `NetworkKey::forLimits($ip)` is IPv4 /32 and IPv6 **/48** (business end sites
and free tunnel brokers hand out a /48; at /56 one /48 held 256 counted guest votes per duel),
`NetworkKey::endSite($ip)` is IPv4 /32 and IPv6 /56 (one household), and `NetworkKey::keyed($ip,
$secret, endSite: false)` is the HMAC of either (null for an invalid address or a secret under 32
bytes). Dedupe one-per-household by `endSite()` and cap aggregates (guest votes per item, rate limits)
by `forLimits()` with a small N: a residential ISP's /48 holds up to 256 neighbouring /56 customers, so
"one vote per /48" would drop honest neighbours. IPv4 stays one address in both.

### Private browsing is context, not fraud

`storageProfile` (probe set 5, tier 2, no permission prompt) sends three coarse facts: the storage quota and the Chromium heap limit as half-octave steps (no byte count) and what the origin-private file system did. `SmartSignals::privateMode()` reads them per engine. Measured 2026-10-31 on the installed Chromium 153, Firefox 155 and WebKit 26.6, normal against private/ephemeral contexts, and by the real collector in the capture harness:

| engine | normal profile | private / non-persistent | rule | confidence |
|---|---|---|---|---|
| Chromium | quota 10 GiB, heap limit 3.5-4.1 GiB (ratio 2.3-2.9) | `--incognito`: quota 3 GiB (ratio 0.86) | quota not above the heap limit | low: one machine; a nearly full disk makes a normal profile look private; much more RAM than the heap cap hides it |
| Firefox | quota 10 GiB, OPFS ok | `privatebrowsing.autostart`: OPFS `SecurityError` (quota identical) | OPFS rejected with SecurityError | medium (also fires when all site data is blocked: a storage-restricted mode) |
| WebKit | quota 1000 MB, OPFS ok | ephemeral context: OPFS `UnknownError` | OPFS rejected | low: Safari itself could not be measured |

The decision: private mode is **exposed as a feature (`sig_private_mode`, 1 or 0.5) and a context flag, and scored only as `private_mode_with_other_signals` (3)** when another signal is present. A private tab is a legitimate privacy choice, and alone it says nothing about fraud. The capture harness's Chromium and WebKit contexts are ephemeral, so its "honest" runs read as private; no rule fires on them.

### Data sources and licences (checked 2026-10-31; re-check, terms change)

**No source that needs public credit is used**: a credit on a page would reveal a method. The catalogues refuse to load any feed with an attribution text or the status `public_credit_required` (a test pins it), `NetworkDatabase::attribution()` is always empty, and the licence notices that only have to travel with the data (MIT) are in [`LICENSE-THIRD-PARTY.md`](LICENSE-THIRD-PARTY.md). Nothing is shown to visitors or in a host's footer.

| data | source | licence | account | used for |
|---|---|---|---|---|
| IP to country | sapics/ip-location-db `user-country` (IPv4 and IPv6 CSV, daily) | PDDL 1.0, "free use without attribution" | none | the country. A **registration and routing** country, not a measurement: 97.5 % agreement with GeoLite2 on IPv4 (the maintainer's measurement, 2026-06-14) |
| IP to ASN and registered name | IPtoASN `ip2asn-combined.tsv.gz`, hourly | Public Domain (PDDL 1.0) | none | the ASN; the name is classified `vpn` or `hosting` at refresh. Its country column is the ASN's *registration* country: stored as the second opinion `NetworkFacts::$registrationCountry`, never a location |
| hosting/cloud ASN list | `brianhama/bad-asn-list` (about 740 ASNs) | MIT, notice in `LICENSE-THIRD-PARTY.md` | none | extra hosting ASNs; ignored after a year |
| country bounding boxes | Natural Earth admin-0 1:50m | Public Domain | none | impossible travel (`tools/network/generate-country-bounds.php` regenerates `CountryBounds`) |
| Tor exits | Tor Project CollecTor `tordnsel` exit list (newest file of the directory, hourly) | CC0 (Tor Metrics) | none | `torExit` |
| cloud ranges | AWS, Google Cloud, Oracle, DigitalOcean | no licence text; `unverified`, host opt-in, none asks for credit | none | `datacenterRange` |

Removed on 2026-10-31 because they require public credit: **DB-IP Lite** (a link back "on pages that display or use results") and **Spamhaus DROP** ("credit for the use must be given", and its name may not appear in commercial materials). No CC0 or PDDL replacement for a netblock drop list was found, so the abuse signal is first-party: `NetworkReputation` turns the host's own labelled history of a network (7-day distinct-device counts, k-floor 20, `not_abuse` clearances subtract) into the soft feature `net_history_bad`, next to the hosting, Tor and bad-asn signals. The `abuse_list` category remains for a list a host supplies under a licence of its own.

Not used, with reasons: **MaxMind GeoLite2** needs an account and a licence key, requires attribution of the use, forbids disclosing the data to third parties and requires destroying superseded versions within 30 days. **ipverse/rir-ip** (CC0, pure registration country) is a possible alternative key; not wired. **RIPE NCC delegated files** read directly: their copyright statement restricts use and its scope over the statistics files is unclear. **X4BNet/lists_vpn and IPLocate**: derived from a CC BY-SA 4.0 database (share-alike). **A licensed list of VPN ASNs**: none was found, so VPN detection is the name classifier (it finds a VPN company that says so in its name, and misses one that does not).

**Caveat of the country source.** sapics compiles `user-country` from RIR delegated statistics, Route Views and RIPE RIS routing data and public geofeeds; its README says many geofeeds "lack explicitly defined licenses" and that the RIR input is subject to the NRO licence and the RIR copyright statements. The PDDL statement is the maintainer's. A lawyer should confirm that chain before launch.

**Optional paid source (host-supplied, not integrated): MaxMind GeoIP Country.** USD 418 per year and legal entity at the time of checking, no attribution clause in the EULA or the GeoIP database addendum, daily updates, use limited to the licensee's internal business purposes (fraud prevention for yourself is named), old versions destroyed within 30 days, no passing the data to third parties. The package therefore never fetches it. A host that buys it reads its own copy and builds the facts itself, which replaces `NetworkDatabase::lookup()` for the country:

```php
$facts = new NetworkFacts(NetworkFacts::STATE_OK, $countryFromYourMaxMindCopy, $asn, $category);   // registrationCountry stays null: the rule then uses the single country
```

### Host API

```php
// 1. Scheduled job (daily is enough). Never on a request. The country files come from raw.githubusercontent.com (no redirect; the release URL redirects).
$network = NetworkDatabase::withDefaults($yourRangeFetcher, $yourCrawlerCache);   // the same interfaces the crawlers and IpReputation use
$network->refreshStale();            // ['country_ipv4' => 'refreshed'|'fresh'|'failed', 'country_ipv6' => ..., 'iptoasn' => ..., 'bad_asn_list' => ...]
// Or from a shell:  php -d memory_limit=512M tools/network/refresh.php --cache-dir=/var/cache/device-id
//                   php tools/network/refresh.php --cache-dir=/var/cache/device-id --lookup=8.8.8.8

// 2. Per request (cache reads only, ~0.1 ms, no network):
$facts   = $network->lookup($ip)->withReputation($ipReputation->lookup($ip));      // NetworkFacts; or build one from your CDN's country header
$verdict = $verdictScorer->score($claims, $transport, $deviceKey, $salt, $confidence, $facts);   // adds the network and locale rules
$soft    = SmartSignals::features($claims, $facts, $transport) + $facts->features();            // model features
[$verdict, $opinion] = $modelScorer->score($scored, $soft + $reputation->features());
$row     = $trainingRowBuilder->build($scored, $deviceKey, $engine, $mobile, $protected, $label, $source, $weight, $at, $soft, $facts);  // country + category bucket only

// 3. Velocity (pure functions over history YOU select; thresholds from fingerprint.velocity.*):
Velocity::burst('signup', 'device_key', $key, $timestampsOfThatKeyInTheLastDay, time());          // ?VelocityFinding
Velocity::burst('login', 'network_hash', $hash, $timestamps, time());
Velocity::impossibleTravel($accountId, $sessions);   // [['at' => int, 'country' => 'NL', 'anonymised' => bool], ...]
Velocity::features($findings);  $finding->toReviewItem();                                    // model features, review queue
```

Cache cost (measured 2026-10-31): about 470 keys and 35 MB for the network datasets (shards are base64 so a JSON cache stores them); a refresh needs `ext-zlib` and about 120 MB of memory and took 5 seconds. Velocity configuration (`fingerprint.velocity.*`): `window_seconds` 3600, `signups_per_device` 3, `logins_per_device` 10, `signups_per_network` 8, `logins_per_network` 30, `max_speed_kmh` 1000, `min_distance_km` 500, `min_seconds_between` 300.

Impossible travel judges the *smallest possible* distance between two countries (between their bounding boxes, overseas territories included, so neighbours and France or the USA are 0 km from much of the world). It under-detects by design and cannot raise a false alarm from a large country's centroid. A VPN, proxy, hosting or Tor session (`anonymised: true`) is skipped, because its country says nothing about the person.

## E-mail, account novelty, velocity v2, feedback and reasons (minFraud lessons, 2026-10-31)

All of this is soft evidence: features and reason codes, never a block by itself, and silent (`null`, `unknown`) when its data is missing. Nothing here shows a credit to a visitor. The pieces are pure functions or cache readers; the package stores nothing and runs no query, and no DNS or download runs on a request.

### E-mail (`src/Email/`)

| piece | what it does |
|---|---|
| `EmailNormalizer` | WelZoLekker's canonical form, ported and made strict: lower case, `+tag` removed everywhere, dots removed and `googlemail.com` folded for Gmail, a keyed HMAC `hash()` for equality, `aliasSpread()` (distinct typed addresses per mailbox, counts only) |
| `DomainLists` + `DomainFeedCatalogue` | host-refreshed (same `RangeFetcher` and `CrawlerCache` as the network data) disposable domains from disposable-email-domains (CC0) and disposable/disposable `domains_mx.txt` (MIT, notice in `LICENSE-THIRD-PARTY.md`), and free-mailbox providers and alias services (Hide My Email, SimpleLogin, Firefox Relay, DuckDuckGo) from `mailservices.json` (MIT). Sharded by `crc32(domain) % 64`; a subdomain of a disposable domain is disposable; a stale list answers `null`, never "not disposable". The strict list is not used (it contains outlook.com) |
| `DomainMailCheck` + `MailDnsResolver` | the optional "can this domain receive mail?" check. `refresh()` runs in a **host job** and stores the outcome; `peek()` reads the cache on the request. `no_mail` needs two resolver answers an hour apart (a DNS outage never flags a domain); a resolver failure is `unknown` and never changes a stored outcome. `NativeMailDnsResolver` is a fallback over `dns_get_record()` with a control lookup |
| `GeneratedAddress` | random or machine-made local parts: five independent signs (digits, entropy, letter/digit switches, consonant runs, hex, letters plus a long number); one sign is `possible`, two are `likely`; not judged on a forwarding domain. `largestStemFamily()` counts `name123`, `name124`... among addresses from one network |
| `EmailAssessor` / `EmailAssessment` | puts it together for one address: `domainClass` (disposable, forwarding, free, other, unknown, invalid), features (`email_disposable`, `email_free`, `email_forwarding_alias`, `email_domain_no_mx`, `email_generated`, `email_tagged`), reason codes with direction, and three training buckets. It has no score, band or weight: a disposable address alone never blocks |

```php
// Scheduled job: $lists = DomainLists::withDefaults($fetcher, $cache);  $lists->refreshStale();
// Queue job after a sign-up:  $assessor->checkDomain($email);              // DNS happens here, with a MailDnsResolver
// Request:                    $assessment = $assessor->assess($email);    // cache reads only
$soft = $assessment->features() + ['email_multiple_aliases' => 1.0 /* from EmailNormalizer::aliasSpread */];
$row  = $trainingRowBuilder->build($scored, $deviceKey, $engine, $mobile, $protected, $label, $source, $weight, $at, $soft, $facts, $assessment);
```

Training rows carry the e-mail facts only as feature names and numbers and as three buckets (`email.domain_class`, `email.mx`, `email.generated`); `assertDeidentified()` now also refuses any string that looks like a domain. Never an address, a domain or a hash of either.

### Account novelty (`Signals\AccountNovelty`)

`AccountNovelty::assess($history, $current)` over observations the host selects from its own tables (`device_key`, `country`, `asn`, `language`, `os`; history also `at`, `trusted`, `anonymised`) answers `acct_new_device`, `acct_new_country`, `acct_new_asn`, `acct_new_language`, `acct_new_os`, and the lowering `acct_known_device` / `acct_known_country`. Never on an account's first observation; a dimension the history never knew is unknown, not new; `trusted: false` and anonymised (VPN, hosting, Tor) entries do not become the baseline, and an anonymised current visit raises neither country nor network; history older than `fingerprint.novelty.history_days` (365) is ignored. A new device in a new country sets `suggestsStepUp` (ask for a challenge before a sensitive action, do not refuse). `AccountNovelty::observationFrom($deviceKey, $claims, $facts)` builds the current observation.

### Velocity v2 (`Velocity::distinct()`)

Distinct counts over three windows (1 hour, 24 hours, 7 days): distinct **accounts per device key**, distinct **device keys per account**, distinct **e-mail hashes per network**. One finding per window that reaches its limit, one model feature each (`vel_accounts_per_device_1h` ... `vel_emails_per_network_7d`). A device key shared by `distinct_k_floor` (20) accounts is a device class and stays silent; a network is shared by design (informational at the limit). Configuration `fingerprint.velocity.distinct.<relation>.<window>` (defaults: accounts per device 3/4/6, devices per account 3/5/8, e-mails per network 6/12/25; limits never decrease with the window) and `fingerprint.velocity.distinct_k_floor`.

```php
Velocity::distinct(Velocity::ACCOUNTS_PER_DEVICE, $deviceKey, $events /* [['at' => int, 'value' => $accountId], ...] */, time());   // list<VelocityFinding>
```

### First-party network history (`Signals\NetworkReputation`)

`NetworkReputation::assess($devices, $confirmed, $suspected, $cleared)` turns the host's own labelled history of one network (distinct devices in 7 days) into `net_history_bad`, with a k-floor of 20, `suspected` worth half and `not_abuse` clearances subtracted. It replaces the removed credited abuse list. `fingerprint.network_reputation.{k_floor,minimum_bad,bad_share}`.

### Feedback labels and shadow weights

* `Feedback\FeedbackLabel` is a closed vocabulary: `confirmed_fraud` (training weight 1), `suspected` (0.5), `not_abuse` (label `honest`, weight 1) and `clear` (retract). `FeedbackResolver::resolve()` takes the reports on a subject (the last one wins, `clear` retracts the earlier ones) and `relabelRows()` applies the result to the training rows of that device in the reported week, so a false-positive report lowers the positive rows it contradicts. Notes are for people and never enter a row.
* **Shadow weights** (minFraud's `test` disposition for a rule): put a code and a weight in `fingerprint.constraint_weights_shadow`; `ShadowWeights::compare($claims, $transport, $network, $liveVerdict)` returns the weight, score and band the visit WOULD have had next to the live ones, and which tested rules fired. A rule live at weight 0 shows what it would have added. Nothing shadow is ever summed into a verdict; promote by moving the number to `constraint_weights`.

### Reason codes with direction (`Reasons\ReasonCatalogue`)

Every rule code, every soft reason and the de-escalators have a **direction**, `raises` or `lowers` (minFraud's multiplier above or below one, kept additive here). Rule codes always raise; the lowering ones are `acct_known_device`, `acct_known_country`, `history_not_abuse`, `allow_listed` and a `model_adjustment` with a negative weight. `ReasonCatalogue::explain($verdict, $softFeatures, $extraCodes)` returns the list a review screen renders, raising reasons first by weight, identically in every host; `all()` is the catalogue for a documentation page. A test pins that every optional model feature has a reason or is declared context only (`email_free`, `email_tagged`, `sig_private_mode`).

### Future work (documented, not built)

* **Host composite rules** (`fingerprint.custom_rules`: `{all: [codes, features, thresholds], then: weight|review|allow, label, mode: shadow|active}`, capped, respecting the maximum of 45 and no-single-block): worth building once these features exist in production data, otherwise there is little to combine.
* **Residential-proxy and relay heuristics** (TCP versus application round-trip gap, per-network share of locale-mismatching visitors over 7 days, iCloud Private Relay ranges): feature-only until the capture harness has measured them; needs `TCP_INFO` plumbing that is unverified on the hosts; no free licensed residential-proxy list exists.
* Domain age through RDAP, first-seen-in-our-system for an e-mail hash, a per-device top-2 % activity percentile: host-side storage.

## Machine learning (`src/Model/`, `src/Scoring/ModelScorer.php`, `src/Matching/`, `src/Detectors/`, `src/Reputation/`, `tools/ml/`)

Everything here is plain PHP 8.2: no extension, no Python, no network, no GPU. Training runs on the application's own server. The rules stay the decision-maker; the model is a bounded second opinion, and every part falls back to the rules when it is missing.

### What the model is

A calibrated logistic regression over **rule hits and facts the client did not type**: one indicator per `CheckRegistry` code, the number of distinct rule families, integrity findings, coverage, untrusted components, omitted probes, a protected-privacy-mode flag, and optional soft IP-reputation flags. **Never** the User-Agent or any token of it, brands, claimed OS, a declared crawler, an IP, an id or a device key (`FeatureCatalogue::EXCLUDED`; a test pins it). A silenced (weight 0) rule is silent to the model too.

The model is a sealed JSON file (`ModelSpec`, schema 1, sha256 over the content). The package ships none; the host points `fingerprint.model.path` at one. Any file problem is a state, never an exception: `absent`, `stale` (older than `fingerprint.model.max_age_days`, default 45), `incompatible` (wrong schema or a feature this engine cannot produce), `corrupt` (hash mismatch, a tampered model is never evaluated), `error`. In every state the rules decide.

### Modes (`fingerprint.model.mode`)

| mode | effect |
|---|---|
| `off` (default) | nothing computed |
| `shadow` | the opinion is computed and returned for logging (`ModelOpinion::toArray()`), the verdict is untouched |
| `advise` | as shadow; the host shows the opinion and its top contributions beside the rule list |
| `bounded` | the opinion becomes ONE disagreement, `model_adjustment`, inside the verdict |

`bounded` is limited by construction (each bound has a test): the score still reconstructs from `Verdict::totalWeight()`; the weight is capped at `fingerprint.model.max_adjustment_weight` (20, never above 60); a positive adjustment needs rule hits in at least 2 distinct families; a visitor with no contradiction is never touched; the model never moves a verdict into `block` that the rules had not reached (the adjustment is reduced and `ModelOpinion::$suggestsReview` is set so the host can open a 48-hour human-reviewed hold); a negative adjustment can never take a verdict below `elevated` while transport evidence is present; allowed traffic (verified crawler, monitor, operator list) is never adjusted; `fingerprint.model.allow_deescalation` can forbid negative adjustments.

### The API a host calls

```php
$scorer  = ModelScorer::fromConfig($verdictScorer);            // reads fingerprint.model.*
$scored  = ...;                                                  // the host's existing ScoredClaims
[$verdict, $opinion] = $scorer->score($scored, $reputation?->features() ?? []);
// store $opinion->toArray() with the observation; act on $verdict as before
```

### Training on the server

```
php tools/ml/train.php --rows=training-rows.jsonl --out=storage/fingerprint/models/verdict.json
```

`training-rows.jsonl` is one `TrainingRowBuilder::build()` result per line (de-identified: features, label, a KEYED group hash, an ISO week, bucketed context, `retention_days` and `expires_on`, no IP, no User-Agent, no id; `assertDeidentified()` enforces it). The trainer splits **by linked unit, never by row**: the connected components of "same `group`" (a device, machine or evasion recipe) and "same `account_group`" (the keyed account hash `TrainingRowBuilder::build(..., accountKey:)` adds, because labels are per account), so no account and no device is on two sides. It splits three ways (`--calibration=0.25`, `--validation=0.25`): it fits L2 logistic regression by Newton's method on train (a rule-hit coefficient may not be negative), fits the Platt calibration and the rules' calibration on the calibration split, and measures every reported metric on the validation split, which neither trained nor calibrated the model (before 2026-10-31 the calibration was fitted on the validation rows themselves, so ECE was in-sample). Platt needs at least 20 calibration rows with both classes; below that the identity is used and the document says so (`calibration.fitted_on`). It writes the sealed model plus a report with the learned-versus-shipped weight proposal and bootstrap intervals. The calibration is to the training prevalence unless `--assumed-prevalence` is given. With no `--rows` it trains on the committed harness dataset.

### Evaluation

```
php tools/ml/evaluate.php --model=verdict.json --fail-on-slice-regression
```

Offline. Reports, for the rules alone and the model on the same held-out rows, overall and per slice (engine, mobile/desktop, privacy mode, label class): recall and false-positive rate at the shipped challenge band, precision and recall at fixed false-positive rates (1 %, 0.5 %, 0.1 %, flagged `resolution-limited` when there are fewer honest rows than 1/target), AUC, and calibration (ECE with the reliability bins). A rate with no honest rows in the slice is `n/a`, never 0. `--fail-on-slice-regression` exits 1 when the model's false-positive rate exceeds the rules' on any slice.

Harness data: `npm run ml:variants` runs the real collector in Playwright browsers over honest context variants and spoof recipes (user agent and navigator patches, WebGL, screen, time zone, canvas noise, a stealth bundle, device emulation) written as plain init scripts; `php tools/ml/make-dataset.php` turns the runs into dataset records (`tests/Fixtures/ml/dataset`). Its honest class is scripted browsers on one machine, not people, and it has no honest WebKit, mobile or privacy-mode rows.

**Honest metrics on the committed harness set (66 rows, run 2026-10-31, after the split fix):** train 32 /
calibration 17 / validation 17 rows. 17 calibration rows are below Platt's minimum of 20, so the model is
UNcalibrated (identity) on this set. On the 17 validation rows (5 honest): rules recall 0.75, FPR 0, AUC 0.967;
model recall 0.917 and FPR 0 at p = 0.5, AUC 0.967, ECE 0.093 (above the 0.05 criterion). Before the fix the
same command reported ECE 0.082 measured on the rows it was calibrated on, and model FPR 0.8 at p = 0.5. Five
honest rows cannot support any FPR claim; the harness rows carry no account linkage, so for them the unit is
the group. These numbers say the pipeline works, not that a model is ready.

### Promotion criteria (all required, on held-out rows the model never trained on or was calibrated on)

1. At the rules' false-positive rate the model's recall is at least 10 points higher and its false-positive rate is not higher.
2. On every slice (Chromium, Gecko, WebKit, protected modes, mobile) the model's false-positive rate is not higher than the rules'.
3. ECE of at most 0.05 per slice.
4. At least 1,000 labelled honest rows per slice and at least 200 non-honest rows from at least two label sources.
5. Two consecutive retrains agree on the sign of every coefficient.
6. A person has read the top 20 coefficients and none is a self-reported or privacy-protective feature with a positive weight.

Until then keep `shadow` or `advise`. A model blocks nothing on its own.

### Learned matcher (Fellegi-Sunter)

`DeviceMatcher::comparisons()` is the one place the component comparison rules live. `tools/ml/fit-matcher.php --pairs=pairs.jsonl` estimates `m` and `u` by EM (labelled where the host knows, unlabelled otherwise) into asymmetric agree/disagree weights in bits (`LearnedWeights`, loaded through a `MatcherWeightsSource`). `fingerprint.matcher_learned.mode` is `off`, `shadow` (the learned posterior is returned on `MatchResult::$shadowPosterior`, the decision is the hand matcher's) or `active`, which is honoured only when every slice has 1,000 pairs; otherwise it runs as `shadow`.

Hand defaults from the 2026-10-31 literature survey, always on (`MatcherPolicy`, `fingerprint.matcher_policy`): `gpuCaps` (static) weighs more than `gpuMath` (an output hash) when the host did not configure it; `gpuMath`, `keyboard`, `gpuCaps` never veto; a mobile (touch) or WebKit match needs a posterior of 0.9 to link (`mobile_webkit_link_posterior`), below that it is `possible` with veto `stricter_threshold`; keyboard layout is not counted on top of an agreeing voice set (`keyboard_independent_of_language` switches that off).

### Detectors, reputation and the rest

* `RingDetectors` are pure functions over aggregates the host computes with its own SQL (accounts per device key, devices per account, bursts per network), with a k-floor of 20: a key shared by 20 or more accounts is a device class, not a ring, and a burst is not judged against a baseline of fewer than 20 observations. They produce `ReviewItem`s for a review queue (`ReviewSink`); they enforce nothing. An anomaly model is deliberately **not built**: `AnomalyModel` is an interface and its docblock records the evidence that would justify one.
* `IpReputation` loads free feeds through the crawler `RangeFetcher`/`CrawlerCache` interfaces. The licence finding for each feed is in `FeedCatalogue` (dated 2026-10-31): the Tor exit list (CollecTor, CC0) is on by default; AWS, Google Cloud, Oracle and DigitalOcean publish no licence text and are loaded only when the host accepts them by key (`$acceptUnverified`); Spamhaus DROP was removed because it requires credit; FireHOL level1 is excluded because it contains DShield data (NonCommercial). A list older than 7 days is ignored, never read as clean; a failed fetch keeps the last good list. The result carries no score or band: it is a soft model feature and a rule input, and an address alone never blocks.
* Retention of training rows is metadata on the row (`retention_days`, default 365); the host's job deletes at `expires_on`.

