# `jw-1980/device-id`

Device fingerprinting for PHP: the server-side engine that turns a browser collector's claims
into a **keyed device key**, a **risk verdict** (score + band + reasons) and a **confidence**
number (1–100: how much of the expected measurement surface answered). Framework-free: plain
PHP 8.2+, no Laravel, no Symfony, no PSR-7.

This repository is the **single place the engine is developed**. Applications install it with
Composer; they never copy it. Current consumers: NutriCompare and WelZoLekker.

> The PHP namespace is still `NutriCompare\Fingerprint\…` (where the engine was born). It is kept
> so the move into this package did not rewrite every `use` statement in the consumers; renaming
> it is a separate, mechanical change.

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
| `behavior` (passive input aggregates) | ported from WelZoLekker's collector, changed: listener lifecycle (stopped after the tier-2 snapshot), handlers cannot raise page errors; tier 2, `late`, no key (session data) |
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

## Usage without a framework

```php
require 'vendor/autoload.php';   // or src/autoload.php for a drop-in copy

use NutriCompare\Fingerprint\Settings;

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
  PSR-4 map points `NutriCompare\Fingerprint\` at `vendor/jw-1980/device-id/src/`.
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
resolves every `NutriCompare\Fingerprint\…` import to a file and refuses to pass if one does
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
