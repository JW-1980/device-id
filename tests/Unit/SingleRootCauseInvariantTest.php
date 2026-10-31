<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\CheckRegistry;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Scoring\ModelScorer;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Settings;
use DeviceId\Support\Config;
use DeviceId\Support\TransportRequestFacts;
use DeviceId\Support\Verdict;
use DeviceId\Tests\Support\SingleCausePerturbations;
use DeviceId\Transport\TransportIntegrity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../tools/capture/CaptureAnalysis.php';
require_once __DIR__.'/../Support/SingleCausePerturbations.php';

/**
 * No single root cause can block (skeptical review H2).
 *
 * Several rules can read one underlying fact: a User-Agent switcher makes the UA disagree with
 * Sec-CH-UA-Full-Version-List (`transport_sec_ch_full_version_mismatch`), with the un-redacted
 * version list in JavaScript (`ua_vs_ch_major`) and with the engine's feature set
 * (`ua_vs_feature_version`). Summed, that one fact weighed 95 and scored 92 (`block`) on a real
 * Chromium whose only change was its User-Agent. `CheckRegistry::EVIDENCE_GROUPS` declares which
 * rules share evidence, and the scorer counts each group once, at its heaviest member.
 *
 * The invariant is enforced on facts, not on rules: every honest capture fixture under every
 * single-cause perturbation ({@see SingleCausePerturbations}) and the real single-cause captures
 * stay below `block`, and no perturbation of any capture adds more than one group's weight.
 */
final class SingleRootCauseInvariantTest extends TestCase
{
    private const CAPTURES = __DIR__.'/../Fixtures/fingerprint/captures';

    private const REDTEAM = __DIR__.'/../Fixtures/fingerprint/redteam';

    private const SINGLE_CAUSE = __DIR__.'/../Fixtures/fingerprint/single-cause';

    private const MODEL_FIXTURE = __DIR__.'/../Fixtures/model/verdict-logit-test.json';

    protected function setUp(): void
    {
        parent::setUp();
        CaptureAnalysis::configure();
    }

    protected function tearDown(): void
    {
        Config::reset();
        ModelScorer::forgetLoadedModels();
        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private static function load(string $path): array
    {
        /** @var array<string, mixed> $record */
        $record = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);

        return $record;
    }

    /**
     * @return list<string>
     */
    private static function honestFixtures(): array
    {
        // Honest = headed with automation switches suppressed (`labels.class` honest); the red-team
        // headless baseline is a headless browser and already challenged on its own.
        $files = [...(glob(self::CAPTURES.'/*.honest.json') ?: []), ...(glob(self::REDTEAM.'/*.headed.honest-baseline.json') ?: [])];
        sort($files);

        return $files;
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function honestPerturbations(): array
    {
        $out = [];
        foreach (self::honestFixtures() as $file) {
            foreach (array_keys(SingleCausePerturbations::all()) as $name) {
                $out[basename($file, '.json').' / '.$name] = [$file, $name];
            }
        }

        return $out;
    }

    #[Test]
    public function there_are_honest_fixtures_and_perturbations_to_test(): void
    {
        $this->assertGreaterThanOrEqual(2, count(self::honestFixtures()));
        $this->assertGreaterThanOrEqual(30, count(SingleCausePerturbations::all()));
    }

    #[Test]
    #[DataProvider('honestPerturbations')]
    public function one_root_cause_never_blocks_an_honest_browser(string $file, string $perturbation): void
    {
        $perturbed = (SingleCausePerturbations::all()[$perturbation])(self::load($file));
        if ($perturbed === null) {
            $this->assertTrue(true, 'the cause does not apply to this capture');

            return;
        }

        $answer = CaptureAnalysis::analyse($perturbed);
        foreach (['merged', 'tier1'] as $view) {
            $this->assertNotSame('block', $answer[$view]['band'], sprintf(
                '%s view: %s blocked an honest capture (score %d, codes %s)',
                $view, $perturbation, $answer[$view]['score'], implode(', ', array_keys($answer[$view]['codes'])),
            ));
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function everyCapture(): array
    {
        $files = [...(glob(self::CAPTURES.'/*.json') ?: []), ...(glob(self::REDTEAM.'/*.json') ?: [])];
        $out = [];
        foreach ($files as $file) {
            if (basename($file) !== 'expectations.json') {
                $out[basename($file, '.json')] = [$file];
            }
        }
        ksort($out);

        return $out;
    }

    #[Test]
    #[DataProvider('everyCapture')]
    public function one_root_cause_adds_at_most_one_evidence_group_to_any_capture(string $file): void
    {
        $record = self::load($file);
        $base = CaptureAnalysis::analyse($record);

        foreach (SingleCausePerturbations::all() as $name => $perturb) {
            $perturbed = $perturb($record);
            if ($perturbed === null) {
                continue;
            }
            $answer = CaptureAnalysis::analyse($perturbed);
            foreach (['merged', 'tier1'] as $view) {
                $added = $answer[$view]['total_weight'] - $base[$view]['total_weight'];
                $this->assertLessThanOrEqual(EnvironmentConsistency::MAX_WEIGHT, $added, sprintf(
                    '%s view: %s added effective weight %d (codes %s)', $view, $name, $added, implode(', ', array_keys($answer[$view]['codes'])),
                ));
            }
        }
    }

    #[Test]
    public function a_real_chromium_with_only_its_user_agent_overridden_is_challenged_not_blocked(): void
    {
        $answer = CaptureAnalysis::analyse(self::load(self::SINGLE_CAUSE.'/linux-container.linux.chromium.headed.ua-override.json'));

        foreach (['merged', 'tier1'] as $view) {
            // Still detected: the UA is a lie the transport proves. One lie, one group: challenge.
            $this->assertSame('challenge', $answer[$view]['band'], $view);
            $this->assertArrayHasKey('transport_sec_ch_full_version_mismatch', $answer[$view]['codes']);
            $this->assertArrayHasKey('ua_vs_ch_major', $answer[$view]['codes']);
            $this->assertArrayHasKey('ua_vs_feature_version', $answer[$view]['codes']);
        }
        // 45 for the User-Agent group (its heaviest member) + 6 for the harness's UTC/en-US artefact.
        $this->assertSame(51, $answer['merged']['total_weight']);
        $this->assertSame(72, $answer['merged']['score']);
    }

    #[Test]
    public function a_real_chromium_with_only_its_time_zone_overridden_passes(): void
    {
        $answer = CaptureAnalysis::analyse(self::load(self::SINGLE_CAUSE.'/linux-container.linux.chromium.headed.timezone-override.json'));

        $this->assertSame('pass', $answer['merged']['band']);
        $this->assertSame(['tz_vs_lang_region'], array_keys($answer['merged']['codes']));
    }

    #[Test]
    public function firefox_resist_fingerprinting_alone_stays_below_challenge(): void
    {
        $answer = CaptureAnalysis::analyse(self::load(self::SINGLE_CAUSE.'/linux-container.linux.firefox.headed.resist-fingerprinting.json'))['merged'];

        // The capture is driven, so navigator.webdriver is true (20, the automation class's own
        // signal). Without it, what the privacy mode alone costs must stay below challenge.
        $this->assertArrayHasKey('webdriver_true', $answer['codes']);
        $withoutDriver = array_filter($answer['codes'], static fn (string $code): bool => $code !== 'webdriver_true', ARRAY_FILTER_USE_KEY);
        $disagreements = array_map(static fn (string $code, array $meta): array => ['code' => $code, 'detail' => '', 'weight' => $meta['weight']], array_keys($withoutDriver), $withoutDriver);
        $scorer = new VerdictScorer(new EnvironmentConsistency);

        $this->assertNotSame('challenge', $scorer->bandFor($scorer->scoreFor(CheckRegistry::effectiveWeight($disagreements))));
        $this->assertNotSame('block', $answer['band']);
    }

    #[Test]
    public function the_headers_of_a_ua_switcher_alone_do_not_block(): void
    {
        // The review's band_math.php: a Chrome 141 user whose UA header alone says Chrome 139.
        $headers = [
            ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'],
            ['sec-ch-ua', '"Chromium";v="141", "Google Chrome";v="141", "Not?A_Brand";v="99"'],
            ['sec-ch-ua-full-version-list', '"Chromium";v="141.0.7390.54", "Google Chrome";v="141.0.7390.54", "Not?A_Brand";v="99.0.0.0"'],
            ['sec-ch-ua-mobile', '?0'], ['sec-ch-ua-platform', '"Windows"'], ['accept', 'text/html'], ['upgrade-insecure-requests', '1'],
            ['sec-fetch-site', 'none'], ['sec-fetch-mode', 'navigate'], ['sec-fetch-user', '?1'], ['sec-fetch-dest', 'document'],
            ['accept-language', 'nl-NL'], ['accept-encoding', 'gzip, deflate, br, zstd'],
        ];
        $transport = (new TransportIntegrity)->analyse($headers, new TransportRequestFacts(headerOrderAvailable: false));

        $verdict = (new VerdictScorer(new EnvironmentConsistency))->score([], $transport);

        $this->assertSame(['transport_sec_ch_full_version_mismatch', 'ua_vs_ch_major'], $verdict->reasons);
        $this->assertSame(Verdict::BAND_CHALLENGE, $verdict->band);
        $this->assertSame(45, $verdict->totalWeight());
    }

    #[Test]
    public function every_evidence_group_is_bounded_by_the_rule_ceiling_and_the_ceiling_cannot_block(): void
    {
        $scorer = new VerdictScorer(new EnvironmentConsistency);
        $weights = EnvironmentConsistency::weights();

        foreach (CheckRegistry::evidenceGroups() as $group => $codes) {
            $this->assertNotEmpty($codes, $group);
            foreach ($codes as $code) {
                $this->assertTrue(CheckRegistry::isKnown($code), "{$group}: {$code} is not a registered check");
                $this->assertSame($group, CheckRegistry::evidenceGroupOf($code));
            }
        }
        foreach (CheckRegistry::codes() as $code) {
            $this->assertLessThanOrEqual(EnvironmentConsistency::MAX_WEIGHT, $weights[$code] ?? CheckRegistry::weightFor($code, new Settings), $code);
        }

        // The ceiling: one root cause is one group, and one group weighs at most MAX_WEIGHT.
        $this->assertLessThan(80, $scorer->scoreFor(EnvironmentConsistency::MAX_WEIGHT));
        $this->assertSame('challenge', $scorer->bandFor($scorer->scoreFor(EnvironmentConsistency::MAX_WEIGHT)));
        $this->assertFalse($scorer->singleCauseCanBlock());

        // An operator override cannot lift a weight above the ceiling.
        Config::use(['fingerprint' => ['constraint_weights' => ['ua_vs_ch_major' => 99]]]);
        $this->assertSame(EnvironmentConsistency::MAX_WEIGHT, EnvironmentConsistency::weights()['ua_vs_ch_major']);
    }

    #[Test]
    public function a_scoring_configuration_that_lets_one_cause_block_is_reported(): void
    {
        Config::use(['fingerprint' => ['score_divisor' => 10, 'bands' => ['elevated' => 40, 'challenge' => 60, 'block' => 80]]]);

        $this->assertTrue((new VerdictScorer(new EnvironmentConsistency))->singleCauseCanBlock());
    }

    #[Test]
    public function rules_in_one_group_count_once_and_independent_groups_still_add_up(): void
    {
        $scorer = new VerdictScorer(new EnvironmentConsistency);
        $hit = static fn (string $code, int $weight): array => ['code' => $code, 'detail' => '', 'weight' => $weight];

        $oneCause = $scorer->merged([], [$hit('transport_sec_ch_full_version_mismatch', 45), $hit('ua_vs_ch_major', 25), $hit('ua_vs_feature_version', 25)]);
        $this->assertSame(45, $oneCause->totalWeight());
        $this->assertSame(95, $oneCause->rawWeight(), 'every rule is still listed at its own weight');
        $this->assertSame(Verdict::BAND_CHALLENGE, $oneCause->band);

        // Two independent causes (a UA lie and a patched descriptor) are two groups: block.
        $twoCauses = $scorer->merged([], [$hit('transport_sec_ch_full_version_mismatch', 45), $hit('ua_vs_ch_major', 25), $hit('descriptor_patched', 30)]);
        $this->assertSame(75, $twoCauses->totalWeight());
        $this->assertSame(Verdict::BAND_BLOCK, $twoCauses->band);
    }

    #[Test]
    public function one_root_cause_plus_the_model_at_its_cap_never_blocks(): void
    {
        $rules = new VerdictScorer(new EnvironmentConsistency);
        Config::use(['fingerprint' => ['model' => ['mode' => ModelScorer::MODE_BOUNDED, 'path' => self::MODEL_FIXTURE, 'max_age_days' => 100000, 'max_adjustment_weight' => EnvironmentConsistency::MAX_WEIGHT]]]);
        $model = ModelScorer::fromConfig($rules, 1793491200);

        // Every member of every group firing at once, at the ceiling: still one cause per group.
        foreach (CheckRegistry::evidenceGroups() as $group => $codes) {
            $verdict = $rules->merged([], array_map(static fn (string $code): array => ['code' => $code, 'detail' => '', 'weight' => EnvironmentConsistency::MAX_WEIGHT], $codes));
            $this->assertNotSame(Verdict::BAND_BLOCK, $verdict->band, $group);

            // The fixture model is maximally suspicious (integrity, low coverage, untrusted, omitted).
            [$adjusted, $opinion] = [$model->apply($verdict, $opinion = $model->opinion($verdict, 5, 0, 6, 6)), $opinion];
            $this->assertNotSame(Verdict::BAND_BLOCK, $adjusted->band, "{$group} + model");
            $this->assertLessThanOrEqual(0, $opinion->adjustmentWeight, "{$group}: one cause is one independent group, so the model may not escalate it");
        }
    }
}
