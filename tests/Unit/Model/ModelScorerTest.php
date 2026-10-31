<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Model;

use DeviceId\Model\ModelSpec;
use DeviceId\Rules\EnvironmentConsistency;
use DeviceId\Scoring\ModelScorer;
use DeviceId\Scoring\VerdictScorer;
use DeviceId\Support\Config;
use DeviceId\Support\Verdict;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The bounded second opinion. Every bound in the {@see ModelScorer} docblock has a test that
 * fails when the bound is removed, and the fixture model's numbers are worked by hand in the
 * comments (rules calibration: sigmoid(0.08 * weight - 2); model: see the golden test).
 */
final class ModelScorerTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../../Fixtures/model/verdict-logit-test.json';

    private const NOW = 1793491200;

    private VerdictScorer $rules;

    protected function setUp(): void
    {
        parent::setUp();
        $this->rules = new VerdictScorer(new EnvironmentConsistency);
        ModelScorer::forgetLoadedModels();
    }

    protected function tearDown(): void
    {
        Config::reset();
        ModelScorer::forgetLoadedModels();
        parent::tearDown();
    }

    /**
     * @param  array<string, mixed>  $model
     */
    private function scorer(string $mode, array $model = []): ModelScorer
    {
        Config::use(['fingerprint' => ['model' => ['mode' => $mode, 'path' => self::FIXTURE, 'max_age_days' => 100000] + $model]]);

        return ModelScorer::fromConfig($this->rules, self::NOW);
    }

    /**
     * @param  list<array{string, int}>  $hits
     */
    private function verdict(array $hits): Verdict
    {
        return $this->rules->merged([], array_map(static fn (array $h): array => ['code' => $h[0], 'detail' => '', 'weight' => $h[1]], $hits));
    }

    /** webdriver_missing (integrity, 25) + ua_vs_ua_header (transport, 20) = 45: rules p = sigmoid(1.6) */
    private function twoFamilies(): Verdict
    {
        return $this->verdict([['webdriver_missing', 25], ['ua_vs_ua_header', 20]]);
    }

    #[Test]
    public function off_computes_nothing_and_changes_nothing(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_OFF);
        $verdict = $this->twoFamilies();

        $opinion = $scorer->opinion($verdict, 3, 90);

        $this->assertSame(ModelSpec::STATE_OFF, $opinion->state);
        $this->assertFalse($opinion->isUsable());
        $this->assertSame($verdict, $scorer->apply($verdict, $opinion));
    }

    #[Test]
    public function shadow_computes_the_adjustment_but_leaves_the_verdict_alone(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_SHADOW);
        $verdict = $this->twoFamilies();

        // z = -3 + 2.4 + 1.2 + 2*0.6 + 3*0.4 - 0.5*0.9 = 2.55; p = sigmoid(1.1*2.55 - 0.2) = sigmoid(2.605)
        // delta = (2.605 - 1.6) / 0.08 = 12.56 -> +13
        $opinion = $scorer->opinion($verdict, 3, 90);

        $this->assertSame(ModelSpec::STATE_OK, $opinion->state);
        $this->assertEqualsWithDelta(0.93127, $opinion->probability ?? 0.0, 1e-4);
        $this->assertSame(13, $opinion->adjustmentWeight);
        $this->assertFalse($opinion->applied);
        $this->assertSame($verdict, $scorer->apply($verdict, $opinion), 'shadow never touches the verdict');
    }

    #[Test]
    public function advise_also_leaves_the_verdict_alone(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_ADVISE);
        $verdict = $this->twoFamilies();

        $this->assertSame($verdict, $scorer->apply($verdict, $scorer->opinion($verdict, 3, 90)));
    }

    #[Test]
    public function bounded_adds_one_model_adjustment_disagreement_and_the_score_still_reconstructs(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        $verdict = $this->twoFamilies();

        $adjusted = $scorer->apply($verdict, $scorer->opinion($verdict, 3, 90));

        $entries = array_values(array_filter($adjusted->disagreements, static fn (array $d): bool => $d['code'] === ModelScorer::CODE));
        $this->assertCount(1, $entries);
        $this->assertSame(13, $entries[0]['weight']);
        $this->assertStringContainsString('hit:webdriver_missing', $entries[0]['detail']);
        $this->assertSame(58, $adjusted->totalWeight());
        $this->assertSame($this->rules->scoreFor(58), $adjusted->score, 'the score is a function of the disagreements, model included');
        $this->assertTrue($adjusted->hasReason(ModelScorer::CODE));
        $this->assertGreaterThan($verdict->score, $adjusted->score);
    }

    #[Test]
    public function the_adjustment_is_capped_at_the_configured_maximum(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED, ['max_adjustment_weight' => 5]);
        $verdict = $this->twoFamilies();

        $this->assertSame(5, $scorer->opinion($verdict, 3, 90)->adjustmentWeight);
    }

    #[Test]
    public function a_visitor_with_no_contradiction_is_never_touched(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        $clean = $this->rules->merged([], []);

        // Whatever the extras say, with no rule hit there is nothing to adjust.
        $opinion = $scorer->opinion($clean, 5, 10, 6, 6);

        $this->assertSame(0, $opinion->adjustmentWeight);
        $this->assertSame($clean, $scorer->apply($clean, $opinion));
        $this->assertTrue($scorer->apply($clean, $opinion)->isPass());
    }

    #[Test]
    public function one_rule_family_cannot_be_escalated(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        // Both hits are integrity rules: one family. The model would add weight, but may not.
        $verdict = $this->verdict([['webdriver_missing', 25], ['headless_shell_geometry', 8]]);

        $opinion = $scorer->opinion($verdict, 5, 90);

        $this->assertSame(0, $opinion->adjustmentWeight);
        $this->assertSame($verdict, $scorer->apply($verdict, $opinion));
    }

    #[Test]
    public function the_model_never_moves_a_verdict_into_block_on_its_own_and_asks_for_review(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        // Weight 60 is score 78, challenge. The model wants +20, which would be 80, block. Three
        // independent evidence groups (lied_os would share claimed_identity with ua_vs_ua_header).
        $verdict = $this->verdict([['webdriver_missing', 25], ['ua_vs_ua_header', 20], ['tz_intl_vs_date', 15]]);
        $this->assertSame(Verdict::BAND_CHALLENGE, $verdict->band);

        $opinion = $scorer->opinion($verdict, 5, 90);
        $adjusted = $scorer->apply($verdict, $opinion);

        $this->assertSame(3, $opinion->adjustmentWeight, 'weight 63 is score 79, the last value below block');
        $this->assertTrue($opinion->suggestsReview, 'a withheld block is a candidate for a human-reviewed hold');
        $this->assertNotSame(Verdict::BAND_BLOCK, $adjusted->band);
    }

    #[Test]
    public function a_rules_only_block_is_untouched_by_a_model_that_agrees_or_not(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        $blocked = $this->verdict([['webdriver_missing', 25], ['ua_vs_ua_header', 20], ['lied_os', 20], ['ua_headless_token', 30]]);
        $this->assertSame(Verdict::BAND_BLOCK, $blocked->band);

        $opinion = $scorer->opinion($blocked, 5, 90);

        $this->assertGreaterThanOrEqual(0, $opinion->adjustmentWeight, 'the model may agree; it does not need to be reduced below block');
        $this->assertSame(Verdict::BAND_BLOCK, $scorer->apply($blocked, $opinion)->band);
    }

    #[Test]
    public function the_model_cannot_argue_away_transport_evidence_below_elevated(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        // ua_vs_ua_header is a transport rule: evidence the client cannot rewrite. Weight 26 is score 48.
        $verdict = $this->verdict([['ua_vs_ua_header', 20], ['dom_blocker_threw', 6]]);
        $this->assertSame(Verdict::BAND_ELEVATED, $verdict->band);

        // protected = true pulls the model far below the rules (it wants -20).
        $opinion = $scorer->opinion($verdict, 0, 90, 0, 0, true);
        $adjusted = $scorer->apply($verdict, $opinion);

        $this->assertSame(-5, $opinion->adjustmentWeight, 'weight 21 is score 41, the last value at or above elevated (40)');
        $this->assertGreaterThanOrEqual(40, $adjusted->score);
    }

    #[Test]
    public function without_transport_evidence_the_same_model_may_de_escalate_further(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        // The negative control for the test above: no transport rule, so only the cap (-20) binds.
        $verdict = $this->verdict([['lied_languages', 15], ['dom_blocker_threw', 6], ['tz_vs_lang_region', 5]]);

        $opinion = $scorer->opinion($verdict, 0, 90, 0, 0, true);

        $this->assertSame(-20, $opinion->adjustmentWeight);
    }

    #[Test]
    public function de_escalation_can_be_switched_off(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED, ['allow_deescalation' => false]);
        $verdict = $this->verdict([['lied_languages', 15], ['dom_blocker_threw', 6], ['tz_vs_lang_region', 5]]);

        $this->assertSame(0, $scorer->opinion($verdict, 0, 90, 0, 0, true)->adjustmentWeight);
    }

    #[Test]
    public function allowed_traffic_is_never_adjusted(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_BOUNDED);
        $allowed = $this->twoFamilies()->withAllowance(Verdict::ALLOW_VERIFIED_CRAWLER, true);

        $opinion = $scorer->opinion($allowed, 3, 90);

        $this->assertSame(0, $opinion->adjustmentWeight);
        $this->assertSame($allowed, $scorer->apply($allowed, $opinion));
    }

    #[Test]
    public function a_silenced_rule_is_silent_to_the_model_too(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_SHADOW);
        $withHit = $scorer->opinion($this->verdict([['lied_os', 20], ['ua_vs_ua_header', 20]]), 0, 90);
        $silenced = $scorer->opinion($this->verdict([['lied_os', 0], ['ua_vs_ua_header', 20]]), 0, 90);

        $this->assertLessThan($withHit->probability ?? 0.0, $silenced->probability ?? 1.0);
        $this->assertNotContains('hit:lied_os', array_map(static fn ($c) => $c->feature, $silenced->contributions));
    }

    #[Test]
    public function a_missing_model_falls_back_to_the_rules_with_the_state_recorded(): void
    {
        Config::use(['fingerprint' => ['model' => ['mode' => 'bounded', 'path' => '/nonexistent/model.json']]]);
        $scorer = ModelScorer::fromConfig($this->rules);
        $verdict = $this->twoFamilies();

        $opinion = $scorer->opinion($verdict, 3, 90);

        $this->assertSame(ModelSpec::STATE_ABSENT, $opinion->state);
        $this->assertSame($verdict, $scorer->apply($verdict, $opinion));
        $this->assertSame(0, $opinion->adjustmentWeight);
    }

    #[Test]
    public function a_stale_model_falls_back_to_the_rules(): void
    {
        Config::use(['fingerprint' => ['model' => ['mode' => 'bounded', 'path' => self::FIXTURE, 'max_age_days' => 45]]]);
        $scorer = ModelScorer::fromConfig($this->rules, strtotime('2027-03-01'));
        $verdict = $this->twoFamilies();

        $opinion = $scorer->opinion($verdict, 3, 90);

        $this->assertSame(ModelSpec::STATE_STALE, $opinion->state);
        $this->assertSame($verdict, $scorer->apply($verdict, $opinion));
    }

    #[Test]
    public function a_corrupt_model_falls_back_to_the_rules(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'model');
        $this->assertNotFalse($path);
        $document = json_decode((string) file_get_contents(self::FIXTURE), true);
        $document['intercept'] = 5.0;
        file_put_contents($path, json_encode($document));
        Config::use(['fingerprint' => ['model' => ['mode' => 'bounded', 'path' => $path, 'max_age_days' => 100000]]]);

        try {
            $scorer = ModelScorer::fromConfig($this->rules, self::NOW);
            $verdict = $this->twoFamilies();

            $this->assertSame(ModelSpec::STATE_CORRUPT, $scorer->opinion($verdict, 3, 90)->state);
            $this->assertSame($verdict, $scorer->apply($verdict, $scorer->opinion($verdict, 3, 90)));
        } finally {
            @unlink($path);
        }
    }

    #[Test]
    public function an_unset_mode_is_off(): void
    {
        Config::use(['fingerprint' => ['model' => ['path' => self::FIXTURE]]]);

        $this->assertSame(ModelScorer::MODE_OFF, ModelScorer::fromConfig($this->rules)->mode());
    }

    #[Test]
    public function the_opinion_array_carries_names_and_logit_contributions_but_no_values_of_a_person(): void
    {
        $scorer = $this->scorer(ModelScorer::MODE_SHADOW);

        $array = $scorer->opinion($this->twoFamilies(), 3, 90)->toArray();

        $this->assertSame(['state', 'mode', 'model_id', 'p', 'p_rules', 'adjustment', 'applied', 'suggests_review', 'contributions', 'reason'], array_keys($array));
        $this->assertSame(['feature', 'value', 'weight'], array_keys($array['contributions'][0]));
    }

    #[Test]
    public function mutatio_n_a_model_with_the_signs_flipped_does_not_escalate(): void
    {
        $document = json_decode((string) file_get_contents(self::FIXTURE), true);
        $document['coefficients'] = array_map(static fn (float $c): float => -$c, $document['coefficients']);
        $path = tempnam(sys_get_temp_dir(), 'model');
        $this->assertNotFalse($path);
        file_put_contents($path, json_encode(ModelSpec::seal($document)));
        Config::use(['fingerprint' => ['model' => ['mode' => 'shadow', 'path' => $path, 'max_age_days' => 100000]]]);

        try {
            $opinion = ModelScorer::fromConfig($this->rules, self::NOW)->opinion($this->twoFamilies(), 3, 90);

            $this->assertLessThan(0, $opinion->adjustmentWeight, 'the golden +13 above only holds for the real coefficients');
        } finally {
            @unlink($path);
        }
    }
}
