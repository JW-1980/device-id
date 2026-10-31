<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Model;

use DeviceId\Model\LogisticModel;
use DeviceId\Model\ModelSpec;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Golden outputs of the fixture model, written out by hand from the fixture's coefficients
 * (intercept -3.0, Platt a 1.1 b -0.2), so a change to the evaluator, the calibration or the
 * contribution arithmetic fails here. Re-recording means editing these numbers deliberately.
 */
final class LogisticModelGoldenTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../../Fixtures/model/verdict-logit-test.json';

    private function model(?array $document = null): LogisticModel
    {
        $document ??= json_decode((string) file_get_contents(self::FIXTURE), true, 32, JSON_THROW_ON_ERROR);
        $load = ModelSpec::fromArray(ModelSpec::seal($document), 100000, strtotime('2026-11-01'));
        $this->assertNotNull($load['model'], $load['reason']);

        return $load['model'];
    }

    #[Test]
    public function a_visitor_with_two_strong_hits_scores_high_with_the_hits_as_the_reasons(): void
    {
        // z = -3 + 2.4 (webdriver_missing) + 2.0 (ua_headless_token) + 2*0.6 (family_count) - 0.5*0.9 (coverage) = 2.15
        $prediction = $this->model()->predict(['hit:webdriver_missing' => 1.0, 'hit:ua_headless_token' => 1.0, 'family_count' => 2.0, 'coverage' => 0.9]);

        $this->assertEqualsWithDelta(2.15, $prediction->logit, 1e-12);
        $this->assertEqualsWithDelta(0.897062, $prediction->probability, 1e-6, 'sigmoid(1.1 * 2.15 - 0.2)');
        $this->assertSame(['hit:webdriver_missing', 'hit:ua_headless_token', 'family_count'], array_map(static fn ($c) => $c->feature, $prediction->top(3)));
        $this->assertEqualsWithDelta(2.4, $prediction->top(1)[0]->weight, 1e-12);
    }

    #[Test]
    public function one_weak_hit_stays_low(): void
    {
        // z = -3 + 1.0 + 0.6 - 0.5 = -1.9
        $prediction = $this->model()->predict(['hit:lied_os' => 1.0, 'family_count' => 1.0, 'coverage' => 1.0]);

        $this->assertEqualsWithDelta(-1.9, $prediction->logit, 1e-12);
        $this->assertEqualsWithDelta(0.091955, $prediction->probability, 1e-6);
    }

    #[Test]
    public function an_empty_vector_is_the_intercept_through_the_calibration(): void
    {
        $prediction = $this->model()->predict([]);

        $this->assertEqualsWithDelta(0.029312, $prediction->probability, 1e-6, 'sigmoid(1.1 * -3 - 0.2)');
        $this->assertSame([], $prediction->contributions);
    }

    #[Test]
    public function contributions_sum_to_the_logit_minus_the_intercept(): void
    {
        $features = ['hit:webdriver_missing' => 1.0, 'hit:lied_os' => 1.0, 'integrity_count' => 3.0, 'protected' => 1.0, 'coverage' => 0.4];
        $prediction = $this->model()->predict($features);

        $sum = array_sum(array_map(static fn ($c) => $c->weight, $prediction->contributions));

        $this->assertEqualsWithDelta($prediction->logit + 3.0, $sum, 1e-12);
    }

    #[Test]
    public function a_privacy_mode_flag_lowers_the_score(): void
    {
        $plain = $this->model()->predict(['hit:lied_os' => 1.0]);
        $protected = $this->model()->predict(['hit:lied_os' => 1.0, 'protected' => 1.0]);

        $this->assertLessThan($plain->probability, $protected->probability);
    }

    #[Test]
    public function mutatio_n_flipping_one_coefficient_changes_the_golden_probability(): void
    {
        $document = json_decode((string) file_get_contents(self::FIXTURE), true, 32, JSON_THROW_ON_ERROR);
        $document['coefficients'][7] = -$document['coefficients'][7]; // hit:webdriver_missing
        $mutant = $this->model($document)->predict(['hit:webdriver_missing' => 1.0, 'hit:ua_headless_token' => 1.0, 'family_count' => 2.0, 'coverage' => 0.9]);

        $this->assertGreaterThan(0.01, abs($mutant->probability - 0.897062), 'the golden assertion above would fail for this mutant');
    }

    #[Test]
    public function mutatio_n_dropping_the_calibration_changes_the_golden_probability(): void
    {
        $document = json_decode((string) file_get_contents(self::FIXTURE), true, 32, JSON_THROW_ON_ERROR);
        $document['calibration'] = ['method' => 'platt', 'a' => 1.0, 'b' => 0.0];
        $mutant = $this->model($document)->predict(['hit:webdriver_missing' => 1.0, 'hit:ua_headless_token' => 1.0, 'family_count' => 2.0, 'coverage' => 0.9]);

        $this->assertGreaterThan(0.001, abs($mutant->probability - 0.897062));
    }

    #[Test]
    public function the_rules_calibration_maps_weight_to_a_probability(): void
    {
        // sigmoid(0.08 * 45 - 2) = sigmoid(1.6)
        $this->assertEqualsWithDelta(0.832018, $this->model()->rulesProbability(45) ?? -1.0, 1e-6);
    }
}
