<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Model;

use DeviceId\Model\Evaluator;
use DeviceId\Model\LogisticModel;
use DeviceId\Model\LogisticTrainer;
use DeviceId\Model\Metrics;
use DeviceId\Model\ModelBuilder;
use DeviceId\Model\ModelSpec;
use DeviceId\Model\Platt;
use DeviceId\Model\Splitter;
use DeviceId\Model\TrainingRow;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Pure-PHP training and evaluation on small synthetic sets whose right answer is known.
 */
final class TrainingTest extends TestCase
{
    /**
     * A deterministic set: 40 groups of 2 rows. `hit:webdriver_missing` marks bots (with 10 % noise),
     * `hit:tz_vs_lang_region` fires on honest and bot rows alike (so it must get ~no weight).
     *
     * @return list<TrainingRow>
     */
    private static function rows(int $groups = 40): array
    {
        $rows = [];
        for ($g = 0; $g < $groups; $g++) {
            $bot = $g % 2 === 0;
            for ($i = 0; $i < 2; $i++) {
                $features = [];
                if ($bot && ($g + $i) % 10 !== 0) {
                    $features['hit:webdriver_missing'] = 1.0;
                }
                if (! $bot && $g % 10 === 1 && $i === 0) {
                    $features['hit:ua_vs_ua_header'] = 1.0; // one honest false positive
                }
                if (($g + $i) % 3 === 0) {
                    $features['hit:tz_vs_lang_region'] = 1.0;
                }
                $rows[] = new TrainingRow(
                    $features, $bot ? 'automation' : 'honest', "m{$g}",
                    ['engine' => $g % 4 < 2 ? 'chromium' : 'gecko', 'device' => 'desktop', 'privacy' => 'none'],
                    (int) (($features['hit:webdriver_missing'] ?? 0) * 25 + ($features['hit:ua_vs_ua_header'] ?? 0) * 20 + ($features['hit:tz_vs_lang_region'] ?? 0) * 4),
                );
            }
        }

        return $rows;
    }

    #[Test]
    public function training_learns_the_discriminating_rule_and_ignores_the_uninformative_one(): void
    {
        $fit = LogisticTrainer::fit(self::rows(), 1.0);
        $coefficients = array_combine($fit['features'], $fit['coefficients']);

        $this->assertTrue($fit['converged']);
        $this->assertGreaterThan(1.0, $coefficients['hit:webdriver_missing']);
        $this->assertLessThan(0.5 * $coefficients['hit:webdriver_missing'], abs($coefficients['hit:tz_vs_lang_region']));
    }

    #[Test]
    public function training_is_deterministic(): void
    {
        $this->assertSame(LogisticTrainer::fit(self::rows(), 1.0), LogisticTrainer::fit(self::rows(), 1.0));
    }

    #[Test]
    public function stronger_l2_shrinks_every_coefficient(): void
    {
        $weak = LogisticTrainer::fit(self::rows(), 0.1);
        $strong = LogisticTrainer::fit(self::rows(), 10.0);

        $this->assertLessThan(abs(array_sum($weak['coefficients'])), abs(array_sum($strong['coefficients'])));
    }

    #[Test]
    public function a_rule_hit_that_only_ever_fires_on_honest_rows_is_frozen_at_zero_not_negative(): void
    {
        $rows = [];
        for ($i = 0; $i < 30; $i++) {
            $bot = $i % 2 === 0;
            $rows[] = new TrainingRow($bot ? ['hit:webdriver_missing' => 1.0] : ['hit:lied_os' => 1.0], $bot ? 'automation' : 'honest', "g{$i}", ['engine' => 'chromium', 'device' => 'desktop', 'privacy' => 'none'], 0);
        }

        $fit = LogisticTrainer::fit($rows, 0.5);
        $coefficients = array_combine($fit['features'], $fit['coefficients']);

        $this->assertSame(0.0, $coefficients['hit:lied_os'], 'a contradiction is never evidence of honesty');
        $this->assertContains('hit:lied_os', $fit['frozen']);
    }

    #[Test]
    public function a_privacy_mode_flag_may_be_negative(): void
    {
        $rows = [];
        for ($i = 0; $i < 40; $i++) {
            $protected = $i % 2 === 0;
            // Protected visitors trip a rule as often as bots do, but are honest.
            $rows[] = new TrainingRow(['hit:lied_os' => 1.0] + ($protected ? ['protected' => 1.0] : []), $protected ? 'honest' : 'automation', "g{$i}", ['engine' => 'gecko', 'device' => 'desktop', 'privacy' => $protected ? 'protected' : 'none'], 0);
        }

        $coefficients = (static fn (array $fit): array => array_combine($fit['features'], $fit['coefficients']))(LogisticTrainer::fit($rows, 0.5));

        $this->assertLessThan(0.0, $coefficients['protected']);
    }

    #[Test]
    public function the_split_never_puts_one_group_on_both_sides_and_both_sides_have_both_classes(): void
    {
        $split = Splitter::byGroup(self::rows(), 0.3, 'seed');

        $this->assertSame([], array_intersect($split['groups']['train'], $split['groups']['validation']));
        foreach (['train', 'validation'] as $side) {
            $this->assertNotEmpty(array_filter($split[$side], static fn (TrainingRow $r): bool => $r->isPositive()), "{$side} has no positives");
            $this->assertNotEmpty(array_filter($split[$side], static fn (TrainingRow $r): bool => ! $r->isPositive()), "{$side} has no honest rows");
        }
        $this->assertSame(80, count($split['train']) + count($split['validation']));
    }

    #[Test]
    public function the_split_is_reproducible_and_seed_dependent(): void
    {
        $this->assertSame(Splitter::byGroup(self::rows(), 0.3, 'a')['groups'], Splitter::byGroup(self::rows(), 0.3, 'a')['groups']);
        $this->assertNotSame(Splitter::byGroup(self::rows(), 0.3, 'a')['groups'], Splitter::byGroup(self::rows(), 0.3, 'b')['groups']);
    }

    #[Test]
    public function auc_of_a_perfect_inverted_and_tied_ranking(): void
    {
        $perfect = [['score' => 0.9, 'positive' => true], ['score' => 0.1, 'positive' => false]];
        $inverted = [['score' => 0.1, 'positive' => true], ['score' => 0.9, 'positive' => false]];
        $tied = [['score' => 0.5, 'positive' => true], ['score' => 0.5, 'positive' => false]];

        $this->assertSame(1.0, Metrics::auc($perfect));
        $this->assertSame(0.0, Metrics::auc($inverted));
        $this->assertSame(0.5, Metrics::auc($tied));
        $this->assertNull(Metrics::auc([['score' => 0.5, 'positive' => true]]), 'one class has no AUC');
    }

    #[Test]
    public function ece_is_zero_for_a_calibrated_set_and_large_for_an_overconfident_one(): void
    {
        $calibrated = [];
        for ($i = 0; $i < 10; $i++) {
            $calibrated[] = ['score' => 0.7, 'positive' => $i < 7];
        }
        $overconfident = array_map(static fn (array $i): array => ['score' => 0.95, 'positive' => $i['positive']], $calibrated);

        $this->assertEqualsWithDelta(0.0, Metrics::ece($calibrated)['ece'], 1e-9);
        $this->assertEqualsWithDelta(0.25, Metrics::ece($overconfident)['ece'], 1e-9);
    }

    #[Test]
    public function recall_at_a_false_positive_rate_flags_the_resolution_limit_instead_of_inventing_precision(): void
    {
        $items = [];
        for ($i = 0; $i < 10; $i++) {
            $items[] = ['score' => $i / 10, 'positive' => false];
        }
        $items[] = ['score' => 0.95, 'positive' => true];
        $items[] = ['score' => 0.05, 'positive' => true];

        $point = Metrics::atFalsePositiveRate($items, 0.001);

        $this->assertTrue($point['resolution_limited'], '10 honest rows cannot resolve a 0.1 % rate');
        $this->assertSame(0.5, $point['recall']);
        $this->assertSame(0.0, $point['fpr']);

        $loose = Metrics::atFalsePositiveRate($items, 0.2);
        $this->assertFalse($loose['resolution_limited']);
        $this->assertLessThanOrEqual(0.2, $loose['fpr']);
    }

    #[Test]
    public function platt_scaling_recovers_a_calibrating_slope_and_declines_to_fit_tiny_sets(): void
    {
        $items = [];
        for ($i = 0; $i < 200; $i++) {
            $score = ($i - 100) / 25.0;
            $items[] = ['score' => $score, 'positive' => $i >= 100 && $i % 7 !== 0 || $i < 100 && $i % 13 === 0];
        }

        $fit = Platt::fit($items);

        $this->assertTrue($fit['fitted']);
        $this->assertGreaterThan(0.0, $fit['a']);
        $this->assertFalse(Platt::fit(array_slice($items, 0, 5))['fitted']);
    }

    #[Test]
    public function a_built_model_loads_beats_chance_on_held_out_groups_and_is_reproducible(): void
    {
        $options = ['seed' => 's', 'trained_at' => strtotime('2026-10-31'), 'training_set_sha256' => str_repeat('a', 64)];
        $one = ModelBuilder::build(self::rows(), $options);
        $two = ModelBuilder::build(self::rows(), $options);

        $load = ModelSpec::fromArray($one['document'], 45, strtotime('2026-11-01'));

        $this->assertSame(ModelSpec::STATE_OK, $load['state'], $load['reason']);
        $this->assertSame($one['document'], $two['document'], 'same rows and seed give the same sealed document');
        $this->assertGreaterThan(0.8, $one['document']['metrics']['validation']['model']['auc']);
        $this->assertTrue($one['document']['calibration']['fitted']);
        $this->assertSame(str_repeat('a', 64), $one['document']['training_set_sha256']);
        $this->assertSame([], array_intersect($one['document']['split']['train_groups'], $one['document']['split']['validation_groups']));
    }

    #[Test]
    public function mutatio_n_training_on_shuffled_labels_loses_the_signal(): void
    {
        $rows = self::rows();
        $labels = array_map(static fn (TrainingRow $r): string => $r->label, $rows);
        // Rotate labels by 3 rows so no feature lines up with its label.
        $shifted = array_merge(array_slice($labels, 3), array_slice($labels, 0, 3));
        $mutant = [];
        foreach ($rows as $index => $row) {
            $mutant[] = new TrainingRow($row->features, $shifted[$index], $row->group, $row->slice, $row->rulesWeight);
        }

        $honest = ModelBuilder::build($rows, ['seed' => 's'])['document']['metrics']['validation']['model']['auc'];
        $broken = ModelBuilder::build($mutant, ['seed' => 's'])['document']['metrics']['validation']['model']['auc'];

        $this->assertGreaterThan(0.8, $honest);
        $this->assertLessThan(0.8, $broken ?? 0.0, 'a test that cannot fail when the labels are wrong would prove nothing');
    }

    #[Test]
    public function training_refuses_a_set_with_one_class(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        ModelBuilder::build(array_filter(self::rows(), static fn (TrainingRow $r): bool => $r->isPositive()));
    }

    #[Test]
    public function the_assumed_prevalence_moves_the_calibration_and_is_recorded(): void
    {
        $plain = ModelBuilder::build(self::rows(), ['seed' => 's'])['document'];
        $prior = ModelBuilder::build(self::rows(), ['seed' => 's', 'assumed_prevalence' => 0.02])['document'];

        $this->assertLessThan($plain['calibration']['b'], $prior['calibration']['b']);
        $this->assertSame('assumed_prevalence:0.02', $prior['calibration']['calibrated_to']);
        $this->assertSame('training_prevalence', $plain['calibration']['calibrated_to']);
    }

    #[Test]
    public function the_evaluator_reports_slices_and_leaves_unknown_rates_null(): void
    {
        $model = LogisticModel::class;
        $this->assertSame('DeviceId\Model\LogisticModel', $model);

        $report = Evaluator::evaluate(self::rows(), static fn (TrainingRow $r): float => isset($r->features['hit:webdriver_missing']) ? 0.9 : 0.1);

        $this->assertSame(80, $report['all']['n']);
        $this->assertArrayHasKey('engine:chromium', $report);
        $this->assertArrayHasKey('engine:gecko', $report);
        $this->assertNull($report['class:automation']['rules']['false_positive_rate_at_flag'], 'no honest rows in that slice: the rate is unknown');
        $this->assertNull($report['class:honest']['rules']['recall_at_flag']);
        $this->assertGreaterThan(0.8, $report['all']['model']['auc']);
    }
}
