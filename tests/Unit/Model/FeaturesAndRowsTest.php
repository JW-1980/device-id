<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Model;

use DeviceId\Capture\CaptureAnalysis;
use DeviceId\CheckRegistry;
use DeviceId\Ml\CaptureRows;
use DeviceId\Model\Evaluator;
use DeviceId\Model\FeatureCatalogue;
use DeviceId\Model\ModelBuilder;
use DeviceId\Model\ModelSpec;
use DeviceId\Model\TrainingRow;
use DeviceId\Model\TrainingRowBuilder;
use DeviceId\Reputation\ReputationResult;
use DeviceId\Scoring\ScoredClaims;
use DeviceId\Support\Confidence;
use DeviceId\Support\Config;
use DeviceId\Support\Verdict;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/../../../tools/ml/CaptureRows.php';

final class FeaturesAndRowsTest extends TestCase
{
    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    #[Test]
    public function every_registry_code_is_a_feature_and_nothing_self_reported_is(): void
    {
        $names = FeatureCatalogue::names();

        foreach (CheckRegistry::codes() as $code) {
            $this->assertContains('hit:'.$code, $names);
        }
        $this->assertSame([], array_intersect($names, FeatureCatalogue::EXCLUDED), 'no excluded kind of fact is a feature');
        foreach ($names as $name) {
            $this->assertTrue(FeatureCatalogue::knows($name), $name);
        }
        $this->assertFalse(FeatureCatalogue::knows('user_agent'));
        $this->assertFalse(FeatureCatalogue::knows('hit:not_a_rule'));
    }

    #[Test]
    public function the_vector_holds_only_emitted_hits_and_bounded_extras(): void
    {
        $features = FeatureCatalogue::build(
            [['code' => 'webdriver_missing', 'detail' => '', 'weight' => 25], ['code' => 'lied_os', 'detail' => '', 'weight' => 0], ['code' => 'transport_made_up', 'detail' => '', 'weight' => 45], ['code' => 'model_adjustment', 'detail' => '', 'weight' => 9]],
            99, 85, 99, 99, true,
        );

        $this->assertSame(1.0, $features['hit:webdriver_missing']);
        $this->assertArrayNotHasKey('hit:lied_os', $features, 'a silenced rule is silent');
        $this->assertSame(1.0, $features[FeatureCatalogue::UNLISTED_HIT]);
        $this->assertArrayNotHasKey('hit:model_adjustment', $features, 'the model must not learn from its own output');
        $this->assertSame(2.0, $features['family_count']);
        $this->assertSame(5.0, $features['integrity_count']);
        $this->assertSame(6.0, $features['untrusted_count']);
        $this->assertSame(0.85, $features['coverage']);
        $this->assertSame(1.0, $features['protected']);
    }

    #[Test]
    public function reputation_enters_as_soft_features_only_when_present(): void
    {
        $listed = new ReputationResult(ReputationResult::STATE_OK, ['datacenter'], ['aws']);

        $features = FeatureCatalogue::build([], 0, null, 0, 0, false, $listed->features());

        $this->assertSame(['rep_datacenter' => 1.0], $features);
        $this->assertSame([], FeatureCatalogue::build([], 0, null, 0, 0, false, (new ReputationResult(ReputationResult::STATE_OK))->features()));
    }

    private function scored(): ScoredClaims
    {
        $verdict = new Verdict(Verdict::BAND_CHALLENGE, 68, ['webdriver_missing'], [['code' => 'webdriver_missing', 'detail' => 'Mozilla/5.0 should never be copied', 'weight' => 25], ['code' => 'ua_vs_ua_header', 'detail' => '', 'weight' => 20]]);

        return new ScoredClaims($verdict, new Confidence(87, 10, 12), [], 0, [], ['tier1' => ['expected' => 3, 'omitted' => ['a', 'b']]], ['gpu'], 2);
    }

    #[Test]
    public function a_training_row_is_deidentified_bucketed_and_carries_its_retention(): void
    {
        $builder = new TrainingRowBuilder(str_repeat('k', 40), 365);

        $row = $builder->build($this->scored(), 'device-key-abcdef', 'chromium', false, false, 'automation', 'honeypot', 1.0, new \DateTimeImmutable('2026-10-31 13:45:12'));

        $this->assertSame(365, $row['retention_days']);
        $this->assertSame('2027-10-31', $row['expires_on']);
        $this->assertSame('2026-W44', $row['observed_week'], 'a week, not a timestamp');
        $this->assertSame(0.9, $row['features']['coverage'], '87 is bucketed to 90 before it becomes a feature');
        $this->assertSame(16, strlen($row['group']));
        $this->assertStringNotContainsString('device-key', json_encode($row));
        $this->assertStringNotContainsString('Mozilla', json_encode($row), 'the detail sentences are never copied');
        $this->assertSame(45, $row['rules_weight']);
        $keys = array_keys($row);
        sort($keys);
        $this->assertSame(['expires_on', 'features', 'group', 'id', 'label', 'label_weight', 'observed_week', 'retention_days', 'rules_weight', 'schema', 'slice', 'source'], $keys);
    }

    #[Test]
    public function the_group_is_keyed_stable_per_device_and_changes_with_the_secret(): void
    {
        $at = new \DateTimeImmutable('2026-10-31');
        $one = new TrainingRowBuilder(str_repeat('a', 40));
        $two = new TrainingRowBuilder(str_repeat('b', 40));

        $a1 = $one->build($this->scored(), 'dev-1', 'gecko', true, false, null, 'none', 1.0, $at)['group'];
        $a2 = $one->build($this->scored(), 'dev-1', 'gecko', true, false, null, 'none', 1.0, $at)['group'];
        $other = $one->build($this->scored(), 'dev-2', 'gecko', true, false, null, 'none', 1.0, $at)['group'];
        $rotated = $two->build($this->scored(), 'dev-1', 'gecko', true, false, null, 'none', 1.0, $at)['group'];

        $this->assertSame($a1, $a2);
        $this->assertNotSame($a1, $other);
        $this->assertNotSame($a1, $rotated, 'rotating the secret severs the link');
    }

    #[Test]
    public function a_short_secret_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new TrainingRowBuilder('short');
    }

    #[Test]
    public function the_deidentification_check_rejects_an_address_a_user_agent_and_an_unknown_key(): void
    {
        $good = (new TrainingRowBuilder(str_repeat('k', 40)))->build($this->scored(), 'd', 'webkit', false, false, 'honest', 'harness', 1.0, new \DateTimeImmutable('2026-10-31'));
        TrainingRowBuilder::assertDeidentified($good);

        foreach ([
            ['ip' => '203.0.113.9'],
            ['source' => '203.0.113.9'],
            ['source' => 'Mozilla/5.0 (X11; Linux x86_64)'],
            ['source' => 'person@example.com'],
            ['slice' => ['engine' => '2001:db8::1', 'device' => 'desktop', 'privacy' => 'none']],
        ] as $tainted) {
            try {
                TrainingRowBuilder::assertDeidentified(array_merge($good, $tainted));
                $this->fail('accepted '.json_encode($tainted));
            } catch (\UnexpectedValueException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    #[Test]
    public function a_row_survives_the_export_and_import_round_trip(): void
    {
        $row = (new TrainingRowBuilder(str_repeat('k', 40)))->build($this->scored(), 'd', 'webkit', false, false, 'spoof', 'harness', 0.5, new \DateTimeImmutable('2026-10-31'));

        $imported = TrainingRow::fromArray(json_decode(json_encode($row), true));

        $this->assertNotNull($imported);
        $this->assertSame('spoof', $imported->label);
        $this->assertSame(0.5, $imported->labelWeight);
        $this->assertSame(45, $imported->rulesWeight);
        $this->assertNull(TrainingRow::fromArray(['label' => 'unknown-label', 'features' => [], 'group' => 'g']));
    }

    #[Test]
    public function the_committed_capture_dataset_loads_with_every_class_and_trains_a_model_that_loads(): void
    {
        $loaded = CaptureRows::load([__DIR__.'/../../Fixtures/ml/dataset']);
        $rows = $loaded['rows'];
        $classes = array_count_values(array_map(static fn (TrainingRow $r): string => $r->label, $rows));

        foreach (['honest', 'automation', 'headless', 'spoof'] as $class) {
            $this->assertGreaterThanOrEqual(3, $classes[$class] ?? 0, "too few {$class} rows");
        }
        foreach ($rows as $row) {
            $this->assertNotContains('user_agent', array_keys($row->features));
            foreach (array_keys($row->features) as $name) {
                $this->assertTrue(FeatureCatalogue::knows($name), $name);
            }
        }

        $build = ModelBuilder::build($rows, ['seed' => 'dataset', 'training_set_sha256' => $loaded['sha256'], 'validation_fraction' => 0.4]);

        $this->assertSame('ok', ModelSpec::fromArray($build['document'], 45)['state']);
        $this->assertSame([], array_intersect($build['document']['split']['train_groups'], $build['document']['split']['validation_groups']));
        $this->assertGreaterThan(0.5, $build['document']['metrics']['validation']['model']['auc'], 'better than chance on groups it never saw');
    }

    #[Test]
    public function the_rules_alone_evaluation_over_the_dataset_has_slices_with_honest_rows_and_slices_without(): void
    {
        $rows = CaptureRows::load([__DIR__.'/../../Fixtures/ml/dataset'])['rows'];

        $report = Evaluator::evaluate($rows);

        $this->assertNotNull($report['engine:chromium']['rules']['false_positive_rate_at_flag'], 'chromium has honest rows');
        $this->assertNull($report['engine:webkit']['rules']['false_positive_rate_at_flag'], 'the harness has no honest WebKit: the rate is unknown, not zero');
        $this->assertNull($report['privacy:protected']['rules']['false_positive_rate_at_flag']);
        $this->assertNotNull(CaptureAnalysis::DATASET_SCHEMA);
    }
}
