<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Model;

use DeviceId\Model\ModelBuilder;
use DeviceId\Model\Splitter;
use DeviceId\Model\TrainingRow;
use DeviceId\Model\TrainingRowBuilder;
use DeviceId\Scoring\ScoredClaims;
use DeviceId\Support\Confidence;
use DeviceId\Support\Verdict;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The promotion metrics must be measured on rows that neither trained nor calibrated the model,
 * and no account may sit on both sides (skeptical review M8).
 *
 * Before: Platt calibration was fitted on the validation rows and ECE/FPR were then judged on the
 * same rows (in-sample calibration), and the split unit was the device group while labels are per
 * account, so one account's visits from two devices (or a protected browser's per-visit random
 * keys) could land on both sides.
 */
final class SplitLeakageTest extends TestCase
{
    /**
     * 60 accounts, each seen on two devices (two groups), linked by a keyed account group.
     *
     * @return list<TrainingRow>
     */
    private static function linkedRows(): array
    {
        $rows = [];
        for ($a = 0; $a < 60; $a++) {
            $bot = $a % 2 === 0;
            foreach (['laptop', 'phone'] as $d => $device) {
                $features = $bot && ($a + $d) % 7 !== 0 ? ['hit:webdriver_missing' => 1.0] : [];
                if (! $bot && $a % 9 === 1) {
                    $features['hit:ua_vs_ua_header'] = 1.0;
                }
                $rows[] = new TrainingRow(
                    $features, $bot ? 'automation' : 'honest', "device-{$a}-{$device}",
                    ['engine' => 'chromium', 'device' => $d === 0 ? 'desktop' : 'mobile', 'privacy' => 'none'],
                    (int) (($features['hit:webdriver_missing'] ?? 0) * 25 + ($features['hit:ua_vs_ua_header'] ?? 0) * 20),
                    links: ["account-{$a}"],
                );
            }
        }

        return $rows;
    }

    /**
     * @param  list<TrainingRow>  $rows
     * @return list<string>
     */
    private static function accounts(array $rows): array
    {
        return array_values(array_unique(array_merge(...array_map(static fn (TrainingRow $r): array => $r->links, $rows))));
    }

    #[Test]
    public function no_account_is_on_two_sides_of_the_split(): void
    {
        $split = Splitter::byGroup(self::linkedRows(), 0.3, 'seed');

        $this->assertSame([], array_intersect(self::accounts($split['train']), self::accounts($split['validation'])));
    }

    #[Test]
    public function the_three_way_split_keeps_accounts_whole_and_every_side_has_both_classes(): void
    {
        $split = Splitter::threeWay(self::linkedRows(), 0.2, 0.25, 'seed');

        $sides = ['train', 'calibration', 'validation'];
        foreach ($sides as $i => $a) {
            $this->assertNotEmpty(array_filter($split[$a], static fn (TrainingRow $r): bool => $r->isPositive()), "{$a} has no positives");
            $this->assertNotEmpty(array_filter($split[$a], static fn (TrainingRow $r): bool => ! $r->isPositive()), "{$a} has no honest rows");
            foreach (array_slice($sides, $i + 1) as $b) {
                $this->assertSame([], array_intersect(self::accounts($split[$a]), self::accounts($split[$b])), "{$a}/{$b} share an account");
                $this->assertSame([], array_intersect($split['groups'][$a], $split['groups'][$b]), "{$a}/{$b} share a group");
            }
        }
        $this->assertSame(120, count($split['train']) + count($split['calibration']) + count($split['validation']));
    }

    #[Test]
    public function a_chain_of_links_is_one_unit(): void
    {
        // Device A is account 1's; account 1 also used device B; device B also served account 2.
        $slice = ['engine' => 'chromium', 'device' => 'desktop', 'privacy' => 'none'];
        $rows = [
            new TrainingRow([], 'honest', 'device-A', $slice, 0, links: ['account-1']),
            new TrainingRow([], 'honest', 'device-B', $slice, 0, links: ['account-1']),
            new TrainingRow([], 'honest', 'device-B', $slice, 0, links: ['account-2']),
            new TrainingRow([], 'honest', 'device-C', $slice, 0, links: ['account-2']),
        ];

        $components = Splitter::components($rows);

        $this->assertCount(1, $components);
    }

    #[Test]
    public function the_model_is_calibrated_on_rows_it_is_not_evaluated_on(): void
    {
        $build = ModelBuilder::build(self::linkedRows(), ['seed' => 'seed', 'trained_at' => 1793491200]);
        $split = $build['document']['split'];

        $this->assertGreaterThan(0, $split['calibration_rows']);
        $this->assertGreaterThan(0, $split['validation_rows']);
        $this->assertSame([], array_intersect($split['calibration_groups'], $split['validation_groups']));
        $this->assertSame([], array_intersect($split['train_groups'], $split['validation_groups']));
        $this->assertSame([], array_intersect($split['train_groups'], $split['calibration_groups']));
        $this->assertSame($split['validation_rows'], $build['document']['metrics']['validation']['n']);
        $this->assertSame($split['calibration_rows'], $build['document']['metrics']['calibration']['n']);
        $this->assertSame('calibration', $build['document']['calibration']['fitted_on']);
        $this->assertStringContainsString('account', $split['unit']);
    }

    #[Test]
    public function the_row_builder_links_an_accounts_rows_by_a_keyed_account_group(): void
    {
        $builder = new TrainingRowBuilder(str_repeat('k', 40), 365);
        $scored = new ScoredClaims(new Verdict(Verdict::BAND_PASS, 0, [], []), new Confidence(90, 10, 10), [], 0, [], [], [], 0);
        $at = new \DateTimeImmutable('2026-10-31');

        $laptop = $builder->build($scored, 'device-laptop', 'chromium', false, false, 'fraud', 'review', 1.0, $at, accountKey: '4711');
        $phone = $builder->build($scored, 'device-phone', 'chromium', true, false, 'fraud', 'review', 1.0, $at, accountKey: '4711');
        $guest = $builder->build($scored, 'device-guest', 'chromium', false, false, null, 'none', 1.0, $at);

        $this->assertNotSame($laptop['group'], $phone['group']);
        $this->assertSame($laptop['account_group'], $phone['account_group']);
        $this->assertSame(16, strlen($laptop['account_group']));
        $this->assertStringNotContainsString('4711', json_encode($laptop));
        $this->assertArrayNotHasKey('account_group', $guest);
        TrainingRowBuilder::assertDeidentified($laptop);

        $rows = array_map(static fn (array $row): ?TrainingRow => TrainingRow::fromArray(['label' => 'fraud'] + $row), [$laptop, $phone]);
        $this->assertCount(1, Splitter::components(array_values(array_filter($rows))), 'one account, one unit');
    }
}
