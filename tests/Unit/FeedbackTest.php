<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Feedback\FeedbackLabel;
use DeviceId\Feedback\FeedbackReport;
use DeviceId\Feedback\FeedbackResolver;
use DeviceId\Model\TrainingRow;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The closed feedback vocabulary and how reports become training labels.
 */
final class FeedbackTest extends TestCase
{
    private static function report(string $label, int $at, string $reporter = 'admin-1', string $notes = ''): FeedbackReport
    {
        return new FeedbackReport($label, $at, $reporter, $notes);
    }

    #[Test]
    public function the_vocabulary_is_closed(): void
    {
        $this->assertSame(['confirmed_fraud', 'suspected', 'not_abuse', 'clear'], FeedbackLabel::all());
        $this->assertFalse(FeedbackLabel::isValid('chargeback'));
        $this->expectException(\InvalidArgumentException::class);
        self::report('maybe_bad', 1);
    }

    #[Test]
    public function a_report_needs_a_reporter_and_a_bounded_note(): void
    {
        $this->assertNull(FeedbackReport::tryFromArray(['label' => 'whatever', 'reported_at' => 1, 'reporter' => 'a']));
        $this->assertNull(FeedbackReport::tryFromArray(['label' => 'clear', 'reported_at' => 1, 'reporter' => '']));
        $this->assertNull(FeedbackReport::tryFromArray(['label' => 'clear', 'reported_at' => 'yesterday', 'reporter' => 'a']));
        $this->assertNull(FeedbackReport::tryFromArray(['label' => 'clear', 'reported_at' => 1, 'reporter' => 'a', 'notes' => str_repeat('x', 501)]));
        $this->assertNotNull(FeedbackReport::tryFromArray(['label' => 'clear', 'reported_at' => 1, 'reporter' => 'a', 'notes' => 'fine']));
    }

    #[Test]
    public function the_last_report_decides_and_each_label_maps_to_a_training_label_and_weight(): void
    {
        $confirmed = FeedbackResolver::resolve([self::report(FeedbackLabel::CONFIRMED_FRAUD, 10)]);
        $this->assertSame(['confirmed_fraud', 'fraud', 1.0], [$confirmed->label, $confirmed->trainingLabel, $confirmed->labelWeight]);

        $suspected = FeedbackResolver::resolve([self::report(FeedbackLabel::SUSPECTED, 10)], 'automation');
        $this->assertSame(['suspected', 'automation', 0.5], [$suspected->label, $suspected->trainingLabel, $suspected->labelWeight]);

        $honest = FeedbackResolver::resolve([self::report(FeedbackLabel::CONFIRMED_FRAUD, 10), self::report(FeedbackLabel::NOT_ABUSE, 20)]);
        $this->assertSame(['not_abuse', 'honest', 1.0], [$honest->label, $honest->trainingLabel, $honest->labelWeight], 'an admin who corrects himself is obeyed');

        $again = FeedbackResolver::resolve([self::report(FeedbackLabel::NOT_ABUSE, 20), self::report(FeedbackLabel::CONFIRMED_FRAUD, 10)]);
        $this->assertSame('not_abuse', $again->label, 'order of the array does not matter, the time does');
    }

    #[Test]
    public function clear_retracts_everything_before_it_and_nothing_stands(): void
    {
        $resolution = FeedbackResolver::resolve([self::report(FeedbackLabel::CONFIRMED_FRAUD, 10), self::report(FeedbackLabel::CLEAR, 20)]);

        $this->assertNull($resolution->label);
        $this->assertNull($resolution->trainingLabel);
        $this->assertTrue($resolution->retracted);
        $this->assertFalse($resolution->isDecided());
        $this->assertSame(2, $resolution->reports);

        $after = FeedbackResolver::resolve([self::report(FeedbackLabel::CLEAR, 20), self::report(FeedbackLabel::SUSPECTED, 30)]);
        $this->assertSame('suspected', $after->label, 'a report after the clear stands again');

        $none = FeedbackResolver::resolve([]);
        $this->assertFalse($none->isDecided());
        $this->assertFalse($none->retracted);
    }

    #[Test]
    public function only_a_real_abuse_kind_is_accepted(): void
    {
        foreach (['honest', 'unicorn'] as $kind) {
            try {
                FeedbackResolver::resolve([self::report(FeedbackLabel::SUSPECTED, 1)], $kind);
                $this->fail("{$kind} is not an abuse kind");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertContains('fraud', TrainingRow::LABELS);
    }

    #[Test]
    public function relabelling_touches_only_the_rows_of_that_device_in_that_week(): void
    {
        $rows = [
            ['id' => 'a', 'group' => 'g1', 'observed_week' => '2026-W44', 'label' => 'fraud', 'label_weight' => 1.0, 'source' => 'honeypot', 'features' => ['x' => 1.0]],
            ['id' => 'b', 'group' => 'g1', 'observed_week' => '2026-W43', 'label' => 'fraud', 'label_weight' => 1.0, 'source' => 'honeypot', 'features' => []],
            ['id' => 'c', 'group' => 'g2', 'observed_week' => '2026-W44', 'label' => 'fraud', 'label_weight' => 1.0, 'source' => 'honeypot', 'features' => []],
        ];
        $notAbuse = FeedbackResolver::resolve([self::report(FeedbackLabel::NOT_ABUSE, 5, 'admin-1', 'a student, I called him')]);

        $out = FeedbackResolver::relabelRows($rows, 'g1', '2026-W44', $notAbuse);

        $this->assertSame(['honest', 1.0, 'feedback'], [$out[0]['label'], $out[0]['label_weight'], $out[0]['source']]);
        $this->assertSame($rows[1], $out[1], 'another week is not touched');
        $this->assertSame($rows[2], $out[2], 'another device is not touched');
        $this->assertSame(['x' => 1.0], $out[0]['features']);
        $this->assertStringNotContainsString('student', json_encode($out), 'the note never enters a training row');

        $cleared = FeedbackResolver::relabelRows($rows, 'g1', '2026-W44', FeedbackResolver::resolve([self::report(FeedbackLabel::CLEAR, 5)]));
        $this->assertNull($cleared[0]['label'], 'a retracted label leaves the row unlabelled and so untrained');
        $this->assertSame(0.0, $cleared[0]['label_weight']);

        $this->assertSame($rows, FeedbackResolver::relabelRows($rows, 'g1', '2026-W44', FeedbackResolver::resolve([])), 'no reports, no change');
    }
}
