<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * `tools/probe-bypass-shapes.php` is a gate (`composer gates`, README "Try it"); this runs it so the
 * suite fails the moment a probe feeding several rules has no recorded direction.
 */
final class ProbeBypassAuditTest extends TestCase
{
    private const SCRIPT = __DIR__.'/../../tools/probe-bypass-shapes.php';

    /**
     * @return array{0: int, 1: string}
     */
    private static function execute(string $script): array
    {
        $output = [];
        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg($script).' 2>&1', $output, $status);

        return [$status, implode("\n", $output)];
    }

    #[Test]
    public function every_multi_rule_probe_is_classified(): void
    {
        [$status, $output] = self::execute(self::SCRIPT);

        $this->assertSame(0, $status, $output);
        $this->assertStringContainsString('Every probe that feeds more than one check has been classified', $output);
        $this->assertStringNotContainsString('UNCLASSIFIED', $output);
    }

    #[Test]
    public function an_unclassified_probe_fails_the_audit(): void
    {
        // Negative control: the same script with the `workerScope` classification removed must exit 1.
        $source = (string) file_get_contents(self::SCRIPT);
        $broken = preg_replace("/    'workerScope' => \['silence'.*\n/", '', $source, 1, $count);
        $this->assertSame(1, $count, 'the classification line was found');

        $copy = dirname(self::SCRIPT).'/.probe-bypass-shapes.negative-control.php';
        file_put_contents($copy, $broken);
        try {
            [$status, $output] = self::execute($copy);
        } finally {
            unlink($copy);
        }

        $this->assertSame(1, $status);
        $this->assertStringContainsString('workerScope', $output);
        $this->assertStringContainsString('UNCLASSIFIED', $output);
    }
}
