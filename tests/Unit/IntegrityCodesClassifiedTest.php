<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Rules\IntegrityFindings;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The contract between the v3 collector (`resources/js/v3/integrity.ts`) and the engine: every
 * integrity code the client can send is either derived on the server
 * (`IntegrityFindings::DERIVED_CODES`) or recorded here as not derivable.
 */
final class IntegrityCodesClassifiedTest extends TestCase
{
    /**
     * Client codes the server cannot derive, and why. Every code in integrity.ts
     * `INTEGRITY_CODES` must be in `IntegrityFindings::DERIVED_CODES` or here
     * (`every_client_code_is_classified`).
     */
    private const NOT_DERIVED = [
        'wrong_receiver_data_property' => 'defined in INTEGRITY_CODES and never emitted by collectIntegrity()',
        'wrong_receiver_no_descriptor' => 'defined in INTEGRITY_CODES and never emitted by collectIntegrity()',
    ];

    #[Test]
    public function every_client_code_is_classified(): void
    {
        // Read from the client source, so a code added to integrity.ts fails here until it
        // is either derived on the server or recorded as not derivable, with a reason.
        $source = (string) file_get_contents(__DIR__.'/../../resources/js/v3/integrity.ts');
        if (preg_match('/export const INTEGRITY_CODES = \{(.*?)\} as const;/s', $source, $block) !== 1) {
            self::fail('INTEGRITY_CODES not found in integrity.ts');
        }
        self::assertSame(19, preg_match_all("/:\\s*'([a-z_]+)'/", $block[1], $codes), 'the INTEGRITY_CODES block changed size; re-run the derivability inventory (HOW-IT-WORKS §3.3)');

        foreach ($codes[1] as $code) {
            self::assertTrue(
                in_array($code, IntegrityFindings::DERIVED_CODES, true) || array_key_exists($code, self::NOT_DERIVED),
                "client code {$code} is neither derived nor recorded as not derivable",
            );
        }
        foreach (array_keys(self::NOT_DERIVED) as $code) {
            $constant = 'INTEGRITY_CODES.'.self::constantFor($block[1], $code);
            self::assertStringNotContainsString($constant, $source, "{$code} is recorded as never emitted, but integrity.ts now uses {$constant}");
        }
    }

    /** The `INTEGRITY_CODES` key whose value is `$code`. */
    private static function constantFor(string $block, string $code): string
    {
        if (preg_match('/(\w+):\s*\''.preg_quote($code, '/').'\'/', $block, $m) !== 1) {
            self::fail("{$code} is not in INTEGRITY_CODES");
        }

        return $m[1];
    }
}
