<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Scoring\ConfidenceScorer;
use DeviceId\Support\Config;
use PHPUnit\Framework\TestCase;

/**
 * A host-supplied probe catalogue (`fingerprint.confidence_probes`): the override mechanism
 * stays, although the shipped list is exactly the probe set of the one collector in this
 * package (see ProbeSetTest). The catalogue below is a small host list that drops most probes.
 */
final class ConfidenceCatalogueTest extends TestCase
{
    private const CATALOGUE = [
        'tier1:environment' => ['weight' => 1100, 'charge' => 1.0],
        'tier1:dateParsing' => ['weight' => 1014, 'charge' => 1.0],
        'tier1:codecs' => ['weight' => 617, 'charge' => 1.0],
        'tier2:voices' => ['weight' => 200, 'charge' => 0.25],
        'tier2:gpu' => ['weight' => 500, 'charge' => 0.25],
        'tier2:webrtc' => ['weight' => 250, 'charge' => 0.25],
        'tier2:behavior' => ['weight' => 300, 'charge' => 0.25],
    ];

    protected function setUp(): void
    {
        parent::setUp();

        Config::use(['fingerprint' => ['confidence_probes' => self::CATALOGUE]]);
    }

    protected function tearDown(): void
    {
        Config::reset();

        parent::tearDown();
    }

    public function test_the_host_catalogue_replaces_the_shipped_list(): void
    {
        $this->assertSame(array_keys(self::CATALOGUE), array_keys(ConfidenceScorer::catalogue()));

        $confidence = (new ConfidenceScorer)->score([]);

        $this->assertSame(array_sum(array_column(self::CATALOGUE, 'weight')), $confidence->expected);
        $this->assertNotContains('tier1:engineIdentity', $confidence->missing);
        $this->assertContains('tier2:webrtc', $confidence->missing);
    }

    public function test_without_a_host_catalogue_the_shipped_list_applies(): void
    {
        Config::reset();

        $this->assertArrayHasKey('tier1:engineIdentity', ConfidenceScorer::catalogue());
        $this->assertArrayHasKey('tier2:webrtc', ConfidenceScorer::catalogue());
        $this->assertArrayHasKey('tier2:behavior', ConfidenceScorer::catalogue());
        $this->assertArrayNotHasKey('tier1:stackDepth', ConfidenceScorer::catalogue());
    }

    public function test_malformed_catalogue_entries_are_skipped(): void
    {
        Config::use(['fingerprint' => ['confidence_probes' => [
            'tier1:environment' => ['weight' => 100, 'charge' => 1.0],
            'tier3:nope' => ['weight' => 100, 'charge' => 1.0],
            'tier2:zero' => ['weight' => 0, 'charge' => 0.25],
            'tier2:text' => ['weight' => 'heavy', 'charge' => 0.25],
            'tier2:clamped' => ['weight' => 50, 'charge' => 7],
        ]]]);

        $this->assertSame([
            'tier1:environment' => ['weight' => 100, 'charge' => 1.0],
            'tier2:clamped' => ['weight' => 50, 'charge' => 1.0],
        ], ConfidenceScorer::catalogue());
    }

    public function test_an_entirely_malformed_catalogue_falls_back_to_the_shipped_list(): void
    {
        Config::use(['fingerprint' => ['confidence_probes' => ['bogus' => 1]]]);

        $this->assertArrayHasKey('tier1:engineIdentity', ConfidenceScorer::catalogue());
    }

    /**
     * @param  array<string, mixed>  $node
     * @return array<string, mixed>
     */
    private static function claimsWithVoices(array $node): array
    {
        return [
            'tier2' => [
                'voices' => $node,
            ],
        ];
    }

    public function test_a_present_voice_list_is_expected_and_not_missing(): void
    {
        $confidence = (new ConfidenceScorer)->score(self::claimsWithVoices([
            'state' => 'ok',
            'value' => ['count' => 12, 'osCount' => 12, 'osHash' => 'a1b2c3d4'],
        ]));

        $this->assertNotContains('tier2:voices', $confidence->missing);
        $this->assertGreaterThan(0, $confidence->earned);
    }

    public function test_an_absent_voice_list_is_reported_as_missing(): void
    {
        $confidence = (new ConfidenceScorer)->score(['tier2' => []]);

        $this->assertContains('tier2:voices', $confidence->missing);
        $this->assertSame(0, $confidence->earned);
    }

    public function test_a_present_gpu_result_is_expected_and_not_missing(): void
    {
        $confidence = (new ConfidenceScorer)->score([
            'tier2' => [
                'gpu' => [
                    'state' => 'ok',
                    'value' => ['renderer' => 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060)', 'software' => false],
                ],
            ],
        ]);

        $this->assertNotContains('tier2:gpu', $confidence->missing);
        $this->assertGreaterThan(0, $confidence->earned);
    }

    public function test_present_webrtc_and_behavior_results_are_expected_and_not_missing(): void
    {
        $confidence = (new ConfidenceScorer)->score([
            'tier2' => [
                'webrtc' => [
                    'state' => 'ok',
                    'value' => ['audio' => ['count' => 2, 'hash' => 'a1b2c3d4']],
                ],
                'behavior' => [
                    'state' => 'ok',
                    'value' => ['pointer' => ['moves' => 12], 'keyboard' => ['down' => 3]],
                ],
            ],
        ]);

        $this->assertNotContains('tier2:webrtc', $confidence->missing);
        $this->assertNotContains('tier2:behavior', $confidence->missing);
        $this->assertGreaterThan(0, $confidence->earned);
    }

    public function test_a_declined_voice_list_earns_partial_credit_and_is_not_missing(): void
    {
        $confidence = (new ConfidenceScorer)->score(self::claimsWithVoices([
            'state' => 'unavailable',
            'reason' => 'empty',
        ]));

        $this->assertNotContains('tier2:voices', $confidence->missing);
        $this->assertGreaterThan(0, $confidence->earned);
    }
}
