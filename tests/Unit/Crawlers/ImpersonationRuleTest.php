<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Crawlers;

use NutriCompare\Fingerprint\CheckRegistry;
use NutriCompare\Fingerprint\Crawlers\CrawlerVerification;
use NutriCompare\Fingerprint\Rules\EnvironmentConsistency;
use NutriCompare\Fingerprint\Scoring\VerdictScorer;
use NutriCompare\Fingerprint\Settings;
use NutriCompare\Fingerprint\Support\TransportRequestFacts;
use NutriCompare\Fingerprint\Support\Verdict;
use NutriCompare\Fingerprint\Transport\TransportIntegrity;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ImpersonationRuleTest extends TestCase
{
    /** @return list<array{string, string}> */
    private function headers(): array
    {
        return [['Host', 'example.test'], ['User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1)'], ['Accept', '*/*']];
    }

    #[Test]
    public function a_forged_crawler_claim_is_a_hard_transport_finding(): void
    {
        $facts = new TransportRequestFacts(crawler: CrawlerVerification::forged('googlebot', 'host9.example.net'));

        $result = (new TransportIntegrity)->analyse($this->headers(), $facts);

        self::assertContains('crawler_impersonation', $result->hardCodes());
    }

    #[Test]
    public function verified_pending_unverifiable_and_absent_claims_add_no_finding(): void
    {
        foreach ([
            CrawlerVerification::verified('googlebot', 'crawl.googlebot.com'),
            CrawlerVerification::pending('googlebot'),
            CrawlerVerification::unverifiable('googlebot'),
            CrawlerVerification::none(),
            null,
        ] as $verification) {
            $result = (new TransportIntegrity)->analyse($this->headers(), new TransportRequestFacts(crawler: $verification));

            self::assertNotContains('crawler_impersonation', $result->codes());
        }
    }

    #[Test]
    public function the_weight_is_45_registered_and_below_the_block_band_alone(): void
    {
        self::assertSame(45, EnvironmentConsistency::weights()['transport_crawler_impersonation']);
        self::assertSame(45, CheckRegistry::weightFor('transport_crawler_impersonation', new Settings));

        $facts = new TransportRequestFacts(crawler: CrawlerVerification::forged('googlebot'));
        $transport = (new TransportIntegrity)->analyse($this->headers(), $facts);
        $verdict = (new VerdictScorer(new EnvironmentConsistency))->score([], $transport);

        self::assertContains('transport_crawler_impersonation', $verdict->reasons);
        $weights = array_column($verdict->disagreements, 'weight', 'code');
        self::assertSame(45, $weights['transport_crawler_impersonation']);
        self::assertSame(68, $this->scoreOf(45), 'alone it scores 68: challenge, not block');
    }

    private function scoreOf(int $weight): int
    {
        return (new VerdictScorer(new EnvironmentConsistency))->scoreFor($weight);
    }

    #[Test]
    public function the_allowance_overrides_the_band_for_allowed_traffic_only(): void
    {
        $transport = (new TransportIntegrity)->analyse($this->headers(), new TransportRequestFacts(crawler: CrawlerVerification::forged('googlebot')));
        $verdict = (new VerdictScorer(new EnvironmentConsistency))->score([], $transport);

        self::assertSame(Verdict::BAND_PASS, $verdict->withAllowance(Verdict::ALLOW_LISTED, true)->band);
        self::assertSame(Verdict::BAND_CHALLENGE, $verdict->band);
    }
}
