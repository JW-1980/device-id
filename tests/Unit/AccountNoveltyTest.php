<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\Model\FeatureCatalogue;
use DeviceId\Network\NetworkFacts;
use DeviceId\Reasons\ReasonCatalogue;
use DeviceId\Signals\AccountNovelty;
use DeviceId\Support\Config;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Account novelty: a value the account has not shown before, never on the first observation,
 * never from untrusted or anonymised history.
 */
final class AccountNoveltyTest extends TestCase
{
    private const NOW = 1_793_000_000;

    protected function tearDown(): void
    {
        Config::reset();
        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private static function seen(string $device = 'dk1', string $country = 'NL', int $asn = 1136, string $language = 'nl', string $os = 'windows', int $daysAgo = 3, array $extra = []): array
    {
        return ['device_key' => $device, 'country' => $country, 'asn' => $asn, 'language' => $language, 'os' => $os, 'at' => self::NOW - $daysAgo * 86400] + $extra;
    }

    #[Test]
    public function the_first_observation_of_an_account_has_nothing_new(): void
    {
        $result = AccountNovelty::assess([], self::seen(), self::NOW);

        $this->assertTrue($result->firstObservation);
        $this->assertSame([], $result->features());
        $this->assertSame([], $result->reasons());
        $this->assertFalse($result->suggestsStepUp);
    }

    #[Test]
    public function the_same_values_as_before_are_known_and_lower_the_risk(): void
    {
        $result = AccountNovelty::assess([self::seen(daysAgo: 9), self::seen(daysAgo: 2)], self::seen(daysAgo: 0), self::NOW);

        $this->assertFalse($result->firstObservation);
        $this->assertSame([], $result->features());
        $this->assertSame([['code' => 'acct_known_device', 'direction' => 'lowers'], ['code' => 'acct_known_country', 'direction' => 'lowers']], $result->reasons());
    }

    #[Test]
    public function each_dimension_is_new_on_its_own_and_features_hold_only_for_those(): void
    {
        $history = [self::seen()];

        $this->assertSame(['acct_new_device' => 1.0], AccountNovelty::assess($history, self::seen(device: 'dk2'), self::NOW)->features());
        $this->assertSame(['acct_new_country' => 1.0], AccountNovelty::assess($history, self::seen(country: 'DE'), self::NOW)->features());
        $this->assertSame(['acct_new_asn' => 1.0], AccountNovelty::assess($history, self::seen(asn: 6830), self::NOW)->features());
        $this->assertSame(['acct_new_language' => 1.0], AccountNovelty::assess($history, self::seen(language: 'de'), self::NOW)->features());
        $this->assertSame(['acct_new_os' => 1.0], AccountNovelty::assess($history, self::seen(os: 'android'), self::NOW)->features());
        foreach (FeatureCatalogue::NOVELTY as $feature) {
            $this->assertTrue(ReasonCatalogue::coversFeature($feature), $feature);
        }
    }

    #[Test]
    public function a_new_device_in_a_new_country_suggests_a_step_up_but_either_alone_does_not(): void
    {
        $history = [self::seen()];

        $both = AccountNovelty::assess($history, self::seen(device: 'dk2', country: 'BR'), self::NOW);
        $this->assertTrue($both->suggestsStepUp);
        $this->assertSame(['acct_new_device', 'acct_new_country'], $both->new);
        $this->assertFalse(AccountNovelty::assess($history, self::seen(device: 'dk2'), self::NOW)->suggestsStepUp, 'a new phone at home');
        $this->assertFalse(AccountNovelty::assess($history, self::seen(country: 'BR'), self::NOW)->suggestsStepUp, 'a trip with the same laptop');
    }

    #[Test]
    public function untrusted_and_expired_history_never_becomes_the_baseline(): void
    {
        // An attacker's session was recorded as untrusted: his device is still new on the next visit.
        $history = [self::seen(), self::seen(device: 'attacker', country: 'RU', extra: ['trusted' => false])];
        $result = AccountNovelty::assess($history, self::seen(device: 'attacker', country: 'RU'), self::NOW);
        $this->assertSame(['acct_new_device', 'acct_new_country'], $result->new);

        // Only history older than a year: there is no baseline, so the visit is a first observation.
        $old = AccountNovelty::assess([self::seen(daysAgo: 400)], self::seen(device: 'dk2'), self::NOW);
        $this->assertTrue($old->firstObservation);
        $this->assertSame([], $old->features());

        Config::use(['fingerprint' => ['novelty' => ['history_days' => 500]]]);
        $this->assertSame(['acct_new_device' => 1.0], AccountNovelty::assess([self::seen(daysAgo: 400)], self::seen(device: 'dk2'), self::NOW)->features(), 'the window is configurable');
    }

    #[Test]
    public function a_dimension_the_history_never_knew_is_unknown_not_new(): void
    {
        $history = [['device_key' => 'dk1', 'at' => self::NOW - 86400]];

        $result = AccountNovelty::assess($history, self::seen(), self::NOW);

        $this->assertSame([], $result->new, 'the account never had a country on record, so a country is not new');
        $this->assertSame(['device_key'], $result->known);
    }

    #[Test]
    public function an_anonymised_network_says_nothing_about_country_or_network(): void
    {
        $history = [self::seen()];

        $viaVpn = AccountNovelty::assess($history, self::seen(country: 'SE', asn: 9009, extra: ['anonymised' => true]), self::NOW);
        $this->assertSame([], $viaVpn->new, 'a VPN exit is not a new country of the person');

        // A past VPN session does not teach the account that country either.
        $afterVpn = AccountNovelty::assess([self::seen(), self::seen(country: 'SE', asn: 9009, extra: ['anonymised' => true])], self::seen(country: 'SE', asn: 9009), self::NOW);
        $this->assertSame(['acct_new_country', 'acct_new_asn'], $afterVpn->new);
    }

    #[Test]
    public function an_observation_is_built_from_the_claims_and_the_network_facts_without_keeping_an_address(): void
    {
        $claims = ['tier1' => ['environment' => ['state' => 'ok', 'value' => ['identity' => [
            'userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'language' => 'nl-NL',
        ]]]]];

        $observation = AccountNovelty::observationFrom('dk1', $claims, new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 1136));
        $this->assertSame(['device_key' => 'dk1', 'country' => 'NL', 'asn' => 1136, 'language' => 'nl', 'os' => 'windows', 'anonymised' => false], $observation);

        $hosting = AccountNovelty::observationFrom('dk1', $claims, new NetworkFacts(NetworkFacts::STATE_OK, 'NL', 16509, NetworkFacts::CATEGORY_HOSTING));
        $this->assertTrue($hosting['anonymised']);
        $this->assertSame(['device_key' => null, 'country' => null, 'asn' => null, 'language' => null, 'os' => null, 'anonymised' => false], AccountNovelty::observationFrom(null, [], null));
    }
}
