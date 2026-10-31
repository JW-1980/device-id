<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use DeviceId\CheckRegistry;
use DeviceId\Model\FeatureCatalogue;
use DeviceId\Reasons\ReasonCatalogue;
use DeviceId\Support\Verdict;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The reason catalogue: a direction for every reason, no feature without one, and an explanation
 * that lists what raised the risk before what lowered it.
 */
final class ReasonCatalogueTest extends TestCase
{
    #[Test]
    public function every_rule_code_is_described_and_raises_because_a_contradiction_is_never_evidence_of_honesty(): void
    {
        foreach (CheckRegistry::codes() as $code) {
            $entry = ReasonCatalogue::describe($code);
            $this->assertNotNull($entry, $code);
            $this->assertSame(ReasonCatalogue::RAISES, $entry['direction'], $code);
            $this->assertNotSame('', $entry['description'], $code);
        }
    }

    #[Test]
    public function every_entry_has_a_direction_a_family_and_a_description_and_the_lowering_ones_are_the_declared_ones(): void
    {
        $lowers = [];
        foreach (ReasonCatalogue::all() as $code => $entry) {
            $this->assertContains($entry['direction'], [ReasonCatalogue::RAISES, ReasonCatalogue::LOWERS], $code);
            $this->assertNotSame('', $entry['family'], $code);
            $this->assertNotSame('', $entry['description'], $code);
            if ($entry['direction'] === ReasonCatalogue::LOWERS) {
                $lowers[] = $code;
            }
        }
        sort($lowers);
        $this->assertSame(['acct_known_country', 'acct_known_device', 'allow_listed', 'history_not_abuse'], $lowers);
    }

    #[Test]
    public function every_optional_model_feature_has_a_reason_or_is_declared_context_only(): void
    {
        foreach (FeatureCatalogue::optional() as $feature) {
            $this->assertTrue(ReasonCatalogue::coversFeature($feature), "{$feature} reaches the model but has no direction");
        }
        foreach (ReasonCatalogue::CONTEXT_ONLY as $feature) {
            $this->assertTrue(FeatureCatalogue::knows($feature), "{$feature} is declared context but is not a feature");
            $this->assertNull(ReasonCatalogue::directionOf($feature), 'context is not a reason');
        }
    }

    #[Test]
    public function the_direction_of_a_model_adjustment_follows_the_sign_of_its_weight(): void
    {
        $this->assertSame(ReasonCatalogue::LOWERS, ReasonCatalogue::directionOfDisagreement(['code' => 'model_adjustment', 'weight' => -6]));
        $this->assertSame(ReasonCatalogue::RAISES, ReasonCatalogue::directionOfDisagreement(['code' => 'model_adjustment', 'weight' => 6]));
        $this->assertSame(ReasonCatalogue::RAISES, ReasonCatalogue::directionOfDisagreement(['code' => 'transport_default', 'weight' => 45]));
        $this->assertNull(ReasonCatalogue::directionOfDisagreement(['code' => 'made_up_code', 'weight' => 5]));
        $this->assertNull(ReasonCatalogue::directionOf('made_up_code'));
    }

    #[Test]
    public function an_explanation_lists_raising_reasons_by_weight_then_lowering_ones(): void
    {
        $verdict = new Verdict(Verdict::BAND_ELEVATED, 40, ['model_adjustment', 'network_vpn', 'transport_default'], [
            ['code' => 'network_vpn', 'detail' => 'vpn', 'weight' => 4],
            ['code' => 'model_adjustment', 'detail' => 'model', 'weight' => -3],
            ['code' => 'transport_default', 'detail' => 'transport', 'weight' => 45],
            ['code' => 'brand_new_rule', 'detail' => 'a rule nobody described', 'weight' => 7],
        ]);

        $explained = ReasonCatalogue::explain($verdict, ['email_disposable' => 1.0, 'email_free' => 1.0, 'sig_private_mode' => 1.0], ['acct_known_device', 'not_a_reason']);

        $this->assertSame(['transport_default', 'brand_new_rule', 'network_vpn', 'email_disposable', 'model_adjustment', 'acct_known_device'], array_column($explained, 'code'));
        $this->assertSame([ReasonCatalogue::RAISES, ReasonCatalogue::RAISES, ReasonCatalogue::RAISES, ReasonCatalogue::RAISES, ReasonCatalogue::LOWERS, ReasonCatalogue::LOWERS], array_column($explained, 'direction'));
        $this->assertSame('unlisted', $explained[1]['family'], 'an undescribed rule is still visible');
        $this->assertSame('a rule nobody described', $explained[1]['description']);
        $this->assertSame(-3, $explained[4]['weight']);
        $this->assertNotContains('email_free', array_column($explained, 'code'), 'context is not a reason');
    }

    #[Test]
    public function allowed_traffic_gets_a_lowering_allowance_reason(): void
    {
        $verdict = (new Verdict(Verdict::BAND_PASS, 0, [], []))->withAllowance(Verdict::ALLOW_VERIFIED_CRAWLER);

        $this->assertSame([['code' => 'allow_listed', 'direction' => 'lowers']], array_map(static fn (array $e): array => ['code' => $e['code'], 'direction' => $e['direction']], ReasonCatalogue::explain($verdict)));
    }
}
