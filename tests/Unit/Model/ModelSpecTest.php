<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Model;

use DeviceId\Model\ModelSpec;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The only door a model enters the engine through: every way a file can be wrong has a state,
 * and every state means "the rules decide".
 */
final class ModelSpecTest extends TestCase
{
    public const FIXTURE = __DIR__.'/../../Fixtures/model/verdict-logit-test.json';

    private const NOW = 1793491200; // 2026-11-01

    /**
     * @return array<string, mixed>
     */
    private static function document(): array
    {
        return json_decode((string) file_get_contents(self::FIXTURE), true, 32, JSON_THROW_ON_ERROR);
    }

    #[Test]
    public function the_fixture_model_loads(): void
    {
        $load = ModelSpec::load(self::FIXTURE, 45, self::NOW);

        $this->assertSame(ModelSpec::STATE_OK, $load['state'], $load['reason']);
        $this->assertSame('verdict-logit-fixture-0001', $load['model']?->id);
        $this->assertCount(10, $load['model']->features);
    }

    #[Test]
    public function a_missing_file_is_absent(): void
    {
        $this->assertSame(ModelSpec::STATE_ABSENT, ModelSpec::load('/nonexistent/model.json')['state']);
    }

    #[Test]
    public function a_file_that_is_not_json_is_corrupt(): void
    {
        $this->assertSame(ModelSpec::STATE_CORRUPT, ModelSpec::fromJson('not json')['state']);
        $this->assertSame(ModelSpec::STATE_CORRUPT, ModelSpec::fromJson('"a string"')['state']);
    }

    #[Test]
    public function editing_a_coefficient_without_resealing_is_corrupt_and_yields_no_model(): void
    {
        $document = self::document();
        $document['coefficients'][0] = 9.0;

        $load = ModelSpec::fromArray($document, 45, self::NOW);

        $this->assertSame(ModelSpec::STATE_CORRUPT, $load['state']);
        $this->assertNull($load['model'], 'a tampered model must never be evaluated');
    }

    #[Test]
    public function a_different_schema_is_incompatible_even_when_sealed(): void
    {
        $document = self::document();
        $document['schema'] = 2;

        $this->assertSame(ModelSpec::STATE_INCOMPATIBLE, ModelSpec::fromArray(ModelSpec::seal($document), 45, self::NOW)['state']);
    }

    #[Test]
    public function a_feature_the_engine_cannot_produce_is_incompatible(): void
    {
        $document = self::document();
        $document['features'][2] = 'hit:a_rule_that_was_removed';

        $load = ModelSpec::fromArray(ModelSpec::seal($document), 45, self::NOW);

        $this->assertSame(ModelSpec::STATE_INCOMPATIBLE, $load['state']);
        $this->assertStringContainsString('a_rule_that_was_removed', $load['reason']);
    }

    #[Test]
    public function a_coefficient_list_of_the_wrong_length_is_incompatible(): void
    {
        $document = self::document();
        array_pop($document['coefficients']);

        $this->assertSame(ModelSpec::STATE_INCOMPATIBLE, ModelSpec::fromArray(ModelSpec::seal($document), 45, self::NOW)['state']);
    }

    #[Test]
    public function an_old_model_is_stale_but_a_young_one_is_not(): void
    {
        $this->assertSame(ModelSpec::STATE_OK, ModelSpec::load(self::FIXTURE, 45, strtotime('2026-12-10'))['state'], '40 days');
        $this->assertSame(ModelSpec::STATE_STALE, ModelSpec::load(self::FIXTURE, 45, strtotime('2026-12-20'))['state'], '50 days');
    }

    #[Test]
    public function the_hash_is_independent_of_key_order(): void
    {
        $document = self::document();
        $shuffled = array_reverse($document, true);

        $this->assertSame(ModelSpec::hash($document), ModelSpec::hash($shuffled));
        $this->assertSame(ModelSpec::STATE_OK, ModelSpec::fromArray($shuffled, 45, self::NOW)['state']);
    }

    #[Test]
    public function the_hash_survives_a_json_tool_that_drops_zero_fractions(): void
    {
        $json = json_encode(self::document()); // no PRESERVE_ZERO_FRACTION: 1.0 becomes 1

        $this->assertSame(ModelSpec::STATE_OK, ModelSpec::fromJson((string) $json, 45, self::NOW)['state']);
    }
}
