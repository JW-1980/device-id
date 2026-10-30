<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit;

use NutriCompare\Fingerprint\Transport\StructuredFieldList;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The RFC 8941 list parser behind `Sec-CH-UA` / `Sec-CH-UA-Full-Version-List`
 * (round-2 STD-22: one parser, and an invalid field is discarded as a whole).
 */
final class StructuredFieldListTest extends TestCase
{
    #[Test]
    public function a_real_full_version_list_parses_in_order(): void
    {
        $field = '"Chromium";v="153.0.8010.12", "Not_A Brand";v="8.0.0.0", "Google Chrome";v="153.0.8010.12"';

        self::assertSame([
            ['Chromium', '153.0.8010.12'],
            ['Not_A Brand', '8.0.0.0'],
            ['Google Chrome', '153.0.8010.12'],
        ], StructuredFieldList::brandList($field));
    }

    #[Test]
    public function a_bare_token_brand_and_extra_parameters_are_accepted(): void
    {
        self::assertSame([['Chromium', '153']], StructuredFieldList::brandList('Chromium;v="153";q=1.0'));
        // SP after `;` and OWS around `,` are allowed (§4.2.1, §4.2.3.2); SP before `;` is not.
        self::assertSame([['Chromium', '153']], StructuredFieldList::brandList(' "Chromium"; v="153" , "X";other=?1'));
    }

    #[Test]
    public function members_without_a_string_version_are_skipped_not_invented(): void
    {
        // An integer `v` is not an sf-string: the member carries no version.
        self::assertSame([['B', '2']], StructuredFieldList::brandList('"A";v=1, "B";v="2"'));
        self::assertSame([], StructuredFieldList::brandList('"A", "B"'));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function invalidFields(): iterable
    {
        yield 'inner list where a brand is expected' => ['("Chromium" "Chrome");v="153"'];
        yield 'inner list among valid members' => ['"Chromium";v="153", ("a" "b")'];
        yield 'invalid string escape' => ['"Chrom\9ium";v="153"'];
        yield 'unterminated string' => ['"Chromium;v="153"'];
        yield 'trailing comma' => ['"Chromium";v="153",'];
        yield 'stray character between members' => ['"Chromium";v="153" x, "B";v="1"'];
        yield 'parameter key starting with a digit' => ['"Chromium";1v="153"'];
        yield 'space before the parameter separator' => ['"Chromium" ;v="153"'];
        yield 'non-ascii in a string' => ["\"Chr\xC3\xB6mium\";v=\"153\""];
        yield 'control character in a string' => ["\"Chr\x01omium\";v=\"153\""];
        yield 'boolean without a digit' => ['"Chromium";v=?x'];
        yield 'empty parameter value' => ['"Chromium";v='];
    }

    #[Test]
    #[DataProvider('invalidFields')]
    public function an_invalid_field_is_discarded_as_a_whole(string $field): void
    {
        self::assertSame([], StructuredFieldList::brandList($field), 'RFC 8941 §4.2: a parse error fails the whole field');
    }

    #[Test]
    public function an_empty_field_is_an_empty_list(): void
    {
        self::assertSame([], StructuredFieldList::parseList(''));
        self::assertSame([], StructuredFieldList::brandList('   '));
    }

    #[Test]
    public function parameters_keep_their_types_and_a_later_duplicate_wins(): void
    {
        $members = StructuredFieldList::parseList('"A";v="1";n=5;d=1.5;b;b=?0, tok;v="2";v="3"');

        self::assertNotNull($members);
        self::assertSame('A', $members[0][0]);
        self::assertSame(['v' => '1', 'n' => 5, 'd' => 1.5, 'b' => false], $members[0][1]);
        self::assertSame('tok', $members[1][0]);
        self::assertSame(['v' => '3'], $members[1][1]);
    }

    #[Test]
    public function escaped_quotes_and_backslashes_are_the_only_escapes(): void
    {
        self::assertSame([['Not"A\\Brand', '8']], StructuredFieldList::brandList('"Not\"A\\\\Brand";v="8"'));
    }
}
