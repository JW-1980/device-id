<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * Heuristics for a machine-generated or random local part (Castle's `generated_email` and
 * `low_quality_email`), kept honest by requiring AGREEMENT of independent signs:
 *
 * - `digits`: at least five digits (a birth year is four) and digits are 40 % or more of the characters
 * - `entropy`: 14 or more characters with a Shannon entropy of 3.7 bits per character or more
 *   (a 12-character string cannot exceed 3.58, so shorter strings never qualify)
 * - `mixed`: five or more switches between a letter and a digit in a name of 8 or more characters
 * - `consonants`: a run of 6 or more consonants in a name of 8 or more characters
 * - `hex`: 12 or more characters, all hexadecimal, with at least one digit and one letter
 * - `stem_digits`: letters followed by five or more digits (`jessica48201937`)
 *
 * One sign gives `possible`, two or more give `likely`; none gives `none`. Names with many
 * consonants exist (`Schrijvers`), so a single sign is only a hint. Privacy services (Hide My
 * Email, SimpleLogin, Firefox Relay) generate random local parts on purpose, so an address on a
 * forwarding domain is not judged ({@see assess()} with `$onForwardingDomain`).
 *
 * A model feature and a review hint, never a rule: the false-positive risk of entropy alone is
 * medium.
 */
final class GeneratedAddress
{
    public const NONE = 'none';

    public const POSSIBLE = 'possible';

    public const LIKELY = 'likely';

    /**
     * @return array{level: string, signs: list<string>}
     */
    public static function assess(string $localPart, bool $onForwardingDomain = false): array
    {
        $local = strtolower($localPart);
        $plus = strpos($local, '+');
        if ($plus !== false && $plus > 0) {
            $local = substr($local, 0, $plus);
        }
        $local = str_replace(['.', '_', '-'], '', $local);
        $length = strlen($local);
        if ($onForwardingDomain || $length < 6 || preg_match('/^[a-z0-9]+$/', $local) !== 1) {
            return ['level' => self::NONE, 'signs' => []];
        }

        $signs = [];
        $digits = preg_match_all('/\d/', $local);
        if ($digits >= 5 && $digits / $length >= 0.4) {
            $signs[] = 'digits';
        }
        if ($length >= 14 && self::entropy($local) >= 3.7) {
            $signs[] = 'entropy';
        }
        if ($length >= 8 && preg_match_all('/(?<=[a-z])\d|(?<=\d)[a-z]/', $local) >= 5) {
            $signs[] = 'mixed';
        }
        if ($length >= 8 && preg_match('/[^aeiouy\d]{6,}/', $local) === 1) {
            $signs[] = 'consonants';
        }
        if ($length >= 12 && preg_match('/^[0-9a-f]+$/', $local) === 1 && preg_match('/\d/', $local) === 1 && preg_match('/[a-f]/', $local) === 1) {
            $signs[] = 'hex';
        }
        if (preg_match('/^[a-z]{3,}\d{5,}$/', $local) === 1) {
            $signs[] = 'stem_digits';
        }

        return ['level' => match (true) {
            count($signs) >= 2 => self::LIKELY,
            count($signs) === 1 => self::POSSIBLE,
            default => self::NONE,
        }, 'signs' => $signs];
    }

    /**
     * The size of the largest family of local parts that share a letter stem and differ in the
     * digits after it (`name123`, `name124`, `name130`), among the addresses seen from one network
     * or in one burst. Counts only; no address leaves.
     *
     * @param  list<string>  $localParts
     */
    public static function largestStemFamily(array $localParts): int
    {
        $families = [];
        foreach ($localParts as $local) {
            $local = strtolower(is_string($local) ? $local : '');
            $plus = strpos($local, '+');
            if ($plus !== false && $plus > 0) {
                $local = substr($local, 0, $plus);
            }
            $local = str_replace(['.', '_', '-'], '', $local);
            if (preg_match('/^([a-z]{3,})(\d{1,})$/', $local, $m) === 1) {
                $families[$m[1]][$m[2]] = true;
            }
        }

        return $families === [] ? 0 : max(array_map('count', $families));
    }

    private static function entropy(string $text): float
    {
        $length = strlen($text);
        $entropy = 0.0;
        foreach (count_chars($text, 1) as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }
}
