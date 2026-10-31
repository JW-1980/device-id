<?php

declare(strict_types=1);

namespace DeviceId\Transport;

/**
 * An RFC 8941 (Structured Field Values) LIST parser, for the `Sec-CH-UA*` family.
 *
 * `Sec-CH-UA-Full-Version-List` is a list of sf-strings with a `v` parameter:
 *
 *     "Chromium";v="153.0.1234.5", "Not_A Brand";v="8.0.0.0"
 *
 * The parser follows RFC 8941 §4.2 (list, item, bare item, parameters) for the shapes a
 * brand list can take: sf-string and sf-token members, string/token/integer/decimal/boolean
 * parameter values, and inner lists. Per §4.2 an invalid field is discarded as a WHOLE —
 * an inner list where a brand is expected, an invalid string escape, a stray character —
 * which is what makes the result safe to score: malformed input is "no evidence", never a
 * member parsed from the wrong place (standards review STD-22 found the previous regex
 * accepting inner lists and `\9` escapes, and attributing versions to the wrong brand).
 *
 * Only what the two consumers read is modelled; dates, display strings and byte sequences
 * (RFC 9651 additions) fail the parse like any other unknown bare item, which for a UA-CH
 * header is the right answer. Framework-free; ported to the standalone package.
 */
final class StructuredFieldList
{
    /**
     * The `"brand";v="version"` members, in order, or `[]` when the field is not a valid
     * RFC 8941 list of items (an inner list anywhere fails the whole field). Members
     * without a string-valued `v` parameter are skipped; a bare-token brand is kept.
     *
     * @return list<array{0: string, 1: string}>
     */
    public static function brandList(string $field): array
    {
        $members = self::parseList($field);
        if ($members === null) {
            return [];
        }

        $out = [];
        foreach ($members as [$item, $params]) {
            if ($item === null) {
                // An inner list is not a brand: RFC 8941 §4.2 says to fail the field.
                return [];
            }
            $version = $params['v'] ?? null;
            if (is_string($version)) {
                $out[] = [$item, $version];
            }
        }

        return $out;
    }

    /**
     * RFC 8941 §4.2.1 — a list of items (inner lists are returned as a null item so the
     * caller can refuse them), or null when the field is invalid anywhere.
     *
     * @return list<array{0: string|null, 1: array<string, string|int|float|bool>}>|null
     */
    public static function parseList(string $field): ?array
    {
        $input = trim($field, " \t");
        $length = strlen($input);
        $pos = 0;
        $members = [];

        while ($pos < $length) {
            $member = self::parseItemOrInnerList($input, $pos);
            if ($member === null) {
                return null;
            }
            $members[] = $member;

            self::skipOws($input, $pos);
            if ($pos >= $length) {
                return $members;
            }
            if ($input[$pos] !== ',') {
                return null;
            }
            $pos++;
            self::skipOws($input, $pos);
            if ($pos >= $length) {
                // A trailing comma is a parse error (§4.2.1 step 2.5).
                return null;
            }
        }

        return $members;
    }

    /**
     * @return array{0: string|null, 1: array<string, string|int|float|bool>}|null
     */
    private static function parseItemOrInnerList(string $input, int &$pos): ?array
    {
        if (($input[$pos] ?? '') === '(') {
            // An inner list: consumed so the field can be judged as a whole, reported as
            // a null item because no consumer here wants one.
            $pos++;
            while ($pos < strlen($input)) {
                self::skipSpaces($input, $pos);
                if (($input[$pos] ?? '') === ')') {
                    $pos++;
                    $params = self::parseParameters($input, $pos);

                    return $params === null ? null : [null, $params];
                }
                $inner = self::parseBareItem($input, $pos);
                if ($inner === null || self::parseParameters($input, $pos) === null) {
                    return null;
                }
                if ($pos < strlen($input) && $input[$pos] !== ' ' && $input[$pos] !== ')') {
                    return null;
                }
            }

            return null;
        }

        $item = self::parseBareItem($input, $pos);
        if ($item === null) {
            return null;
        }
        $params = self::parseParameters($input, $pos);
        if ($params === null) {
            return null;
        }

        return [is_string($item) ? $item : (string) var_export($item, true), $params];
    }

    /**
     * RFC 8941 §4.2.3.1 — parameters: `;key[=value]`, a value defaulting to true.
     *
     * @return array<string, string|int|float|bool>|null
     */
    private static function parseParameters(string $input, int &$pos): ?array
    {
        $params = [];
        $length = strlen($input);

        while ($pos < $length && $input[$pos] === ';') {
            $pos++;
            self::skipSpaces($input, $pos);
            $key = self::parseKey($input, $pos);
            if ($key === null) {
                return null;
            }
            $value = true;
            if ($pos < $length && $input[$pos] === '=') {
                $pos++;
                $value = self::parseBareItem($input, $pos);
                if ($value === null) {
                    return null;
                }
            }
            // A later duplicate overwrites the earlier one, keeping its position (§4.2.3.1).
            $params[$key] = $value;
        }

        return $params;
    }

    private static function parseKey(string $input, int &$pos): ?string
    {
        if (preg_match('/\G[a-z*][a-z0-9_\-.*]*/', $input, $m, 0, $pos) !== 1) {
            return null;
        }
        $pos += strlen($m[0]);

        return $m[0];
    }

    /**
     * RFC 8941 §4.2.3.1 — a bare item: string, token, integer/decimal or boolean. Byte
     * sequences and the RFC 9651 types are not produced by UA-CH and fail the parse.
     */
    private static function parseBareItem(string $input, int &$pos): string|int|float|bool|null
    {
        $char = $input[$pos] ?? '';

        if ($char === '"') {
            return self::parseString($input, $pos);
        }

        if ($char === '?') {
            $flag = $input[$pos + 1] ?? '';
            if ($flag !== '0' && $flag !== '1') {
                return null;
            }
            $pos += 2;

            return $flag === '1';
        }

        if ($char === '-' || ctype_digit($char)) {
            if (preg_match('/\G-?\d{1,15}(\.\d{1,3})?/', $input, $m, 0, $pos) !== 1) {
                return null;
            }
            $pos += strlen($m[0]);

            return isset($m[1]) ? (float) $m[0] : (int) $m[0];
        }

        if (preg_match('/\G[A-Za-z*][A-Za-z0-9:\/!#$%&\'*+\-.^_`|~]*/', $input, $m, 0, $pos) === 1) {
            $pos += strlen($m[0]);

            return $m[0];
        }

        return null;
    }

    /**
     * RFC 8941 §4.2.5 — an sf-string: only `\"` and `\\` escapes, only printable ASCII.
     */
    private static function parseString(string $input, int &$pos): ?string
    {
        $length = strlen($input);
        $pos++; // the opening quote
        $out = '';

        while ($pos < $length) {
            $char = $input[$pos];
            $pos++;

            if ($char === '\\') {
                $next = $input[$pos] ?? '';
                if ($next !== '"' && $next !== '\\') {
                    return null;
                }
                $out .= $next;
                $pos++;

                continue;
            }

            if ($char === '"') {
                return $out;
            }

            $code = ord($char);
            if ($code < 0x20 || $code > 0x7E) {
                return null;
            }

            $out .= $char;
        }

        return null;
    }

    private static function skipOws(string $input, int &$pos): void
    {
        while ($pos < strlen($input) && ($input[$pos] === ' ' || $input[$pos] === "\t")) {
            $pos++;
        }
    }

    private static function skipSpaces(string $input, int &$pos): void
    {
        while ($pos < strlen($input) && $input[$pos] === ' ') {
            $pos++;
        }
    }
}
