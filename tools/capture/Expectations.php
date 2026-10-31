<?php

declare(strict_types=1);

namespace DeviceId\Capture;

/**
 * Judges one analysed capture against `expectations.php`.
 *
 * Every failure names the capture, the code and the engine's own detail sentence, so a false
 * positive on an honest browser can be read off the report without opening the claims.
 */
final class Expectations
{
    private const BAND_ORDER = ['pass' => 0, 'elevated' => 1, 'challenge' => 2, 'block' => 3];

    /**
     * @return array<string, mixed>
     */
    public static function load(): array
    {
        /** @var array<string, mixed> $rules */
        $rules = require __DIR__.'/expectations.php';

        return $rules;
    }

    /**
     * @param  array<string, mixed>  $record  the dataset record
     * @param  array<string, mixed>  $analysis  {@see CaptureAnalysis::analyse()}
     * @param  array<string, mixed>  $rules
     * @return list<array{kind: string, code: string|null, message: string}>
     */
    public static function evaluate(array $record, array $analysis, array $rules): array
    {
        $failures = [];
        $class = (string) $record['labels']['class'];
        $browser = (string) $record['browser']['name'];
        $os = (string) $record['machine']['os'];
        $variant = (string) ($record['browser']['variant'] ?? 'default');

        $allowed = array_fill_keys($rules['allowed'][$class] ?? [], true);
        foreach ($rules['environment_artefacts'] ?? [] as $artefact) {
            if (in_array($os, $artefact['os'], true) && in_array($browser, $artefact['browser'], true)
                && (! isset($artefact['class']) || in_array($class, $artefact['class'], true))) {
                $allowed[$artefact['code']] = true;
            }
        }

        $maxBand = $rules['max_band'][$class] ?? null;
        foreach (['merged', 'tier1'] as $view) {
            $answer = $analysis[$view];

            if ($maxBand !== null && self::BAND_ORDER[$answer['band']] > self::BAND_ORDER[$maxBand]) {
                $failures[] = ['kind' => 'band', 'code' => null, 'message' => sprintf(
                    '%s view reached band %s (score %d), above the %s ceiling for a %s capture; codes: %s',
                    $view, $answer['band'], $answer['score'], $maxBand, $class, implode(', ', array_keys($answer['codes'])) ?: 'none',
                )];
            }
            foreach ($answer['codes'] as $code => $meta) {
                if (! isset($allowed[$code])) {
                    $failures[] = ['kind' => 'unexpected_code', 'code' => $code, 'message' => sprintf(
                        '%s view: %s (weight %d) fired on a %s %s capture: %s',
                        $view, $code, $meta['weight'], $class, $browser, $meta['detail'],
                    )];
                }
            }
        }

        $merged = $analysis['merged'];
        foreach ($rules['must_fire'] ?? [] as $assertion) {
            if (! self::applies($assertion, $class, $browser, $os, $variant)) {
                continue;
            }
            if (array_intersect($assertion['any_of'], array_keys($merged['codes'])) === []) {
                $failures[] = ['kind' => 'rule_silent', 'code' => null, 'message' => sprintf(
                    'none of [%s] fired on a %s %s capture (%s); fired: %s',
                    implode(', ', $assertion['any_of']), $class, $browser, $assertion['reason'], implode(', ', array_keys($merged['codes'])) ?: 'none',
                )];
            }
        }
        foreach ($rules['must_penalise'] ?? [] as $assertion) {
            if (self::applies($assertion, $class, $browser, $os, $variant) && ! in_array($assertion['penalty'], $merged['confidence']['penalties'], true)) {
                $failures[] = ['kind' => 'penalty_missing', 'code' => null, 'message' => sprintf(
                    'confidence penalty "%s" missing on a %s %s capture (%s); penalties: %s',
                    $assertion['penalty'], $class, $browser, $assertion['reason'], implode(', ', $merged['confidence']['penalties']) ?: 'none',
                )];
            }
        }
        foreach ($rules['must_not_penalise'] ?? [] as $assertion) {
            if (self::applies($assertion, $class, $browser, $os, $variant) && in_array($assertion['penalty'], $merged['confidence']['penalties'], true)) {
                $failures[] = ['kind' => 'penalty_present', 'code' => null, 'message' => sprintf(
                    'confidence penalty "%s" on a %s %s capture (%s)', $assertion['penalty'], $class, $browser, $assertion['reason'],
                )];
            }
        }

        return $failures;
    }

    /**
     * @param  array<string, mixed>  $assertion
     */
    private static function applies(array $assertion, string $class, string $browser, string $os, string $variant = 'default'): bool
    {
        return in_array($class, $assertion['class'], true)
            && in_array($browser, $assertion['browser'], true)
            && (! isset($assertion['os']) || in_array($os, $assertion['os'], true))
            && (! isset($assertion['variant']) || in_array($variant, $assertion['variant'], true));
    }

    /**
     * The documented reason a pair did not link, or '' when none of `pair_notes` explains it.
     *
     * @param  array<string, mixed>  $pair
     * @param  array<string, mixed>  $match
     * @param  array<string, array<string, mixed>>  $recordsById
     * @param  array<string, mixed>  $rules
     */
    public static function pairNote(array $pair, array $match, array $recordsById, array $rules): string
    {
        $mode = (string) $recordsById[$pair['a']]['browser']['mode'];
        foreach ($rules['pair_notes'] ?? [] as $note) {
            if (isset($note['mode']) && ! in_array($mode, $note['mode'], true)) {
                continue;
            }
            if (isset($note['veto']) && $match['veto'] !== $note['veto']) {
                continue;
            }
            if (isset($note['browser']) && ! in_array($note['browser'], $pair['browsers'], true)) {
                continue;
            }
            if (isset($note['hardware_key_equal']) && $match['hardware_key_equal'] !== $note['hardware_key_equal']) {
                continue;
            }

            return $note['reason'];
        }

        return '';
    }
}
