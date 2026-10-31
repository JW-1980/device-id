<?php

declare(strict_types=1);

namespace DeviceId\Model;

/**
 * Loads and validates a model file; the only door a model enters the engine through.
 *
 * ## The JSON schema (schema 1)
 *
 * ```
 * schema 1, model_id, kind "logistic", task "verdict", trained_at (ISO 8601),
 * training_set_sha256, trainer {lib, version}, features [names], intercept, coefficients [floats],
 * calibration {method "platt", a, b}, rules_calibration {a, b} | null,
 * bounds {max_adjustment_weight, min_rule_families_for_escalation},
 * retention {training_row_days}, split {...}, metrics {...}, sha256
 * ```
 *
 * `sha256` covers every other key (canonical JSON, sorted keys): a model edited by hand, or a
 * truncated copy, is `corrupt` and rules decide. A tampered model is a decision bypass, so the
 * hash is verified on every load.
 *
 * States: `ok`; `absent` (no file); `stale` (older than the maximum age); `incompatible` (a
 * different schema, an unknown kind, a feature this engine cannot produce, or a coefficient
 * list of the wrong length); `corrupt` (not JSON, wrong shape, or hash mismatch).
 */
final class ModelSpec
{
    public const SCHEMA = 1;

    public const STATE_OK = 'ok';

    public const STATE_ABSENT = 'absent';

    public const STATE_STALE = 'stale';

    public const STATE_INCOMPATIBLE = 'incompatible';

    public const STATE_CORRUPT = 'corrupt';

    public const STATE_OFF = 'off';

    public const STATE_ERROR = 'error';

    /**
     * @return array{state: string, model: LogisticModel|null, reason: string}
     */
    public static function load(string $path, int $maxAgeDays = 45, ?int $now = null): array
    {
        if (! is_file($path)) {
            return ['state' => self::STATE_ABSENT, 'model' => null, 'reason' => 'no model file at the configured path'];
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return ['state' => self::STATE_ABSENT, 'model' => null, 'reason' => 'the model file is unreadable'];
        }

        return self::fromJson($raw, $maxAgeDays, $now);
    }

    /**
     * @return array{state: string, model: LogisticModel|null, reason: string}
     */
    public static function fromJson(string $json, int $maxAgeDays = 45, ?int $now = null): array
    {
        $document = json_decode($json, true);
        if (! is_array($document)) {
            return self::fail(self::STATE_CORRUPT, 'not a JSON object');
        }

        return self::fromArray($document, $maxAgeDays, $now);
    }

    /**
     * @param  array<array-key, mixed>  $document
     * @return array{state: string, model: LogisticModel|null, reason: string}
     */
    public static function fromArray(array $document, int $maxAgeDays = 45, ?int $now = null): array
    {
        $hash = $document['sha256'] ?? null;
        if (! is_string($hash) || ! hash_equals(self::hash($document), $hash)) {
            return self::fail(self::STATE_CORRUPT, 'the sha256 does not match the content');
        }

        if (($document['schema'] ?? null) !== self::SCHEMA) {
            return self::fail(self::STATE_INCOMPATIBLE, 'schema '.json_encode($document['schema'] ?? null).' is not '.self::SCHEMA);
        }
        if (($document['kind'] ?? null) !== 'logistic' || ($document['task'] ?? null) !== 'verdict') {
            return self::fail(self::STATE_INCOMPATIBLE, 'only task "verdict" of kind "logistic" is supported');
        }

        $features = $document['features'] ?? null;
        $coefficients = $document['coefficients'] ?? null;
        $calibration = $document['calibration'] ?? null;
        if (! is_array($features) || ! is_array($coefficients) || ! is_numeric($document['intercept'] ?? null) || ! is_string($document['model_id'] ?? null)
            || ! is_array($calibration) || ! is_numeric($calibration['a'] ?? null) || ! is_numeric($calibration['b'] ?? null)) {
            return self::fail(self::STATE_CORRUPT, 'a required key is missing or has the wrong type');
        }
        if (! array_is_list($features) || ! array_is_list($coefficients) || count($features) !== count($coefficients)) {
            return self::fail(self::STATE_INCOMPATIBLE, 'features and coefficients differ in length');
        }
        foreach ($features as $index => $name) {
            if (! is_string($name) || ! is_numeric($coefficients[$index])) {
                return self::fail(self::STATE_CORRUPT, 'a feature name or coefficient has the wrong type');
            }
            if (! FeatureCatalogue::knows($name)) {
                return self::fail(self::STATE_INCOMPATIBLE, "feature {$name} is not one this engine produces");
            }
        }

        $bounds = is_array($document['bounds'] ?? null) ? $document['bounds'] : [];
        $rules = $document['rules_calibration'] ?? null;
        $rulesCalibration = is_array($rules) && is_numeric($rules['a'] ?? null) && is_numeric($rules['b'] ?? null)
            ? ['a' => (float) $rules['a'], 'b' => (float) $rules['b']] : null;

        $trainedAt = is_string($document['trained_at'] ?? null) ? strtotime($document['trained_at']) : false;
        $trainedAt = $trainedAt === false ? null : $trainedAt;
        if ($trainedAt === null) {
            return self::fail(self::STATE_CORRUPT, 'trained_at is missing or not a date');
        }

        $model = new LogisticModel(
            $document['model_id'],
            array_values($features),
            array_map(static fn (mixed $c): float => (float) $c, array_values($coefficients)),
            (float) $document['intercept'],
            ['a' => (float) $calibration['a'], 'b' => (float) $calibration['b']],
            $rulesCalibration,
            is_numeric($bounds['max_adjustment_weight'] ?? null) ? max(0, (int) $bounds['max_adjustment_weight']) : 20,
            is_numeric($bounds['min_rule_families_for_escalation'] ?? null) ? max(1, (int) $bounds['min_rule_families_for_escalation']) : 2,
            $trainedAt,
            $document,
        );

        $age = (($now ?? time()) - $trainedAt) / 86400;
        if ($age > $maxAgeDays) {
            return ['state' => self::STATE_STALE, 'model' => $model, 'reason' => sprintf('trained %d days ago, the limit is %d', (int) $age, $maxAgeDays)];
        }

        return ['state' => self::STATE_OK, 'model' => $model, 'reason' => ''];
    }

    /**
     * The sha256 of a document without its own `sha256` key, in canonical form.
     *
     * @param  array<array-key, mixed>  $document
     */
    public static function hash(array $document): string
    {
        unset($document['sha256']);

        return hash('sha256', self::canonical($document));
    }

    /**
     * @param  array<array-key, mixed>  $document
     */
    public static function seal(array $document): array
    {
        $document['sha256'] = self::hash($document);

        return $document;
    }

    private static function canonical(mixed $value): string
    {
        if (is_array($value)) {
            if (! array_is_list($value)) {
                ksort($value);
            }

            return json_encode(array_map(static fn (mixed $v): mixed => json_decode(self::canonical($v), true), $value), JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
        }

        // 1 and 1.0 are the same number to every JSON tool; the hash must not tell them apart.
        if (is_int($value)) {
            $value = (float) $value;
        }

        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }

    /**
     * @return array{state: string, model: null, reason: string}
     */
    private static function fail(string $state, string $reason): array
    {
        return ['state' => $state, 'model' => null, 'reason' => $reason];
    }
}
