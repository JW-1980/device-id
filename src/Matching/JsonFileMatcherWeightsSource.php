<?php

declare(strict_types=1);

namespace DeviceId\Matching;

/**
 * Reads `LearnedWeights` from a JSON file written by `tools/ml/fit-matcher.php`. A missing,
 * unreadable or malformed file is `null` (rules and hand weights decide), never an exception.
 */
final class JsonFileMatcherWeightsSource implements MatcherWeightsSource
{
    private ?LearnedWeights $cached = null;

    private ?int $cachedMtime = null;

    public function __construct(private readonly string $path) {}

    public function load(): ?LearnedWeights
    {
        $mtime = @filemtime($this->path);
        if ($mtime === false) {
            return null;
        }
        if ($this->cachedMtime === $mtime) {
            return $this->cached;
        }

        $this->cachedMtime = $mtime;
        $raw = @file_get_contents($this->path);
        $data = $raw === false ? null : json_decode($raw, true);
        $this->cached = is_array($data) ? LearnedWeights::fromArray($data) : null;

        return $this->cached;
    }
}
