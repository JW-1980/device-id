<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

use NutriCompare\Fingerprint\Transport\TransportIntegrity;

/**
 * The outcome of inspecting what the server could see about a request.
 *
 * ## The separation this class enforces
 *
 * `findings` are things that are *wrong with the request*. `witnesses` are things
 * that were merely *observed* and are not wrong at all - the User-Agent the client
 * claimed, the timezone, the `Accept-Language`, the protocol version, the header
 * order.
 *
 * They are kept in different properties on purpose. Witnesses exist to be
 * *cross-checked against something else*: the client's own JavaScript reports
 * `navigator.platform` and the server already holds `Sec-CH-UA-Platform`, and the
 * interesting event is the disagreement. A property that mixes "wrong" with
 * "observed" makes it impossible to write that check without re-deciding, for
 * every field, which category it is in. `NutriCompare\Fingerprint\Rules\EnvironmentConsistency`
 * reads only from `witnesses()`; `App\Http\Middleware\TransportIntegrityMiddleware`
 * reacts only to `findings()`.
 *
 * @see TransportIntegrity
 */
final class TransportIntegrityResult
{
    /**
     * Witnesses that are derived only when a consumer asks (round-2 PERF-19: the FastCGI
     * header order was derived on every request for a witness nothing reads). Resolved at
     * most once; a resolved value overrides a static one of the same name, a null drops it.
     *
     * @var (\Closure(): array<string, mixed>)|null
     */
    private ?\Closure $lazyWitnesses = null;

    private bool $lazyResolved = false;

    /** @var array<string, string|bool|int|float|list<string>|array<array-key, mixed>> */
    private array $witnesses;

    /**
     * @param  list<TransportFinding>  $findings
     * @param  array<string, string|bool|int|float|list<string>|array<array-key, mixed>>  $witnesses
     */
    public function __construct(
        public readonly array $findings = [],
        array $witnesses = [],
    ) {
        $this->witnesses = $witnesses;
    }

    /**
     * This result with a resolver for on-demand witnesses (see `$lazyWitnesses`).
     *
     * @param  \Closure(): array<string, mixed>  $resolver
     */
    public function withLazyWitnesses(\Closure $resolver): self
    {
        $copy = new self($this->findings, $this->witnesses);
        $copy->lazyWitnesses = $resolver;

        return $copy;
    }

    private function resolveLazy(): void
    {
        if ($this->lazyResolved || $this->lazyWitnesses === null) {
            return;
        }

        $this->lazyResolved = true;
        foreach (($this->lazyWitnesses)() as $name => $value) {
            if (! is_string($name)) {
                continue;
            }
            if ($value === null) {
                unset($this->witnesses[$name]);
            } elseif (is_scalar($value) || is_array($value)) {
                $this->witnesses[$name] = $value;
            }
        }
    }

    /**
     * How many findings a conforming browser cannot produce.
     *
     * This is the number an enforcement decision should be based on, not the
     * total: a request can easily accumulate a dozen soft findings by being
     * unusual, and none of them justify a refusal.
     */
    public function hardCount(): int
    {
        return count(array_filter($this->findings, static fn (TransportFinding $f): bool => $f->isHard()));
    }

    public function softCount(): int
    {
        return count($this->findings) - $this->hardCount();
    }

    /**
     * @return list<string>
     */
    public function codes(): array
    {
        return array_map(static fn (TransportFinding $f): string => $f->code, $this->findings);
    }

    /**
     * @return list<string>
     */
    public function hardCodes(): array
    {
        return array_values(array_map(
            static fn (TransportFinding $f): string => $f->code,
            array_filter($this->findings, static fn (TransportFinding $f): bool => $f->isHard()),
        ));
    }

    public function has(string $code): bool
    {
        return in_array($code, $this->codes(), true);
    }

    public function isClean(): bool
    {
        return $this->findings === [];
    }

    /**
     * An observed-but-not-wrong value, or null when it was absent.
     *
     * The union is deliberate and wider than a scalar, because witnesses come in three
     * shapes and all three are needed:
     *
     * - scalars — `user_agent`, `sec_ch_ua_mobile`, `protocol_is_http2`
     * - lists of strings — `cookie_names` and `header_order`, where the ORDER is the
     *   signal and the values are session material this system has no business holding
     * - structures — `subresource_window`, which carries four named numbers an
     *   operator needs to see
     *
     * Read a list with `witnessList()` and a scalar with `witnessString()`. This
     * accessor returns whatever shape the witness has, unmodified.
     *
     * @return string|bool|int|float|array<array-key, mixed>|null
     */
    public function witness(string $name): string|bool|int|float|array|null
    {
        $this->resolveLazy();
        $value = $this->witnesses[$name] ?? null;

        if (is_array($value)) {
            // Returned AS-IS.
            //
            // This used to filter the array down to its string members, because the
            // only array witnesses at the time were `cookie_names` and `header_order`
            // and both are lists of strings. The moment a structured witness was added
            // — `subresource_window`, which is
            // `{documents, subresources, ratio, degraded}` — the filter silently
            // returned an empty array for it, and every value was quietly lost.
            //
            // That is the worst possible failure mode for a witness: no error, no
            // warning, just an empty structure that a consumer reads as "nothing to
            // report". Use `witnessList()` for a list of strings; use `witness()` for
            // anything else.
            return $value;
        }

        return is_scalar($value) ? $value : null;
    }

    /**
     * A witness as a string, or null when absent or not a scalar.
     */
    public function witnessString(string $name): ?string
    {
        $value = $this->witness($name);

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * A list witness, or null when absent or not a list.
     *
     * @return list<string>|null
     */
    public function witnessList(string $name): ?array
    {
        $value = $this->witness($name);

        if (! is_array($value)) {
            return null;
        }

        $out = [];
        foreach ($value as $item) {
            if (is_string($item)) {
                $out[] = $item;
            }
        }

        return $out;
    }

    /**
     * Every observed value, keyed by name.
     *
     * The value type is the union of the three shapes witnesses actually take: a scalar
     * (`user_agent`), a list of strings (`cookie_names`, `header_order`), and a
     * structure (`subresource_window`). A narrower type here was a lie the analyser
     * could not see through, and it would have been found at the first structured
     * witness rather than in review.
     *
     * @return array<string, string|bool|int|float|list<string>|array<array-key, mixed>>
     */
    public function witnesses(): array
    {
        $this->resolveLazy();

        return $this->witnesses;
    }

    /**
     * @return list<array{code: string, severity: string, detail: string}>
     */
    public function findingsToArray(): array
    {
        return array_map(static fn (TransportFinding $f): array => $f->toArray(), $this->findings);
    }

    /**
     * This result plus one more finding.
     *
     * ## Why this exists
     *
     * `TransportIntegrity` is a pure function of ONE request, so it cannot see history.
     * The subresource-ratio checks need a rolling window, which means the finding is
     * produced by the middleware *after* the analyser has run.
     *
     * Returning a new value object rather than mutating this one keeps the analyser's
     * purity intact — it stays a function of its arguments, which is what makes it
     * exhaustively testable — and keeps the "findings and witnesses are separate
     * lists" property, which several consumers depend on.
     *
     * Duplicates are collapsed: a finding added twice is one problem, and the
     * `hardCount()` and `codes()` consumers should not have to de-duplicate.
     */
    public function withFinding(TransportFinding $finding): self
    {
        foreach ($this->findings as $existing) {
            if ($existing->code === $finding->code) {
                return $this;
            }
        }

        return $this->copyWith([...$this->findings, $finding], $this->witnesses);
    }

    /**
     * A copy with other findings or witnesses that keeps the lazy resolver (unresolved).
     *
     * @param  list<TransportFinding>  $findings
     * @param  array<string, string|bool|int|float|list<string>|array<array-key, mixed>>  $witnesses
     */
    private function copyWith(array $findings, array $witnesses): self
    {
        $copy = new self($findings, $witnesses);
        if (! $this->lazyResolved) {
            $copy->lazyWitnesses = $this->lazyWitnesses;
        }

        return $copy;
    }

    /**
     * The subresource counts this request contributed, as a witness.
     *
     * A witness rather than part of the finding detail, so an operator can see the
     * numbers behind a judgement without parsing prose. `ratio` is null when the state
     * was unavailable, which is distinguishable from zero — "the cache was down" and
     * "this client fetched no subresources" are different facts, and conflating them is
     * how a degraded control starts looking like a detection.
     *
     * @param  array{documents: int, subresources: int, ratio: float|null, degraded: bool}  $window
     */
    public function withSubresourceWindow(array $window): self
    {
        return $this->copyWith($this->findings, [...$this->witnesses, 'subresource_window' => $window]);
    }
}
