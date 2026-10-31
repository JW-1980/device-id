<?php

declare(strict_types=1);

namespace DeviceId\Email;

use DeviceId\Model\FeatureCatalogue;
use DeviceId\Reasons\ReasonCatalogue;

/**
 * What the e-mail module found about one address: soft features and reason codes, as buckets.
 * It holds no address and no domain, so it may be logged and put into a training row
 * ({@see trainingBuckets()}); it carries no score, band or weight, so a disposable address alone
 * never blocks anything.
 */
final readonly class EmailAssessment
{
    public const CLASS_DISPOSABLE = 'disposable';

    public const CLASS_FORWARDING = 'forwarding';

    public const CLASS_FREE = 'free';

    public const CLASS_OTHER = 'other';

    public const CLASS_UNKNOWN = 'unknown';

    public const CLASS_INVALID = 'invalid';

    /**
     * @param  string  $domainClass  one of the CLASS_ constants (disposable beats forwarding beats free)
     * @param  bool|null  $disposable  null: no usable list
     * @param  string  $mx  `ok`, `no_mail` or `unknown` ({@see DomainMailCheck})
     * @param  string  $generated  {@see GeneratedAddress::NONE}, POSSIBLE or LIKELY
     * @param  bool  $tagged  the local part carries a `+tag`
     */
    public function __construct(
        public string $domainClass,
        public ?bool $disposable = null,
        public ?bool $free = null,
        public ?bool $forwarding = null,
        public string $mx = DomainMailCheck::UNKNOWN,
        public string $generated = GeneratedAddress::NONE,
        public bool $tagged = false,
    ) {}

    public static function invalid(): self
    {
        return new self(self::CLASS_INVALID);
    }

    /**
     * Model features ({@see FeatureCatalogue::EMAIL}); only those that hold.
     *
     * @return array<string, float>
     */
    public function features(): array
    {
        return array_filter([
            'email_disposable' => $this->disposable === true ? 1.0 : 0.0,
            'email_free' => $this->free === true && $this->disposable !== true ? 1.0 : 0.0,
            'email_forwarding_alias' => $this->forwarding === true ? 1.0 : 0.0,
            'email_domain_no_mx' => $this->mx === DomainMailCheck::NO_MAIL ? 1.0 : 0.0,
            'email_generated' => match ($this->generated) {
                GeneratedAddress::LIKELY => 1.0,
                GeneratedAddress::POSSIBLE => 0.5,
                default => 0.0,
            },
            'email_tagged' => $this->tagged ? 1.0 : 0.0,
        ], static fn (float $v): bool => $v > 0.0);
    }

    /**
     * Reason codes with their direction ({@see ReasonCatalogue}), for the
     * explanations. Free mail and plus-tags are context and give none.
     *
     * @return list<array{code: string, direction: string}>
     */
    public function reasons(): array
    {
        $out = [];
        foreach (array_keys($this->features()) as $code) {
            $info = in_array($code, ReasonCatalogue::CONTEXT_ONLY, true) ? null : ReasonCatalogue::describe($code);
            if ($info !== null) {
                $out[] = ['code' => $code, 'direction' => $info['direction']];
            }
        }

        return $out;
    }

    /**
     * The only e-mail context a training row may carry: three buckets, never an address or a
     * domain.
     *
     * @return array{domain_class: string, mx: string, generated: string}
     */
    public function trainingBuckets(): array
    {
        return ['domain_class' => $this->domainClass, 'mx' => $this->mx, 'generated' => $this->generated];
    }
}
