<?php

declare(strict_types=1);

namespace DeviceId\Feedback;

use DeviceId\Model\TrainingRow;

/**
 * The closed vocabulary of the labels an admin gives a visit or a device, modelled on minFraud's
 * Report Transactions tags (`chargeback`, `suspected_fraud`, `not_fraud`, `clear`) and the same in
 * every host, so the training rows of two hosts are comparable.
 *
 * - `confirmed_fraud`: a person decided this was abuse (a confirmed ring member, a refunded
 *   fraudulent order, a banned spammer). Training label weight 1.
 * - `suspected`: probably abuse, not decided. Training label weight 0.5.
 * - `not_abuse`: a false positive, a person decided this visitor is honest. Training label
 *   `honest`, weight 1: it is the label that teaches the model what NOT to flag.
 * - `clear`: retract the earlier tag of this subject. No label remains.
 *
 * The kind of abuse (`automation`, `headless`, `spoof`, `fraud`) stays a {@see TrainingRow}
 * label chosen by the host; this vocabulary only says how sure the human is.
 */
final class FeedbackLabel
{
    public const CONFIRMED_FRAUD = 'confirmed_fraud';

    public const SUSPECTED = 'suspected';

    public const NOT_ABUSE = 'not_abuse';

    public const CLEAR = 'clear';

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [self::CONFIRMED_FRAUD, self::SUSPECTED, self::NOT_ABUSE, self::CLEAR];
    }

    public static function isValid(string $label): bool
    {
        return in_array($label, self::all(), true);
    }
}
