<?php

declare(strict_types=1);

namespace DeviceId\Email;

/**
 * The DNS the host provides for the optional mail-domain check. Both outcomes of "the domain has
 * no mail" are reported, and so is "I do not know":
 *
 * - {@see MAIL_OK}: at least one MX host, or (RFC 5321 section 5.1, the implicit MX) an A or AAAA
 *   record.
 * - {@see NO_MAIL}: the resolver is SURE the domain cannot receive mail: it does not exist, has no
 *   MX and no address, or publishes a null MX (RFC 7505, a single `.` target).
 * - {@see UNKNOWN}: a timeout, a server failure, an exception, a resolver that cannot tell
 *   "does not exist" from "failed". Anything doubtful is this, never {@see NO_MAIL}.
 *
 * Implementations must not throw. The calls block on the network, so the check runs in a host
 * job, never in a request.
 */
interface MailDnsResolver
{
    public const MAIL_OK = 'mail_ok';

    public const NO_MAIL = 'no_mail';

    public const UNKNOWN = 'unknown';

    /**
     * @return self::MAIL_OK|self::NO_MAIL|self::UNKNOWN
     */
    public function mailStatus(string $domain): string;
}
